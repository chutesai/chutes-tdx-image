#!/bin/bash
# Runs inside the tools container (privileged): proves the built disk's app partition opens the way
# the guest opens it. dm-verity over the ciphertext with chutes.app_roothash=, then plain dm-crypt
# aes-xts-plain64 with the build's data key (derived from the owner's app key and the build's
# app_context, as chutes-key-fetch derives it) on cryptsetup's standard input, exactly the guest's
# invocation, must give back the app filesystem byte for byte; the owner key itself must not open
# it; a flipped ciphertext byte must fail verity. Each partition gets its own read-only loop device
# (offset and size from the GPT): a container has no udev to make partition nodes.
#
#   build/verify-app.sh VARIANT
set -euo pipefail
VARIANT=${1:?variant}
OUT=/out/$VARIANT
W=/work/verify-$VARIANT
rm -rf "$W" && mkdir -p "$W"
tar -xzf "$OUT/disk.tar.gz" -C "$W"
roothash=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["app_root_hash"])' "$OUT/verity.json")
loops=()
cleanup() {
    cryptsetup close verify-app 2>/dev/null || true
    cryptsetup close verify-app-owner 2>/dev/null || true
    veritysetup close verify-app-verity 2>/dev/null || true
    veritysetup close verify-flipped 2>/dev/null || true
    for l in "${loops[@]}"; do losetup -d "$l" 2>/dev/null || true; done
}
trap cleanup EXIT

# loop FILE NAME: a read-only loop device over the named GPT partition of FILE, in $DEV (not a
# command substitution: the device must be recorded in this shell for the cleanup).
loop() {
    local range
    range=$(sfdisk --json "$1" | python3 -c '
import json, sys
t = json.load(sys.stdin)["partitiontable"]
p = [p for p in t["partitions"] if p.get("name") == sys.argv[1]][0]
print(p["start"] * 512, p["size"] * 512)' "$2")
    set -- "$1" $range
    DEV=$(losetup --find --show --read-only --offset "$2" --sizelimit "$3" "$1")
    loops+=("$DEV")
}

loop "$W/disk.raw" chutes-app; data=$DEV
loop "$W/disk.raw" chutes-app-verity; hash=$DEV
veritysetup open "$data" verify-app-verity "$hash" "$roothash"
context=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["app_context"])' "$OUT/app.meta.json")
size=$(stat -c %s "$OUT/app.erofs")
# close NAME, retrying while the host's udev still probes a new mapping.
close() {
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        cryptsetup close "$1" 2>/dev/null && return 0
        sleep 0.5
    done
    cryptsetup close "$1"
}
# The owner key itself is not the dm-crypt key: it opens to something else.
cryptsetup open --type plain --cipher aes-xts-plain64 --key-size 512 --key-file /dev/stdin --keyfile-size 64 \
    --readonly /dev/mapper/verify-app-verity verify-app-owner < /keys/app.key
if cmp -s -n "$size" /dev/mapper/verify-app-owner "$OUT/app.erofs"; then
    echo "the owner key opens the app partition: it must be the build's data key"
    exit 1
fi
close verify-app-owner
# The guest's exact invocation (chutes-key-fetch): the data key on standard input as /dev/stdin.
/stage/appseal --key /keys/app.key --context "$context" --data-key | \
    cryptsetup open --type plain --cipher aes-xts-plain64 --key-size 512 --key-file /dev/stdin --keyfile-size 64 \
    --readonly /dev/mapper/verify-app-verity verify-app
cmp -n "$size" /dev/mapper/verify-app "$OUT/app.erofs"
echo "app partition: verity and dm-crypt with the derived data key give back the app filesystem ($size bytes)"
close verify-app
veritysetup close verify-app-verity

# A flipped ciphertext byte must fail verity.
cp --sparse=always "$W/disk.raw" "$W/flipped.raw"
start=$(sfdisk --json "$W/disk.raw" | python3 -c '
import json, sys
t = json.load(sys.stdin)["partitiontable"]
print([p for p in t["partitions"] if p.get("name") == "chutes-app"][0]["start"])')
printf '\xff' | dd of="$W/flipped.raw" bs=1 seek=$((start * 512 + 100)) conv=notrunc status=none
loop "$W/flipped.raw" chutes-app; fdata=$DEV
loop "$W/flipped.raw" chutes-app-verity; fhash=$DEV
veritysetup open "$fdata" verify-flipped "$fhash" "$roothash"
if dd if=/dev/mapper/verify-flipped of=/dev/null bs=4096 count=1 status=none 2>/dev/null; then
    echo "a flipped ciphertext byte was read"
    exit 1
fi
veritysetup close verify-flipped
echo "app partition: a flipped ciphertext byte fails dm-verity"
