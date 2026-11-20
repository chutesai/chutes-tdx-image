#!/bin/bash
# Runs inside the tools container (build/Containerfile), as root: one image variant, end to end.
#
#   build/build.sh VARIANT        VARIANT = sample | probe | capture
#
# Mounts: /src (this repository, read-only), /stage (the host-built binaries: tdx-gate,
# chutes-key-fetch, sample-app, sample-app-probe, chutes-capture, appseal, pehash), /keys (the
# build's key-window inputs: app.key, ca.pem, server_name, tag; read-only), /out (the outputs).
# SOURCE_DATE_EPOCH fixes every timestamp. Nothing here prints a key.
#
# The UKI's stub is this container's systemd-stub (Debian's systemd-boot-efi 257): it measures the
# UKI's sections, and anything it adds (an addon's or the firmware's command line, ESP sidecars)
# into the TDX registers as well as the vTPM, and ignores SMBIOS command-line additions in a
# confidential VM. Noble's own stub (255) measures into the vTPM only.
set -euo pipefail
VARIANT=${1:?variant}
SDE=${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH}
export SOURCE_DATE_EPOCH=$SDE
W=/work/$VARIANT
OUT=/out/$VARIANT
rm -rf "$W" "$OUT"
mkdir -p "$W" "$OUT"
cp -a /src/mkosi "$W/mkosi"
# A checkout's file modes follow the builder's umask, and its file times the checkout. Give every
# file git's mode (0755 when executable, else 0644), every directory 0755 and every time
# SOURCE_DATE_EPOCH, so any clean checkout of a commit builds the same image.
find "$W/mkosi" -type d -exec chmod 0755 {} +
find "$W/mkosi" -type f -perm -u=x -exec chmod 0755 {} +
find "$W/mkosi" -type f ! -perm -u=x -exec chmod 0644 {} +
find "$W/mkosi" -exec touch -h -d "@$SDE" {} +
EXTRA=$W/extra
BUILD=$EXTRA/usr/lib/chutes-build
mkdir -p "$EXTRA/usr/local/bin" "$EXTRA/usr/lib/systemd/system" "$BUILD"
cmdline=""
# The stub, as its own tree (repart keeps /usr/lib/systemd/boot/ out of the root partition).
STUB=$W/stub
install -D -m 0644 /usr/lib/systemd/boot/efi/linuxx64.efi.stub "$STUB/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
stub_version=$(dpkg-query -W -f='${Version}' systemd-boot-efi)
case "$stub_version" in 25[6-9]*|2[6-9][0-9]*) ;; *) echo "systemd-stub $stub_version: 256 or later needed" >&2; exit 2 ;; esac

# A deterministic UUID and salt from a label (the same on every builder).
derive() { printf '%s' "chutes-tdx-image:$VARIANT:$1" | sha256sum | cut -c1-64; }
uuid_of() { local h; h=$(derive "$1"); echo "${h:0:8}-${h:8:4}-4${h:13:3}-8${h:17:3}-${h:20:12}"; }

case "$VARIANT" in
sample|probe)
    install -m 0755 /stage/tdx-gate /stage/chutes-key-fetch "$EXTRA/usr/local/bin/"
    install -m 0644 /src/units/tdx-gate.service /src/units/chutes-key-fetch.service \
        /src/units/chutes-unlock.service /src/units/app.service "$EXTRA/usr/lib/systemd/system/"
    printf '%s\n' tdx-gate.service chutes-key-fetch.service chutes-unlock.service app.service > "$BUILD/units.enable"
    mkdir -p "$EXTRA/etc/tdx-gate"
    routes='{"path": "/v1/echo", "stream": false, "app_path": "/v1/echo"},
            {"path": "/v1/sealed-error", "stream": false, "app_path": "/v1/sealed-error"},
            {"path": "/v1/stream", "stream": true, "app_path": "/v1/stream"}'
    if [ "$VARIANT" = probe ]; then
        routes="$routes, {\"path\": \"/v1/probe\", \"stream\": false, \"app_path\": \"/v1/probe\"}"
    fi
    python3 - "$EXTRA/etc/tdx-gate/config.json" "$routes" <<'PY'
import json, sys
routes = json.loads("[" + sys.argv[2] + "]")
doc = {"schema": "chutes.tdx-gate-config.v1", "listen": "0.0.0.0:8080",
       "app": {"base": "http://127.0.0.1:9000", "health_path": "/health", "timeout_s": 600},
       "health_path": "/health", "routes": routes, "identity": {"source": "gce-metadata"},
       "limits": {"max_request_bytes": 8454144, "max_plaintext_bytes": 67108864, "max_answer_bytes": 16777216,
                  "max_inflight": 64, "replay_cache_entries": 65536},
       "tsm_report_dir": "/sys/kernel/config/tsm/report"}
open(sys.argv[1], "w").write(json.dumps(doc, indent=1) + "\n")
PY
    # The app partition: the sample app on erofs, encrypted under this build's data key (derived
    # from the owner's app key and the app's content: internal/appkey), then dm-verity over the
    # ciphertext.
    mkdir -p "$W/app/bin"
    if [ "$VARIANT" = probe ]; then app=/stage/sample-app-probe; else app=/stage/sample-app; fi
    install -m 0755 "$app" "$W/app/bin/sample-app"
    echo "chutes-tdx-image $VARIANT" > "$W/app/VERSION"
    mkfs.erofs -T "$SDE" --all-root -U "$(uuid_of app-erofs)" "$W/app.erofs" "$W/app"
    /stage/appseal --key /keys/app.key --in "$W/app.erofs" --out "$BUILD/app.ct" --meta "$W/app.meta.json"
    veritysetup format --data-block-size 4096 --hash-block-size 4096 --salt "$(derive app-verity-salt)" \
        --uuid "$(uuid_of app-verity)" --root-hash-file "$W/app.roothash" "$BUILD/app.ct" "$BUILD/app.verity" >/dev/null
    app_roothash=$(tr -d '\n' < "$W/app.roothash")
    cmdline="chutes.app_roothash=$app_roothash"
    python3 - "$EXTRA/etc/chutes-key-fetch.json" "$W/app.meta.json" <<'PY'
import json, sys
meta = json.load(open(sys.argv[2]))
doc = {"server_name": open("/keys/server_name").read().strip(), "ca_pem": open("/keys/ca.pem").read(),
       "tag": open("/keys/tag").read().strip(), "app_context": meta["app_context"], "app_kcv": meta["app_kcv"]}
open(sys.argv[1], "w").write(json.dumps(doc, indent=1) + "\n")
PY
    cp "$W/app.meta.json" "$OUT/app.meta.json"
    cp "$W/app.erofs" "$OUT/app.erofs"
    ;;
capture)
    install -m 0755 /stage/chutes-capture "$EXTRA/usr/local/bin/"
    install -m 0644 /src/units/chutes-capture.service "$EXTRA/usr/lib/systemd/system/"
    echo chutes-capture.service > "$BUILD/units.enable"
    rm "$W/mkosi/mkosi.repart/20-app.conf" "$W/mkosi/mkosi.repart/21-app-verity.conf"
    app_roothash=""
    ;;
*) echo "unknown variant $VARIANT" >&2; exit 2 ;;
esac

mkdir -p "$W/mkosi/mkosi.conf.d"
cat > "$W/mkosi/mkosi.conf.d/90-build.conf" <<EOF
[Output]
ImageId=chutes-tdx-$VARIANT

[Content]
ExtraTrees=$EXTRA
ExtraTrees=$STUB
SourceDateEpoch=$SDE
EOF
# Appended to mkosi.conf's command line (an empty KernelCommandLine= would reset it).
if [ -n "$cmdline" ]; then
    echo "KernelCommandLine=$cmdline" >> "$W/mkosi/mkosi.conf.d/90-build.conf"
fi

cd "$W/mkosi"
mkosi --force --output-directory="$W/mkosi-out" build
cd "$W"

# The ESP's FAT has 512-byte sectors, as the disk (an EDK2 firmware does not mount it otherwise).
python3 - "$W/mkosi-out/disk.raw" <<'PY'
import struct, sys
with open(sys.argv[1], "rb") as d:
    d.seek(1024)
    entry = d.read(128)
    d.seek(struct.unpack_from("<Q", entry, 32)[0] * 512)
    boot = d.read(512)
if entry[:16] != bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b") or struct.unpack_from("<H", boot, 11)[0] != 512:
    sys.exit("the first partition is not an ESP with 512-byte FAT sectors")
PY

# GCE's format: a raw disk of whole GiB (the GPT's backup header moved to the new end), then one
# member disk.raw in an oldgnu sparse tar (holes found from the content: --hole-detection=raw).
cp --sparse=always "$W/mkosi-out/disk.raw" "$W/disk.raw"
size=$(stat -c %s "$W/disk.raw")
gib=$((1024 * 1024 * 1024))
truncate -s $(( (size + gib - 1) / gib * gib )) "$W/disk.raw"
sfdisk --quiet --relocate gpt-bak-std "$W/disk.raw"
tar --format=oldgnu --sparse --hole-detection=raw --mtime="@$SDE" --owner=0 --group=0 --numeric-owner \
    --mode=0644 -C "$W" -cf "$W/disk.tar" disk.raw
gzip -n -9 -c "$W/disk.tar" > "$OUT/disk.tar.gz"
cp "$W/mkosi-out/disk.efi" "$OUT/uki.efi"
( cd "$OUT" && sha256sum disk.tar.gz > disk.tar.gz.sha256 )

# The UKI's measured facts: its command line (the root and app root hashes), its stub, its
# Authenticode digests, and the sizes. The build fails unless the command line holds every token
# that closes an unmeasured input, the stub is the container's, and the initrd masks every
# code-running extension point with root locked.
python3 - "$OUT" "$app_roothash" "$(stat -c %s "$W/disk.raw")" "$stub_version" \
    "$(sha256sum /usr/lib/systemd/boot/efi/linuxx64.efi.stub | cut -c1-64)" <<'PY'
import json, re, sys, pefile
out, app_roothash, raw_size, stub_version, stub_sha256 = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
pe = pefile.PE(out + "/uki.efi", fast_load=True)
sections = {s.Name.rstrip(b"\0").decode(): s.get_data()[: s.Misc_VirtualSize] for s in pe.sections}
cmdline = sections[".cmdline"].rstrip(b"\0").decode()
tokens = cmdline.split()
for need in ("root=/dev/mapper/root", "rootfstype=erofs", "systemd.gpt_auto=no", "efi=noruntime",
             "systemd.import_credentials=no", "random.trust_bootloader=off"):
    if need not in tokens:
        sys.exit(f"the UKI's command line lacks {need}")
magic = sections[".sdmagic"].rstrip(b"\0").decode()
if f"systemd-stub {stub_version} " not in magic:
    sys.exit(f"the UKI's stub is not the container's {stub_version}: {magic!r}")
m = re.search(r"(?:^|\s)roothash=([0-9a-f]{64})(?:\s|$)", cmdline)
doc = {"schema": "chutes.tdx-image-verity.v1", "cmdline": cmdline, "root_hash": m.group(1) if m else None,
       "app_root_hash": app_roothash or None, "disk_raw_bytes": raw_size, "disk_size_gb": raw_size // 2**30,
       "systemd_stub": {"package": "systemd-boot-efi", "version": stub_version, "sha256": stub_sha256},
       "uki_sections": sorted(sections)}
open(out + "/verity.json", "w").write(json.dumps(doc, indent=1) + "\n")
PY
# The UKI's initrd (mkosi's, then the kernel modules initrd) holds what mounts the root.
python3 - "$OUT/uki.efi" <<'PY'
import pefile, re, subprocess, sys
pe = pefile.PE(sys.argv[1], fast_load=True)
initrd = next(s.get_data()[: s.Misc_VirtualSize] for s in pe.sections if s.Name.rstrip(b"\0") == b".initrd")
names = set()
# The initrds are concatenated (padded): decompress from every zstd frame start, keep what parses.
for start in (m.start() for m in re.finditer(re.escape(b"\x28\xb5\x2f\xfd"), initrd)):
    data = subprocess.run(["zstd", "-dcq"], input=initrd[start:], capture_output=True).stdout
    pos = 0
    while pos + 110 <= len(data):  # newc archives
        if data[pos:pos + 6] != b"070701":
            pos += 4
            continue
        try:
            size, namesize = int(data[pos + 54:pos + 62], 16), int(data[pos + 94:pos + 102], 16)
        except ValueError:
            pos += 4
            continue
        names.add(data[pos + 110:pos + 110 + namesize - 1].decode("utf-8", "replace"))
        pos = (pos + 110 + namesize + 3) // 4 * 4
        pos = (pos + size + 3) // 4 * 4
for module in ("kernel/fs/erofs/erofs.ko", "kernel/drivers/md/dm-verity.ko", "kernel/drivers/nvme/host/nvme.ko"):
    if not any(module in n for n in names):
        sys.exit(f"the UKI's initrd has no {module}")
PY
# The initrd mkosi built (mkosi.images/initrd): every mask, and root locked.
mkdir -p "$W/initrd-check" && (cd "$W/initrd-check" && zstd -dc "$W/mkosi-out/initrd.cpio.zst" | cpio -id --quiet etc/shadow 'etc/systemd/system/*' 2>/dev/null)
for unit in systemd-sysext.service systemd-sysext@.service systemd-sysext.socket systemd-confext.service \
            debug-shell.service emergency.service rescue.service; do
    [ "$(readlink "$W/initrd-check/etc/systemd/system/$unit")" = /dev/null ] || { echo "the initrd does not mask $unit" >&2; exit 1; }
done
grep -Eq '^root:[*!]' "$W/initrd-check/etc/shadow" || { echo "the initrd's root is not locked" >&2; exit 1; }
/stage/pehash "$OUT/uki.efi" > "$OUT/uki.efi.authenticode"
ls -l "$OUT"
cat "$OUT/disk.tar.gz.sha256" "$OUT/uki.efi.authenticode"
