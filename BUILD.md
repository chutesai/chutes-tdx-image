# Building chutes-tdx-image

Requirements on the build host: Linux x86_64, Docker (the image build runs in a privileged
container), `make`, `git`, any Go 1.21 or later (it downloads the pinned Go 1.27.4 once), network
access to `proxy.golang.org`, `snapshot.debian.org` and `snapshot.ubuntu.com`, and a checkout of
`chutesai/chutes-tdx-gate` (`GATE_REPO`, default `../chutes-tdx-gate`).

This builds the Ubuntu 26.04 template; the Ubuntu 24.04 template is on the `ubuntu-24.04` branch,
with its own BUILD.md.

## 1. The key-window inputs

For the sample image (testing only), make throwaway inputs:

```sh
make dev-keys                      # keys/: app.key, ca.pem, ca.key, service.pem, service.key, server_name, tag
```

For your image, put your own in a private directory and pass `KEYS=/path`: `app.key` (64 random
bytes: your app key, which your key service releases; each build derives its own dm-crypt key from
it and the app's content), `ca.pem` (the CA your key service's certificate chains to),
`server_name` (its TLS name), `tag` (your REPORTDATA tag; never one that starts with
`chutes-tdx-endpoint-attest-v1` or holds a NUL). `app.key` is read by `appseal` and `verify-app`
only and is never printed; `verify-app` pipes the derived data key to `cryptsetup` as the guest does.

## 2. The image

```sh
make image VARIANT=sample          # or probe, capture; GATE_REPO=... if not ../chutes-tdx-gate
make verify-app VARIANT=sample     # the app partition opens as the guest opens it
```

`make image` runs, in order:

1. `make binaries`: the Go programs with the pinned toolchain, `-trimpath`, no build id
   (`out/stage/`);
2. `make gate`: `tdx-gate` from `GATE_REPO` at `GATE_COMMIT`, built by its own `make build`, which
   must hash to `GATE_SHA256`;
3. `make tools-image`: `build/Containerfile` (Debian trixie by digest, its packages from
   `snapshot.debian.org` at 2026-11-15: mkosi 25.3, systemd-repart and ukify 257, erofs-utils,
   cryptsetup; no systemd-stub);
4. `build/build.sh VARIANT` in that container: the app filesystem (`mkfs.erofs`, timestamps fixed),
   encrypted by `appseal` under the build's data key (aes-xts-plain64, sector n tweaked by n),
   dm-verity over the ciphertext (`veritysetup format`, salt and UUID derived from the variant), then
   mkosi (Ubuntu 26.04 `resolute` with its updates and security updates, all from
   `snapshot.ubuntu.com` at 2026-11-22T00:00:00Z: `Mirror=` and
   `mkosi/mkosi.sandbox/etc/apt/sources.list.d/mkosi.sources`; `Seed=` fixed,
   `SOURCE_DATE_EPOCH=1794700800`; first the initrd, `mkosi/mkosi.images/initrd`, then the image,
   its UKI on the image's own systemd-stub from `systemd-boot-efi`, systemd 259), then the disk
   rounded up to a whole GiB (the GPT's backup header moved to the end) and archived as GCE wants:
   `tar --format=oldgnu --sparse
   --hole-detection=raw` (holes found from the content, not the file system) and `gzip -n -9`. The
   build fails unless the UKI's command line holds every token of README "What is measured", its
   stub is the image's `systemd-boot-efi` at 257 or later (checked against the package manifest),
   and the initrd masks the extension and shell units with root locked.

Outputs in `out/images/<variant>/`: `disk.tar.gz`, `disk.tar.gz.sha256`, `uki.efi`,
`uki.efi.authenticode` (its SHA-256 and SHA-384 Authenticode digests), `verity.json` (the command
line, the root and app root hashes, the raw disk size in GiB, the stub's package and version),
`manifest.json` (mkosi's manifest: every package in the image and its version) and, for the sample
variants, `app.erofs` (the app filesystem in plaintext, for `verify-app`) and `app.meta.json` (the
build's `app_context` and `app_kcv`).

## 3. Reproducibility

```sh
make repro VARIANT=sample          # two builds from empty work directories: disk.tar.gz, uki.efi, verity.json, manifest.json equal
```

Two builders with the same commit, the same `GATE_COMMIT`, the same key-window inputs and the same
snapshots get the same bytes (the app partition's ciphertext depends on `app.key`). Build from a
clean git checkout of the commit: `build/build.sh` resets the copied files' modes and times, so
the builder's umask and the checkout time do not change the image. Compare `disk.tar.gz.sha256`
across builders.

## 4. Measurements

With `chutesai/chutes-tdx-measure`:

```sh
chutes-tdx-measure predict --archive out/images/sample/disk.tar.gz --platform-data platform-data.json \
    --machine-type c3-standard-4 -o prediction.json
chutes-tdx-measure write --image-sha256 $(cut -d' ' -f1 out/images/sample/disk.tar.gz.sha256) \
    --entries prediction.json -o m.json
chutes-tdx-measure sign --key key.pem m.json -o m.json.sig
```

`predict` models RTMR1 and RTMR2 from your archive. On GCP, RTMR2 holds systemd-stub's section
measurements (the image's stub, systemd 259), which the stub makes through the firmware's CC
measurement protocol. With Secure Boot off, systemd-stub 258 and later map the kernel themselves, so
RTMR1 holds the UKI's event and no kernel event: use a `chutes-tdx-measure` whose `predict` models
that (its `rtmr1.model` says the stub maps its kernel itself).

A capture of a test boot (`chutes-tdx-measure capture --nonce <nonce>`, which verifies the quote
with Intel DCAP and requires it to carry your nonce) confirms the prediction, but it is not a
source of values to sign: it shows what one genuine TD measured, not that the TD booted your
image. A capture someone else made, Chutes included, describes the VM they booted. Sign only the
measurements `predict` gives for your own archive. Where the model and the machine differ, find
the event that differs and reproduce it from your archive before you sign anything.

## 5. The reference key service

```sh
make binaries
out/stage/chutes-key-service --config keyservice/config.json   # see keyservice/config.example.json
```

It needs `chutes-tdx-measure` on `PATH` (`verify.command`), the TLS certificate and key for
`server_name`, the 64-byte key file (mode 0600), your endpoint ids, your signed documents and your
measurement key; `verify.firmware_dir` keeps the firmware index between verifications (run one
verification before the first window to warm it). It passes `--allowed-project` with
`verify.gce_project` (the pin) besides the VM's own claim. Reference only: replace it with yours.

## Tests

```sh
make test                          # go vet (with and without -tags probe), go test ./... (templatecheck included)
python3 mutants/run.py             # every mutant of mutants/mutants.json must be killed
```
