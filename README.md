# chutes-tdx-image

An image template for Chutes' **bring-your-own Intel TDX VM endpoints**: an Ubuntu 26.04 LTS guest
that boots directly from one unified kernel image on a GCE `c3` TDX machine, fetches its app key
through Chutes' key window from **your** key service, unlocks an encrypted and verified app
partition, and serves through `tdx-gate`. It also holds the reference key service, the VM's
key-fetch program, and Chutes' sample application used for testing. Build everything yourself
(`BUILD.md`).

The same template on Ubuntu 24.04 is on the `ubuntu-24.04` branch. Ubuntu 24.04's own systemd-stub
(systemd 255) measures only into the vTPM, so that branch boots its UKI on Debian's systemd-stub 257
from the tools container.

## Licence

MIT (`LICENSE`).

## What the image is

| Part | What |
|---|---|
| Disk | GPT, a whole number of GiB, GCE's archive format (`disk.tar.gz`: one member `disk.raw`, oldgnu, sparse) |
| ESP | the UKI as `\EFI\BOOT\BOOTX64.EFI` (the image's own systemd-stub, systemd 259: kernel, initrd, command line); no shim, no GRUB, no boot entries; Secure Boot off; nothing writes `dbx` or boot variables |
| Root | read-only erofs under dm-verity; `roothash=` on the UKI's command line (measured) |
| App partition | the app filesystem (erofs), encrypted with plain dm-crypt `aes-xts-plain64` under this build's own 512-bit data key (derived from your app key and the app's content), with dm-verity over the **ciphertext**; `chutes.app_roothash=` on the command line |
| Kernel | Ubuntu 26.04 (`linux-image-virtual`, 7.0): `tdx_guest`, `tsm_report` (configfs-tsm), `gve`, `nvme`, dm-verity, dm-crypt, erofs; only these modules (and their dependencies) are in the image |
| Initrd | mkosi's default initrd for Ubuntu 26.04, with system and configuration extensions (`systemd-sysext-initrd` and `systemd-confext-initrd` included), `debug-shell`, `emergency`, `rescue` and the boot breakpoints (`breakpoint-pre-*`) masked, and root locked (`mkosi/mkosi.images/initrd`) |
| Packages | Ubuntu 26.04 (`resolute`): the release, its updates and its security updates, all from one `snapshot.ubuntu.com` instant; `manifest.json` lists every package and version in the image |
| Runtime | systemd 259; systemd-networkd DHCP on the gVNIC, timesyncd to 169.254.169.254, an empty `/etc/resolv.conf`, `/tmp` and `/var` in memory, no swap; no Google guest agent, cloud-init, sshd or getty; the same units masked as in the initrd, root locked |

Command line: `roothash=<hex> console=ttyS0 loglevel=3 root=/dev/mapper/root rootfstype=erofs
systemd.gpt_auto=no efi=noruntime systemd.import_credentials=no random.trust_bootloader=off
chutes.app_roothash=<hex>`.

## What is measured, and what is not

A key service releases your key only to a VM whose MRTD and RTMR0-2 match your signed documents.
Every boot input that can run code before the key fetch is therefore either measured or ignored:

| Input | Register, or how it is ignored |
|---|---|
| The firmware (TDVF) | MRTD |
| The firmware's configuration, Secure Boot variables, `BootOrder` and the `Boot####` it lists (such an entry carrying options changes it) | RTMR0 |
| The GPT; the UKI's Authenticode (so the stub, kernel, initrd, command line, os-release, uname, sbat) | RTMR1. With Secure Boot off, systemd-stub 259 maps the kernel itself, so the firmware adds no event for the kernel: the kernel is covered by the UKI's digest here and by the stub's `.linux` event in RTMR2 |
| Any other EFI image the firmware loads, such as an ESP addon (`\loader\addons\*.addon.efi`, `BOOTX64.EFI.extra.d\*.addon.efi`) | RTMR1: the firmware measures every PE image it loads through LoadImage, and systemd-stub loads each addon that way. An addon of any kind therefore changes RTMR1, including one carrying only an initrd or microcode, whose payloads the stub measures into the vTPM only |
| Each UKI section the stub uses (name and content); a command line the stub takes from a boot entry (one outside `BootOrder`, selected by `BootNext`, included: RTMR2 is then its **only** TDX evidence) or an addon; credentials, sysext or confext files the stub packs from the ESP | RTMR2: GCE's TDVF offers the CC measurement protocol, and systemd-stub (257 and later; the image's is 259) measures through it as well as into the vTPM. An all-zero RTMR2 is never signable (`predict` does not offer it) |
| SMBIOS type-11 strings (`io.systemd.stub.kernel-cmdline-extra`, `io.systemd.credential:*`) | ignored in a confidential VM, by the stub and by PID 1; credential import is off (and the image has no `dmi-sysfs` module to read them) |
| EFI variables (`SystemdOptions`, `LoaderDevicePartUUID`, `FactoryResetRequest`, ...: host-writable with Secure Boot off) | `efi=noruntime`: Linux reads none; the root is `root=/dev/mapper/root` with `systemd.gpt_auto=no`, never found from them. systemd 259 also no longer reads `SystemdOptions` at all |
| fw_cfg and command-line credentials | `systemd.import_credentials=no` |
| The ESP's random seed | mixed in, never credited (`random.trust_bootloader=off`; the CPU's RDRAND is mixed in as well) |
| System and configuration extensions | masked in the initrd and the root |
| A shell on the console (`systemd.debug_shell`, emergency or rescue mode, `systemd.break=` breakpoints) | masked in the initrd and the root; root locked; and asking for one needs a changed, measured, command line |
| The root and app partitions | dm-verity, both root hashes on the measured command line |
| Other attached disks | nothing mounts them (no partition discovery; fstab has tmpfs only) |

### Boot, in order

1. GCE's TDVF loads `BOOTX64.EFI` (RTMR1 records the GPT and its Authenticode digest); systemd-stub
   boots the kernel; the initrd opens the root with dm-verity (`roothash=`).
2. `chutes-key-fetch.service` (after the clock is synchronized: `time-sync.target`) reads
   `chutes-key-relay`, `chutes-endpoint-id`, `instance/id` and `instance/zone` from the metadata
   server and runs the key window (below), retrying until it has the key. It derives this build's
   data key from it (`internal/appkey`) and checks it against the build's check value: a key for
   another image prints `key_check_failed` on the serial console and stops (no retry fixes it).
   It then opens the app partition: dm-verity over the ciphertext with `chutes.app_roothash=`, then
   dm-crypt with the data key on `cryptsetup`'s standard input. No key is written to disk or logged.
3. `chutes-unlock.service` mounts the plaintext app filesystem read-only at `/opt/app`.
4. `app.service` runs the application from `/opt/app` on `127.0.0.1:9000`.
5. `tdx-gate.service` (from `chutesai/chutes-tdx-gate` at a pinned commit) serves port 8080. Its
   `/health` is 503 until the application answers: the first 2xx closes Chutes' key window. If the
   gate fails, systemd restarts it with the same per-boot key (its file descriptor store).

### The key window (reference protocol, `internal/keyrel`)

The VM connects to the relay address (`chutes-key-relay`); Chutes forwards that connection to your
key service's host name on port 443. TLS 1.3 runs end to end (the VM pins your CA and server name in
`/etc/chutes-key-fetch.json`: `{"server_name", "ca_pem", "tag", "app_context", "app_kcv"}`). Over
that one connection:

    GET  /v1/nonce    -> {"nonce": "<64 hex>"}
    POST /v1/release  {"nonce", "quote_b64", "endpoint_id", "instance": {"project_number", "zone", "instance_id"}}
                      -> {"key_b64"}

The quote's REPORTDATA is `SHA-512(tag || 0x00 || nonce || exporter || endpoint_id)`: `exporter` is
the connection's TLS exported keying material (label `EXPORTER-chutes-tdx-key-release`, no context,
32 bytes), `endpoint_id` the 36 ASCII bytes of `chutes-endpoint-id`, `tag` by default
`chutes-tdx-image-keyrelease-ref-v1` (never the gate's `/attest` tag: the code refuses any tag that
starts with it or holds a NUL byte).

**Each attempt is one of the window's four connections.** The VM gives one attempt 180 s, longer
than the reference service's verification (at most 120 s), so a slow first verification (a cold
firmware index: Google's endorsement and binary, Intel's collateral, Google's registry) is waited
for. Make your key service answer within that, keep its firmware index between verifications
(`verify.firmware_dir`), and refuse rather than stall: every abandoned or failed
attempt spends a connection, and after four the VM waits for its deadline and is replaced.

### The reference key service (`keyservice/`: reference only, replace with yours)

Releases the key to a VM only when, over the connection that will carry it: the nonce is the one
issued on that connection, unused and at most 60 s old; the endpoint id is in its list of **your
own** endpoints (a copy of your image booted under someone else's endpoint gets nothing); the
instance's project is Chutes' customer-VM project; and `chutes-tdx-measure verify-quote` passes
**every** row: Intel's collateral and debug off, the REPORTDATA above, the platform, your signed
measurement documents with the firmware floor, and Google's provenance of the instance
(`provider_root` is mandatory). See `keyservice/config.example.json`.

On a public port it bounds what anyone can make it hold or run: a nonce is deleted when used or
expired, at most 4096 are outstanding (then `503 nonce_busy`), and at most 4 verifications run at
once (the others wait for a slot).

### Variants (`make image VARIANT=…`)

| Variant | For |
|---|---|
| `sample` | Chutes' sample app (`/v1/echo`, `/v1/sealed-error` 418, `/v1/stream`, a `/health` that turns 200 after 60 s) |
| `probe` | the sample plus `/v1/probe`, which tries every path out of the VM and returns what happened in its sealed answer, to test the VM's network isolation. Test image only |
| `capture` | no gate, no key window, no app partition: `chutes-capture` prints `CHUTES-CAPTURE-V1 <base64 {"quote","ccel"}>` on the serial console, from which Chutes records the platform's firmware measurements |

For your own image, replace `sample-app` with your service (it goes on the encrypted app partition),
the gate's routes in `build/build.sh`, and the key-window inputs (`KEYS=`). What Chutes requires:
the metadata reads (`chutes-key-relay`, `chutes-endpoint-id`, `instance/id`), the disk format, the
health rule and the gate configuration. Everything else is yours to change.

## Layout

```
mkosi/          the mkosi template: mkosi.conf, mkosi.repart/ (ESP, root and its verity, app and its verity),
                mkosi.extra/ (networkd, timesyncd, fstab, modules, an empty resolv.conf), mkosi.postinst.chroot,
                mkosi.images/initrd/ (the initrd: mkosi's default with the masks), mkosi.sandbox/ (the package
                sources, pinned to one snapshot)
units/          chutes-key-fetch.service, chutes-unlock.service, tdx-gate.service, app.service, chutes-capture.service
keyfetch/       the VM's side of the key window (cmd/chutes-key-fetch)
keyservice/     the reference key service (cmd/chutes-key-service)
sample-app/     the sample app (cmd/sample-app; -tags probe adds /v1/probe) and the capture program (cmd/chutes-capture)
internal/       configfs-tsm, the metadata server, the key-release protocol, the app partition's key derivation
tools/          appseal (the app partition's encryption), pehash (Authenticode digests), devkeys (dev inputs)
build/          the pinned tools container, build.sh (one variant end to end, with its checks), verify-app.sh
templatecheck/  tests of the template's files: the command line, the stub, the package sources, the masks, the units
mutants/        one mutant per check of the key fetch, the key service and the template
```
