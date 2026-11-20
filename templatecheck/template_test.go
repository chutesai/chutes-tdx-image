// Package templatecheck checks the image template's files for what closes the boot inputs the TDX
// measurement does not cover, and the units' ordering and hardening. The build itself checks the
// built UKI and initrd (build/build.sh).
package templatecheck_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func read(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// setting returns every value of key= in an INI-like file, continuation lines included.
func setting(text, key string) []string {
	var out []string
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], key+"=") {
			continue
		}
		out = append(out, strings.Fields(strings.TrimPrefix(lines[i], key+"="))...)
		for i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), "#") {
			i++
			out = append(out, strings.Fields(lines[i])...)
		}
	}
	return out
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// The command line closes the inputs Linux and systemd would otherwise take from the host.
func TestCommandLine(t *testing.T) {
	cmdline := setting(read(t, "mkosi", "mkosi.conf"), "KernelCommandLine")
	for _, token := range []string{"root=/dev/mapper/root", "rootfstype=erofs", "systemd.gpt_auto=no", "efi=noruntime",
		"systemd.import_credentials=no", "random.trust_bootloader=off"} {
		if !has(cmdline, token) {
			t.Errorf("mkosi.conf's command line lacks %s", token)
		}
	}
}

// The UKI's stub is the tools container's systemd-stub (256 or later), never noble's 255.
func TestStub(t *testing.T) {
	if has(setting(read(t, "mkosi", "mkosi.conf"), "Packages"), "systemd-boot-efi") {
		t.Error("the image installs noble's systemd-boot-efi (stub 255)")
	}
	build := read(t, "build", "build.sh")
	for _, want := range []string{
		`install -D -m 0644 /usr/lib/systemd/boot/efi/linuxx64.efi.stub "$STUB/usr/lib/systemd/boot/efi/linuxx64.efi.stub"`,
		`case "$stub_version" in 25[6-9]*|2[6-9][0-9]*) ;; *) echo`,
		"ExtraTrees=$STUB",
	} {
		if !strings.Contains(build, want) {
			t.Errorf("build.sh lacks %q", want)
		}
	}
	if !has(setting(read(t, "mkosi", "mkosi.repart", "10-root.conf"), "ExcludeFiles"), "/usr/lib/systemd/boot/") {
		t.Error("the root partition keeps /usr/lib/systemd/boot/")
	}
	if !strings.Contains(read(t, "build", "Containerfile"), "systemd-boot-efi") {
		t.Error("the tools container does not install systemd-boot-efi")
	}
}

var masked = []string{"systemd-sysext.service", "systemd-sysext@.service", "systemd-sysext.socket", "systemd-confext.service",
	"debug-shell.service", "emergency.service", "rescue.service"}

// maskList is the units a postinst script's `for unit in ...; do systemctl mask "$unit"; done` masks.
func maskList(t *testing.T, script string) []string {
	t.Helper()
	re := regexp.MustCompile(`(?s)for unit in ([^;]*); do\s+systemctl mask "\$unit"\n`)
	var units []string
	for _, m := range re.FindAllStringSubmatch(script, -1) {
		units = append(units, strings.Fields(strings.ReplaceAll(m[1], "\\", " "))...)
	}
	return units
}

func checkMasksAndRoot(t *testing.T, name, script string) {
	t.Helper()
	units := maskList(t, script)
	for _, u := range masked {
		if !has(units, u) {
			t.Errorf("%s does not mask %s", name, u)
		}
	}
	if !strings.Contains(script, `case "$(awk -F: '$1 == "root" { print $2 }' /etc/shadow)" in`) ||
		!strings.Contains(script, `'*'*|'!'*) ;;`) {
		t.Errorf("%s does not check that root is locked", name)
	}
}

// Both the root and the initrd mask the units that would run code or mount content from outside the
// measured image, or open a shell, and both check that root is locked.
func TestMasks(t *testing.T) {
	checkMasksAndRoot(t, "the root's postinst", read(t, "mkosi", "mkosi.postinst.chroot"))
	checkMasksAndRoot(t, "the initrd's postinst", read(t, "mkosi", "mkosi.images", "initrd", "mkosi.postinst.chroot"))
	conf := read(t, "mkosi", "mkosi.conf")
	if !has(setting(conf, "Dependencies"), "initrd") || !has(setting(conf, "Initrds"), "%O/initrd.cpio.zst") {
		t.Error("the image does not boot the masked initrd (Dependencies=initrd, Initrds=)")
	}
	if !has(setting(read(t, "mkosi", "mkosi.images", "initrd", "mkosi.conf"), "Include"), "mkosi-initrd") {
		t.Error("the initrd is not mkosi's default one")
	}
	build := read(t, "build", "build.sh")
	if !strings.Contains(build, `the initrd does not mask $unit`) || !strings.Contains(build, `the initrd's root is not locked`) {
		t.Error("build.sh does not check the built initrd")
	}
}

// mkosi never downloads its own tools tree.
func TestToolsTree(t *testing.T) {
	if !regexp.MustCompile(`(?m)^\[Build\]\n(#.*\n)*ToolsTree=\n`).MatchString(read(t, "mkosi", "mkosi.conf")) {
		t.Error("mkosi.conf does not set ToolsTree= (empty: the container's tools)")
	}
}

// The key fetch waits for a synchronized clock.
func TestKeyFetchAfterTimeSync(t *testing.T) {
	unit := read(t, "units", "chutes-key-fetch.service")
	if !has(setting(unit, "After"), "time-sync.target") || !has(setting(unit, "Wants"), "time-sync.target") {
		t.Error("chutes-key-fetch.service is not ordered after time-sync.target")
	}
	if !strings.Contains(read(t, "mkosi", "mkosi.postinst.chroot"), "systemd-time-wait-sync.service") {
		t.Error("systemd-time-wait-sync is not enabled")
	}
}

// The image's gate unit restarts the gate with its key (the fd store) and bounds its memory.
func TestGateUnit(t *testing.T) {
	unit := read(t, "units", "tdx-gate.service")
	for _, line := range []string{"Restart=on-failure\n", "FileDescriptorStoreMax=2\n", "NotifyAccess=main\n", "MemoryMax=1G\n",
		"--memory-budget 536870912\n", "LimitCORE=0\n"} {
		if !strings.Contains(unit, line) {
			t.Errorf("units/tdx-gate.service lacks %q", strings.TrimSpace(line))
		}
	}
}

// The disk and its ESP's FAT use 512-byte sectors (an EDK2 firmware does not mount a FAT with
// 4096-byte sectors on a 512-byte disk); the root's verity keeps 4096-byte blocks.
func TestSectorSize(t *testing.T) {
	if !has(setting(read(t, "mkosi", "mkosi.conf"), "SectorSize"), "512") {
		t.Error("mkosi.conf does not set SectorSize=512")
	}
	verity := read(t, "mkosi", "mkosi.repart", "11-root-verity.conf")
	if !has(setting(verity, "VerityDataBlockSizeBytes"), "4096") || !has(setting(verity, "VerityHashBlockSizeBytes"), "4096") {
		t.Error("the root's verity block sizes are not 4096")
	}
	if !strings.Contains(read(t, "build", "build.sh"), "the first partition is not an ESP with 512-byte FAT sectors") {
		t.Error("build.sh does not check the ESP's sector size")
	}
}

// The module patterns (matched like mkosi: anywhere in the path below the kernel's module
// directory, no leading slash) keep every module the VM needs, in the image and in the initrd.
func TestKernelModules(t *testing.T) {
	conf := read(t, "mkosi", "mkosi.conf")
	check := func(key string, paths []string) {
		re := regexp.MustCompile(strings.Join(setting(conf, key), "|"))
		for _, p := range paths {
			if !re.MatchString(p) {
				t.Errorf("%s keeps no %s", key, p)
			}
		}
	}
	check("KernelModulesInclude", []string{"fs/erofs/erofs.ko.zst", "drivers/nvme/host/nvme.ko.zst", "drivers/md/dm-verity.ko.zst",
		"drivers/md/dm-crypt.ko.zst", "drivers/virt/coco/tdx-guest/tdx-guest.ko.zst", "drivers/net/ethernet/google/gve/gve.ko.zst",
		"crypto/xts.ko.zst", "arch/x86/crypto/aesni-intel.ko.zst"})
	check("KernelModulesInitrdInclude", []string{"fs/erofs/erofs.ko.zst", "drivers/nvme/host/nvme.ko.zst", "drivers/md/dm-verity.ko.zst"})
	if !strings.Contains(read(t, "build", "build.sh"), "the UKI's initrd has no {module}") {
		t.Error("build.sh does not check the initrd's modules")
	}
}

// The guest's cryptsetup invocation (chutes-key-fetch) is the one verify-app tests, and takes the
// key from standard input as a key file: named "-", plain mode would hash it as a passphrase.
func TestCryptsetupInvocation(t *testing.T) {
	src := read(t, "keyfetch", "cmd", "chutes-key-fetch", "main.go")
	m := regexp.MustCompile(`run\(key, "cryptsetup", ([^)]*)\)`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("no cryptsetup call in chutes-key-fetch")
	}
	var guest []string
	for _, lit := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(m[1], -1) {
		guest = append(guest, lit[1])
	}
	want := "open --type plain --cipher aes-xts-plain64 --key-size 512 --key-file /dev/stdin --keyfile-size 64 --readonly"
	if got := strings.Join(guest[:len(guest)-1], " "); got != want { // the last literal is "/dev/mapper/"
		t.Fatalf("chutes-key-fetch runs cryptsetup %s", got)
	}
	verify := strings.ReplaceAll(read(t, "build", "verify-app.sh"), "\\\n    ", "")
	if !strings.Contains(verify, "| cryptsetup "+want+" /dev/mapper/verify-app-verity verify-app\n") {
		t.Error("verify-app.sh does not run the guest's cryptsetup invocation with the piped data key")
	}
}
