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

// The UKI's stub is the image's own systemd-stub (Ubuntu 26.04's systemd-boot-efi, systemd 259), which
// measures into the TDX registers; the build checks its version (257 or later) against the UKI's
// .sdmagic, and the tools container carries no stub the UKI could be built on instead.
func TestStub(t *testing.T) {
	if !has(setting(read(t, "mkosi", "mkosi.conf"), "Packages"), "systemd-boot-efi") {
		t.Error("the image does not install systemd-boot-efi (the UKI's stub)")
	}
	build := read(t, "build", "build.sh")
	for _, want := range []string{
		`stub_version = packages.get("systemd-boot-efi")`,
		`if int(re.match(r"\d+", stub_version).group(0)) < 257:`,
		`if f"systemd-stub {stub_version} " not in magic:`,
		`cp "$W/mkosi-out/disk.manifest" "$OUT/manifest.json"`,
	} {
		if !strings.Contains(build, want) {
			t.Errorf("build.sh lacks %q", want)
		}
	}
	if strings.Contains(build, "ExtraTrees=$STUB") || strings.Contains(build, "/usr/lib/systemd/boot/efi/linuxx64.efi.stub") {
		t.Error("build.sh puts another stub into the image")
	}
	if !has(setting(read(t, "mkosi", "mkosi.conf"), "ManifestFormat"), "json") {
		t.Error("mkosi.conf does not write the package manifest")
	}
	if !has(setting(read(t, "mkosi", "mkosi.repart", "10-root.conf"), "ExcludeFiles"), "/usr/lib/systemd/boot/") {
		t.Error("the root partition keeps /usr/lib/systemd/boot/")
	}
	if strings.Contains(read(t, "build", "Containerfile"), "systemd-boot-efi") {
		t.Error("the tools container installs systemd-boot-efi")
	}
}

// Every package comes from one snapshot.ubuntu.com instant: the release, its updates and its
// security updates (mkosi would otherwise take the security pocket from the live archive).
func TestPackageSources(t *testing.T) {
	conf := read(t, "mkosi", "mkosi.conf")
	release, mirror := setting(conf, "Release"), setting(conf, "Mirror")
	if len(release) != 1 || release[0] != "resolute" {
		t.Fatalf("mkosi.conf's Release= is %v, not resolute (Ubuntu 26.04)", release)
	}
	if len(mirror) != 1 || !regexp.MustCompile(`^https://snapshot\.ubuntu\.com/ubuntu/[0-9]{8}T[0-9]{6}Z$`).MatchString(mirror[0]) {
		t.Fatalf("mkosi.conf's Mirror= is %v, not one snapshot.ubuntu.com instant", mirror)
	}
	sources := read(t, "mkosi", "mkosi.sandbox", "etc", "apt", "sources.list.d", "mkosi.sources")
	field := func(key string) []string {
		m := regexp.MustCompile(`(?m)^` + key + `: (.*)$`).FindAllStringSubmatch(sources, -1)
		if len(m) != 1 {
			t.Fatalf("mkosi.sources has %d %s: lines", len(m), key)
		}
		return strings.Fields(m[0][1])
	}
	if uris := field("URIs"); len(uris) != 1 || uris[0] != mirror[0] {
		t.Errorf("mkosi.sources' URIs %v differ from Mirror= %s", uris, mirror[0])
	}
	if suites := strings.Join(field("Suites"), " "); suites != "resolute resolute-updates resolute-security" {
		t.Errorf("mkosi.sources' suites are %q", suites)
	}
	if field("Types")[0] != "deb" || strings.Join(field("Components"), " ") != "main universe" {
		t.Error("mkosi.sources' types or components changed")
	}
	if strings.Join(field("Signed-By"), " ") != "/usr/share/keyrings/ubuntu-archive-keyring.gpg" {
		t.Error("mkosi.sources is not checked against the Ubuntu archive key")
	}
}

var masked = []string{"systemd-sysext.service", "systemd-sysext@.service", "systemd-sysext.socket", "systemd-confext.service",
	"systemd-sysext-initrd.service", "systemd-confext-initrd.service", "debug-shell.service", "emergency.service", "rescue.service",
	"breakpoint-pre-udev.service", "breakpoint-pre-basic.service", "breakpoint-pre-mount.service", "breakpoint-pre-switch-root.service"}

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
	if !strings.Contains(script, "pw=$(awk -F: '$1 == \"root\" { print $2 }' /etc/passwd)\n"+
		"[ \"$pw\" != x ] || pw=$(awk -F: '$1 == \"root\" { print $2 }' /etc/shadow)\n"+
		"case \"$pw\" in\n    '*'*|'!'*) ;;\n") {
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
	m := regexp.MustCompile(`(?s)for unit in ([^;]*); do\s+\[ "\$\(readlink "\$W/initrd-check/`).FindStringSubmatch(build)
	if m == nil {
		t.Fatal("build.sh has no loop over the built initrd's masks")
	}
	checked := strings.Fields(strings.ReplaceAll(m[1], "\\", " "))
	for _, u := range masked {
		if !has(checked, u) {
			t.Errorf("build.sh does not check that the built initrd masks %s", u)
		}
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

// The unlock maps the app partition without udev's confirmation: the image has no device-mapper
// udev rules, so libdevmapper would wait for that confirmation forever and the boot would hang in
// veritysetup open after the key arrived.
func TestKeyFetchMapsWithoutUdev(t *testing.T) {
	unit := read(t, "units", "chutes-key-fetch.service")
	if !strings.Contains(unitSection(unit, "Service"), "\nEnvironment=DM_DISABLE_UDEV=1\n") {
		t.Error("chutes-key-fetch.service does not set DM_DISABLE_UDEV=1 in [Service]")
	}
}

// unitSection is the body of one [Name] section of a systemd unit (systemd ignores Environment= elsewhere).
func unitSection(unit, name string) string {
	start := strings.Index(unit, "\n["+name+"]\n")
	if strings.HasPrefix(unit, "["+name+"]\n") {
		start = -1
	} else if start < 0 {
		return ""
	}
	body := unit[start+len(name)+3:]
	if end := strings.Index(body, "\n["); end >= 0 {
		body = body[:end+1]
	}
	return body
}

func TestUnitSection(t *testing.T) {
	unit := "[Unit]\nEnvironment=A=1\n\n[Service]\nType=oneshot\nEnvironment=B=1\n\n[Install]\nWantedBy=x\n"
	if got := unitSection(unit, "Service"); !strings.Contains(got, "\nEnvironment=B=1\n") || strings.Contains(got, "A=1") || strings.Contains(got, "WantedBy") {
		t.Errorf("unitSection(Service) = %q", got)
	}
	if got := unitSection(unit, "Unit"); !strings.Contains(got, "\nEnvironment=A=1\n") || strings.Contains(got, "B=1") {
		t.Errorf("unitSection(Unit) = %q", got)
	}
	if unitSection(unit, "Timer") != "" {
		t.Error("a missing section is not empty")
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
