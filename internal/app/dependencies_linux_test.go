//go:build integration && linux

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/model"
	"github.com/parhamfa/chr-install/internal/platform"
)

func TestInitramfsDependencyInstallUbuntu2604(t *testing.T) {
	if os.Getenv("CHR_DEPENDENCY_INTEGRATION") != "1" {
		t.Skip("set CHR_DEPENDENCY_INTEGRATION=1 inside a disposable Ubuntu 26.04 environment")
	}
	if os.Geteuid() != 0 {
		t.Fatal("dependency integration requires root inside a disposable environment")
	}
	releaseData, err := os.ReadFile("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	release := platform.ParseOSRelease(string(releaseData))
	if release["ID"] != "ubuntu" || release["VERSION_ID"] != "26.04" {
		t.Fatalf("dependency integration requires Ubuntu 26.04, found %s %s", release["ID"], release["VERSION_ID"])
	}
	runner := command.OSRunner{}
	if missing := missingInitramfsCommands(runner); len(missing) != 2 {
		t.Fatalf("disposable base image unexpectedly contains initramfs tooling: missing=%v", missing)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	host := model.Host{Distribution: "ubuntu", Version: "26.04", Supported: true}
	if err := installInitramfsTools(ctx, runner, host, os.Stdout); err != nil {
		t.Fatal(err)
	}
	if missing := missingInitramfsCommands(runner); len(missing) != 0 {
		t.Fatalf("required commands remain unavailable: %v", missing)
	}
	for _, path := range []string{
		"/etc/initramfs-tools/initramfs.conf",
		"/usr/share/initramfs-tools/hook-functions",
	} {
		info, err := os.Lstat(filepath.Clean(path))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("required initramfs resource %s is unavailable or unsafe", path)
		}
	}
	for _, packageName := range []string{initramfsToolsPackage, "dracut-install"} {
		status, err := runner.Run(ctx, "dpkg-query", "-W", "-f=${db:Status-Abbrev}", packageName)
		if err != nil || string(status) != "ii " {
			t.Fatalf("required package %s is not fully installed: status=%q err=%v", packageName, status, err)
		}
	}
	if status, err := runner.Run(ctx, "dpkg-query", "-W", "-f=${db:Status-Abbrev}", "initramfs-tools"); err == nil && string(status) == "ii " {
		t.Fatal("core-tool installation unexpectedly installed the initramfs-tools automation package")
	}
}
