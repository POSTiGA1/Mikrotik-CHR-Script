package app

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/parhamfa/chr-install/internal/model"
)

func TestDependencyInstallOfferRequiresOnlyRepairableBlockers(t *testing.T) {
	report := model.Preflight{
		Host: model.Host{Distribution: "ubuntu", Version: "26.04", Supported: true},
		Issues: []model.Issue{
			{Severity: model.SeverityBlocker, Code: "initramfs-builder"},
			{Severity: model.SeverityInfo, Code: "dhcp-absent"},
			{Severity: model.SeverityBlocker, Code: "initramfs-inspector"},
		},
	}
	missing, offered := dependencyInstallOffer(report)
	if !offered || strings.Join(missing, ",") != "lsinitramfs,mkinitramfs" {
		t.Fatalf("unexpected dependency offer: offered=%t missing=%v", offered, missing)
	}
	report.Issues = append(report.Issues, model.Issue{Severity: model.SeverityBlocker, Code: "staging"})
	if missing, offered := dependencyInstallOffer(report); offered || missing != nil {
		t.Fatalf("unrelated blocker must suppress package mutation: offered=%t missing=%v", offered, missing)
	}
}

func TestDependencyInstallOfferRejectsUnsupportedHost(t *testing.T) {
	report := model.Preflight{
		Host:   model.Host{Distribution: "ubuntu", Version: "future", Supported: false},
		Issues: []model.Issue{{Severity: model.SeverityBlocker, Code: "initramfs-builder"}},
	}
	if missing, offered := dependencyInstallOffer(report); offered || missing != nil {
		t.Fatalf("unsupported host must suppress package mutation: offered=%t missing=%v", offered, missing)
	}
}

func TestInstallInitramfsToolsUsesBoundedNoninteractiveAPT(t *testing.T) {
	runner := &dependencyRunner{paths: map[string]string{
		"apt-get": "/usr/bin/apt-get",
		"env":     "/usr/bin/env",
	}}
	var output bytes.Buffer
	host := model.Host{Distribution: "ubuntu", Version: "26.04", Supported: true}
	if err := installInitramfsTools(context.Background(), runner, host, &output); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("APT calls = %v", runner.calls)
	}
	update := strings.Join(runner.calls[0], " ")
	install := strings.Join(runner.calls[1], " ")
	for _, required := range []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "Dpkg::Lock::Timeout=60", "/usr/bin/apt-get", "update"} {
		if !strings.Contains(update, required) {
			t.Fatalf("APT update lacks %q: %s", required, update)
		}
	}
	for _, required := range []string{"install", "--yes", initramfsToolsPackage} {
		if !strings.Contains(install, required) {
			t.Fatalf("APT install lacks %q: %s", required, install)
		}
	}
	if !strings.Contains(output.String(), "installed and verified") {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func TestInstallInitramfsToolsDoesNothingWhenPresent(t *testing.T) {
	runner := &dependencyRunner{paths: map[string]string{
		"lsinitramfs": "/usr/bin/lsinitramfs",
		"mkinitramfs": "/usr/sbin/mkinitramfs",
	}}
	host := model.Host{Distribution: "debian", Version: "13", Supported: true}
	if err := installInitramfsTools(context.Background(), runner, host, nil); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unexpected package-manager calls: %v", runner.calls)
	}
}

func TestInstallInitramfsToolsFailsClosedOnAPTError(t *testing.T) {
	runner := &dependencyRunner{
		paths:  map[string]string{"apt-get": "/usr/bin/apt-get", "env": "/usr/bin/env"},
		runErr: fmt.Errorf("repository unavailable"),
	}
	host := model.Host{Distribution: "ubuntu", Version: "26.04", Supported: true}
	err := installInitramfsTools(context.Background(), runner, host, nil)
	if err == nil || !strings.Contains(err.Error(), "refresh APT package metadata") {
		t.Fatalf("expected fail-closed APT error, got %v", err)
	}
}

type dependencyRunner struct {
	paths  map[string]string
	calls  [][]string
	runErr error
}

func (runner *dependencyRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	runner.calls = append(runner.calls, call)
	if runner.runErr != nil {
		return nil, runner.runErr
	}
	if len(args) >= 3 && args[len(args)-3] == "install" && args[len(args)-2] == "--yes" && args[len(args)-1] == initramfsToolsPackage {
		runner.paths["lsinitramfs"] = "/usr/bin/lsinitramfs"
		runner.paths["mkinitramfs"] = "/usr/sbin/mkinitramfs"
	}
	return nil, nil
}

func (runner *dependencyRunner) LookPath(name string) (string, error) {
	if path := runner.paths[name]; path != "" {
		return path, nil
	}
	return "", fmt.Errorf("%s is unavailable", name)
}
