package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/model"
)

const initramfsToolsPackage = "initramfs-tools-core"

var initramfsPackageByDistribution = map[string]string{
	"debian": initramfsToolsPackage,
	"ubuntu": initramfsToolsPackage,
}

func dependencyInstallOffer(report model.Preflight) ([]string, bool) {
	if !report.Host.Supported {
		return nil, false
	}
	if _, supported := initramfsPackageByDistribution[report.Host.Distribution]; !supported {
		return nil, false
	}
	missing := make(map[string]struct{}, 2)
	for _, issue := range report.Issues {
		if issue.Severity != model.SeverityBlocker {
			continue
		}
		switch issue.Code {
		case "initramfs-builder":
			missing["mkinitramfs"] = struct{}{}
		case "initramfs-inspector":
			missing["lsinitramfs"] = struct{}{}
		default:
			return nil, false
		}
	}
	if len(missing) == 0 {
		return nil, false
	}
	commands := make([]string, 0, len(missing))
	for name := range missing {
		commands = append(commands, name)
	}
	sort.Strings(commands)
	return commands, true
}

func installInitramfsTools(ctx context.Context, runner command.Runner, host model.Host, output io.Writer) error {
	packageName, supported := initramfsPackageByDistribution[host.Distribution]
	if !host.Supported || !supported {
		return fmt.Errorf("automatic package installation is unavailable for %s %s", host.Distribution, host.Version)
	}
	missing := missingInitramfsCommands(runner)
	if len(missing) == 0 {
		return nil
	}
	aptPath, err := runner.LookPath("apt-get")
	if err != nil {
		return fmt.Errorf("apt-get is unavailable")
	}
	envPath, err := runner.LookPath("env")
	if err != nil {
		return fmt.Errorf("env is unavailable")
	}
	if output == nil {
		output = io.Discard
	}
	fmt.Fprintf(output, "Installing %s for missing commands: %s\n", packageName, strings.Join(missing, ", "))
	base := []string{
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
		"NEEDRESTART_MODE=l",
		aptPath,
		"-o", "Acquire::Retries=3",
		"-o", "Dpkg::Lock::Timeout=60",
		"-o", "Dpkg::Use-Pty=0",
	}
	if _, err := runner.Run(ctx, envPath, append(append([]string(nil), base...), "update")...); err != nil {
		return fmt.Errorf("refresh APT package metadata: %w", err)
	}
	installArguments := append(append([]string(nil), base...), "install", "--yes", packageName)
	if _, err := runner.Run(ctx, envPath, installArguments...); err != nil {
		return fmt.Errorf("install %s: %w", packageName, err)
	}
	if unresolved := missingInitramfsCommands(runner); len(unresolved) > 0 {
		return fmt.Errorf("%s completed but required commands remain unavailable: %s", packageName, strings.Join(unresolved, ", "))
	}
	fmt.Fprintln(output, "Required initramfs tooling installed and verified.")
	return nil
}

func missingInitramfsCommands(runner command.Runner) []string {
	missing := make([]string, 0, 2)
	for _, name := range []string{"lsinitramfs", "mkinitramfs"} {
		if _, err := runner.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}
