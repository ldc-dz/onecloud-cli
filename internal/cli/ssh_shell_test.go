package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/target"
)

// stubShellService makes the cluster DNS of the test answer for one name
// with a private address whose SSH port accepts connections.
func stubShellService(t *testing.T, name, ip string) {
	t.Helper()
	oldLookup, oldProbe := lookupHost, probeService
	t.Cleanup(func() { lookupHost, probeService = oldLookup, oldProbe })
	lookupHost = func(_ context.Context, host string) ([]string, error) {
		if host != name {
			return nil, errors.New("no such host")
		}
		return []string{ip}, nil
	}
	probeService = func(address string, port int) bool { return address == ip && port == sshPort }
}

// UAT 2026-11 VM-SH-CLI-01 (OneCloud #2834): in OneCloud Shell, ocd ssh
// reaches the VM SSH Service through the cluster DNS when the portal gave no
// usable tenant-network address, instead of refusing the gateway path.
func TestShellSSHRoute(t *testing.T) {
	tg, err := target.Parse("uat-999002/uatvm02")
	if err != nil {
		t.Fatal(err)
	}
	stubShellService(t, "uatvm02-ssh.tenant-uat-999002-vm", "10.96.7.8")

	t.Setenv("OCD_CLOUD_SHELL", "1")
	path, address, err := shellSSHRoute("auto", "proxied", "", tg)
	if err != nil || path != "direct" || address != "10.96.7.8" {
		t.Fatalf("Shell auto route = %q %q %v; want direct to the Service", path, address, err)
	}
	// An address published by the portal that answered is kept.
	path, address, err = shellSSHRoute("auto", "direct", "172.30.16.15", tg)
	if err != nil || path != "direct" || address != "172.30.16.15" {
		t.Fatalf("portal address replaced: %q %q %v", path, address, err)
	}
	// The gateway cannot be used from the Shell: forced, or nothing answers.
	if _, _, err := shellSSHRoute("proxied", "proxied", "", tg); !errors.Is(err, errCloudShellGateway) {
		t.Fatalf("forced gateway in the Shell: %v", err)
	}
	other, _ := target.Parse("uat-999002/absent")
	if _, _, err := shellSSHRoute("auto", "proxied", "", other); !errors.Is(err, errCloudShellGateway) {
		t.Fatalf("Service that does not answer: %v", err)
	}
	// A bare tenant id does not name the namespace of the Service.
	bare, _ := target.Parse("999002/uatvm02")
	if _, _, err := shellSSHRoute("auto", "proxied", "", bare); !errors.Is(err, errCloudShellGateway) {
		t.Fatalf("bare tenant id: %v", err)
	}

	// Outside the Shell the gateway path is left alone, with no lookup.
	t.Setenv("OCD_CLOUD_SHELL", "")
	path, address, err = shellSSHRoute("auto", "proxied", "", tg)
	if err != nil || path != "proxied" || address != "" {
		t.Fatalf("workstation route changed: %q %q %v", path, address, err)
	}
}

// In OneCloud Shell a missing or expired SSH sign-in starts the device
// sign-in; on a workstation it stays the browser sign-in.
func TestEnsureLoginUsesDeviceCodeInCloudShell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	old := signIn
	t.Cleanup(func() { signIn = old })
	var device []bool
	signIn = func(_ config.Cluster, noBrowser, dev bool) error {
		if noBrowser {
			t.Error("ensureLogin must not ask for --no-browser")
		}
		device = append(device, dev)
		return nil
	}
	cl := config.Cluster{Name: "test"}
	keyPath, err := cl.KeyPath()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCD_CLOUD_SHELL", "1")
	if err := ensureLogin(cl, keyPath); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OCD_CLOUD_SHELL", "")
	if err := ensureLogin(cl, keyPath); err != nil {
		t.Fatal(err)
	}
	if len(device) != 2 || !device[0] || device[1] {
		t.Fatalf("device sign-in per call = %v; want [true false]", device)
	}
}

const fakeSSH = `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_SSH_ARGS"
case " $* " in
  *" -l onecloud-join "*) echo "Your account on this VM is: t03" ;;
esac
`

// The whole command in OneCloud Shell, not signed in and with no portal
// session: one run signs in with a device code, then joins and connects
// directly to the Service address under the VM's stable host-key name.
func TestSSHInCloudShellIsOneCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake ssh is a bash script")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	t.Setenv("OCD_CLOUD_SHELL", "1")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(fakeSSH), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("FAKE_SSH_ARGS", argsFile)
	stubShellService(t, "uatvm02-ssh.tenant-uat-999002-vm", "10.96.7.8")
	old := signIn
	t.Cleanup(func() { signIn = old })
	signedIn := 0
	signIn = func(_ config.Cluster, _, device bool) error {
		if !device {
			t.Error("the Shell sign-in must use a device code")
		}
		signedIn++
		return nil
	}

	if _, err := run(t, "ssh", "--cluster", "ocd-prd-01", "uat-999002/uatvm02", "--", "uptime"); err != nil {
		t.Fatalf("ocd ssh in OneCloud Shell: %v", err)
	}
	if signedIn != 1 {
		t.Fatalf("sign-in ran %d times, want 1", signedIn)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(calls) != 2 {
		t.Fatalf("ssh ran %d times, want join then session:\n%s", len(calls), raw)
	}
	for i, call := range calls {
		for _, want := range []string{"HostName=10.96.7.8", "HostKeyAlias=uatvm02-ssh-999002.", "ProxyCommand=none", "StrictHostKeyChecking=ask"} {
			if !strings.Contains(call, want) {
				t.Errorf("ssh call %d lacks %s: %s", i+1, want, call)
			}
		}
	}
	if !strings.Contains(calls[0], "-l onecloud-join ") || !strings.HasSuffix(calls[1], " uptime") || !strings.Contains(calls[1], "-l t03 ") {
		t.Fatalf("unexpected ssh calls:\n%s", raw)
	}
}
