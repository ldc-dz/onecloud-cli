package sshcmd

import (
	"strings"
	"testing"
)

func TestArgsLinux(t *testing.T) {
	got := strings.Join(Args(Options{Self: "/usr/local/bin/ocd", KeyPath: "/h/.ssh/ocd-ocd-dev-01", User: "anis-fathallah", Host: "vmsso-ssh-000001.tcp.x", Command: []string{"uptime"}}), "|")
	want := "-o|ProxyCommand=/usr/local/bin/ocd tunnel %h:443|-o|StrictHostKeyChecking=accept-new|-o|UserKnownHostsFile=/h/.ssh/ocd-ocd-dev-01-known_hosts|-o|IdentitiesOnly=yes|-o|IdentityFile=/h/.ssh/ocd-ocd-dev-01|-o|CertificateFile=/h/.ssh/ocd-ocd-dev-01-cert.pub|-o|PasswordAuthentication=no|-o|KbdInteractiveAuthentication=no|-l|anis-fathallah|vmsso-ssh-000001.tcp.x|uptime"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

func TestProxyCommandWindowsPathWithSpaces(t *testing.T) {
	got := QuoteProxyCommand(`C:\Program Files\ocd\ocd.exe`, true)
	if got != `"C:/Program Files/ocd/ocd.exe"` {
		t.Fatalf("got %s", got)
	}
	if QuoteProxyCommand(`C:\ocd\ocd.exe`, true) != `C:/ocd/ocd.exe` {
		t.Fatal("plain windows path changed unexpectedly")
	}
}

func TestArgsWindowsKnownHostsWithSpaces(t *testing.T) {
	j := strings.Join(Args(Options{Self: `C:\ocd\ocd.exe`, KeyPath: `C:\Users\Some User\.ssh\ocd-ocd-dev-01`, User: "u", Host: "h", Windows: true}), "|")
	if !strings.Contains(j, `|UserKnownHostsFile="C:/Users/Some User/.ssh/ocd-ocd-dev-01-known_hosts"|`) {
		t.Fatalf("known_hosts not quoted: %s", j)
	}
	if !strings.Contains(j, "|StrictHostKeyChecking=accept-new|") {
		t.Fatalf("host key prompt not disabled: %s", j)
	}
}

func TestJoinArgs(t *testing.T) {
	args := JoinArgs(Options{Self: "ocd", KeyPath: "k", User: "ignored", Host: "h", Command: []string{"x"}})
	j := strings.Join(args, " ")
	if !strings.Contains(j, "-T") || !strings.HasSuffix(j, "-l onecloud-join h") {
		t.Fatalf("bad join args: %s", j)
	}
}

func TestParseJoinOutput(t *testing.T) {
	out := "Your OneCloud SSO account on this VM is: anis-fathallah\nConnect with the same opkssh key as: ssh anis-fathallah@<this host>\n"
	if a, ok := ParseJoinOutput(out); !ok || a != "anis-fathallah" {
		t.Fatalf("got %q %v", a, ok)
	}
	for _, bad := range []string{"", "onecloud-sso: no verified opkssh key", "account on this VM is: Root;rm"} {
		if _, ok := ParseJoinOutput(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestArgsGatewayURL(t *testing.T) {
	// ocd-prd-01 TCP route names are CONNECT authorities, not DNS names: the
	// tunnel must go through the shared gateway endpoint.
	j := strings.Join(Args(Options{Self: "/bin/ocd", KeyPath: "/k", User: "u", Host: "h", PomeriumURL: "https://access.onecloud.ldc.dz:8443"}), "|")
	if !strings.Contains(j, "ProxyCommand=/bin/ocd tunnel --gateway-url https://access.onecloud.ldc.dz:8443 %h:443|") {
		t.Fatalf("proxy does not use the access-gateway endpoint: %s", j)
	}
}

func TestHostKeyChangedHint(t *testing.T) {
	out := "@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n...\nHost key verification failed.\n"
	if !HostKeyChanged(out) || HostKeyChanged("Permission denied (publickey).") {
		t.Fatal("host key change detection wrong")
	}
	h := HostKeyHint("vm-ssh-000001.tcp.x", `C:\Users\Some User\.ssh\ocd-ocd-prd-01`, true, false)
	if !strings.Contains(h, `ssh-keygen -R vm-ssh-000001.tcp.x -f "C:/Users/Some User/.ssh/ocd-ocd-prd-01-known_hosts"`) {
		t.Fatalf("hint: %s", h)
	}
	direct := HostKeyHint("vm-ssh-000001.tcp.x", "key", false, true)
	if !strings.Contains(direct, "--via proxied") || strings.Contains(direct, "ssh-keygen") {
		t.Fatalf("direct host-key mismatch must not suggest removing the trusted key: %s", direct)
	}
}

func TestArgsDirectUsesNetworkWithoutProxy(t *testing.T) {
	args := Args(Options{Self: "/bin/ocd", KeyPath: "/k", User: "onecloud", Host: "vm-ssh-000001.tcp.x", Address: "10.20.30.40"})
	got := strings.Join(args, "|")
	for _, want := range []string{"ProxyCommand=none", "ProxyJump=none", "HostName=10.20.30.40", "HostKeyAlias=vm-ssh-000001.tcp.x", "StrictHostKeyChecking=ask", "CertificateFile=/k-cert.pub", "PasswordAuthentication=no"} {
		if !strings.Contains(got, want) {
			t.Fatalf("direct ssh args lack %q: %s", want, got)
		}
	}
	if strings.Contains(got, "ProxyCommand=/") || strings.Contains(got, "accept-new") {
		t.Fatalf("direct ssh unexpectedly proxies or accepts a host key without review: %s", got)
	}
	join := strings.Join(JoinArgs(Options{Self: "/bin/ocd", KeyPath: "/k", Host: "vm-ssh-000001.tcp.x", Address: "10.20.30.40"}), "|")
	if !strings.Contains(join, "HostName=10.20.30.40") || !strings.Contains(join, "-l|onecloud-join|") || !strings.Contains(join, "ProxyCommand=none") || strings.Contains(join, "ProxyCommand=/") {
		t.Fatalf("direct join must use same IP and certificate: %s", join)
	}
}

func TestProxyCommandPosixQuoting(t *testing.T) {
	if QuoteProxyCommand("/usr/local/bin/ocd", false) != "/usr/local/bin/ocd" {
		t.Fatal("plain path changed")
	}
	for in, want := range map[string]string{
		"/home/a b/ocd":       `'/home/a b/ocd'`,
		"/tmp/$(id)/ocd":      `'/tmp/$(id)/ocd'`,
		"/tmp/`id`;x/ocd":     "'/tmp/`id`;x/ocd'",
		"/tmp/it's/ocd":       `'/tmp/it'\''s/ocd'`,
		"/tmp/100%h/ocd":      "/tmp/100%%h/ocd",
		"/tmp/100% $HOME/ocd": "'/tmp/100%% $HOME/ocd'",
	} {
		if got := QuoteProxyCommand(in, false); got != want {
			t.Errorf("%q: got %s want %s", in, got, want)
		}
	}
	if got := QuoteProxyCommand(`C:\a%b\ocd.exe`, true); got != "C:/a%%b/ocd.exe" {
		t.Errorf("windows %%: %s", got)
	}
}

func TestArgsDropsUnsafeGatewayURL(t *testing.T) {
	j := strings.Join(Args(Options{Self: "/bin/ocd", KeyPath: "/k", User: "u", Host: "h", PomeriumURL: "https://x;touch /tmp/p"}), "|")
	if strings.Contains(j, "touch") || strings.Contains(j, "--gateway-url") {
		t.Fatalf("unsafe gateway URL reached ProxyCommand: %s", j)
	}
}
