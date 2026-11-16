// Package sshcmd builds the argument list for the user's own ssh client so it
// reaches a VM through ocd's embedded Pomerium tunnel with the opkssh key.
package sshcmd

import (
	"regexp"
	"strings"
)

// JoinUser is the forced-command account that provisions or looks up the
// caller's personal account on the VM.
const JoinUser = "onecloud-join"

// Options describes one ssh invocation.
type Options struct {
	Self string // absolute path of the ocd binary
	// PomeriumURL is the cluster's shared Pomerium CONNECT endpoint. When set,
	// the tunnel connects there instead of dialing the VM's TCP route name
	// (on ocd-prd-01 those names are not in DNS).
	PomeriumURL string
	KeyPath     string // opkssh private key; ssh loads <KeyPath>-cert.pub itself
	User        string
	Host        string // stable gateway host used as the SSH host-key/account identity
	Address     string // tenant-network IP; nonempty means direct, no ProxyCommand
	Windows     bool
	Extra       []string // extra ssh arguments (before the destination)
	Command     []string // remote command (after the destination)
}

// QuoteProxyCommand quotes the ocd path for the ssh ProxyCommand option.
// OpenSSH expands %-tokens in ProxyCommand first, so a literal % is doubled.
// On POSIX ssh then runs the command through /bin/sh -c: a path holding any
// shell metacharacter ($, backtick, ;, quotes, spaces...) is single-quoted,
// which disables every expansion. Win32-OpenSSH has no shell and only
// honours double quotes, so Windows paths keep double quotes.
func QuoteProxyCommand(self string, windows bool) string {
	self = strings.ReplaceAll(self, "%", "%%")
	if windows {
		self = strings.ReplaceAll(self, `\`, `/`)
		if strings.ContainsAny(self, " \t\"") {
			return `"` + strings.ReplaceAll(self, `"`, `\"`) + `"`
		}
		return self
	}
	if plainProxyWord.MatchString(self) {
		return self
	}
	return `'` + strings.ReplaceAll(self, `'`, `'\''`) + `'`
}

// plainProxyWord matches words that need no shell quoting.
var plainProxyWord = regexp.MustCompile(`^[A-Za-z0-9_./:@+=,%-]+$`)

// safeGatewayURL accepts only scheme://host[:port] made of URL-safe
// characters, so the value cannot inject shell syntax or ssh %-tokens into
// ProxyCommand. Config validation enforces https; this is a last guard.
var safeGatewayURL = regexp.MustCompile(`^https?://[A-Za-z0-9.\-\[\]:]+$`)

// KnownHostsPath returns the ocd-owned known_hosts file for a cluster key:
// <KeyPath>-known_hosts, kept apart from the user's ~/.ssh/known_hosts.
func KnownHostsPath(keyPath string) string { return keyPath + "-known_hosts" }

// quoteFileOption quotes a path for ssh options that are split on
// whitespace (UserKnownHostsFile accepts a list), e.g. Windows profiles
// with a space in the user name.
func quoteFileOption(p string, windows bool) string {
	if windows {
		p = strings.ReplaceAll(p, `\`, `/`)
	}
	if strings.ContainsAny(p, " \t") {
		return `"` + p + `"`
	}
	return p
}

// Args returns the ssh argument list (without the program name).
//
// For gateway connections new keys are accepted without a prompt as before;
// the gateway authenticates the route and Win32-OpenSSH cannot always read
// the yes/no prompt while ProxyCommand owns the session. For direct network
// connections, keep the host key scoped to the same stable gateway hostname
// but require an explicit first-use confirmation (StrictHostKeyChecking=ask).
// A changed key is never silently accepted on either path.
func Args(o Options) []string {
	args := []string{
		"-o", "UserKnownHostsFile=" + quoteFileOption(KnownHostsPath(o.KeyPath), o.Windows),
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityFile=" + o.KeyPath,
		"-o", "CertificateFile=" + o.KeyPath + "-cert.pub",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
	}
	if o.Address == "" {
		proxy := QuoteProxyCommand(o.Self, o.Windows) + " tunnel"
		if o.PomeriumURL != "" && safeGatewayURL.MatchString(o.PomeriumURL) {
			proxy += " --gateway-url " + o.PomeriumURL
		}
		proxy += " %h:443"
		args = append([]string{"-o", "ProxyCommand=" + proxy, "-o", "StrictHostKeyChecking=accept-new"}, args...)
	} else {
		// HostName tells ssh which VPC address to dial while HostKeyAlias
		// preserves the per-VM identity across direct/proxied connections.
		// A user's ~/.ssh/config may specify a jump host or proxy. Direct
		// means a direct TCP socket, never an inherited ProxyCommand/Jump.
		args = append([]string{"-o", "ProxyCommand=none", "-o", "ProxyJump=none",
			"-o", "HostName=" + o.Address, "-o", "HostKeyAlias=" + o.Host,
			"-o", "StrictHostKeyChecking=ask"}, args...)
	}
	args = append(args, o.Extra...)
	args = append(args, "-l", o.User, o.Host)
	return append(args, o.Command...)
}

// JoinArgs returns the ssh arguments for the onecloud-join step.
func JoinArgs(o Options) []string {
	o.User = JoinUser
	o.Extra = append([]string{"-T"}, o.Extra...)
	o.Command = nil
	return Args(o)
}

// HostKeyChanged reports ssh output that refused a known host because its
// key changed (typically the VM was rebuilt).
func HostKeyChanged(stderr string) bool {
	return strings.Contains(stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED") ||
		strings.Contains(stderr, "Host key verification failed")
}

// HostKeyHint explains a changed host key. Direct mode recommends checking
// the gateway route rather than automatically removing a previously trusted
// host key on the basis of a tenant-network response.
func HostKeyHint(host, keyPath string, windows, direct bool) string {
	if direct {
		return "The SSH host key of " + host + " differs on the tenant network.\n" +
			"Do not trust the changed key until the tenant administrator confirms it.\n" +
			"Compare with the access-gateway route: ocd ssh --via proxied <tenant>/<vm>"
	}
	return "The SSH host key of " + host + " changed. This is expected after the VM was rebuilt or reinstalled;\n" +
		"if it was not, ask the tenant administrator before going on.\n" +
		"To trust the new key, remove the old one and connect again:\n" +
		"  ssh-keygen -R " + host + " -f " + quoteFileOption(KnownHostsPath(keyPath), windows)
}

var accountRe = regexp.MustCompile(`(?m)account on this VM is: ([a-z_][a-z0-9_-]{0,31})\s*$`)

// ParseJoinOutput extracts the personal account name printed by onecloud-join.
func ParseJoinOutput(out string) (string, bool) {
	m := accountRe.FindStringSubmatch(out)
	if m == nil {
		return "", false
	}
	return m[1], true
}
