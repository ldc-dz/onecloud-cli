<p align="center">
  <img src="docs/assets/onecloud.png" alt="OneCloud" width="320">
</p>

# ocd - OneCloud CLI

`ocd` gives OneCloud tenant members single sign-on access to their resources
from a terminal:

- **`ocd ssh`**: SSH to a tenant VM with a short-lived certificate from your
  OneCloud account (no keys to distribute).
- **`ocd psql`**: connect `psql` to a managed PostgreSQL instance with OneCloud
  sign-in (OAuth) and full TLS verification.

By default `--via auto` connects directly over the tenant VPC when the
portal publishes a VPC IP and the target port answers within 1.5 seconds;
otherwise it uses the OneCloud access gateway. `ocd` embeds
[opkssh](https://github.com/openpubkey/opkssh) and the OneCloud access
transport. You need the system `ssh` client and, for databases, `psql` 18+.

Default cluster: **`ocd-prd-01`** (production). Use `--cluster ocd-dev-01` for
the development cluster.

## Install

No account or token is needed to install.

**Linux and macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/ldc-dz/onecloud-cli/main/install.sh | sh
```

If `GITHUB_TOKEN` or `GH_TOKEN` is set (or `gh auth token` works), the
installer sends it to the GitHub API; this only raises the API rate limit.

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/ldc-dz/onecloud-cli/main/install.ps1 | iex
```

The installer picks the archive for your OS and CPU (amd64 or arm64) from the
latest stable release, checks it against `SHA256SUMS`, and installs `ocd` into
`~/.local/bin` (Linux, macOS) or `%LOCALAPPDATA%\Programs\ocd` (Windows, added
to your user `PATH`). Options:

| Variable | Default | Effect |
|---|---|---|
| `OCD_VERSION` | latest stable | install a given release, e.g. `v0.2.0` or an rc |
| `OCD_INSTALL_DIR` | see above | install somewhere else |

Run the same command again to upgrade. Manual install: download the archive
from [Releases](https://github.com/ldc-dz/onecloud-cli/releases), check it with
`sha256sum -c SHA256SUMS --ignore-missing`, and put `ocd` on your `PATH`.

Check the install:

```bash
ocd version
ocd doctor      # checks ssh, psql, cluster settings, VPN probe, and sign-in
```

## Quick start

```bash
# VM SSH (the VM must have sso: true)
ocd ssh demo-000001/vmsso                 # signs you in, then connects
ocd ssh demo-000001/vmsso -- uptime       # run one command
ocd ssh --via direct --address 10.0.0.12 demo-000001/vmsso
ocd ssh --via proxied demo-000001/vmsso   # force gateway even over VPN

# Managed PostgreSQL
ocd psql demo-000001/pgoidc01
ocd psql demo-000001/pgoidc01 -- -c 'select current_user'
ocd psql --via direct demo-000001/pgoidc01 # require portal VPC IP
```

Targets are `<tenant>/<name>`. For `ocd ssh` the tenant can be `demo-000001`
or `000001`; `ocd psql` needs the full tenant name.

## Commands

| Command | What it does |
|---|---|
| `ocd login` | browser sign-in; writes a 12h SSH certificate to `~/.ssh/ocd-<cluster>-cert.pub` |
| `ocd login --device` | device-code sign-in without a localhost callback; uses the device-only client `onecloud-ssh-device` |
| `ocd ssh <tenant>/<vm> [-- cmd]` | SSH directly over VPC when reachable or via gateway; refreshes expired certificate |
| `ocd psql <tenant>/<instance> [-- psql args]` | psql directly or via gateway with OAuth sign-in and `verify-full` TLS |
| `ocd tunnel <host:port>` | raw access-gateway TCP tunnel (used by proxied `ocd ssh` as ProxyCommand) |
| `ocd clickhouse` (`ch`) `[<tenant>/<instance>] [-- args]` | `clickhouse-client` through the access gateway, password from the portal |
| `ocd mssql [<tenant>/<instance>] [-- args]` | `sqlcmd` through the access gateway, password from the portal |
| `ocd s3 ls\|get\|put\|rm [<tenant>/<instance>]` | objects of a managed object-storage instance |
| `ocd services [--json] [--type t] [--tenant t]` | list the services you can reach and their status |
| `ocd connect [<tenant>/<instance>]` | choose a service with the arrow keys and connect to it |
| `ocd config show` / `ocd config path` | effective settings / override file location |
| `ocd doctor` | environment checks |
| `ocd version` | version and embedded opkssh version |

Global flags: `--cluster <name>`, `--via auto|direct|proxied` (default `auto`
for SSH and psql), `-v/--verbose`. Run `ocd <command> --help` for every flag.

`auto` reads the instance's `vpcAddress` from the portal's
`GET /api/provisioning/connections` inventory. For VM instances not yet in
that inventory it falls back to the portal's tenant-scoped public
`GET /api/provisioning/instances` facade output `vpc.address`. The first
interactive lookup prompts once; the portal bearer is cached under the ocd
config directory in a 0600 file, bound to the issuer/client/portal and expired
before its JWT `exp`. Validated private IPv4 addresses (RFC1918 or 100.64/10)
are cached for two minutes per cluster/tenant/instance; later runs reuse them
without opening a browser. Headless scripts without a saved token skip the
lookup and select the gateway with one notice line. If the target port (SSH 22,
PostgreSQL 5432) accepts TCP before the 1.5-second deadline, `ocd` uses the
tenant VPC. Otherwise it uses the gateway, without retrying an SSH or database
authentication failure on another path. Explicit `direct` requires a VPC
address but does not require a successful reachability probe; `proxied` always
uses the gateway. Each connection announces its path. No database password or
SSH private key is fetched from the portal.

### ClickHouse, SQL Server, S3 and service navigation

```bash
ocd services                                  # TYPE  TARGET  STATUS  CLUSTER
ocd connect                                   # pick an instance, then connect
ocd ch demo-000001/ch01 -- --query 'SELECT version()'
ocd mssql demo-000001/mssql01 -- -Q 'SELECT @@VERSION'
ocd s3 ls demo-000001/store01 --prefix reports/
ocd s3 get demo-000001/store01 --key reports/jan.pdf -o jan.pdf
ocd s3 put demo-000001/store01 ./jan.pdf --key reports/jan.pdf
ocd s3 rm demo-000001/store01 --prefix reports/ --recursive --dry-run
```

- Without a target these commands list your instances and let you choose one
  on the terminal. Without a terminal they fail and ask for the target; they
  never read the choice from piped input.
- Database passwords and S3 keys are read from the portal for the current run,
  kept in memory only, and passed to `clickhouse-client` (`CLICKHOUSE_PASSWORD`)
  and `sqlcmd` (`SQLCMDPASSWORD`) through the environment, never on the command
  line or on disk. Install `clickhouse-client` or `sqlcmd` yourself.
- **Compatibility TLS.** The access gateway encrypts and authorizes the
  connection, but the database leg is not verified yet: ClickHouse uses native
  TCP without database TLS (no notice is printed for it), and SQL Server runs
  with `-C` (server certificate not checked) and prints that notice each run.
- **S3.** The target is the object-storage instance; its endpoint and bucket
  come from the portal. Keys are used exactly as written (no wildcards).
  `get`/`put` refuse to replace an existing file or object without
  `--overwrite`; upload protection relies on the gateway honoring
  `If-None-Match` (verified on the ocd-dev-01 gateway). `rm` takes an exact `--key`, or `--prefix <dir/>
  --recursive`; it refuses the bucket root and folder-like keys, needs
  `--dry-run` or `--yes`, removes only the objects listed once at the start,
  never removes old versions, and is not transactional.

### `ocd ssh`

- The first connection to a VM runs the `onecloud-join` step, which creates
  your personal account on the VM. `ocd` remembers the account name
  (`accounts.json` next to the config file); `--rejoin` forgets it, `-l <user>`
  overrides it.
- `ocd ssh --via direct --address <ip> <tenant>/<vm>` uses an explicit VPC IP
  and skips the portal lookup (still requires a valid SSO SSH certificate).
  `--address` is only accepted together with `--via direct` and must be an IP.
  A non-private address produces a warning but still connects when explicitly
  provided. A portal-provided public, loopback, IPv6 or malformed IP is ignored.
- Keys live in `~/.ssh/ocd-<cluster>` and `~/.ssh/ocd-<cluster>-cert.pub`; VM
  host keys in `~/.ssh/ocd-<cluster>-known_hosts`. On direct connections the
  first host key prompts for confirmation; a changed key is refused on either
  path with instructions. Direct mode disables any proxy/jump host inherited
  from your SSH config; on a direct host-key mismatch it suggests
  `--via proxied` and never automatically removes the trusted key. The same
  host-key identity is used for both paths.
- The access gateway asks you to sign in in the browser on the first proxied
  connection (the session is cached).

### `ocd psql`

Needs psql 18 or newer built with OAuth support (Debian/Ubuntu: install
`postgresql-client-18` and `libpq-oauth`; macOS: Homebrew `libpq` 18).

1. The first time, `ocd` signs you in to the OneCloud portal in the browser,
   downloads the instance CA and keeps it in
   `~/.config/ocd/postgres/<cluster>/<tenant>/<instance>-ca.crt`.
2. When direct TCP to the VPC IP is unavailable, a gateway tab opens to
   authorize the tunnel. On the direct path psql uses `host=<TLS name>` and
   `hostaddr=<VPC IP>` for `sslmode=verify-full`.
3. psql starts the database sign-in: `ocd` opens the sign-in page with the code
   already filled in (like `aws sso login`); confirm it and psql connects.
   `--no-browser` only prints the link and code.

Flags: `-d/--dbname` (default `app`), `-U/--username` (default `app`),
`--port` (gateway-only local tunnel port), `--ca <file>` (use a CA you downloaded from the
portal, "TLS CA certificate"; it replaces the stored copy and is kept for later runs).
A CA file in the current directory is never used implicitly: pass it with `--ca`.

## Clusters and configuration

| Cluster | Portal | Notes |
|---|---|---|
| `ocd-prd-01` (default) | https://portal.onecloud.dz | production |
| `ocd-dev-01` | https://portal.dev-01.onecloud.ldc.dz | development |

During the production domain move, commands using the built-in production
cluster read public OIDC discovery from `auth.onecloud.dz` before using a
credential. Only the exact old and new `prd-01-portal` issuers are accepted.
While the old issuer is advertised, the CLI uses the old issuer and portal;
after the switch it uses the new pair. A cached portal session is not copied
between origins: sign in again (in Cloud Shell, start a fresh session once the
broker is configured for the new pair). `ocd config show` is offline and shows
the configured defaults, not the discovered issuer. TCP and S3 gateway names
are unchanged.

Settings are built in. An override file changes them field by field:
`~/.config/ocd/config.yaml` (Linux), `~/Library/Application Support/ocd/config.yaml`
(macOS), `%APPDATA%\ocd\config.yaml` (Windows); `OCD_CONFIG_DIR` moves it.
`ocd config path` prints the one in use. `ocd doctor` reports VPN
reachability for a known target when `OCD_VPN_PROBE_ADDRESS=<tenant-IP>` is
set (port 22 by default; set `OCD_VPN_PROBE_PORT=5432` for a PostgreSQL target).
Without a target, it explicitly reports that no probe was performed. A failed
probe is advisory; the sign-in checks still determine the doctor's exit code.

```yaml
defaultCluster: ocd-dev-01      # make dev the default
browser: firefox {url}          # command used to open sign-in pages ("none" = print only)
```

### Sign-in pages

Native portal login and ordinary `ocd login` use browser loopback PKCE
callbacks: a browser on another machine cannot complete them automatically.
In Cloud Shell run `ocd login --device`; enter the printed code in your own
browser. The CLI uses an OAuth device grant against the configured issuer and
binds the returned ID token to an opkssh SSH certificate, with a three-minute
timeout. The OneCloud SSH Keycloak client **must enable the device authorization
grant** before this succeeds (the CLI cannot enable it). `OCD_CLOUD_SHELL=1`
fails fast for ordinary `ocd login` or expired SSH sign-ins rather than waiting
for an unreachable callback; `ocd ssh --via direct --address <ip>` works with an
existing valid certificate. Portal auto lookups in Cloud Shell use an existing
saved token/address only; without one, they skip to the gateway. `psql` itself
has the OAuth **device flow** available in the toolbox.

**Callback workaround (only if your Keycloak client still lacks the SSH device
grant):** In the same Cloud Shell tab run `OCD_CLOUD_SHELL=0 ocd login --no-browser`.
Use your laptop's browser to complete the printed sign-in link. The browser's
final `localhost:PORT/login-callback?code=...&state=...` page cannot reach the
pod; copy the full URL from your browser's address bar and immediately run
`curl -fsS --max-time 10 '<full-callback-url>'` **inside that same Cloud Shell
session**. Treat the callback URL as a one-time secret: do not paste it into
support chat or logs. Prevent storing it in shell history (for example run
`set +o history` before pasting, and `set -o history` afterwards); do not
reuse it on another session.
Timeout after three minutes means repeat the flow. A laptop-installed CLI
avoids this workaround entirely.

`ocd` opens sign-in pages without taking the focus away from your terminal
where it can:

| Platform | Behaviour |
|---|---|
| macOS | `open -g`: the page opens behind your terminal |
| Linux, Hyprland or X11 with `xdotool` | the page opens, then the focus returns to your terminal |
| Windows, other Wayland desktops | the default browser opens the page |

Set `browser:` in the config file or `OCD_BROWSER` to use another command
(`{url}` is replaced by the address, otherwise appended). `none` only prints
the address, as do `ocd login --no-browser` and `ocd psql --no-browser`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| installer: `cannot read the latest release` | GitHub API rate limit: retry later or export `GITHUB_TOKEN` |
| `ocd: command not found` after install | add the install directory to `PATH` (the installer prints the line), open a new terminal |
| macOS: "cannot be opened because the developer cannot be verified" | the binaries are not notarized yet: after checking `SHA256SUMS`, run `xattr -d com.apple.quarantine ~/.local/bin/ocd` yourself (the installer no longer does it) |
| `ocd ssh`: permission denied | `ocd login` again; check you are a member of the tenant and the VM has `sso: true` |
| `ocd ssh`: host key changed | check with the tenant administrator; in direct mode compare `--via proxied`, never automatically remove the trusted key |
| `ocd psql`: `no OAuth flows are available` | install `libpq-oauth` (Debian/Ubuntu) or a psql 18 built with libcurl |
| `ocd psql`: no CA certificate | the portal did not publish one yet: download "TLS CA certificate" from the portal and pass `--ca <instance>-ca.crt` |
| `ocd psql`: the stored CA is outdated | pass the new file explicitly with `--ca <file>`; a CA file in the current directory is never picked up on its own |
| `ocd psql`: `role ... not permitted` / authentication failed | your account is not a member of the instance's tenant |
| anything else | rerun with `-v` (and `OCD_LOG_LEVEL=debug` for tunnel logs), then `ocd doctor` |

## Develop

```bash
make vet test     # unit tests, including the third-party notices check
make build        # -> bin/ocd
make cross        # linux, darwin, windows x amd64, arm64 into dist/
make notices      # regenerate NOTICE and THIRD_PARTY_NOTICES.md after a dependency change
make vuln         # known vulnerabilities reachable from ocd (govulncheck)
```

Go toolchain: the `go` line of `go.mod` is the minimum Go release, and it
follows the Go security releases. Release builds run with `GOTOOLCHAIN=local`,
so a build image older than that line fails instead of shipping a binary
linked with an outdated standard library. When Go publishes a security
release: raise the `go` line, move the build image to that release, run
`make vuln` and cut a patch release. See [CONTRIBUTING.md](CONTRIBUTING.md)
for pull requests.

Before a stable release, check on Linux (and on Windows and macOS when
possible):

1. `ocd version` shows the release and embedded opkssh version.
2. `ocd login` opens the browser and writes `~/.ssh/ocd-ocd-prd-01-cert.pub`.
3. `ocd doctor` reports all `ok`.
4. `ocd ssh <tenant>/<vm>` lands in your personal account, again on a second
   run without the join step; same with `--cluster ocd-dev-01`.
5. `ocd psql <tenant>/<instance>` without a local CA downloads it and connects.

## Release

Releases are automatic. Use conventional commit titles (`feat:` minor,
`fix:` patch, `!` major); `.release-please-manifest.json` holds the current
version. Each release publishes the archives for every platform and a
`SHA256SUMS` file that the installers check. Every archive carries `LICENSE`,
`NOTICE` and `THIRD_PARTY_NOTICES.md`, the license texts of everything linked
into the binary.

Keep the embedded opkssh version (`opkssh v0.19.2`) in step with the one on
the OneCloud VMs.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open
a public issue.

Known limit: a database session through the access gateway (`ocd psql`,
`ocd clickhouse`, `ocd mssql`) listens on a local port for the time it runs.
On Linux `ocd` refuses connections to that port from other local users. On
macOS and Windows it cannot check who connects, so another user of the same
machine could reach the database port through your gateway session while it
is open (the database sign-in still applies). Use those commands on a machine
you do not share with untrusted local users.

## License

Apache-2.0. See `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md`.
