#!/bin/sh
# Offline tests for install.sh: curl is replaced by a stub that serves local
# fixtures, so nothing is downloaded and no real release binary is run.
#   sh tests/security/install_sh_test.sh
set -eu

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
API="https://api.github.com/repos/ldc-dz/onecloud-cli"
pass=0 fail=0

case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) echo "skip: unsupported OS"; exit 0 ;; esac
case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; *) echo "skip"; exit 0 ;; esac
if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | awk '{print $1}'; }; else sha() { shasum -a 256 "$1" | awk '{print $1}'; }; fi

# Stub curl: logs headers and URL, serves $FIX/<url with / replaced by _>.
mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'EOF'
#!/bin/sh
out= url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -H) printf 'H %s\n' "$2" >>"$LOG"; shift ;;
    --proto | --proto-redir) printf 'P %s %s\n' "$1" "$2" >>"$LOG"; shift ;;
    https://*) url="$1" ;;
  esac
  shift
done
printf 'U %s\n' "$url" >>"$LOG"
f="$FIX/$(printf '%s' "$url" | tr '/:' '__')"
[ -f "$f" ] || exit 22
if [ -n "$out" ]; then cp "$f" "$out"; else cat "$f"; fi
EOF
chmod +x "$work/bin/curl"
# Hide any real gh so the token path is driven only by the test env.
printf '#!/bin/sh\nexit 1\n' >"$work/bin/gh"; chmod +x "$work/bin/gh"

# setup <case> <tag> <asset-url-for-archive> ; builds fixtures in $work/<case>
setup() {
  c="$1" tag="$2" aurl="$3"
  FIX="$work/$c/fix"; mkdir -p "$FIX" "$work/$c/src"
  plain="${tag#v}"; d="ocd_${plain}_${os}_${arch}"; archive="$d.tar.gz"
  mkdir -p "$work/$c/src/$d"
  # The fake binary records any execution: it must never run.
  printf '#!/bin/sh\ntouch "%s/EXECUTED"\n' "$work/$c" >"$work/$c/src/$d/ocd"
  chmod +x "$work/$c/src/$d/ocd"
  tar -czf "$FIX/archive" -C "$work/$c/src" "$d"
  printf '%s  %s\n' "$(sha "$FIX/archive")" "$archive" >"$FIX/sums"
  cat >"$FIX/$(printf '%s' "$API/releases/latest" | tr '/:' '__')" <<JSON
{"tag_name": "$tag", "assets": [
 {"url": "$aurl", "name": "$archive"},
 {"url": "$API/releases/assets/2", "name": "SHA256SUMS"}]}
JSON
  cp "$FIX/archive" "$FIX/$(printf '%s' "$API/releases/assets/1" | tr '/:' '__')"
  cp "$FIX/sums" "$FIX/$(printf '%s' "$API/releases/assets/2" | tr '/:' '__')"
  LOG="$work/$c/log"; : >"$LOG"
}
run() { # run <case> [env...]; sets rc
  c="$1"; shift
  rc=0
  env -i PATH="$work/bin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$work/$c" FIX="$FIX" LOG="$LOG" \
    OCD_INSTALL_DIR="$work/$c/inst" "$@" sh "$root/install.sh" >"$work/$c/out" 2>&1 || rc=$?
}
ok() { pass=$((pass + 1)); echo "ok   $1"; }
ko() { fail=$((fail + 1)); echo "FAIL $1"; sed 's/^/     /' "$work/$2/out"; }
never_run() { [ ! -e "$work/$1/EXECUTED" ]; }

# 1. unauthenticated happy path: installs, no Authorization, https-only, not run.
setup anon v1.2.3 "$API/releases/assets/1"
run anon
if [ $rc -eq 0 ] && [ -x "$work/anon/inst/ocd" ] && ! grep -q Authorization "$LOG" &&
  grep -q "P --proto-redir =https" "$LOG" && never_run anon; then ok "unauthenticated install"; else ko "unauthenticated install" anon; fi

# 2. authenticated path: token sent only to the API host, binary still not run.
setup auth v1.2.3 "$API/releases/assets/1"
run auth GITHUB_TOKEN=ghp_testtoken123
if [ $rc -eq 0 ] && grep -q "H Authorization: Bearer ghp_testtoken123" "$LOG" &&
  ! grep '^U ' "$LOG" | grep -vq "^U $API/" && never_run auth; then ok "authenticated install"; else ko "authenticated install" auth; fi

# 3. checksum mismatch: fails, nothing installed, nothing run.
setup badsum v1.2.3 "$API/releases/assets/1"
printf '%064d  %s\n' 0 "ocd_1.2.3_${os}_${arch}.tar.gz" >"$FIX/$(printf '%s' "$API/releases/assets/2" | tr '/:' '__')"
run badsum
if [ $rc -ne 0 ] && grep -q "checksum mismatch" "$work/badsum/out" && [ ! -e "$work/badsum/inst/ocd" ] && never_run badsum; then ok "checksum mismatch rejected"; else ko "checksum mismatch rejected" badsum; fi

# 4. missing SHA256SUMS entry.
setup nosum v1.2.3 "$API/releases/assets/1"
: >"$FIX/$(printf '%s' "$API/releases/assets/2" | tr '/:' '__')"
run nosum
if [ $rc -ne 0 ] && [ ! -e "$work/nosum/inst/ocd" ] && never_run nosum; then ok "missing checksum entry rejected"; else ko "missing checksum entry rejected" nosum; fi

# 5. invalid archive (matching checksum, wrong content): rejected, not run.
setup badarc v1.2.3 "$API/releases/assets/1"
a="$FIX/$(printf '%s' "$API/releases/assets/1" | tr '/:' '__')"
printf 'not a tarball' >"$a"
printf '%s  %s\n' "$(sha "$a")" "ocd_1.2.3_${os}_${arch}.tar.gz" >"$FIX/$(printf '%s' "$API/releases/assets/2" | tr '/:' '__')"
run badarc
if [ $rc -ne 0 ] && [ ! -e "$work/badarc/inst/ocd" ] && never_run badarc; then ok "invalid archive rejected"; else ko "invalid archive rejected" badarc; fi

# 6. malicious tag in metadata (path characters): rejected before download.
setup badtag "v1.2.3/../../x" "$API/releases/assets/1"
run badtag
if [ $rc -ne 0 ] && grep -q "unexpected release tag" "$work/badtag/out" && ! grep -q "assets/1" "$LOG"; then ok "invalid tag rejected"; else ko "invalid tag rejected" badtag; fi

# 7. asset URL on a foreign host: token never sent there.
setup foreign v1.2.3 "https://evil.example/releases/assets/1"
run foreign GITHUB_TOKEN=ghp_testtoken123
if [ $rc -ne 0 ] && grep -q "unexpected asset URL" "$work/foreign/out" && ! grep -q "evil.example" "$LOG"; then ok "foreign asset URL rejected"; else ko "foreign asset URL rejected" foreign; fi

# 8. macOS quarantine is not stripped (no xattr call in the script).
if ! grep -q 'xattr' "$root/install.sh"; then ok "no quarantine removal"; else fail=$((fail + 1)); echo "FAIL no quarantine removal"; fi

echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
