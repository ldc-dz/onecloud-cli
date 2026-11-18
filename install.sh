#!/bin/sh
# Install the OneCloud CLI (ocd) from the GitHub releases of ldc-dz/onecloud-cli.
#
#   curl -fsSL https://raw.githubusercontent.com/ldc-dz/onecloud-cli/main/install.sh | sh
#
# No GitHub token is needed. If GITHUB_TOKEN / GH_TOKEN (or `gh auth token`)
# is available it is sent, which only raises the GitHub API rate limit.
#
# Environment:
#   OCD_VERSION      release to install, e.g. v0.2.0 (default: latest stable)
#   OCD_INSTALL_DIR  target directory (default: ~/.local/bin)
set -eu

REPO="ldc-dz/onecloud-cli"
API="https://api.github.com/repos/${REPO}"

say() { printf 'ocd-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need curl
need tar
need uname

token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
if [ -z "$token" ] && command -v gh >/dev/null 2>&1; then
  token="$(gh auth token 2>/dev/null || true)"
fi
# Keep only the line that looks like a GitHub token: a wrapper around gh (mise,
# asdf, ...) can print status lines on stdout, and a line break in the header
# makes curl fail with error 43.
token="$(printf '%s\n' "$token" | tr -d '\r' | sed -n -E 's/^[[:space:]]*((gh[opusr]_|github_pat_)[A-Za-z0-9_]+)[[:space:]]*$/\1/p' | tail -n 1)"
# Optional: without a token the public API is used (lower rate limit).
set --
[ -z "$token" ] || set -- -H "Authorization: Bearer ${token}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "sha256sum or shasum is required to verify the download"
fi

# HTTPS only, including redirects. curl (>= 7.58) never forwards a custom
# Authorization header to a different host on redirect (no --location-trusted).
api() { curl -fsSL --proto '=https' --proto-redir '=https' "$@" -H "Accept: application/vnd.github+json" "$api_url"; }

version="${OCD_VERSION:-}"
if [ -z "$version" ]; then
  api_url="${API}/releases/latest"
  release="$(api "$@")" || die "cannot read the latest release of ${REPO} (repository not public, or GitHub API rate limit: set GITHUB_TOKEN)"
else
  case "$version" in v*) ;; *) version="v${version}" ;; esac
  api_url="${API}/releases/tags/${version}"
  release="$(api "$@")" || die "release ${version} not found"
fi
# Release JSON is small and flat enough for sed; avoids a jq dependency.
release="$(printf '%s' "$release" | tr -d '\n')"
version="$(printf '%s' "$release" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')"
[ -n "$version" ] || die "cannot read the release tag"
# The tag ends up in file names: accept only a plain semver tag.
printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' ||
  die "unexpected release tag"
plain="${version#v}"
archive="ocd_${plain}_${os}_${arch}.tar.gz"

asset_url() {
  # "url" of the asset object whose "name" is $1 (the API download endpoint).
  printf '%s' "$release" | tr '{' '\n' | grep "\"name\": *\"$1\"" |
    sed -n 's/.*"url": *"\([^"]*\/releases\/assets\/[0-9]*\)".*/\1/p' | head -n 1
}
fetch() {
  name="$1" dest="$2"
  shift 2
  url="$(asset_url "$name")"
  [ -n "$url" ] || die "release ${version} has no asset $name"
  # The token is only ever sent to the GitHub API of this repository.
  case "$url" in
    "${API}/releases/assets/"[0-9]*) ;;
    *) die "unexpected asset URL for $name" ;;
  esac
  curl -fsSL --proto '=https' --proto-redir '=https' "$@" -H "Accept: application/octet-stream" -o "$dest" "$url"
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
say "downloading ocd ${version} (${os}/${arch})"
fetch "$archive" "$tmp/$archive" "$@"
fetch SHA256SUMS "$tmp/SHA256SUMS" "$@"

want="$(awk -v f="$archive" '$2 == f || $2 == "*"f {print $1}' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "SHA256SUMS has no entry for $archive"
got="$(sha "$tmp/$archive")"
[ "$want" = "$got" ] || die "checksum mismatch for $archive (want $want, got $got)"
say "checksum ok"

# Extract only the expected member (no stray paths from the archive).
member="ocd_${plain}_${os}_${arch}/ocd"
tar -xzf "$tmp/$archive" -C "$tmp" "$member" 2>/dev/null || die "archive has no ocd binary"
bin="$tmp/$member"
[ -f "$bin" ] && [ ! -L "$bin" ] || die "archive has no ocd binary"

dir="${OCD_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$dir"
install -m 0755 "$bin" "$dir/ocd" 2>/dev/null || { cp "$bin" "$dir/ocd" && chmod 0755 "$dir/ocd"; }
# The macOS quarantine attribute is left untouched (Gatekeeper decides), and
# the downloaded binary is not run by the installer.
say "installed ocd ${version} to $dir/ocd"

case ":${PATH}:" in
  *":${dir}:"*) ;;
  *)
    # zsh (macOS default login shell) never reads ~/.profile.
    rc="$HOME/.profile"
    case "${SHELL:-}" in
      */zsh) rc="$HOME/.zprofile" ;;
      */bash)
        if [ -f "$HOME/.bash_profile" ]; then rc="$HOME/.bash_profile"
        elif [ -f "$HOME/.bashrc" ]; then rc="$HOME/.bashrc"
        fi
        ;;
    esac
    say "add ${dir} to your PATH, e.g.: echo 'export PATH=\"${dir}:\$PATH\"' >> ${rc}"
    ;;
esac
