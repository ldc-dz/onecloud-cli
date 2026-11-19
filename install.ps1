# Install the OneCloud CLI (ocd) on Windows from the GitHub releases of
# ldc-dz/onecloud-cli.
#
#   irm https://raw.githubusercontent.com/ldc-dz/onecloud-cli/main/install.ps1 | iex
#
# No GitHub token is needed. If GITHUB_TOKEN / GH_TOKEN (or `gh auth token`)
# is available it is sent, which only raises the GitHub API rate limit.
#
# Environment:
#   OCD_VERSION      release to install, e.g. v0.2.0 (default: latest stable)
#   OCD_INSTALL_DIR  target directory (default: %LOCALAPPDATA%\Programs\ocd)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Add TLS 1.2 (and 1.3 where the runtime knows it) to the enabled protocols
# instead of replacing them, so TLS 1.3 stays available.
$proto = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') { $proto = $proto -bor [Net.SecurityProtocolType]::Tls13 }
[Net.ServicePointManager]::SecurityProtocol = $proto

$Repo = 'ldc-dz/onecloud-cli'
$Api = "https://api.github.com/repos/$Repo"

function Say($m) { Write-Host "ocd-install: $m" }
function Die($m) { throw "ocd-install: error: $m" }

$token = if ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } elseif ($env:GH_TOKEN) { $env:GH_TOKEN } else { $null }
if (-not $token -and (Get-Command gh -ErrorAction SilentlyContinue)) {
    # gh prints "no oauth token found" on stderr and exits 1 when it is not
    # signed in. Windows PowerShell 5.1 turns redirected stderr of a native
    # command into an error, which 'Stop' made fatal: the install aborted on a
    # machine that has gh but no GitHub login. The token is optional, so that
    # answer is not an error, and gh's exit code must not outlive this call.
    $ErrorActionPreference = 'Continue'
    $token = (& gh auth token 2>$null | Out-String).Trim()
    $ErrorActionPreference = 'Stop'
    $global:LASTEXITCODE = 0
}
# Keep only the line that looks like a GitHub token: a wrapper around gh can
# print status lines on stdout, and a line break breaks the header.
if ($token) { $token = ("$token" -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(gh[opusr]_|github_pat_)[A-Za-z0-9_]+$' } | Select-Object -Last 1) }
# Optional: without a token the public API is used (lower rate limit).
function Hdr($accept) {
    $h = @{ Accept = $accept; 'User-Agent' = 'ocd-install' }
    if ($token) { $h.Authorization = "Bearer $token" }
    $h
}

$cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
# PROCESSOR_ARCHITEW6432 holds the real CPU when a 32-bit shell runs on 64-bit Windows.
$arch = switch ($cpu) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { Die "unsupported CPU $cpu" }
}

$headers = Hdr 'application/vnd.github+json'
try {
    $release = if ($env:OCD_VERSION) {
        $v = $env:OCD_VERSION; if (-not $v.StartsWith('v')) { $v = "v$v" }
        Invoke-RestMethod -Headers $headers "$Api/releases/tags/$v"
    } else {
        Invoke-RestMethod -Headers $headers "$Api/releases/latest"
    }
} catch { Die "cannot read the release of $Repo (repository not public, or GitHub API rate limit: set GITHUB_TOKEN): $($_.Exception.Message)" }

$version = "$($release.tag_name)"
if ($version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$') { Die 'unexpected release tag' }
$plain = $version.TrimStart('v')
$archive = "ocd_${plain}_windows_${arch}.zip"

function Fetch($name, $dest) {
    $asset = $release.assets | Where-Object { $_.name -eq $name } | Select-Object -First 1
    if (-not $asset) { Die "release $version has no asset $name" }
    # The token is only ever sent to the GitHub API of this repository; PowerShell
    # drops Authorization when the asset redirect leaves that host.
    if ("$($asset.url)" -notmatch ('^' + [regex]::Escape("$Api/releases/assets/") + '[0-9]+$')) { Die "unexpected asset URL for $name" }
    $h = Hdr 'application/octet-stream'
    Invoke-WebRequest -UseBasicParsing -Headers $h -Uri $asset.url -OutFile $dest
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ocd-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Say "downloading ocd $version (windows/$arch)"
    Fetch $archive (Join-Path $tmp $archive)
    Fetch 'SHA256SUMS' (Join-Path $tmp 'SHA256SUMS')

    $line = Get-Content (Join-Path $tmp 'SHA256SUMS') | Where-Object { ($_ -split '\s+')[1] -eq $archive -or ($_ -split '\s+')[1] -eq "*$archive" } | Select-Object -First 1
    if (-not $line) { Die "SHA256SUMS has no entry for $archive" }
    $want = ($line -split '\s+')[0].ToLower()
    $got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $archive)).Hash.ToLower()
    if ($want -ne $got) { Die "checksum mismatch for $archive (want $want, got $got)" }
    Say 'checksum ok'

    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp -Force
    $bin = Join-Path $tmp "ocd_${plain}_windows_${arch}\ocd.exe"
    if (-not (Test-Path $bin)) { Die 'archive has no ocd.exe' }

    $dir = if ($env:OCD_INSTALL_DIR) { $env:OCD_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\ocd' }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item -Force $bin (Join-Path $dir 'ocd.exe')
    Say "installed ocd $version to $(Join-Path $dir 'ocd.exe')"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($userPath -split ';') -contains $dir)) {
        [Environment]::SetEnvironmentVariable('Path', ($(if ($userPath) { "$userPath;" } else { '' }) + $dir), 'User')
        $env:Path = "$env:Path;$dir"
        Say "added $dir to your user PATH (open a new terminal to pick it up)"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
