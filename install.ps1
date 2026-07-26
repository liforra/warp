# Installs the latest warp release for Windows.
# Usage: irm https://raw.githubusercontent.com/liforra/warp/master/install.ps1 | iex
$ErrorActionPreference = "Stop"

$Repo = "liforra/warp"
$Binary = "warp"
$InstallDir = if ($env:WARP_INSTALL_DIR) { $env:WARP_INSTALL_DIR } else { "$env:LOCALAPPDATA\warp" }

$arch = if ([Environment]::Is64BitOperatingSystem) {
	if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else {
	throw "warp: unsupported 32-bit OS"
}

$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
$tag = $release.tag_name
$versionNoV = $tag.TrimStart("v")
$asset = "${Binary}_${versionNoV}_windows_${arch}.zip"
$url = "https://github.com/$Repo/releases/download/$tag/$asset"

$tmp = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
	$zipPath = Join-Path $tmp $asset
	Write-Host "warp: downloading $tag for windows/$arch..."
	Invoke-WebRequest -Uri $url -OutFile $zipPath
	Expand-Archive -Path $zipPath -DestinationPath $tmp

	New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
	Copy-Item -Path (Join-Path $tmp "$Binary.exe") -Destination (Join-Path $InstallDir "$Binary.exe") -Force
	Write-Host "warp: installed to $InstallDir\$Binary.exe"

	if ($env:Path -notlike "*$InstallDir*") {
		Write-Host "warp: note - $InstallDir is not on your PATH"
	}
} finally {
	Remove-Item -Recurse -Force $tmp
}
