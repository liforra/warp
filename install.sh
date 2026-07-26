#!/bin/sh
# Installs the latest warp release for the current OS/arch.
# Usage: curl -fsSL https://raw.githubusercontent.com/liforra/warp/master/install.sh | sh
#
# Deliberately POSIX sh, not bash: `curl | sh` runs under whatever /bin/sh
# is (dash on most Linux distros), which doesn't understand bash-only
# syntax like `set -o pipefail` -- that alone previously made dash exit
# immediately, breaking the pipe and failing the curl on the other end.
set -eu

REPO="liforra/warp"
BINARY="warp"
INSTALL_DIR="${WARP_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	arm64 | aarch64) arch="arm64" ;;
	*)
		echo "warp: unsupported architecture: $arch" >&2
		exit 1
		;;
esac
case "$os" in
	linux | darwin) ext="tar.gz" ;;
	*)
		echo "warp: unsupported OS: $os (Windows users: see install.ps1 or Scoop)" >&2
		exit 1
		;;
esac

release_json="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")"
# grep -m1 exits as soon as it finds a match; piping curl straight into it
# can make curl try to write to an already-closed pipe (a harmless but
# noisy "Failure writing output to destination" error) -- capturing the
# full response first avoids that entirely.
latest_tag="$(printf '%s' "$release_json" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
if [ -z "$latest_tag" ]; then
	echo "warp: could not determine latest release" >&2
	exit 1
fi

version_no_v="${latest_tag#v}"
asset="${BINARY}_${version_no_v}_${os}_${arch}.${ext}"
url="https://github.com/${REPO}/releases/download/${latest_tag}/${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "warp: downloading ${latest_tag} for ${os}/${arch}..."
curl -fsSL "$url" -o "$tmp/$asset"
tar -xzf "$tmp/$asset" -C "$tmp"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/$BINARY" "$INSTALL_DIR/$BINARY"
echo "warp: installed to ${INSTALL_DIR}/${BINARY}"

case ":$PATH:" in
	*":$INSTALL_DIR:"*) ;;
	*) echo "warp: note - ${INSTALL_DIR} is not on your \$PATH" ;;
esac
