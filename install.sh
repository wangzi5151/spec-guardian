#!/bin/sh
# Spec-Guardian installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/wangzi5151/spec-guardian/main/install.sh | sh -s -- -b /usr/local/bin
#
# Flags:
#   -b DIR       install directory (default: /usr/local/bin or ~/.local/bin)
#   -v VERSION   version tag (default: latest)
#   -h           show help

set -eu

repo="wangzi5151/spec-guardian"
version="latest"
bindir=""

while getopts "b:v:h" opt; do
  case "$opt" in
    b) bindir="$OPTARG" ;;
    v) version="$OPTARG" ;;
    h) sed -n '2,12p' "$0" 2>/dev/null || true; exit 0 ;;
    *) exit 1 ;;
  esac
done

if [ -z "$bindir" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then bindir="/usr/local/bin"; else bindir="$HOME/.local/bin"; fi
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  i386|i686) arch="386" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  mingw*|msys*|cygwin*) os="windows" ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

ext=""
[ "$os" = "windows" ] && ext=".exe"

if [ "$version" = "latest" ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi
url="$base/spec-guardian_${os}_${arch}${ext}"

mkdir -p "$bindir"
tmp="$(mktemp)"
echo "Downloading $url"
if ! curl -fsSL "$url" -o "$tmp"; then
  echo "Download failed. Check that a release exists for $os/$arch ($version)." >&2
  rm -f "$tmp"
  exit 1
fi
chmod +x "$tmp"
mv "$tmp" "$bindir/spec-guardian$ext"
echo "Installed spec-guardian to $bindir/spec-guardian$ext"
"$bindir/spec-guardian$ext" version || true
