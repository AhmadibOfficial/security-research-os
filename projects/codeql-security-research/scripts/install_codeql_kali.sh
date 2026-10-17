#!/usr/bin/env bash
# CodeQL official Linux bundle installation, no root access or repo writes.
set -euo pipefail
for executable in gh tar sha256sum uname mktemp; do
  command -v "$executable" >/dev/null || { echo "HOLD: missing $executable" >&2; exit 2; }
done
case "$(uname -sm)" in
  'Linux x86_64') platform='linux64' ;;
  'Linux aarch64'|'Linux arm64') platform='linux-arm64' ;;
  *) echo 'HOLD: only Linux x86-64 and ARM64 supported.' >&2; exit 2 ;;
esac
destination="$HOME/.local/opt/codeql-bundle"
if [[ -e "$destination" || -L "$destination" ]]; then
  echo "HOLD: $destination exists; refusing to overwrite." >&2; exit 2
fi
echo 'Read and accept applicable GitHub CodeQL terms before continuing:'
echo 'https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md'
echo 'The terms do not permit unrestricted private-code or production CI analysis.'
if [[ $# != 1 || "$1" != '--accept-reviewed-terms' ]]; then
  echo 'HOLD: rerun with --accept-reviewed-terms only if eligible.' >&2; exit 2
fi
release="$(gh api 'repos/github/codeql-action/releases?per_page=100' \
  --jq '[.[] | select((.tag_name | startswith("codeql-bundle-v")) and .draft == false and .prerelease == false)] | first | .tag_name')"
if [[ ! "$release" =~ ^codeql-bundle-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo 'HOLD: Could not resolve a trustworthy release tag.' >&2; exit 2
fi
asset="codeql-bundle-$platform.tar.gz"
digest="$(gh api "repos/github/codeql-action/releases/tags/$release" \
  --jq ".assets[] | select(.name == \"$asset\") | .digest" | head -n 1)"
if [[ ! "$digest" =~ ^sha256:[0-9a-fA-F]{64}$ ]]; then
  echo "HOLD: $release does not expose a trusted SHA-256 for $asset." >&2; exit 2
fi
echo "Downloading official $release ($asset)"
download_dir="$(mktemp -d)"
trap 'rm -rf -- "$download_dir"' EXIT
gh release download "$release" --repo github/codeql-action \
  --pattern "$asset" --dir "$download_dir"
printf '%s  %s\n' "$(printf '%s' "$digest" | cut -c8-)" "$download_dir/$asset" | sha256sum -c -
mkdir -p "$HOME/.local/opt"
mkdir "$destination"
tar -xzf "$download_dir/$asset" -C "$destination"
if [[ ! -x "$destination/codeql/codeql" ]]; then
  echo 'HOLD: Expected CodeQL executable was not present.' >&2; exit 1
fi
"$destination/codeql/codeql" version
"$destination/codeql/codeql" resolve languages
echo 'PASS: Verified bundle installed without modifying Git or shell startup.'
echo 'To activate in the current shell run:'
echo 'export PATH="$HOME/.local/opt/codeql-bundle/codeql:$PATH"'
echo 'No source database or real CodeQL query has been run.'
