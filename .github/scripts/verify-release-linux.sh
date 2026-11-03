#!/usr/bin/env bash
# Check a published release the way a user meets it: from the public downloads,
# not the workflow's own artifacts.
#
# Usage: verify-release-linux.sh <tag> <amd64|arm64>
# Needs docker, cosign, readelf, gh (GH_TOKEN). VERIFY_DIR and REPO are optional.
set -euo pipefail

tag="${1:?usage: $0 <tag> <amd64|arm64>}"
arch="${2:?usage: $0 <tag> <amd64|arm64>}"
repo="${REPO:-artifact-keeper/artifact-keeper-cli}"
here="$(cd "$(dirname "$0")" && pwd)"
dir="${VERIFY_DIR:-$(mktemp -d)}"
mkdir -p "$dir"

# Cargo.toml has 1.11.0 for the tag v1.11.0-rc.1.
version="${tag#v}"
version="${version%%-*}"
want="ak $version"

check_version() {
  local where="$1" got="$2"
  if [ "$got" != "$want" ]; then
    echo "::error::$where printed '$got', wanted '$want'"
    return 1
  fi
  echo "$where: $got"
}

case "$arch" in
  amd64) rpm_arch=x86_64 ;;
  arm64) rpm_arch=aarch64 ;;
  *)
    echo "::error::Unknown architecture '$arch'"
    exit 1
    ;;
esac

echo "--- install.sh from $tag"
curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors \
  "https://raw.githubusercontent.com/$repo/$tag/install.sh" -o "$dir/install.sh"
sh "$dir/install.sh" --version "$tag" --install-dir "$dir/bin"
check_version "install.sh" "$("$dir/bin/ak" --version)"

echo "--- Download the release"
assets="$dir/assets"
mkdir -p "$assets"
gh release download "$tag" -R "$repo" -D "$assets" --clobber
binary="ak-linux-$arch"

echo "--- Checksum and static linking"
(cd "$assets" && sha256sum -c "$binary.sha256")
chmod +x "$assets/$binary"
"$here/check-static-binary.sh" "$assets/$binary"

# Loop over what was published, not over names built here. GitHub rewrites some
# characters in asset names, and an rc's packages have a ~ in their version.
echo "--- cosign, every published file"
count=0
for file in "$assets"/*; do
  case "$file" in
    *.sha256|*.sig|*.pem) continue ;;
  esac
  cosign verify-blob \
    --certificate "$file.pem" \
    --signature "$file.sig" \
    --certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$file"
  count=$((count + 1))
done
# Five binaries, completions, man pages, two debs, two rpms.
if [ "$count" -ne 11 ]; then
  echo "::error::Verified $count files, wanted 11"
  ls -l "$assets"
  exit 1
fi
echo "Verified $count signatures"

echo "--- The binary in other distributions"
for image in alpine:3.22 ubuntu:22.04 debian:12; do
  check_version "$image" "$(docker run --rm -v "$assets:/w:ro" "$image" "/w/$binary" --version)"
done

# A static binary has no NSS and no system TLS library to lean on, so make it do
# DNS and TLS. Alpine's base image has CA certificates; ubuntu's and debian's
# don't. --no-fail takes any HTTP status: only a failed connection exits non-zero.
echo "--- DNS and TLS on Alpine"
docker run --rm -v "$assets:/w:ro" -e HOME=/tmp -e AK_NO_INPUT=true alpine:3.22 \
  "/w/$binary" api GET https://github.com/ --anon --no-fail --head-only

echo "--- deb on ubuntu:22.04"
# Globs, for the same reason as above. Each matches one file, or the install fails.
check_version "deb" "$(docker run --rm -v "$assets:/w:ro" ubuntu:22.04 \
  sh -c "dpkg -i /w/ak*_$arch.deb >&2 && ak --version")"

echo "--- rpm on rockylinux:9"
check_version "rpm" "$(docker run --rm -v "$assets:/w:ro" rockylinux:9 \
  sh -c "rpm -i /w/ak*.$rpm_arch.rpm >&2 && ak --version")"

echo "All checks passed for $tag on $arch"
