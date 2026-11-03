#!/bin/sh
# Artifact Keeper CLI installer
# Usage: curl -fsSL https://raw.githubusercontent.com/artifact-keeper/artifact-keeper-cli/main/install.sh | sh
#
# To choose the release or the directory, pass options after `sh -s --`:
#   --version <tag>      Install this release, such as v1.11.0 (default: the latest)
#   --install-dir <dir>  Install here (default: /usr/local/bin if writable, else ~/.local/bin)
set -e

REPO="artifact-keeper/artifact-keeper-cli"
BINARY_NAME="ak"
REQUESTED_TAG=""
INSTALL_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version|--install-dir)
      if [ $# -lt 2 ]; then
        echo "Error: $1 needs a value" >&2
        exit 1
      fi
      if [ "$1" = "--version" ]; then REQUESTED_TAG="$2"; else INSTALL_DIR="$2"; fi
      shift 2
      ;;
    *)
      echo "Error: Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux*)  OS_NAME="linux";;
  Darwin*) OS_NAME="darwin";;
  MINGW*|MSYS*|CYGWIN*) OS_NAME="windows";;
  *)
    echo "Error: Unsupported operating system: $OS" >&2
    exit 1
    ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH_NAME="amd64";;
  aarch64|arm64) ARCH_NAME="arm64";;
  *)
    echo "Error: Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

# Determine artifact name
if [ "$OS_NAME" = "windows" ]; then
  ARTIFACT="ak-${OS_NAME}-${ARCH_NAME}.exe"
else
  ARTIFACT="ak-${OS_NAME}-${ARCH_NAME}"
fi

if [ -n "$REQUESTED_TAG" ]; then
  TAG="$REQUESTED_TAG"
  echo "Release: ${TAG}"
else
  # Get latest release tag
  echo "Detecting latest release..."
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

  if [ -z "$TAG" ]; then
    echo "Error: Could not determine latest release" >&2
    exit 1
  fi

  echo "Latest release: ${TAG}"
fi

# Download binary and checksum
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARTIFACT}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ARTIFACT}..."
curl -fsSL "$DOWNLOAD_URL" -o "${TMPDIR}/${ARTIFACT}"
curl -fsSL "$CHECKSUM_URL" -o "${TMPDIR}/${ARTIFACT}.sha256"

# Verify checksum
echo "Verifying checksum..."
cd "$TMPDIR"
if command -v sha256sum > /dev/null 2>&1; then
  sha256sum -c "${ARTIFACT}.sha256"
elif command -v shasum > /dev/null 2>&1; then
  shasum -a 256 -c "${ARTIFACT}.sha256"
else
  echo "Error: No checksum tool found (sha256sum or shasum required)" >&2
  exit 1
fi
cd - > /dev/null

# Determine install directory
if [ -n "$INSTALL_DIR" ]; then
  mkdir -p "$INSTALL_DIR"
else
  INSTALL_DIR="/usr/local/bin"
  if [ ! -w "$INSTALL_DIR" ] 2>/dev/null; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi

# Install
echo "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
cp "${TMPDIR}/${ARTIFACT}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

echo ""
echo "Artifact Keeper CLI (${TAG}) installed to ${INSTALL_DIR}/${BINARY_NAME}"

# Check if install dir is in PATH
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Note: ${INSTALL_DIR} is not in your PATH."
    echo "Add it with: export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac

echo ""
echo "Get started:"
echo "  ak instance add myserver https://your-registry.example.com"
echo "  ak auth login"
echo "  ak repo list"
