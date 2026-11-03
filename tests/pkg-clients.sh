#!/usr/bin/env bash
# Publish with `ak pkg`, then fetch with the format's real client in a container.
#
#   tests/start-backend.sh
#   cargo build
#   tests/pkg-clients.sh                # every format
#   tests/pkg-clients.sh npm pypi       # some of them
#
# This isn't in CI: it pulls one image per client. Run it when a helper changes.
#
#   E2E_BACKEND_URL  backend, default http://localhost:8081
#   AK_BIN           ak binary, default target/debug/ak
#   CONTAINER        docker or podman, default docker
#   AK_PASSWORD      admin password, default the E2E stack's
set -uo pipefail

BASE="${E2E_BACKEND_URL:-http://localhost:8081}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AK_BIN="${AK_BIN:-$ROOT/target/debug/ak}"
CONTAINER="${CONTAINER:-docker}"
RUN_ID="$(date +%s)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export AK_CONFIG_DIR="$WORK/ak" AK_CREDENTIAL_STORE=file AK_NO_INPUT=true NO_COLOR=1
mkdir -p "$AK_CONFIG_DIR"
printf 'default_instance = "t"\n[instances.t]\nurl = "%s"\napi_version = "v1"\n' "$BASE" >"$AK_CONFIG_DIR/config.toml"
export AK_TOKEN
AK_TOKEN="$(curl -s -X POST -H 'content-type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${AK_PASSWORD:-TestRunner!2026secure}\"}" \
  "$BASE/api/v1/auth/login" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')"
# The basic-auth form some clients need.
ADMIN_PASSWORD="${AK_PASSWORD:-TestRunner!2026secure}"
export ADMIN_PASSWORD

ak() { "$AK_BIN" "$@"; }

# box <image> <dir> <script>: run a shell script in a container, on the host's network,
# with <dir> at /w and the credentials in its environment.
box() {
  local image="$1" dir="$2" script="$3"
  "$CONTAINER" run --rm --network host -v "$dir:/w:Z" -w /w \
    -e AK_TOKEN -e ADMIN_PASSWORD -e BASE="$BASE" -e REPO="${REPO:-}" -e RUN_ID="$RUN_ID" \
    --entrypoint /bin/sh "$image" -ec "$script"
}

# repo <format> <name>: make a hosted repository, and print its key.
new_repo() {
  local key="$2-$RUN_ID"
  ak repo create "$key" --pkg-format "$1" --repo-type local --name "$key" --public >/dev/null || return 1
  echo "$key"
}

fresh() { local d="$WORK/$1"; mkdir -p "$d"; chmod 777 "$d"; echo "$d"; }

check_pypi() {
  local d; d="$(fresh pypi)"
  REPO="$(new_repo pypi pypi)" || return 1
  box docker.io/library/python:3.12-slim "$d" '
    mkdir -p src/demo_ak && cd src
    echo "VALUE = 41" > demo_ak/__init__.py
    cat > pyproject.toml <<P
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
[project]
name = "demo-ak"
version = "1.0.$RUN_ID"
description = "demo"
requires-python = ">=3.8"
[tool.setuptools]
packages = ["demo_ak"]
P
    pip -q --disable-pip-version-check install build setuptools >/dev/null
    python -m build -q --outdir /w/dist . >/dev/null' || return 1
  local f
  for f in "$d"/dist/*; do ak pkg pypi publish "$REPO" "$f" || return 1; done
  box docker.io/library/python:3.12-slim "$d" '
    url="${BASE%%://*}://admin:$ADMIN_PASSWORD@${BASE#*://}/pypi/$REPO/simple/"
    python -m venv /tmp/v
    /tmp/v/bin/pip -q --disable-pip-version-check install --no-cache-dir --index-url "$url" "demo-ak==1.0.$RUN_ID"
    /tmp/v/bin/python -c "import demo_ak; assert demo_ak.VALUE == 41"
    /tmp/v/bin/pip -q --disable-pip-version-check uninstall -y demo-ak
    /tmp/v/bin/pip -q --disable-pip-version-check install setuptools
    /tmp/v/bin/pip -q --disable-pip-version-check install --no-cache-dir --no-build-isolation --no-binary demo-ak --no-deps --index-url "$url" "demo-ak==1.0.$RUN_ID"'
}

check_npm() {
  local d; d="$(fresh npm)"
  REPO="$(new_repo npm npm)" || return 1
  box docker.io/library/node:22-slim "$d" '
    for p in plain @ak/scoped; do
      mkdir -p src/$p; (cd src/$p
      printf "{\"name\":\"%s\",\"version\":\"1.0.$RUN_ID\",\"main\":\"i.js\"}" "$p" > package.json
      echo "module.exports = 41" > i.js
      npm pack --silent --pack-destination /w >/dev/null)
    done' || return 1
  local f
  for f in "$d"/*.tgz; do ak pkg npm publish "$REPO" "$f" || return 1; done
  # Tags and removal, which the client below then sees.
  ak pkg npm dist-tag set "$REPO" plain beta "1.0.$RUN_ID" >/dev/null || return 1
  box docker.io/library/node:22-slim "$d" '
    mkdir app; cd app; echo "{}" > package.json
    h="${BASE#*://}"
    { echo "registry=$BASE/npm/$REPO/"; echo "//$h/npm/$REPO/:_authToken=$AK_TOKEN"; } > .npmrc
    npm install --silent --no-audit --no-fund plain@beta @ak/scoped
    node -e "if (require(\"plain\") !== 41 || require(\"@ak/scoped\") !== 41) process.exit(1)"
    test "$(npm view plain dist-tags.beta)" = "1.0.$RUN_ID"'
}

check_cargo() {
  local d; d="$(fresh cargo)"
  REPO="$(new_repo cargo cargo)" || return 1
  # A dependency in the same registry, with a feature, shows the index works. It isn't
  # renamed, because the backend drops the rename from its index: artifact-keeper issue.
  box docker.io/library/rust:1-slim "$d" '
    export CARGO_HOME=/tmp/ch; mkdir -p $CARGO_HOME
    v=1.0.$RUN_ID
    printf "[registries.ak]\nindex = \"sparse+$BASE/cargo/$REPO/\"\n[net]\ngit-fetch-with-cli=true\n" > $CARGO_HOME/config.toml
    mkdir -p base/src; cd base
    printf "[package]\nname=\"akbase\"\nversion=\"$v\"\nedition=\"2021\"\nlicense=\"MIT\"\ndescription=\"d\"\n[features]\nextra=[]\n" > Cargo.toml
    echo "#[cfg(feature = \"extra\")] pub const V: u32 = 41;" > src/lib.rs
    cargo package --quiet --allow-dirty --no-verify
    cp target/package/*.crate /w/' || return 1
  ak pkg cargo publish "$REPO" "$d/akbase-1.0.$RUN_ID.crate" || return 1
  box docker.io/library/rust:1-slim "$d" '
    export CARGO_HOME=/tmp/ch; mkdir -p $CARGO_HOME
    v=1.0.$RUN_ID
    printf "[registries.ak]\nindex = \"sparse+$BASE/cargo/$REPO/\"\n" > $CARGO_HOME/config.toml
    printf "[registries.ak]\ntoken = \"Bearer $AK_TOKEN\"\n" > $CARGO_HOME/credentials.toml
    mkdir -p dep/src; cd dep
    printf "[package]\nname=\"akdep\"\nversion=\"$v\"\nedition=\"2021\"\nlicense=\"MIT\"\ndescription=\"d\"\npublish=[\"ak\"]\n[dependencies]\nakbase={version=\"=$v\",registry=\"ak\",features=[\"extra\"]}\n" > Cargo.toml
    echo "pub const W: u32 = akbase::V + 1;" > src/lib.rs
    cargo package --quiet --allow-dirty --no-verify --registry ak
    cp target/package/*.crate /w/' || return 1
  ak pkg cargo publish "$REPO" "$d/akdep-1.0.$RUN_ID.crate" --endpoint api-cargo || return 1
  box docker.io/library/rust:1-slim "$d" '
    export CARGO_HOME=/tmp/ch2; mkdir -p $CARGO_HOME
    v=1.0.$RUN_ID
    printf "[registries.ak]\nindex = \"sparse+$BASE/cargo/$REPO/\"\n" > $CARGO_HOME/config.toml
    printf "[registries.ak]\ntoken = \"Bearer $AK_TOKEN\"\n" > $CARGO_HOME/credentials.toml
    mkdir -p use/src; cd use
    printf "[package]\nname=\"akuse\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nakdep={version=\"=$v\",registry=\"ak\"}\n" > Cargo.toml
    printf "fn main() { assert_eq!(akdep::W, 42); }\n" > src/main.rs
    cargo run --quiet'
}

check_helm() {
  local d; d="$(fresh helm)"
  REPO="$(new_repo helm helm)" || return 1
  box docker.io/alpine/helm:3.15.4 "$d" '
    export HOME=/tmp/h; mkdir -p $HOME
    helm create demoak >/dev/null
    helm package demoak --version 1.0.$RUN_ID >/dev/null
    helm create other >/dev/null
    helm package other --version 1.0.$RUN_ID >/dev/null' || return 1
  ak pkg helm publish "$REPO" "$d/demoak-1.0.$RUN_ID.tgz" || return 1
  ak pkg helm publish "$REPO" "$d/other-1.0.$RUN_ID.tgz" --endpoint api-helm || return 1
  ak pkg helm delete "$REPO" other "1.0.$RUN_ID" --endpoint api-helm >/dev/null || return 1
  box docker.io/alpine/helm:3.15.4 "$d" '
    export HOME=/tmp/h; mkdir -p $HOME
    helm repo add ak "$BASE/helm/$REPO" --username admin --password "$ADMIN_PASSWORD" >/dev/null
    mkdir -p /tmp/out
    helm pull ak/demoak --version 1.0.$RUN_ID --destination /tmp/out
    test -f /tmp/out/demoak-1.0.$RUN_ID.tgz
    if helm pull ak/other --version 1.0.$RUN_ID --destination /tmp/out 2>/dev/null; then echo "deleted chart still fetchable"; exit 1; fi'
}

check_nuget() {
  local d; d="$(fresh nuget)"
  REPO="$(new_repo nuget nuget)" || return 1
  box mcr.microsoft.com/dotnet/sdk:8.0 "$d" '
    export HOME=/tmp/h DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
    mkdir lib; cd lib
    dotnet new classlib -n DemoAk -o . --no-restore >/dev/null
    dotnet pack -c Release -p:PackageVersion=1.0.$RUN_ID -o /w/out >/dev/null' || return 1
  ak pkg nuget publish "$REPO" "$d/out/DemoAk.1.0.$RUN_ID.nupkg" || return 1
  box mcr.microsoft.com/dotnet/sdk:8.0 "$d" '
    export HOME=/tmp/h2 DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
    mkdir -p app; cd app
    dotnet new console -n App -o . --no-restore >/dev/null
    cat > nuget.config <<N
<configuration><packageSources><clear/><add key="ak" value="$BASE/nuget/$REPO/v3/index.json" allowInsecureConnections="true"/></packageSources>
<packageSourceCredentials><ak><add key="Username" value="admin"/><add key="ClearTextPassword" value="$ADMIN_PASSWORD"/></ak></packageSourceCredentials></configuration>
N
    dotnet add package DemoAk --version 1.0.$RUN_ID >/dev/null
    dotnet build -v q >/dev/null'
}

check_debian() {
  local d; d="$(fresh debian)"
  REPO="$(new_repo debian debian)" || return 1
  box docker.io/library/debian:12-slim "$d" '
    for n in demoak libakdemo; do
      r=$n; mkdir -p $r/DEBIAN $r/usr/share/$n; echo 41 > $r/usr/share/$n/value
      printf "Package: $n\nVersion: 1.0.$RUN_ID\nArchitecture: all\nMaintainer: t <t@example.com>\nDescription: demo\n" > $r/DEBIAN/control
      dpkg-deb --build --root-owner-group $r ${n}_1.0.${RUN_ID}_all.deb >/dev/null
    done' || return 1
  ak pkg debian publish "$REPO" "$d/demoak_1.0.${RUN_ID}_all.deb" || return 1
  ak pkg debian publish "$REPO" "$d/libakdemo_1.0.${RUN_ID}_all.deb" --endpoint upload || return 1
  box docker.io/library/debian:12-slim "$d" '
    echo "deb [trusted=yes] $BASE/debian/$REPO stable main" > /etc/apt/sources.list
    rm -f /etc/apt/sources.list.d/*
    apt-get -qq update
    apt-get -qq install -y demoak libakdemo >/dev/null
    test "$(cat /usr/share/demoak/value)" = 41
    test "$(cat /usr/share/libakdemo/value)" = 41'
}

check_rpm() {
  local d; d="$(fresh rpm)"
  REPO="$(new_repo rpm rpm)" || return 1
  box docker.io/library/fedora:41 "$d" '
    dnf -q -y install rpm-build >/dev/null
    for n in akone aktwo akthree; do
      cat > $n.spec <<S
Name: $n
Version: 1.0.$RUN_ID
Release: 1
Summary: demo
License: MIT
BuildArch: noarch
%description
demo
%install
mkdir -p %{buildroot}/usr/share/$n
echo 41 > %{buildroot}/usr/share/$n/value
%files
/usr/share/$n/value
S
      rpmbuild -bb --quiet --define "_rpmdir /w/out" $n.spec
    done' || return 1
  ak pkg rpm publish "$REPO" "$d/out/noarch/akone-1.0.$RUN_ID-1.noarch.rpm" || return 1
  ak pkg rpm publish "$REPO" "$d/out/noarch/aktwo-1.0.$RUN_ID-1.noarch.rpm" --endpoint upload || return 1
  # What issue #185 reported: the same package through `ak artifact push`.
  ak artifact push "$REPO" "$d/out/noarch/akthree-1.0.$RUN_ID-1.noarch.rpm" >/dev/null || return 1
  box docker.io/library/fedora:41 "$d" '
    cat > /etc/yum.repos.d/ak.repo <<R
[ak]
name=ak
baseurl=$BASE/rpm/$REPO/
gpgcheck=0
repo_gpgcheck=0
R
    dnf -q -y --disablerepo="*" --enablerepo=ak install akone aktwo akthree >/dev/null
    for n in akone aktwo akthree; do test "$(cat /usr/share/$n/value)" = 41; done'
}

check_alpine() {
  local d; d="$(fresh alpine)"
  REPO="$(new_repo alpine alpine)" || return 1
  box docker.io/library/alpine:3.20 "$d" '
    apk add -q alpine-sdk >/dev/null
    adduser -D b; addgroup b abuild; mkdir -p /home/b/akdemo /tmp/out; chown -R b /home/b /tmp/out
    cat > /home/b/akdemo/APKBUILD <<A
pkgname=akdemo
pkgver=1.0.$RUN_ID
pkgrel=0
pkgdesc="demo"
url="https://example.com"
arch="noarch"
license="MIT"
options="!check"
package() { mkdir -p "\$pkgdir/usr/share/akdemo"; echo 41 > "\$pkgdir/usr/share/akdemo/value"; }
A
    su b -c "abuild-keygen -a -n -q; cd ~/akdemo && REPODEST=/tmp/out abuild -d -q -r" 2>&1 | tail -3
    find /tmp/out -name "*.apk" -exec cp {} /w/ \;' || return 1
  ak pkg alpine publish "$REPO" "$d/akdemo-1.0.$RUN_ID-r0.apk" --arch x86_64 || return 1
  box docker.io/library/alpine:3.20 "$d" '
    apk add -q --no-cache --allow-untrusted --repository "$BASE/alpine/$REPO/edge/main" akdemo >/dev/null
    test "$(cat /usr/share/akdemo/value)" = 41'
}

check_pacman() {
  local d; d="$(fresh pacman)"
  REPO="$(new_repo pacman pacman)" || return 1
  box docker.io/library/archlinux:base-devel "$d" '
    useradd -m b; mkdir /tmp/b; chown b /tmp/b; cd /tmp/b
    cat > PKGBUILD <<P
pkgname=akdemo
pkgver=1.0.$RUN_ID
pkgrel=1
pkgdesc=demo
arch=(any)
license=(MIT)
package() { mkdir -p "\$pkgdir/usr/share/akdemo"; echo 41 > "\$pkgdir/usr/share/akdemo/value"; }
P
    su b -c "makepkg -s --noconfirm >/dev/null 2>&1"
    cp *.pkg.tar.* /w/' || return 1
  ak pkg pacman publish "$REPO" "$d/"akdemo-*.pkg.tar.* || return 1
  box docker.io/library/archlinux:base-devel "$d" '
    printf "\n[$REPO]\nSigLevel = Never\nServer = $BASE/pacman/$REPO/\$arch\n" >> /etc/pacman.conf
    pacman -Sy --noconfirm --config /etc/pacman.conf akdemo >/dev/null
    test "$(cat /usr/share/akdemo/value)" = 41'
}

check_conda() {
  local d; d="$(fresh conda)"
  REPO="$(new_repo conda conda)" || return 1
  # conda-build is a large install for a directory of metadata and a tar.bz2.
  box docker.io/library/python:3.12-slim "$d" '
    python -I - <<P
import io, json, os, tarfile
run = os.environ["RUN_ID"]
for name in ("akdemo", "aktoken", "aktoken2", "akgone"):
    index = {"name": name, "version": "1.0."+run, "build": "0", "build_number": 0,
             "subdir": "noarch", "depends": [], "arch": None, "platform": None, "noarch": "generic"}
    files = {"info/index.json": json.dumps(index), "info/files": "share/"+name+"/value\n",
             "info/paths.json": json.dumps({"paths": [{"_path": "share/"+name+"/value", "path_type": "hardlink",
                 "sha256": __import__("hashlib").sha256(b"41\n").hexdigest(), "size_in_bytes": 3}], "paths_version": 1}),
             "share/"+name+"/value": "41\n"}
    with tarfile.open(f"/w/{name}-1.0.{run}-0.tar.bz2", "w:bz2") as t:
        for path, text in files.items():
            data = text.encode(); info = tarfile.TarInfo(path); info.size = len(data); t.addfile(info, io.BytesIO(data))
P' || return 1
  ak pkg conda publish "$REPO" "$d/akdemo-1.0.$RUN_ID-0.tar.bz2" || return 1
  # The token in the URL has to be an API token.
  local api_token
  api_token="$(ak --format json auth token create --description "conda-$RUN_ID" --scope write:artifacts --expires-in 1 |
    python3 -I -c 'import json,sys;print(json.load(sys.stdin)["token"])')" || return 1
  AK_TOKEN="$api_token" ak pkg conda publish "$REPO" "$d/aktoken-1.0.$RUN_ID-0.tar.bz2" --subdir noarch --token-in-url t-conda || return 1
  AK_TOKEN="$api_token" ak pkg conda publish "$REPO" "$d/aktoken2-1.0.$RUN_ID-0.tar.bz2" --token-in-url conda-t || return 1
  # An attestation has to be a signed bundle, which is out of reach here, so this shows
  # only that it reaches the handler: the server reads it, and refuses it for what it is.
  local refused
  refused="$(ak pkg conda attest "$REPO" noarch "akdemo-1.0.$RUN_ID-0.tar.bz2" '{}' 2>&1)" && return 1
  case "$refused" in *404*) echo "$refused"; return 1 ;; esac
  # A withdrawn package isn't offered any more.
  ak pkg conda publish "$REPO" "$d/akgone-1.0.$RUN_ID-0.tar.bz2" --subdir noarch || return 1
  ak pkg conda withdraw "$REPO" noarch "akgone-1.0.$RUN_ID-0.tar.bz2" --reason test --yes || return 1
  box docker.io/mambaorg/micromamba:1.5-bookworm-slim "$d" '
    export MAMBA_ROOT_PREFIX=/tmp/m
    micromamba create -q -y -n e --override-channels -c "$BASE/conda/$REPO" akdemo aktoken aktoken2 >/dev/null
    for n in akdemo aktoken aktoken2; do test "$(cat /tmp/m/envs/e/share/$n/value)" = 41; done
    if micromamba create -q -y -n g --override-channels -c "$BASE/conda/$REPO" akgone >/dev/null 2>&1; then
      echo "a withdrawn package installed"; exit 1
    fi'
}

# A format's check, its outcome on one line, and its output only if it failed.
run() {
  local name="$1" log="$WORK/$1.log"
  if "check_$name" >"$log" 2>&1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  /' "$log" | tail -40
    FAILED=1
  fi
}

FAILED=0
ALL=(pypi npm cargo helm nuget debian rpm alpine pacman conda)
for name in "${@:-${ALL[@]}}"; do run "$name"; done
exit "$FAILED"
