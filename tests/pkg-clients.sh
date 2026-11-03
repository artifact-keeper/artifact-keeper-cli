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

# Whether the backend has what's new in 1.11, for the checks of what isn't on 1.10.
is_1_11() {
  curl -s "$BASE/health" | python3 -I -c '
import json, sys
major, minor = json.load(sys.stdin)["version"].split(".")[:2]
sys.exit(0 if (int(major), int(minor)) >= (1, 11) else 1)'
}

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
  is_1_11 || { echo "needs 1.11"; return 0; }
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
  # 1.10 has only one of the two URL forms, and no withdrawal.
  local form=t-conda
  is_1_11 || form=conda-t
  AK_TOKEN="$api_token" ak pkg conda publish "$REPO" "$d/aktoken-1.0.$RUN_ID-0.tar.bz2" --subdir noarch --token-in-url "$form" || return 1
  if is_1_11; then
    AK_TOKEN="$api_token" ak pkg conda publish "$REPO" "$d/aktoken2-1.0.$RUN_ID-0.tar.bz2" --token-in-url conda-t || return 1
  else
    AK_TOKEN="$api_token" ak pkg conda publish "$REPO" "$d/aktoken2-1.0.$RUN_ID-0.tar.bz2" --subdir noarch --token-in-url conda-t || return 1
  fi
  # An attestation has to be a signed bundle, which is out of reach here, so this shows
  # only that it reaches the handler: the server reads it, and refuses it for what it is.
  local refused
  refused="$(ak pkg conda attest "$REPO" noarch "akdemo-1.0.$RUN_ID-0.tar.bz2" '{}' 2>&1)" && return 1
  case "$refused" in *404*) echo "$refused"; return 1 ;; esac
  # A withdrawn package isn't offered any more.
  local gone=""
  if is_1_11; then
    gone=1
    ak pkg conda publish "$REPO" "$d/akgone-1.0.$RUN_ID-0.tar.bz2" --subdir noarch || return 1
    ak pkg conda withdraw "$REPO" noarch "akgone-1.0.$RUN_ID-0.tar.bz2" --reason test --yes || return 1
  fi
  box docker.io/mambaorg/micromamba:1.5-bookworm-slim "$d" '
    export MAMBA_ROOT_PREFIX=/tmp/m
    micromamba create -q -y -n e --override-channels -c "$BASE/conda/$REPO" akdemo aktoken aktoken2 >/dev/null
    for n in akdemo aktoken aktoken2; do test "$(cat /tmp/m/envs/e/share/$n/value)" = 41; done
    if [ -n "'"$gone"'" ] && micromamba create -q -y -n g --override-channels -c "$BASE/conda/$REPO" akgone >/dev/null 2>&1; then
      echo "a withdrawn package installed"; exit 1
    fi'
}

check_maven() {
  local d; d="$(fresh maven)"
  REPO="$(new_repo maven maven)" || return 1
  box docker.io/library/maven:3-eclipse-temurin-21 "$d" '
    mkdir -p src/main/java/ak
    echo "package ak; public class Demo { public static int v() { return 41; } }" > src/main/java/ak/Demo.java
    cat > pom.xml <<P
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>com.acme.ak</groupId><artifactId>demo</artifactId><version>1.0.$RUN_ID</version><packaging>jar</packaging>
<properties><maven.compiler.source>21</maven.compiler.source><maven.compiler.target>21</maven.compiler.target></properties></project>
P
    mvn -q -B -Dmaven.repo.local=/tmp/m2 package >/dev/null' || return 1
  ak pkg maven publish "$REPO" "$d/target/demo-1.0.$RUN_ID.jar" --group com.acme.ak --artifact demo --version "1.0.$RUN_ID" --pom "$d/pom.xml" || return 1
  # With a generated POM.
  ak pkg maven publish "$REPO" "$d/target/demo-1.0.$RUN_ID.jar" --group com.acme.ak --artifact generated --version "1.0.$RUN_ID" || return 1
  box docker.io/library/maven:3-eclipse-temurin-21 "$d" '
    mkdir -p /tmp/s; cat > /tmp/s/settings.xml <<S
<settings><mirrors><mirror><id>ak</id><url>$BASE/maven/$REPO</url><mirrorOf>ak</mirrorOf></mirror></mirrors></settings>
S
    mkdir -p use; cd use; cat > pom.xml <<P
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>u</groupId><artifactId>u</artifactId><version>1</version>
<repositories><repository><id>ak</id><url>http://ak.invalid/</url></repository></repositories>
<dependencies>
<dependency><groupId>com.acme.ak</groupId><artifactId>demo</artifactId><version>1.0.$RUN_ID</version></dependency>
<dependency><groupId>com.acme.ak</groupId><artifactId>generated</artifactId><version>1.0.$RUN_ID</version></dependency>
</dependencies></project>
P
    mvn -q -B -s /tmp/s/settings.xml -Dmaven.repo.local=/tmp/m3 -Dmaven.wagon.http.ssl.insecure=true \
      -Dmaven.resolver.transport=wagon -Daether.checksums.algorithms=SHA-512,SHA-256,SHA-1,MD5 \
      -Dmaven.resolver.checksumPolicy=fail dependency:resolve 2>&1 | tail -5
    test -f /tmp/m3/com/acme/ak/demo/1.0.$RUN_ID/demo-1.0.$RUN_ID.jar
    test -f /tmp/m3/com/acme/ak/generated/1.0.$RUN_ID/generated-1.0.$RUN_ID.jar'
}

check_go() {
  local d; d="$(fresh go)"
  REPO="$(new_repo go go)" || return 1
  box docker.io/library/golang:1.23 "$d" '
    export GOFLAGS=-mod=mod GOPATH=/tmp/gp GOCACHE=/tmp/gc
    mkdir -p src; cd src
    printf "module example.com/Ak/demo\n\ngo 1.21\n" > go.mod
    printf "package demo\n\nconst V = 41\n" > demo.go
    cd ..
    # A module zip by the book: every path starts with <module>@<version>.
    p="example.com/!ak/demo"; v="v1.0.$RUN_ID"
    mkdir -p "z/example.com/Ak/demo@$v"
    cp src/go.mod src/demo.go "z/example.com/Ak/demo@$v/"
    apt-get -qq update >/dev/null; apt-get -qq install -y zip >/dev/null
    (cd z && zip -qr ../mod.zip "example.com/Ak/demo@$v")' || return 1
  ak pkg go publish "$REPO" "$d/mod.zip" || return 1
  box docker.io/library/golang:1.23 "$d" '
    export GOPATH=/tmp/gp GOCACHE=/tmp/gc GONOSUMDB="*" GONOSUMCHECK=1 GOFLAGS=-mod=mod GOINSECURE="*"
    export GOPROXY="$BASE/go/$REPO"
    mkdir use; cd use
    printf "module u\n\ngo 1.21\n" > go.mod
    printf "package main\n\nimport d \"example.com/Ak/demo\"\n\nfunc main() { if d.V != 41 { panic(d.V) } }\n" > m.go
    go get "example.com/Ak/demo@v1.0.$RUN_ID"
    go run .'
}

check_gems() {
  local d; d="$(fresh gems)"
  REPO="$(new_repo rubygems gems)" || return 1
  box docker.io/library/ruby:3.3-slim "$d" '
    cat > akdemo.gemspec <<G
Gem::Specification.new do |s|
  s.name = "akdemo"; s.version = "1.0.$RUN_ID"; s.summary = "demo"; s.authors = ["t"]
  s.files = ["lib/akdemo.rb"]; s.license = "MIT"; s.homepage = "https://example.com"
end
G
    mkdir lib; echo "module Akdemo; V = 41; end" > lib/akdemo.rb
    gem build -q akdemo.gemspec >/dev/null' || return 1
  ak pkg gems publish "$REPO" "$d/akdemo-1.0.$RUN_ID.gem" || return 1
  box docker.io/library/ruby:3.3-slim "$d" '
    gem install -q --no-document --clear-sources --source "$BASE/gems/$REPO" akdemo -v 1.0.$RUN_ID >/dev/null
    ruby -e "require %q(akdemo); exit(Akdemo::V == 41 ? 0 : 1)"'
}

check_composer() {
  local d; d="$(fresh composer)"
  REPO="$(new_repo composer composer)" || return 1
  box docker.io/library/composer:2 "$d" '
    mkdir -p src/src; cd src
    printf "{\"name\":\"acme/akdemo\",\"version\":\"1.0.$RUN_ID\",\"autoload\":{\"files\":[\"src/v.php\"]}}" > composer.json
    printf "<?php\nconst AK_V = 41;\n" > src/v.php
    apk add -q zip >/dev/null 2>&1 || true
    zip -qr ../akdemo.zip .' || return 1
  ak pkg composer publish "$REPO" "$d/akdemo.zip" || return 1
  box docker.io/library/composer:2 "$d" '
    export COMPOSER_HOME=/tmp/ch
    mkdir use; cd use
    cat > composer.json <<C
{"repositories":[{"type":"composer","url":"$BASE/composer/$REPO"},{"packagist.org":false}],
 "config":{"secure-http":false},"require":{"acme/akdemo":"1.0.$RUN_ID"}}
C
    composer -q --no-interaction install
    php -r "require \"vendor/autoload.php\"; exit(AK_V === 41 ? 0 : 1);"'
}

check_cran() {
  local d; d="$(fresh cran)"
  REPO="$(new_repo cran cran)" || return 1
  box docker.io/rocker/r-ver:4.4 "$d" '
    mkdir -p akdemo/R; cd akdemo
    printf "Package: akdemo\nVersion: 1.0.0\nTitle: Demo\nDescription: A demo.\nLicense: MIT\nAuthor: t\nMaintainer: t <t@example.com>\n" > DESCRIPTION
    echo "export(v)" > NAMESPACE
    echo "v <- function() 41" > R/v.R
    cd ..; R CMD build akdemo >/dev/null' || return 1
  ak pkg cran publish "$REPO" "$d/akdemo_1.0.0.tar.gz" || return 1
  box docker.io/rocker/r-ver:4.4 "$d" '
    Rscript -e "install.packages(\"akdemo\", repos=\"$BASE/cran/$REPO\", lib=\"/tmp\", quiet=TRUE); library(akdemo, lib.loc=\"/tmp\"); stopifnot(v() == 41)"'
}

check_pub() {
  local d; d="$(fresh pub)"
  REPO="$(new_repo pub pub)" || return 1
  box docker.io/library/dart:stable "$d" '
    mkdir -p src/lib; cd src
    printf "name: akdemo\nversion: 1.0.$RUN_ID\nenvironment:\n  sdk: \">=3.0.0 <4.0.0\"\n" > pubspec.yaml
    echo "const v = 41;" > lib/akdemo.dart
    tar czf ../akdemo.tar.gz .' || return 1
  ak pkg pub publish "$REPO" "$d/akdemo.tar.gz" || return 1
  box docker.io/library/dart:stable "$d" '
    export PUB_CACHE=/tmp/pc HOME=/tmp/h; mkdir -p /tmp/h use/bin; cd use
    cat > pubspec.yaml <<P
name: useit
environment:
  sdk: ">=3.0.0 <4.0.0"
dependencies:
  akdemo:
    hosted: $BASE/pub/$REPO
    version: 1.0.$RUN_ID
P
    printf "import \"package:akdemo/akdemo.dart\";\nvoid main() { if (v != 41) throw v; }\n" > bin/m.dart
    dart pub get >/dev/null
    dart run bin/m.dart'
}

check_hex() {
  local d; d="$(fresh hex)"
  REPO="$(new_repo hex hex)" || return 1
  box docker.io/library/elixir:1.17 "$d" '
    export MIX_HOME=/tmp/mh HEX_HOME=/tmp/hh
    mix local.hex --force >/dev/null
    mix new akdemo >/dev/null 2>&1; cd akdemo
    sed -i "s/version: \"0.1.0\"/version: \"1.0.$RUN_ID\", description: \"demo\", package: [licenses: [\"MIT\"], links: %{}]/" mix.exs
    mix hex.build -o /w/akdemo.tar >/dev/null' || return 1
  ak pkg hex publish "$REPO" "$d/akdemo.tar" || return 1
  box docker.io/library/elixir:1.17 "$d" '
    export MIX_HOME=/tmp/mh HEX_HOME=/tmp/hh HEX_UNSAFE_REGISTRY=1
    mix local.hex --force >/dev/null
    # The server signs its registry for a repository named after the key.
    mix hex.repo add "$REPO" "$BASE/hex/$REPO" --auth-key "$AK_TOKEN" >/dev/null
    mix new useit >/dev/null 2>&1; cd useit
    sed -i "s/# {:dep_from_hexpm.*/{:akdemo, \"1.0.$RUN_ID\", repo: \"$REPO\"}/" mix.exs
    mix deps.get >/dev/null
    mix deps.compile >/dev/null
    test -d _build/dev/lib/akdemo'
}

check_ivy() {
  local d; d="$(fresh ivy)"
  REPO="$(new_repo sbt ivy)" || return 1
  box docker.io/library/maven:3-eclipse-temurin-21 "$d" '
    mkdir -p j/ak; echo "package ak; public class Demo {}" > j/ak/Demo.java
    javac -d o j/ak/Demo.java; jar cf demo.jar -C o .
    cat > ivy.xml <<I
<ivy-module version="2.0"><info organisation="com.acme" module="demo" revision="1.0.$RUN_ID"/>
<publications><artifact name="demo" type="jar" ext="jar"/></publications></ivy-module>
I' || return 1
  local a=(--org com.acme --module demo --revision "1.0.$RUN_ID")
  ak pkg ivy publish "$REPO" "$d/demo.jar" "${a[@]}" || return 1
  ak pkg ivy publish "$REPO" "$d/ivy.xml" --descriptor "${a[@]}" || return 1
  box docker.io/library/maven:3-eclipse-temurin-21 "$d" '
    mvn -q -B -Dmaven.repo.local=/tmp/m2 dependency:get -Dartifact=org.apache.ivy:ivy:2.5.2 2>&1 | tail -3
    cat > /tmp/s.xml <<S
<ivysettings><settings defaultResolver="ak"/><resolvers><url name="ak">
<ivy pattern="$BASE/ivy/$REPO/[organisation]/[module]/[revision]/ivy-[revision].xml"/>
<artifact pattern="$BASE/ivy/$REPO/[organisation]/[module]/[revision]/[type]s/[artifact]-[revision].[ext]"/>
</url></resolvers></ivysettings>
S
    cd /tmp; java -jar /tmp/m2/org/apache/ivy/ivy/2.5.2/ivy-2.5.2.jar -settings /tmp/s.xml -cache /tmp/c \
      -dependency com.acme demo 1.0.$RUN_ID -retrieve "/tmp/out/[artifact].[ext]" >/tmp/ivy.log 2>&1 || { tail -20 /tmp/ivy.log; exit 1; }
    jar tf /tmp/out/demo.jar | grep -q ak/Demo.class'
}

check_bazel() {
  local d; d="$(fresh bazel)"
  REPO="$(new_repo bazel bazel)" || return 1
  cat >"$d/MODULE.bazel" <<'M'
module(name = "akdemo", version = "1.0.0")
M
  printf '{"url":"https://example.com/none.tgz","integrity":"sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="}' >"$d/source.json"
  is_1_11 || { echo "publishing needs 1.11"; return 0; }
  ak pkg bazel publish "$REPO" akdemo 1.0.0 "$d/MODULE.bazel" "$d/source.json" || return 1
  box gcr.io/bazel-public/bazel:7.4.1 "$d" '
    export HOME=/tmp/h; mkdir -p $HOME /tmp/use; cd /tmp/use
    printf "bazel_dep(name = \"akdemo\", version = \"1.0.0\")\n" > MODULE.bazel
    bazel --output_user_root=/tmp/o mod graph --registry="$BASE/bazel/$REPO" --registry=https://bcr.bazel.build 2>&1 | tail -6
    bazel --output_user_root=/tmp/o mod graph --registry="$BASE/bazel/$REPO" --registry=https://bcr.bazel.build 2>/dev/null | grep -q "akdemo@1.0.0"'
}

check_oci() {
  local d; d="$(fresh oci)"
  REPO="$(new_repo docker oci)" || return 1
  local host image tls=()
  host="${BASE#*://}"
  image="$host/$REPO/app"
  "$CONTAINER" --version | grep -qi podman && tls=(--tls-verify=false)
  "$CONTAINER" pull -q docker.io/library/alpine:3.20 >/dev/null || return 1
  "$CONTAINER" tag docker.io/library/alpine:3.20 "$image:1.0" || return 1
  "$CONTAINER" login "${tls[@]}" -u admin -p "$ADMIN_PASSWORD" "$host" >/dev/null 2>&1 || return 1
  "$CONTAINER" push "${tls[@]}" -q "$image:1.0" >/dev/null || return 1
  "$CONTAINER" rmi "$image:1.0" >/dev/null

  ak --format json pkg oci catalog --all | grep -q "$REPO/app" || { echo "not in the catalog"; return 1; }
  test "$(ak pkg oci tags "$REPO/app" --format quiet)" = "1.0" || return 1
  local digest
  digest="$(ak pkg oci manifest head "$REPO/app" 1.0 --format quiet)" || return 1
  ak pkg oci manifest get "$REPO/app" 1.0 -o "$d/manifest.json" || return 1
  test "sha256:$(sha256sum "$d/manifest.json" | cut -d' ' -f1)" = "$digest" || { echo "digest differs"; return 1; }
  local config
  config="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["config"]["digest"])' "$d/manifest.json")" || return 1
  ak pkg oci blob get "$REPO/app" "$config" -o "$d/config.json" || return 1
  grep -q architecture "$d/config.json" || return 1
  # A new tag from the same manifest, which the client then pulls.
  ak pkg oci manifest put "$REPO/app" copy "$d/manifest.json" >/dev/null || return 1
  "$CONTAINER" pull "${tls[@]}" -q "$image:copy" >/dev/null || return 1
  "$CONTAINER" rmi "$image:copy" >/dev/null
  ak pkg oci referrers "$REPO/app" "$digest" >/dev/null || return 1
  ak pkg oci manifest delete "$REPO/app" copy --yes >/dev/null || return 1
  if "$CONTAINER" pull "${tls[@]}" -q "$image:copy" >/dev/null 2>&1; then echo "a deleted tag pulled"; return 1; fi
  "$CONTAINER" logout "$host" >/dev/null 2>&1 || true
}

check_lfs() {
  local d; d="$(fresh lfs)"
  REPO="$(new_repo gitlfs lfs)" || return 1
  head -c 300000 /dev/urandom >"$d/model.bin"
  local oid size
  oid="$(ak pkg lfs upload "$REPO" "$d/model.bin" --format quiet)" || return 1
  size="$(stat -c %s "$d/model.bin")"
  # The server has it now, so a second upload does nothing.
  ak --format json pkg lfs upload "$REPO" "$d/model.bin" | grep -q '"uploaded":false' || return 1
  OID="$oid" SIZE="$size" box docker.io/bitnami/git:latest "$d" "
    export HOME=/tmp/h GIT_TERMINAL_PROMPT=0; mkdir -p \$HOME /tmp/r; cd /tmp/r
    git config --global user.email t@example.com; git config --global user.name t
    git config --global http.extraHeader 'Authorization: Bearer '\$AK_TOKEN
    git lfs install >/dev/null
    git init -q .
    printf 'version https://git-lfs.github.com/spec/v1\noid sha256:$oid\nsize $size\n' > model.bin
    git config -f .lfsconfig lfs.url \$BASE/lfs/\$REPO
    echo 'model.bin filter=lfs diff=lfs merge=lfs -text' > .gitattributes
    git add .gitattributes .lfsconfig model.bin; git commit -qm x
    git remote add origin \$BASE/lfs/\$REPO
    git lfs pull origin 2>&1 | tail -3
    test \"\$(sha256sum model.bin | cut -d' ' -f1)\" = $oid"
}

check_conan() {
  local d; d="$(fresh conan)"
  REPO="$(new_repo conan conan)" || return 1
  box docker.io/library/python:3.12-slim "$d" '
    pip -q --disable-pip-version-check install conan >/dev/null 2>&1
    export CONAN_HOME=/tmp/c
    conan profile detect -f >/dev/null 2>&1
    mkdir pk; cd pk
    cat > conanfile.py <<C
from conan import ConanFile
from conan.tools.files import save
import os
class Demo(ConanFile):
    name = "akdemo"
    version = "1.0"
    def package(self):
        save(self, os.path.join(self.package_folder, "share", "value"), "41")
C
    conan create . >/dev/null 2>&1
    conan list "akdemo/1.0#*:*#*" --format=json > /w/list.json 2>/dev/null
    python -I - <<P
import json, os, shutil, subprocess, tarfile
data = json.load(open("/w/list.json"))["Local Cache"]["akdemo/1.0"]["revisions"]
rrev = next(iter(data)); pkgs = data[rrev]["packages"]; pid = next(iter(pkgs)); prev = next(iter(pkgs[pid]["revisions"]))
open("/w/ids", "w").write(f"{rrev} {pid} {prev}")
def path(ref): return subprocess.check_output(["conan", "cache", "path", ref], text=True).strip()
rec = path(f"akdemo/1.0#{rrev}"); pkg = path(f"akdemo/1.0#{rrev}:{pid}#{prev}")
os.makedirs("/w/r"); os.makedirs("/w/p")
for f in os.listdir(rec): shutil.copy(os.path.join(rec, f), "/w/r/")
for f in ("conaninfo.txt", "conanmanifest.txt"): shutil.copy(os.path.join(pkg, f), "/w/p/")
with tarfile.open("/w/p/conan_package.tgz", "w:gz") as t: t.add(os.path.join(pkg, "share"), arcname="share")
P' || return 1
  local rrev pid prev
  read -r rrev pid prev <"$d/ids"
  ak pkg conan upload "$REPO" akdemo/1.0 --revision "$rrev" "$d"/r/* >/dev/null || return 1
  ak pkg conan upload "$REPO" akdemo/1.0 --revision "$rrev" --package-id "$pid" --package-revision "$prev" "$d"/p/* >/dev/null || return 1
  ak pkg conan authenticate "$REPO" | grep -q . || return 1
  box docker.io/library/python:3.12-slim "$d" '
    pip -q --disable-pip-version-check install conan >/dev/null 2>&1
    export CONAN_HOME=/tmp/c2
    conan profile detect -f >/dev/null 2>&1
    conan remote add ak "$BASE/conan/$REPO" --allowed-packages "*" >/dev/null 2>&1 || conan remote add ak "$BASE/conan/$REPO" >/dev/null
    conan remote remove conancenter >/dev/null 2>&1 || true
    conan install --requires=akdemo/1.0 -r ak 2>&1 | tail -3
    p="$(conan cache path "akdemo/1.0:$(python -I -c "print(open(\"/w/ids\").read().split()[1])")")"
    test "$(cat "$p/share/value")" = 41' || return 1
  is_1_11 || return 0
  ak pkg conan remove "$REPO" akdemo/1.0 --revision "$rrev" --all-packages --yes >/dev/null || return 1
  ak pkg conan remove "$REPO" akdemo/1.0 --revision "$rrev" --yes >/dev/null || return 1
}

check_ansible() {
  local d; d="$(fresh ansible)"
  REPO="$(new_repo ansible ansible)" || return 1
  box docker.io/library/python:3.12-slim "$d" '
    pip -q --disable-pip-version-check install ansible-core >/dev/null 2>&1
    export HOME=/tmp/h; mkdir -p $HOME
    mkdir -p acme/demo/plugins; cd acme/demo
    printf "namespace: acme\nname: demo\nversion: 1.0.$RUN_ID\nreadme: README.md\nauthors: [t]\n" > galaxy.yml
    echo demo > README.md
    ansible-galaxy collection build --output-path /w >/dev/null' || return 1
  ak pkg ansible publish "$REPO" "$d/acme-demo-1.0.$RUN_ID.tar.gz" || return 1
  box docker.io/library/python:3.12-slim "$d" '
    pip -q --disable-pip-version-check install ansible-core >/dev/null 2>&1
    export HOME=/tmp/h2; mkdir -p $HOME
    ansible-galaxy collection install "acme.demo:1.0.$RUN_ID" -s "$BASE/ansible/$REPO/" -p /tmp/col 2>&1 | tail -1
    test -f /tmp/col/ansible_collections/acme/demo/galaxy.yml -o -f /tmp/col/ansible_collections/acme/demo/MANIFEST.json'
}

check_huggingface() {
  local d; d="$(fresh huggingface)"
  REPO="$(new_repo huggingface huggingface)" || return 1
  printf 'bytes of a model' >"$d/model.safetensors"
  printf '{"a":1}' >"$d/config.json"
  ak pkg huggingface upload "$REPO" acme/demo "$d/model.safetensors" || return 1
  ak pkg huggingface upload "$REPO" acme/demo "$d/config.json" || return 1
  ak pkg huggingface upload "$REPO" bare "$d/config.json" || return 1
  box docker.io/library/python:3.12-slim "$d" '
    pip -q --disable-pip-version-check install huggingface_hub >/dev/null 2>&1
    export HF_ENDPOINT="$BASE/huggingface/$REPO" HF_HOME=/tmp/hf HF_TOKEN="$AK_TOKEN" HF_HUB_DISABLE_XET=1
    python -I -c "
from huggingface_hub import hf_hub_download
p = hf_hub_download(\"acme/demo\", \"model.safetensors\")
assert open(p).read() == \"bytes of a model\"
p = hf_hub_download(\"bare\", \"config.json\")
assert open(p).read() == \"{\\\"a\\\":1}\"
"'
}

check_swift() {
  local d; d="$(fresh swift)"
  REPO="$(new_repo swift swift)" || return 1
  box docker.io/library/swift:6.0 "$d" '
    export HOME=/tmp/h; mkdir -p $HOME/lib/Sources/Demo; cd $HOME/lib
    cat > Package.swift <<P
// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "Demo", products: [.library(name: "Demo", targets: ["Demo"])], targets: [.target(name: "Demo")])
P
    echo "public let v = 41" > Sources/Demo/d.swift
    git init -q . 2>/dev/null; git add . ; git -c user.email=t@e -c user.name=t commit -qm x
    swift package archive-source --output /w/Demo.zip >/dev/null' || return 1
  ak pkg swift publish "$REPO" acme Demo 1.0.0 "$d/Demo.zip" --metadata '{}' || return 1
  box docker.io/library/swift:6.0 "$d" '
    export HOME=/tmp/h2; mkdir -p $HOME/use/Sources/use; cd $HOME/use
    cat > Package.swift <<P
// swift-tools-version:5.9
import PackageDescription
let package = Package(name: "use", dependencies: [.package(id: "acme.Demo", exact: "1.0.0")],
  targets: [.executableTarget(name: "use", dependencies: [.product(name: "Demo", package: "acme.Demo")])])
P
    printf "import Demo\nguard v == 41 else { fatalError() }\n" > Sources/use/main.swift
    swift package-registry set --allow-insecure-http "$BASE/swift/$REPO" >/dev/null
    swift build --disable-sandbox -q 2>&1 | tail -4'
}

check_puppet() {
  local d; d="$(fresh puppet)"
  REPO="$(new_repo puppet puppet)" || return 1
  mkdir -p "$d/acme-demo-1.0.0/manifests"
  printf 'class demo {}\n' >"$d/acme-demo-1.0.0/manifests/init.pp"
  printf '{"name":"acme-demo","version":"1.0.0","author":"acme","license":"MIT","summary":"s","source":"https://example.com","dependencies":[]}' \
    >"$d/acme-demo-1.0.0/metadata.json"
  tar -czf "$d/acme-demo-1.0.0.tar.gz" -C "$d" acme-demo-1.0.0 || return 1
  ak pkg puppet publish "$REPO" "$d/acme-demo-1.0.0.tar.gz" || return 1
  # `puppet module install` can't list releases yet: artifact-keeper#5229. Until it
  # can, fetch what a client would be pointed at.
  local got="$d/got.tar.gz"
  ak api GET "/puppet/$REPO/v3/files/acme-demo-1.0.0.tar.gz" -o "$got" || return 1
  cmp "$got" "$d/acme-demo-1.0.0.tar.gz"
}

# A format's check, its outcome on one line, and its output only if it failed.
run() {
  local name="$1" log="$WORK/$1.log"
  if "check_$name" >"$log" 2>&1 </dev/null; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  /' "$log" | tail -40
    FAILED=1
  fi
}

FAILED=0
ALL=(pypi npm cargo helm nuget debian rpm alpine pacman conda maven go gems composer cran pub hex ivy bazel oci lfs conan ansible huggingface swift puppet)
for name in "${@:-${ALL[@]}}"; do run "$name"; done
exit "$FAILED"
