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
ALL=(pypi npm cargo helm nuget)
for name in "${@:-${ALL[@]}}"; do run "$name"; done
exit "$FAILED"
