//! The routes `ak system` reaches that aren't in the spec, on a real backend.

mod common;

use predicates::prelude::*;

#[test]
#[ignore]
fn healthz_and_ready_answer_with_the_servers_json() {
    let env = common::TestEnv::setup();
    for route in ["healthz", "ready"] {
        env.ak_cmd()
            .args(["system", route])
            .assert()
            .success()
            .stdout(predicate::str::contains("status"));
    }
}

/// The E2E stack doesn't set ENABLE_SWAGGER, so the document isn't there. The command
/// says so with the server's status and doesn't print an empty success.
#[test]
#[ignore]
fn openapi_without_swagger_enabled_says_what_the_server_said() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["system", "openapi"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("404"));
}
