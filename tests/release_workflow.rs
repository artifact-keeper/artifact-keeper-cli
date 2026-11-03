//! The order of `.github/workflows/release.yml`, and what its failure issue says. A tag
//! is the only real test of that workflow, and it publishes, so the promises that are
//! cheap to break get checked here.

use serde_yaml::Value;

fn jobs() -> Value {
    let text = std::fs::read_to_string(".github/workflows/release.yml").expect("release.yml");
    let workflow: Value = serde_yaml::from_str(&text).expect("valid YAML");
    workflow["jobs"].clone()
}

fn needs(job: &Value) -> Vec<String> {
    match &job["needs"] {
        Value::String(one) => vec![one.clone()],
        Value::Sequence(many) => many
            .iter()
            .filter_map(|n| n.as_str().map(str::to_string))
            .collect(),
        _ => vec![],
    }
}

/// A release that fails Linux verification never reaches the tap. The tap job has
/// to have no way to run past a failed need, which `always()` or `!cancelled()` give it.
#[test]
fn the_tap_moves_only_after_linux_verification_passes() {
    let jobs = jobs();
    let homebrew = &jobs["homebrew"];
    assert!(needs(homebrew).contains(&"verify-release".to_string()));
    let condition = homebrew["if"].as_str().expect("homebrew has a condition");
    assert!(!condition.contains("always()"), "{condition}");
    assert!(!condition.contains("cancelled()"), "{condition}");
    assert!(!condition.contains("failure()"), "{condition}");
    assert!(
        !needs(&jobs["verify-release"]).contains(&"homebrew".to_string()),
        "Linux verification can't wait for the tap"
    );
    assert!(jobs["verify-release"]["if"].is_null());
}

#[test]
fn an_rc_tag_stays_away_from_the_tap_and_still_gets_verified() {
    let jobs = jobs();
    let condition = jobs["homebrew"]["if"].as_str().expect("condition");
    assert!(
        condition.contains("!contains(github.ref_name, '-')"),
        "{condition}"
    );
    let verify = &jobs["verify-release"];
    assert!(!verify.as_mapping().unwrap().contains_key("if"));
    assert_eq!(needs(verify), ["release"]);
}

#[test]
fn brew_is_checked_after_the_tap_moves() {
    let jobs = jobs();
    let verify = &jobs["verify-macos"];
    assert!(needs(verify).contains(&"homebrew".to_string()));
    let condition = verify["if"].as_str().expect("condition");
    assert!(condition.contains("needs.homebrew.result == 'success'"));
}

#[cfg(unix)]
fn body(release: &str, homebrew: &str, verify: &str, macos: &str) -> String {
    let output = std::process::Command::new(".github/scripts/release-failure-body.sh")
        .arg("https://example.test/run")
        .env("RELEASE", release)
        .env("HOMEBREW", homebrew)
        .env("VERIFY", verify)
        .env("VERIFY_MACOS", macos)
        .output()
        .expect("run the script");
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[cfg(unix)]
#[test]
fn the_failure_issue_says_where_the_tap_stands() {
    let linux_failed = body("success", "skipped", "failure", "skipped");
    assert!(
        linux_failed.contains("the tap wasn't touched"),
        "{linux_failed}"
    );
    assert!(!linux_failed.contains("revert"), "{linux_failed}");

    let macos_failed = body("success", "success", "success", "failure");
    assert!(macos_failed.contains("already points"), "{macos_failed}");
    assert!(
        macos_failed.contains("revert Formula/ak.rb"),
        "{macos_failed}"
    );

    let unknown = body("success", "failure", "success", "skipped");
    assert!(unknown.contains("may or may not"), "{unknown}");

    for text in [linux_failed, macos_failed, unknown] {
        assert!(text.contains("stays a prerelease"), "{text}");
        assert!(text.contains("https://example.test/run"), "{text}");
    }
}
