//! A server can answer 2xx and say in its response that the work failed. A script
//! only sees the exit code, so each of these has to exit non-zero, after printing
//! the response. Mock only: real servers rarely fail these on demand.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::{Value, json};

const ID: &str = "00000000-0000-0000-0000-000000000001";

fn backup(status: &str, error: Option<&str>) -> Value {
    json!({
        "id": ID, "status": status, "error_message": error, "artifact_count": 0,
        "size_bytes": 0, "created_at": "2026-01-01T00:00:00Z", "type": "full"
    })
}

fn restore(errors: Value) -> Value {
    json!({
        "tables_restored": [], "artifacts_restored": 0, "errors": errors,
        "integrity_anchor": "recorded"
    })
}

fn execution(errors: Value) -> Value {
    json!({
        "policy_id": ID, "policy_name": "p", "dry_run": false, "artifacts_matched": 0,
        "artifacts_removed": 0, "bytes_freed": 0, "bytes_matched": 0, "errors": errors
    })
}

fn gc(errors: Value) -> Value {
    json!({
        "dry_run": false, "artifacts_removed": 0, "storage_keys_deleted": 0,
        "bytes_freed": 0, "errors": errors
    })
}

fn scrub(errors: Value) -> Value {
    json!({
        "objects_checked": 0, "bytes_read": 0, "intact": 0, "corrupt": 0, "missing": 0,
        "repaired": 0, "unverifiable": 0, "skipped_concurrent": 0, "cycle_completed": true,
        "findings": [], "errors": errors
    })
}

fn reindex(errors: Value) -> Value {
    json!({
        "dry_run": false, "scanned": 0, "registered": 0, "skipped": 0,
        "skipped_recent": 0, "skipped_unknown_age": 0, "missing_objects": 0,
        "truncated": false, "registered_paths": [], "missing_object_paths": [],
        "errors": errors
    })
}

fn webhook_test(success: bool, error: Option<&str>) -> Value {
    json!({ "success": success, "status_code": 500, "error": error })
}

fn delivery(success: bool) -> Value {
    json!({
        "id": ID, "webhook_id": ID, "event": "e", "payload": {}, "attempts": 1,
        "success": success, "response_status": 500, "created_at": "2026-01-01T00:00:00Z"
    })
}

fn ldap(success: bool) -> Value {
    json!({ "success": success, "message": "bind refused", "response_time_ms": 1 })
}

fn smtp(success: bool) -> Value {
    json!({ "success": success, "message": "no route to host" })
}

fn backfill(failed: i64) -> Value {
    json!({
        "artifacts_scanned": 3, "artifacts_failed": failed, "artifacts_skipped": 0,
        "packages_registered": 0, "message": "done"
    })
}

fn sync(succeeded: bool) -> Value {
    json!({ "repository": "r", "triggered": true, "succeeded": succeeded })
}

struct Case {
    args: &'static [&'static str],
    verb: &'static str,
    route: String,
    fails: Value,
    /// A word of the reason, which the error has to carry.
    reason: &'static str,
    works: Value,
}

fn cases() -> Vec<Case> {
    let case = |args, verb, route: String, fails, reason, works| Case {
        args,
        verb,
        route,
        fails,
        reason,
        works,
    };
    vec![
        case(
            &["admin", "backup", "execute", ID],
            "POST",
            format!("/api/v1/admin/backups/{ID}/execute"),
            backup("failed", Some("disk-full")),
            "disk-full",
            backup("completed", None),
        ),
        case(
            &["admin", "backup", "restore", ID, "--artifacts"],
            "POST",
            format!("/api/v1/admin/backups/{ID}/restore"),
            restore(json!(["archive-incomplete"])),
            "archive-incomplete",
            restore(json!([])),
        ),
        case(
            &["lifecycle", "execute", ID],
            "POST",
            format!("/api/v1/admin/lifecycle/{ID}/execute"),
            execution(json!(["bad-pattern"])),
            "bad-pattern",
            execution(json!([])),
        ),
        case(
            &["lifecycle", "preview", ID],
            "POST",
            format!("/api/v1/admin/lifecycle/{ID}/preview"),
            execution(json!(["bad-pattern"])),
            "bad-pattern",
            execution(json!([])),
        ),
        case(
            &["lifecycle", "execute-all"],
            "POST",
            "/api/v1/admin/lifecycle/execute-all".to_string(),
            json!([execution(json!([])), execution(json!(["bad-pattern"]))]),
            "bad-pattern",
            json!([execution(json!([]))]),
        ),
        case(
            &["admin", "storage-gc", "run"],
            "POST",
            "/api/v1/admin/storage-gc".to_string(),
            gc(json!(["key-stuck"])),
            "key-stuck",
            gc(json!([])),
        ),
        case(
            &["repo", "storage-gc", "r", "--yes"],
            "POST",
            "/api/v1/repositories/r/storage-gc".to_string(),
            gc(json!(["key-stuck"])),
            "key-stuck",
            gc(json!([])),
        ),
        case(
            &["admin", "storage-scrub", "run", "--yes"],
            "POST",
            "/api/v1/admin/storage-scrub".to_string(),
            scrub(json!(["read-failed"])),
            "read-failed",
            scrub(json!([])),
        ),
        case(
            &["admin", "reindex-storage", "r", "--yes"],
            "POST",
            "/api/v1/admin/repositories/r/reindex-storage".to_string(),
            reindex(json!(["list-failed"])),
            "list-failed",
            reindex(json!([])),
        ),
        case(
            &["webhook", "test", ID],
            "POST",
            format!("/api/v1/webhooks/{ID}/test"),
            webhook_test(false, Some("connection-refused")),
            "connection-refused",
            webhook_test(true, None),
        ),
        case(
            &["webhook", "redeliver", ID, ID],
            "POST",
            format!("/api/v1/webhooks/{ID}/deliveries/{ID}/redeliver"),
            delivery(false),
            "500",
            delivery(true),
        ),
        case(
            &["sso", "test", ID, "--type", "ldap"],
            "POST",
            format!("/api/v1/admin/sso/ldap/{ID}/test"),
            ldap(false),
            "bind refused",
            ldap(true),
        ),
        case(
            &["admin", "smtp-test", "a@example.com"],
            "POST",
            "/api/v1/admin/smtp/test".to_string(),
            smtp(false),
            "no route to host",
            smtp(true),
        ),
        case(
            &["packages", "backfill"],
            "POST",
            "/api/v1/admin/packages/backfill".to_string(),
            backfill(2),
            "2 of 3",
            backfill(0),
        ),
        case(
            &["curation", "sync", "r"],
            "POST",
            "/api/v1/curation/repos/r/sync".to_string(),
            sync(false),
            "failed upstream",
            sync(true),
        ),
        case(
            &["curation", "bulk-approve", ID, ID, "--reason", "x", "--yes"],
            "POST",
            "/api/v1/curation/packages/bulk-approve".to_string(),
            json!(0),
            "0 of 2",
            json!(2),
        ),
    ]
}

#[tokio::test]
async fn a_failure_in_a_2xx_response_exits_non_zero_with_the_reason() {
    for case in cases() {
        let mock = Mocked::start().await;
        mock.respond(case.verb, &case.route, 200, case.fails.clone())
            .await;
        let output = mock.ak(case.args);
        let stderr = mock::unwrapped(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{:?}: {stderr}", case.args);
        assert!(stderr.contains(case.reason), "{:?}: {stderr}", case.args);
    }
}

#[tokio::test]
async fn the_same_commands_exit_zero_when_it_worked() {
    for case in cases() {
        let mock = Mocked::start().await;
        mock.respond(case.verb, &case.route, 200, case.works.clone())
            .await;
        let output = mock.ak(case.args);
        assert_eq!(output.status.code(), Some(0), "{:?}: {output:?}", case.args);
    }
}

/// The response still goes to stdout, for a script that reads the details.
#[tokio::test]
async fn the_response_prints_before_the_failure() {
    let mock = Mocked::start().await;
    mock.respond(
        "POST",
        &format!("/api/v1/admin/backups/{ID}/restore"),
        200,
        restore(json!(["archive-incomplete"])),
    )
    .await;
    let output = mock.ak(&["admin", "backup", "restore", ID, "--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let printed: Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(printed["errors"][0], "archive-incomplete");
}

/// It printed "Synced" and then failed.
#[tokio::test]
async fn a_failed_sync_doesnt_say_it_synced() {
    let mock = Mocked::start().await;
    mock.respond("POST", "/api/v1/curation/repos/r/sync", 200, sync(false))
        .await;
    let output = mock.ak(&["curation", "sync", "r", "--format", "table"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("Synced"), "{stderr}");
}

/// It said 2 when the server said 0.
#[tokio::test]
async fn a_bulk_approve_reports_the_number_the_server_changed() {
    let mock = Mocked::start().await;
    mock.respond(
        "POST",
        "/api/v1/curation/packages/bulk-approve",
        200,
        json!(0),
    )
    .await;
    let output = mock.ak(&[
        "curation",
        "bulk-approve",
        ID,
        ID,
        "--reason",
        "x",
        "--yes",
        "--format",
        "table",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("0 of 2"), "{stderr}");
    assert!(!stderr.contains("Bulk approved 2"), "{stderr}");
}
