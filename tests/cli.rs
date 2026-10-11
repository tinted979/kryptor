// These tests spawn the compiled binary, which Miri can't do; the
// argument-parsing logic is still covered under Miri by the unit
// tests in src/cli.rs.
#![cfg(not(miri))]

mod common;

use common::BIN;

use std::process::Command;

#[test]
fn help_flag_prints_usage() {
    let output = Command::new(BIN)
        .arg("--help")
        .output()
        .expect("failed to run binary");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in ["Usage:", "<FILE>", "--algorithm", "sha256", "sha512"] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in --help output: {stdout}"
        );
    }
}

#[test]
fn missing_file_is_a_usage_error() {
    let output = Command::new(BIN).output().expect("failed to run binary");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("<FILE>"),
        "unexpected error output: {stderr}"
    );
}
