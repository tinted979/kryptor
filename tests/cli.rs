// Every test here spawns the compiled binary, which Miri can't do, so
// each one needs `#[cfg_attr(miri, ignore = ...)]`. Argument parsing is
// still covered under Miri by the unit tests in src/cli.rs.

mod common;

use common::BIN;

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
#[cfg_attr(miri, ignore = "Miri can't spawn processes")]
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
#[cfg_attr(miri, ignore = "Miri can't spawn processes")]
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

#[test]
#[cfg_attr(miri, ignore = "Miri can't spawn processes")]
fn hashes_file_with_selected_algorithm() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hashes_file_with_selected_algorithm");
    fs::write(&path, "abc").expect("failed to write input file");

    let output = Command::new(BIN)
        .args(["-a", "sha3-256"])
        .arg(&path)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532  {}\n",
            path.display()
        )
    );
}

#[test]
#[cfg_attr(miri, ignore = "Miri can't spawn processes")]
fn unreadable_file_is_an_error() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("unreadable_file_is_an_error");

    let output = Command::new(BIN)
        .arg(&path)
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.display().to_string()),
        "error should name the file: {stderr}"
    );
}
