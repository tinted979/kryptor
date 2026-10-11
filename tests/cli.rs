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
    assert!(stderr.is_empty(), "should be quiet by default: {stderr}");
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
fn verbose_flag_logs_diagnostics_to_stderr() {
    let path =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join("verbose_flag_logs_diagnostics_to_stderr");
    fs::write(&path, "abc").expect("failed to write input file");
    let path_str = path.display().to_string();

    let output = Command::new(BIN)
        .args(["-v", "-a", "md5"])
        .arg(&path)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    // Diagnostics must not leak into stdout, which scripts parse.
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("900150983cd24fb0d6963f7d28e17f72  {path_str}\n")
    );
    for expected in ["finished hashing", "bytes=3", "algorithm=md5", &path_str] {
        assert!(
            stderr.contains(expected),
            "missing {expected:?} in diagnostics: {stderr}"
        );
    }
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
    // "Not found" is OS error 2 on both Windows and Unix. It must appear
    // exactly once: missing means the cause was dropped, twice means it was
    // printed by both the error and its source.
    assert_eq!(
        stderr.matches("(os error 2)").count(),
        1,
        "error should include its cause once: {stderr}"
    );
}
