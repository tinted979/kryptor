// Every test here touches the file system, which Miri's isolation blocks,
// so each one needs `#[cfg_attr(miri, ignore = ...)]`. The hashing itself
// is still covered under Miri by the unit tests in src/hash.rs.

use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;

use kryptor::hash::{self, Algorithm};

#[test]
#[cfg_attr(miri, ignore = "Miri isolation blocks file system access")]
fn hash_file_hashes_the_file_contents() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hash_file_hashes_the_file_contents");
    fs::write(&path, "abc").expect("failed to write input file");

    let digest = hash::hash_file(Algorithm::Sha256, &path).expect("should hash");

    assert_eq!(
        digest.to_string(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
#[cfg_attr(miri, ignore = "Miri isolation blocks file system access")]
fn hash_file_error_names_the_path_and_keeps_the_cause() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hash_file_error_names_the_path");

    let err = hash::hash_file(Algorithm::Sha256, &path).expect_err("should fail");

    let message = err.to_string();
    assert!(message.contains(&path.display().to_string()), "{message}");

    let cause = err
        .source()
        .and_then(|source| source.downcast_ref::<io::Error>())
        .expect("cause should be the io::Error");
    assert_eq!(cause.kind(), io::ErrorKind::NotFound);
}
