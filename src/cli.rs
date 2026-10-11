use std::path::PathBuf;

use clap::Parser;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use kryptor::hash::Algorithm;

#[derive(Parser, Clone, Debug)]
pub struct Cli {
    /// File to hash.
    pub file: PathBuf,

    /// Hash algorithm to use.
    #[arg(short, long, default_value_t, value_parser = algorithm_parser())]
    pub algorithm: Algorithm,
}

impl Cli {
    /// Parses the command-line arguments, printing usage and exiting on error.
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
}

/// Accepts exactly the names of [`Algorithm::ALL`] and lists them in `--help`.
fn algorithm_parser() -> impl TypedValueParser<Value = Algorithm> {
    PossibleValuesParser::new(Algorithm::ALL.iter().map(|algorithm| algorithm.name()))
        .try_map(|name| Algorithm::from_name(&name).ok_or("unknown algorithm"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once(env!("CARGO_BIN_NAME")).chain(args.iter().copied()))
    }

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn file_is_positional() {
        let args = parse(&["file.txt"]).expect("should parse");

        assert_eq!(args.file, PathBuf::from("file.txt"));
        assert_eq!(args.algorithm, Algorithm::Sha256);
    }

    #[test]
    fn algorithm_before_or_after_file() {
        for argv in [["-a", "sha512", "file.txt"], ["file.txt", "-a", "sha512"]] {
            let args = parse(&argv).expect("should parse");

            assert_eq!(args.algorithm, Algorithm::Sha512, "argv: {argv:?}");
        }
    }

    #[test]
    fn hyphenated_algorithm_names_parse() {
        let args = parse(&["-a", "sha3-256", "file.txt"]).expect("should parse");

        assert_eq!(args.algorithm, Algorithm::Sha3_256);
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let err = parse(&["-a", "sha-256", "file.txt"]).expect_err("should fail");

        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }
}
