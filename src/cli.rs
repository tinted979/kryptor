use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(ValueEnum, Clone, Copy, Default, Debug)]
pub enum Algorithm {
    #[default]
    Sha256,
    Sha512,
}

#[derive(Parser, Clone, Debug)]
pub struct Cli {
    /// File to hash.
    pub file: PathBuf,

    /// Hash algorithm to use.
    #[arg(short, long, value_enum, default_value_t)]
    pub algorithm: Algorithm,
}

impl Cli {
    /// Parses the command-line arguments, printing usage and exiting on error.
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
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
        assert!(matches!(args.algorithm, Algorithm::Sha256));
    }

    #[test]
    fn algorithm_before_or_after_file() {
        for argv in [["-a", "sha512", "file.txt"], ["file.txt", "-a", "sha512"]] {
            let args = parse(&argv).expect("should parse");

            assert!(
                matches!(args.algorithm, Algorithm::Sha512),
                "argv: {argv:?}"
            );
        }
    }
}
