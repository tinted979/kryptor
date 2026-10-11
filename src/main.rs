mod cli;

use std::io;
use std::process::ExitCode;

use anyhow::Context as _;
use cli::Cli;
use kryptor::hash;
use tracing::level_filters::LevelFilter;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // `{:#}` prints the whole cause chain on one line.
            eprintln!("kryptor: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    init_logging(cli.verbosity.tracing_level_filter())?;

    let digest = hash::hash_file(cli.algorithm, &cli.file)?;
    println!("{digest}  {}", cli.file.display());
    Ok(())
}

/// Sends `tracing` diagnostics up to `level` to stderr, keeping stdout for
/// digests.
fn init_logging(level: LevelFilter) -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr)
        .without_time()
        .finish();
    tracing::subscriber::set_global_default(subscriber).context("failed to set up logging")
}
