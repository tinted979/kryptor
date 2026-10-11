mod cli;

use std::fs::File;
use std::process::ExitCode;

use cli::Cli;
use kryptor::hash;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match File::open(&cli.file).and_then(|file| hash::hash_reader(cli.algorithm, file)) {
        Ok(digest) => {
            println!("{digest}  {}", cli.file.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("kryptor: {}: {err}", cli.file.display());
            ExitCode::FAILURE
        }
    }
}
