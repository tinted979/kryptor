mod cli;

use cli::Cli;

fn main() {
    let cli = Cli::parse();

    println!("--- Arguments ---");
    println!("File: {:?}", cli.file);
    println!("Algorithm: {:?}", cli.algorithm);
}
