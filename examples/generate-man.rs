use clap_mangen::Man;
use std::fs;
use std::io;
use std::path::PathBuf;

#[allow(dead_code)]
#[path = "../src/cli.rs"]
mod cli;

fn main() -> io::Result<()> {
    let output_dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("build/man"));

    fs::create_dir_all(&output_dir)?;

    let output_path = output_dir.join("password-out.1");
    let command = cli::command_definition();

    let mut output = Vec::new();
    Man::new(command).render(&mut output)?;

    fs::write(&output_path, output)?;

    println!("Generated {}", output_path.display());

    Ok(())
}
