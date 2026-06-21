use std::path::PathBuf;

use crate::vault;

#[derive(Debug)]
pub enum Mode {
    Listen,
    VaultInit,
    EntryAdd,
    EntryList,
    EntryRemove,

    // Internal helper mode.
    // Users should not call this directly.
    Overlay(String),
}

#[derive(Debug)]
pub struct Config {
    pub mode: Mode,
    pub vault_file: PathBuf,
    pub clear_seconds: u64,
}

pub fn usage() {
    eprintln!(
        r#"Usage:
  password-out --listen [--vault PATH] [--clear-seconds SECONDS]
  password-out vault init [--vault PATH]
  password-out entry add [--vault PATH]
  password-out entry list [--vault PATH]
  password-out entry remove [--vault PATH]

Examples:
  password-out --listen
  password-out --listen --vault ./vault.json
  password-out --listen --clear-seconds 60
  password-out vault init
  password-out vault init --vault ./vault.json
  password-out entry add
  password-out entry add --vault ./vault.json
  password-out entry list
  password-out entry list --vault ./vault.json
  password-out entry remove
  password-out entry remove --vault ./vault.json

Defaults:
  --vault platform-specific PasswordOut config directory/vault.json
  --clear-seconds 30
"#
    );
}

pub fn parse_args() -> Result<Config, String> {
    let mut vault_file = vault::default_vault_path()?;
    let mut clear_seconds: u64 = 30;
    let mut mode: Option<Mode> = None;

    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                mode = Some(Mode::Listen);
            }

            "vault" => {
                let command = args
                    .next()
                    .ok_or_else(|| "missing vault command; use 'vault init'".to_string())?;

                match command.as_str() {
                    "init" => {
                        mode = Some(Mode::VaultInit);
                    }
                    _ => {
                        return Err(format!(
                            "unsupported vault command: {command}; use 'vault init'"
                        ));
                    }
                }
            }

            "entry" => {
                let command = args.next().ok_or_else(|| {
                    "missing entry command; use 'entry add', 'entry list', or 'entry remove'"
                        .to_string()
                })?;

                match command.as_str() {
                    "add" => {
                        mode = Some(Mode::EntryAdd);
                    }
                    "list" => {
                        mode = Some(Mode::EntryList);
                    }
                    "remove" => {
                        mode = Some(Mode::EntryRemove);
                    }
                    _ => {
                        return Err(format!(
                            "unsupported entry command: {command}; use 'entry add', 'entry list', or 'entry remove'"
                        ));
                    }
                }
            }

            // Internal helper mode used by the hotkey listener to display
            // the overlay in a separate short-lived process.
            "--overlay" => {
                let message = args
                    .next()
                    .ok_or_else(|| "missing value for internal --overlay".to_string())?;

                mode = Some(Mode::Overlay(message));
            }

            "--vault" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing value for --vault".to_string())?;

                vault_file = PathBuf::from(path);
            }

            "--clear-seconds" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --clear-seconds".to_string())?;

                clear_seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --clear-seconds value: {value}"))?;
            }

            "--help" | "-h" => {
                usage();
                std::process::exit(0);
            }

            _ => {
                return Err(format!("unknown argument: {arg}"));
            }
        }
    }

    let mode = mode.ok_or_else(|| {
        "missing mode: use --listen, vault init, entry add, entry list, or entry remove".to_string()
    })?;

    Ok(Config {
        mode,
        vault_file,
        clear_seconds,
    })
}
