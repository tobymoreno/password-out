mod clipboard;
mod hotkey;
mod overlay;
mod providers;

use std::path::PathBuf;

#[derive(Debug)]
enum Mode {
    Listen,
    // Internal helper mode.
    // Users should not call this directly.
    Overlay(String),
}

#[derive(Debug)]
struct Config {
    mode: Mode,
    secrets_file: PathBuf,
    clear_seconds: u64,
}

fn usage() {
    eprintln!(
        r#"Usage:
  passmgr --listen [--file PATH] [--clear-seconds SECONDS]

Examples:
  passmgr --listen
  passmgr --listen --file ~/.config/passmgr/secrets.txt
  passmgr --listen --clear-seconds 60

Secrets file format:
  # name|hotkey|password
  admin01|CTRL+ALT+1|MyPassword
  svc.acas|CTRL+ALT+2|AnotherPassword
  breakglass|CTRL+ALT+B|BreakGlassPassword

Default:
  --file ~/.config/passmgr/secrets.txt
  --clear-seconds 30
"#
    );
}

fn parse_args() -> Result<Config, String> {
    let mut secrets_file = providers::file::default_secrets_file();
    let mut clear_seconds: u64 = 30;
    let mut mode: Option<Mode> = None;

    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                mode = Some(Mode::Listen);
            }

            // Internal helper mode used by the hotkey listener to show the overlay
            // without blocking/killing the long-running listener.
            "--overlay" => {
                let message = args
                    .next()
                    .ok_or_else(|| "missing value for internal --overlay".to_string())?;
                mode = Some(Mode::Overlay(message));
            }

            "--file" | "-f" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing value for --file".to_string())?;
                secrets_file = providers::file::path_from_arg(&path);
            }

            "--clear-seconds" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --clear-seconds".to_string())?;

                clear_seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --clear-seconds value: {}", value))?;
            }

            "--help" | "-h" => {
                usage();
                std::process::exit(0);
            }

            _ => {
                return Err(format!("unknown argument: {}", arg));
            }
        }
    }

    let mode = mode.ok_or_else(|| "missing mode: use --listen".to_string())?;

    Ok(Config {
        mode,
        secrets_file,
        clear_seconds,
    })
}

fn run() -> Result<(), String> {
    let config = parse_args()?;

    match config.mode {
        Mode::Listen => {
            let entries = providers::file::load_entries(&config.secrets_file)?;
            hotkey::listen(entries, config.clear_seconds)
        }

        Mode::Overlay(message) => {
            overlay::show_overlay(&message);
            Ok(())
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("passmgr error: {}", err);
        usage();
        std::process::exit(1);
    }
}
