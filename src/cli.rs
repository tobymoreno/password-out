use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand};

const DEFAULT_CLEAR_SECONDS: u64 = 30;

/// Credentials at the press of a chord.
///
/// PasswordOut is a cross-platform, hotkey-driven credential manager. It maps
/// global keyboard shortcuts to encrypted credential entries, copies selected
/// secrets to the clipboard temporarily, and displays non-secret confirmation
/// overlays.
#[derive(Debug, Parser)]
#[command(
    name = "password-out",
    version,
    author = "PITT Crew: Roland, Toby, Paul, and Joey",
    about = "Hotkey-driven credential manager",
    long_about = None,
    after_help = "PasswordOut is developed and maintained by the PITT Crew: Roland, Toby, Paul, and Joey.",    
    arg_required_else_help = true
)]
pub struct Cli {
    /// Start the global hotkey listener.
    #[arg(short = 'l', long, global = true)]
    listen: bool,

    /// Path to the encrypted PasswordOut vault.
    ///
    /// If omitted, PasswordOut uses vault.json in the platform-specific
    /// PasswordOut configuration directory.
    #[arg(long, global = true, value_name = "PATH")]
    vault: Option<PathBuf>,

    /// Number of seconds to retain a copied secret in the clipboard.
    #[arg(
        long,
        global = true,
        value_name = "SECONDS",
        default_value_t = DEFAULT_CLEAR_SECONDS
    )]
    clear_seconds: u64,

    /// Internal helper used to display a short-lived overlay.
    #[arg(long, hide = true, value_name = "MESSAGE")]
    overlay: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create and manage the encrypted credential vault.
    Vault(VaultArgs),

    /// Add, list, or remove credential entries.
    Entry(EntryArgs),
}

#[derive(Debug, Args)]
struct VaultArgs {
    #[command(subcommand)]
    command: VaultCommand,
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// Initialize a new encrypted PasswordOut vault.
    ///
    /// The command prompts for the information needed to protect the new vault
    /// and refuses to overwrite an existing vault.
    Init,
}

#[derive(Debug, Args)]
struct EntryArgs {
    #[command(subcommand)]
    command: EntryCommand,
}

#[derive(Debug, Subcommand)]
enum EntryCommand {
    /// Add a credential entry to the encrypted vault.
    Add,

    /// List credential metadata without displaying secret values.
    List,

    /// Remove a credential entry from the encrypted vault.
    Remove,
}

#[derive(Debug)]
pub enum Mode {
    Listen,
    VaultInit,
    EntryAdd,
    EntryList,
    EntryRemove,

    // Internal helper mode. Users should not call this directly.
    Overlay(String),
}

#[derive(Debug)]
pub struct Config {
    pub mode: Mode,
    pub vault_file: PathBuf,
    pub clear_seconds: u64,
}

pub fn parse_args(default_vault_path: PathBuf) -> Result<Config, String> {
    parse_from(Cli::parse(), default_vault_path)
}

fn parse_from(cli: Cli, default_vault_path: PathBuf) -> Result<Config, String> {
    let vault_file = cli.vault.unwrap_or(default_vault_path);

    let mode = if let Some(message) = cli.overlay {
        if cli.listen || cli.command.is_some() {
            return Err("--overlay cannot be combined with another mode".to_string());
        }

        Mode::Overlay(message)
    } else if cli.listen {
        if cli.command.is_some() {
            return Err("--listen cannot be combined with a subcommand".to_string());
        }

        Mode::Listen
    } else {
        match cli.command {
            Some(Command::Vault(VaultArgs {
                command: VaultCommand::Init,
            })) => Mode::VaultInit,

            Some(Command::Entry(EntryArgs {
                command: EntryCommand::Add,
            })) => Mode::EntryAdd,

            Some(Command::Entry(EntryArgs {
                command: EntryCommand::List,
            })) => Mode::EntryList,

            Some(Command::Entry(EntryArgs {
                command: EntryCommand::Remove,
            })) => Mode::EntryRemove,

            None => {
                return Err(
                    "missing mode: use --listen, vault init, entry add, entry list, or entry remove"
                        .to_string(),
                );
            }
        }
    };

    Ok(Config {
        mode,
        vault_file,
        clear_seconds: cli.clear_seconds,
    })
}

#[allow(dead_code)]
pub fn command_definition() -> clap::Command {
    Cli::command()
}
