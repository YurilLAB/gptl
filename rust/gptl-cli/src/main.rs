//! GPTL CLI — configure and manage your anonymity network.
//!
//! Run `gptl --help` for usage or see each subcommand's help.
//! Configuration is stored at `~/.config/gptl/config.toml` (Unix) or
//! `%APPDATA%\gptl\config.toml` (Windows).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod config;
mod display;
mod profile;

use commands::{config_cmd, profile_cmd, security_cmd, status_cmd};

/// GPTL — General Purpose Transport Layer
///
/// Configure protections, switch security levels, and manage named profiles
/// for GPTL's anonymity network.  Security-sensitive changes always show
/// a diff and require confirmation (pass -y/--yes to skip).
#[derive(Parser)]
#[command(name = "gptl")]
#[command(version = "0.1.0")]
#[command(about = "Configure and manage GPTL anonymity network protections")]
#[command(long_about = "
GPTL (General Purpose Transport Layer) defends against 10 classes of
anonymity-network attacks.  This CLI lets you:

  • View and change any configuration setting
  • Switch between Standard / Enhanced / Maximum security levels
  • Save and apply named profiles
  • Audit your configuration for weaknesses

Security-sensitive changes always display a diff and ask for confirmation.
Use -y / --yes to skip prompts in scripts.
")]
struct Cli {
    /// Skip confirmation prompts — apply changes immediately
    #[arg(short = 'y', long = "yes", global = true)]
    yes: bool,

    /// Override the config file path
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Output format (table is default; json/toml for machine-readable output)
    #[arg(long, global = true, value_enum, default_value = "table")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

/// Output format for commands that display configuration.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    /// Human-readable table (default)
    Table,
    /// JSON
    Json,
    /// TOML
    Toml,
}

#[derive(Subcommand)]
enum Commands {
    /// Show and modify the active configuration
    ///
    /// gptl config show
    /// gptl config set core.timing_protection true
    /// gptl config keys
    /// gptl config reset
    /// gptl config path
    #[command(subcommand)]
    Config(config_cmd::ConfigCommand),

    /// Manage the security level and audit the security posture
    ///
    /// gptl security level maximum
    /// gptl security status
    /// gptl security audit
    #[command(subcommand)]
    Security(security_cmd::SecurityCommand),

    /// Manage named configuration profiles
    ///
    /// Built-in profiles: standard, enhanced, maximum
    ///
    /// gptl profile list
    /// gptl profile apply maximum
    /// gptl profile save my-profile
    /// gptl profile show my-profile
    /// gptl profile delete my-profile
    #[command(subcommand)]
    Profile(profile_cmd::ProfileCommand),

    /// Show a one-glance overview of GPTL status
    Status,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Config(cmd) => {
            config_cmd::run(cmd, cli.config, cli.yes, cli.format)
        }
        Commands::Security(cmd) => {
            security_cmd::run(cmd, cli.config, cli.yes)
        }
        Commands::Profile(cmd) => {
            profile_cmd::run(cmd, cli.config, cli.yes)
        }
        Commands::Status => {
            status_cmd::run(cli.config, cli.format)
        }
    };

    if let Err(e) = result {
        eprintln!("\n  {}  {}\n", display::err_str("Error:"), e);
        std::process::exit(1);
    }
}
