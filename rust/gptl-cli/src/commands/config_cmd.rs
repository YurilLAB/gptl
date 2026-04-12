//! `gptl config` — view and mutate the active configuration.

use clap::Subcommand;
use std::path::{Path, PathBuf};

use crate::config::GptlConfig;
use crate::display;
use crate::OutputFormat;

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Show the current configuration
    ///
    /// Use --format to get machine-readable output:
    ///   gptl config show --format json
    ///   gptl config show --format toml
    Show,

    /// Set a configuration key to a new value
    ///
    /// Keys use dot notation.  Run 'gptl config show' to see all keys.
    ///
    /// Examples:
    ///   gptl config set security_level maximum
    ///   gptl config set core.timing_protection true
    ///   gptl config set routing.dns_protection false
    Set {
        /// Key to change (e.g. core.timing_protection)
        key: String,
        /// New value
        value: String,
    },

    /// List all settable keys with their current values and descriptions
    Keys,

    /// Reset all settings to their defaults
    Reset,

    /// Print the path to the active config file
    Path,
}

pub fn run(
    cmd: ConfigCommand,
    config_path: Option<PathBuf>,
    yes: bool,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = resolve_path(config_path)?;
    match cmd {
        ConfigCommand::Show         => cmd_show(&path, &format),
        ConfigCommand::Set { key, value } => cmd_set(&path, &key, &value, yes),
        ConfigCommand::Keys         => cmd_keys(&path),
        ConfigCommand::Reset        => cmd_reset(&path, yes),
        ConfigCommand::Path         => { println!("{}", path.display()); Ok(()) }
    }
}

// ── show ──────────────────────────────────────────────────────────────────────

fn cmd_show(path: &Path, format: &OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = GptlConfig::load(path)?;
    match format {
        OutputFormat::Table => {
            display::print_config_table(&cfg);
            println!("  Config file: {}", display::dim(&path.display().to_string()));
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        OutputFormat::Toml => {
            print!("{}", toml::to_string_pretty(&cfg)?);
        }
    }
    Ok(())
}

// ── keys ──────────────────────────────────────────────────────────────────────

fn cmd_keys(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = GptlConfig::load(path)?;
    println!("\n{}", display::heading("Configurable Keys"));
    println!();
    let mut t = comfy_table::Table::new();
    t.load_preset(comfy_table::presets::UTF8_FULL)
        .apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS);
    t.set_header(vec!["Key", "Current Value", "Accepted Values"]);
    for (key, val, desc) in cfg.all_keys() {
        t.add_row(vec![
            comfy_table::Cell::new(&key),
            comfy_table::Cell::new(&val),
            comfy_table::Cell::new(desc),
        ]);
    }
    println!("{t}");
    Ok(())
}

// ── set ───────────────────────────────────────────────────────────────────────

fn cmd_set(path: &Path, key: &str, value: &str, yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = GptlConfig::load(path)?;

    // Validate key exists and get old value (returns error for unknown keys)
    let old = cfg.get_key(key)?;

    if old == value {
        println!(
            "  {}  '{}' is already '{}'",
            display::info_str("info:"),
            key,
            value
        );
        return Ok(());
    }

    // Security-sensitive changes need a confirmation
    if GptlConfig::is_security_sensitive(key) {
        if GptlConfig::is_dangerous_change(key, value) {
            display::print_danger(&format!(
                "Changing '{}' to '{}' reduces your anonymity protection.",
                key, value
            ));
        } else {
            println!("\n  {}  This is a security-sensitive setting.", display::warn_str("Note:"));
        }

        println!("\n  {}", display::heading("Pending Change"));
        let changes = vec![(key.to_string(), old.clone(), value.to_string())];
        display::print_diff(&changes);
        println!();

        if !display::confirm(&format!("Apply change to '{}'?", key), yes) {
            println!("  {}  Aborted — no changes made.", display::warn_str("Cancelled:"));
            return Ok(());
        }
    }

    cfg.set_key(key, value)?;
    cfg.save(path)?;
    println!(
        "  {}  '{}':  {}  →  {}",
        display::ok("Updated"),
        key,
        display::dim(&old),
        display::info_str(value)
    );
    Ok(())
}

// ── reset ─────────────────────────────────────────────────────────────────────

fn cmd_reset(path: &Path, yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    let current  = GptlConfig::load(path)?;
    let defaults = GptlConfig::default();
    let changes  = current.diff(&defaults);

    if changes.is_empty() {
        println!("  {}  Configuration is already at defaults.", display::info_str("info:"));
        return Ok(());
    }

    println!("\n  {}", display::heading("Reset Summary — settings that will change:"));
    display::print_diff(&changes);
    println!();
    display::print_warning("This will overwrite ALL current settings with defaults.");

    if !display::confirm("Reset configuration to defaults?", yes) {
        println!("  {}  Aborted — no changes made.", display::warn_str("Cancelled:"));
        return Ok(());
    }

    defaults.save(path)?;
    println!("  {}  Configuration reset to defaults.", display::ok("Done:"));
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn resolve_path(
    override_path: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let p = match override_path {
        Some(p) => p,
        None    => GptlConfig::default_path()?,
    };
    Ok(p)
}
