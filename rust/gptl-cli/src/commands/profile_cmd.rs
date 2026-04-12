//! `gptl profile` — save, load and manage named configuration profiles.

use clap::Subcommand;
use std::path::PathBuf;

use crate::config::GptlConfig;
use crate::display;
use crate::profile;

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// List all available profiles (built-ins + saved)
    List,

    /// Show a profile's full settings
    ///
    /// Built-in profiles: standard, enhanced, maximum
    Show {
        /// Profile name
        name: String,
    },

    /// Apply a named profile, replacing the active configuration
    ///
    /// Shows a diff of what will change and asks for confirmation.
    Apply {
        /// Profile name
        name: String,
    },

    /// Save the current configuration as a named profile
    Save {
        /// Profile name (letters, digits, hyphens, underscores)
        name: String,
    },

    /// Delete a saved profile
    Delete {
        /// Profile name
        name: String,
    },
}

pub fn run(
    cmd: ProfileCommand,
    config_path: Option<PathBuf>,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = super::config_cmd::resolve_path(config_path)?;
    match cmd {
        ProfileCommand::List             => cmd_list(&path),
        ProfileCommand::Show { name }    => cmd_show(&path, &name),
        ProfileCommand::Apply { name }   => cmd_apply(&path, &name, yes),
        ProfileCommand::Save { name }    => cmd_save(&path, &name),
        ProfileCommand::Delete { name }  => cmd_delete(&path, &name, yes),
    }
}

// ── list ──────────────────────────────────────────────────────────────────────

fn cmd_list(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let profiles = profile::list(path)?;

    println!("\n{}", display::heading("Available Profiles"));
    println!();

    let mut t = comfy_table::Table::new();
    t.load_preset(comfy_table::presets::UTF8_FULL)
        .apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS);
    t.set_header(vec!["Name", "Type", "Security Level", "Description"]);

    for (name, is_builtin) in &profiles {
        let kind   = if *is_builtin { "built-in" } else { "saved" };
        let pcfg   = profile::load(name, path)?;
        let level  = display::level_badge(pcfg.security_level);
        let desc   = pcfg.security_level.description().split('.').next().unwrap_or("");
        t.add_row(vec![
            comfy_table::Cell::new(name),
            comfy_table::Cell::new(kind)
                .fg(if *is_builtin { comfy_table::Color::Cyan } else { comfy_table::Color::White }),
            comfy_table::Cell::new(level),
            comfy_table::Cell::new(desc),
        ]);
    }
    println!("{t}");
    println!(
        "\n  Use {} to apply a profile.",
        display::info_str("'gptl profile apply <name>'")
    );
    println!();
    Ok(())
}

// ── show ──────────────────────────────────────────────────────────────────────

fn cmd_show(path: &std::path::Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pcfg = profile::load(name, path)?;
    println!("\n{}", display::heading(&format!("Profile: {}", name)));
    display::print_config_table(&pcfg);
    Ok(())
}

// ── apply ─────────────────────────────────────────────────────────────────────

fn cmd_apply(path: &std::path::Path, name: &str, yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    let current = GptlConfig::load(path)?;
    let profile  = profile::load(name, path)?;
    let changes  = current.diff(&profile);

    if changes.is_empty() {
        println!(
            "  {}  Active config already matches profile '{}'.",
            display::info_str("info:"),
            name
        );
        return Ok(());
    }

    // Warn about security downgrades
    if profile.security_level.is_dangerous_downgrade(current.security_level) {
        display::print_danger(&format!(
            "Profile '{}' is a significant downgrade from your current {} level.",
            name,
            current.security_level.to_string().to_uppercase()
        ));
    } else if profile.security_level.is_downgrade_from(current.security_level) {
        display::print_warning(&format!(
            "Profile '{}' lowers the security level from {} to {}.",
            name,
            current.security_level.to_string().to_uppercase(),
            profile.security_level.to_string().to_uppercase()
        ));
    }

    // Warn about disabling protections
    let disabling: Vec<&str> = changes
        .iter()
        .filter(|(_, old, new)| old == "true" && new == "false")
        .map(|(k, _, _)| k.as_str())
        .collect();
    if !disabling.is_empty() {
        display::print_warning(&format!(
            "This profile disables {} protection(s): {}",
            disabling.len(),
            disabling.join(", ")
        ));
    }

    println!("\n  {} Applying profile '{}':", display::heading("Change Summary"), name);
    display::print_diff(&changes);
    println!();

    if !display::confirm(&format!("Apply profile '{}'?", name), yes) {
        println!("  {}  Aborted — no changes made.", display::warn_str("Cancelled:"));
        return Ok(());
    }

    profile.save(path)?;
    println!(
        "  {}  Profile '{}' applied — {} setting(s) changed.",
        display::ok("Done:"),
        name,
        changes.len()
    );
    Ok(())
}

// ── save ──────────────────────────────────────────────────────────────────────

fn cmd_save(path: &std::path::Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = GptlConfig::load(path)?;
    profile::save(name, &cfg, path)?;
    println!(
        "  {}  Configuration saved as profile '{}'.",
        display::ok("Saved:"),
        name
    );
    println!(
        "  Apply it later with: {}",
        display::info_str(&format!("gptl profile apply {}", name))
    );
    Ok(())
}

// ── delete ────────────────────────────────────────────────────────────────────

fn cmd_delete(path: &std::path::Path, name: &str, yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Confirm deletion
    if !display::confirm(&format!("Delete profile '{}'?", name), yes) {
        println!("  {}  Aborted — profile not deleted.", display::warn_str("Cancelled:"));
        return Ok(());
    }
    profile::delete(name, path)?;
    println!(
        "  {}  Profile '{}' deleted.",
        display::ok("Deleted:"),
        name
    );
    Ok(())
}
