//! `gptl status` — one-glance overview of GPTL state.

use std::path::PathBuf;

use crate::config::GptlConfig;
use crate::display;
use crate::OutputFormat;

pub fn run(
    config_path: Option<PathBuf>,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = super::config_cmd::resolve_path(config_path)?;
    let cfg  = GptlConfig::load(&path)?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&cfg)?);
            return Ok(());
        }
        OutputFormat::Toml => {
            print!("{}", toml::to_string_pretty(&cfg)?);
            return Ok(());
        }
        OutputFormat::Table => {}
    }

    let disabled = cfg.disabled_count();
    let enabled  = GptlConfig::TOTAL_PROTECTIONS - disabled;

    println!("\n{}", display::heading("GPTL Status"));
    println!(
        "\n  Security Level: {}",
        display::level_badge(cfg.security_level)
    );
    println!("  {}", display::dim(cfg.security_level.description()));
    println!();

    display::print_protection_list(&cfg);
    println!();

    if disabled == 0 {
        println!(
            "  {}  All {}/{} protections active.",
            display::ok("✔"),
            enabled,
            GptlConfig::TOTAL_PROTECTIONS
        );
    } else {
        println!(
            "  {}  {}/{} protections active  ({} disabled)",
            display::warn_str("!"),
            enabled,
            GptlConfig::TOTAL_PROTECTIONS,
            disabled
        );
    }

    println!("\n  Config: {}", display::dim(&path.display().to_string()));
    println!();

    println!("  Quick commands:");
    println!("    {}  — full configuration", display::info_str("gptl config show"));
    println!("    {}  — protection checklist", display::info_str("gptl security status"));
    println!("    {} — find mismatches", display::info_str("gptl security audit"));
    println!("    {}  — list named profiles", display::info_str("gptl profile list"));
    println!();
    Ok(())
}
