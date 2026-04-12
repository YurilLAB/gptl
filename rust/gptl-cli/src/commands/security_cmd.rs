//! `gptl security` — manage security level and audit security posture.

use clap::Subcommand;
use std::path::PathBuf;

use crate::config::{GptlConfig, SecurityLevel};
use crate::display::{self, AuditSeverity};

#[derive(Subcommand)]
pub enum SecurityCommand {
    /// Change the security level
    ///
    /// Shows exactly which settings will change before asking for confirmation.
    ///
    /// Levels:
    ///   standard  — Basic: DNS/WebRTC guard + core padding only (least overhead)
    ///   enhanced  — Default: adds timing shield, circuit obfuscation, BGP guard
    ///   maximum   — Full: all protections + higher rates and jitter (most overhead)
    Level {
        /// Target security level: standard | enhanced | maximum
        level: String,

        /// Only update the security_level label, do NOT adjust individual settings
        #[arg(long)]
        label_only: bool,
    },

    /// Show a summary of all enabled protections
    Status,

    /// Audit the security configuration for inconsistencies and weaknesses
    Audit,
}

pub fn run(
    cmd: SecurityCommand,
    config_path: Option<PathBuf>,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = super::config_cmd::resolve_path(config_path)?;
    match cmd {
        SecurityCommand::Level { level, label_only } => cmd_level(&path, &level, label_only, yes),
        SecurityCommand::Status => cmd_status(&path),
        SecurityCommand::Audit  => cmd_audit(&path),
    }
}

// ── level ─────────────────────────────────────────────────────────────────────

fn cmd_level(
    path: &std::path::Path,
    level_str: &str,
    label_only: bool,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let target: SecurityLevel = level_str.parse().map_err(|e: crate::config::ConfigError| e)?;
    let mut cfg = GptlConfig::load(path)?;

    // Build what the new config would look like
    let mut proposed = cfg.clone();
    proposed.security_level = target;
    if !label_only {
        proposed.core    = target.recommended_core();
        proposed.routing = target.recommended_routing();
    }

    let changes = cfg.diff(&proposed);
    if changes.is_empty() {
        println!(
            "  {}  Security level is already {}.",
            display::info_str("info:"),
            display::level_badge(target)
        );
        return Ok(());
    }

    // Warn on downgrades
    if target.is_dangerous_downgrade(cfg.security_level) {
        display::print_danger(&format!(
            "Switching from {} to {} disables several critical protections.",
            cfg.security_level.to_string().to_uppercase(),
            target.to_string().to_uppercase()
        ));
    } else if target.is_downgrade_from(cfg.security_level) {
        display::print_warning(&format!(
            "This is a downgrade from {} to {}.",
            cfg.security_level.to_string().to_uppercase(),
            target.to_string().to_uppercase()
        ));
    }

    // Show the diff
    println!(
        "\n  {}  {}  →  {}",
        display::heading("Security Level Change:"),
        display::level_badge(cfg.security_level),
        display::level_badge(target)
    );
    println!("\n  {}", display::dim(target.description()));

    if !changes.is_empty() {
        println!("\n  {}", display::heading("Settings that will change:"));
        display::print_diff(&changes);
    }
    println!();

    if label_only {
        println!(
            "  {}  Only the security_level label will be updated (--label-only).",
            display::info_str("Note:")
        );
    }

    if !display::confirm(
        &format!("Apply {} security level?", target.to_string().to_uppercase()),
        yes,
    ) {
        println!("  {}  Aborted — no changes made.", display::warn_str("Cancelled:"));
        return Ok(());
    }

    cfg = proposed;
    cfg.save(path)?;
    println!(
        "  {}  Security level set to {}.",
        display::ok("Done:"),
        display::level_badge(target)
    );
    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

fn cmd_status(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = GptlConfig::load(path)?;
    let disabled = cfg.disabled_count();
    let enabled  = GptlConfig::TOTAL_PROTECTIONS - disabled;

    println!("\n{}", display::heading("GPTL Security Status"));
    println!(
        "\n  Security Level: {}  {}",
        display::level_badge(cfg.security_level),
        display::dim(cfg.security_level.description())
    );
    println!();
    display::print_protection_list(&cfg);
    println!();

    if disabled == 0 {
        println!(
            "  {}  {}/{} protections enabled — all active.",
            display::ok("✔"),
            enabled,
            GptlConfig::TOTAL_PROTECTIONS
        );
    } else {
        println!(
            "  {}  {}/{} protections enabled — {} disabled.",
            display::warn_str("!"),
            enabled,
            GptlConfig::TOTAL_PROTECTIONS,
            disabled
        );
        println!(
            "\n  Run {} to review or {}",
            display::info_str("'gptl security audit'"),
            display::info_str("'gptl config set <key> true'"),
        );
        println!("  to re-enable individual protections.");
    }
    println!();
    Ok(())
}

// ── audit ─────────────────────────────────────────────────────────────────────

fn cmd_audit(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = GptlConfig::load(path)?;
    let mut issues = 0_usize;

    println!("\n{}", display::heading("GPTL Security Audit"));
    println!(
        "\n  Active level: {}",
        display::level_badge(cfg.security_level)
    );
    println!();

    // ── Compare current config against recommended for active level ──
    let recommended = {
        let mut r = GptlConfig::default();
        r.security_level = cfg.security_level;
        r.core    = cfg.security_level.recommended_core();
        r.routing = cfg.security_level.recommended_routing();
        r
    };
    let deviations = recommended.diff(&cfg);

    // Protections that are OFF but expected ON for the stated level
    let mut regressions: Vec<(&str, &str)> = Vec::new();
    for (key, expected, actual) in &deviations {
        if expected == "true" && actual == "false" {
            regressions.push((key.as_str(), "disabled but expected enabled for this level"));
        }
    }

    // Protections that are OFF at all (regardless of level)
    let always_on = &[
        ("routing.resource_protection", cfg.routing.resource_protection, "Sniper attack defense should always be on"),
        ("routing.dns_protection",      cfg.routing.dns_protection,      "DNS leak prevention should always be on"),
        ("routing.webrtc_protection",   cfg.routing.webrtc_protection,   "WebRTC leak prevention should always be on"),
        ("core.traffic_shaping",        cfg.core.traffic_shaping,        "Traffic shaping should always be on"),
        ("core.adaptive_padding",       cfg.core.adaptive_padding,       "Adaptive padding should always be on"),
    ];

    for (key, enabled, reason) in always_on {
        if !*enabled {
            display::print_audit_line(
                AuditSeverity::Fail,
                &format!("{}: {} — {}", key, display::err_str("disabled"), reason),
            );
            issues += 1;
        }
    }

    // Level-specific regressions
    for (key, msg) in &regressions {
        // Skip if already reported by always_on
        if always_on.iter().any(|(k, _, _)| k == key) {
            continue;
        }
        display::print_audit_line(
            AuditSeverity::Warn,
            &format!("{}: {} ({})", key, display::warn_str("disabled"), msg),
        );
        println!(
            "          Fix: {}",
            display::info_str(&format!("gptl config set {} true", key))
        );
        issues += 1;
    }

    // Check level label vs actual settings
    let more_relaxed = cfg.security_level == SecurityLevel::Standard
        && (cfg.core.timing_protection
            || cfg.core.circuit_obfuscation
            || cfg.routing.bgp_protection);
    if more_relaxed {
        display::print_audit_line(
            AuditSeverity::Warn,
            "Security level is Standard but some Enhanced features are enabled. \
             Consider updating the label:",
        );
        println!(
            "          Fix: {}",
            display::info_str("gptl security level enhanced --label-only")
        );
        issues += 1;
    }

    // All-pass line if no issues
    if issues == 0 {
        display::print_audit_line(
            AuditSeverity::Pass,
            &format!(
                "Configuration matches the {} recommended profile — no issues found.",
                cfg.security_level.to_string().to_uppercase()
            ),
        );

        if cfg.security_level != SecurityLevel::Maximum {
            println!();
            println!(
                "  {}  For stronger protection consider: {}",
                display::info_str("Tip:"),
                display::info_str("gptl security level maximum")
            );
        }
    } else {
        println!();
        println!(
            "  {}  {} issue(s) found. Run the suggested commands above to resolve them.",
            display::warn_str("Summary:"),
            issues
        );
    }

    println!();
    Ok(())
}
