//! Terminal output helpers — colours, tables, confirmation prompts.

use colored::Colorize;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};

use crate::config::{GptlConfig, SecurityLevel};

// ── Semantic colour helpers ───────────────────────────────────────────────────

pub fn ok(s: &str) -> String {
    s.green().bold().to_string()
}

pub fn warn_str(s: &str) -> String {
    s.yellow().bold().to_string()
}

pub fn err_str(s: &str) -> String {
    s.red().bold().to_string()
}

pub fn info_str(s: &str) -> String {
    s.cyan().to_string()
}

pub fn dim(s: &str) -> String {
    s.dimmed().to_string()
}

pub fn heading(s: &str) -> String {
    s.white().bold().underline().to_string()
}

// ── Security level badge ──────────────────────────────────────────────────────

pub fn level_badge(level: SecurityLevel) -> String {
    match level {
        SecurityLevel::Standard => " STANDARD ".white().on_blue().bold().to_string(),
        SecurityLevel::Enhanced => " ENHANCED ".black().on_bright_green().bold().to_string(),
        SecurityLevel::Maximum => " MAXIMUM  ".white().on_bright_red().bold().to_string(),
    }
}

// ── Protection status line ────────────────────────────────────────────────────

pub fn enabled_badge(enabled: bool) -> Cell {
    if enabled {
        Cell::new("enabled").fg(Color::Green)
    } else {
        Cell::new("disabled").fg(Color::Red)
    }
}

// ── Full config table ─────────────────────────────────────────────────────────

/// Print the full configuration as formatted tables.
pub fn print_config_table(config: &GptlConfig) {
    println!("\n{}", heading("GPTL Configuration"));
    println!(
        "  Security Level: {}  {}",
        level_badge(config.security_level),
        dim(config.security_level.description())
    );
    println!();

    // Core settings
    println!("{}", heading("Anti-Surveillance (core)"));
    let mut t = base_table();
    t.set_header(vec!["Setting", "Value", "Defense"]);
    add_bool(
        &mut t,
        "traffic_shaping",
        config.core.traffic_shaping,
        "Traffic confirmation (Murdoch-Danezis)",
    );
    add_bool(
        &mut t,
        "adaptive_padding",
        config.core.adaptive_padding,
        "Website fingerprinting (WTF-PAD)",
    );
    add_bool(
        &mut t,
        "timing_protection",
        config.core.timing_protection,
        "Timing attacks",
    );
    add_bool(
        &mut t,
        "circuit_obfuscation",
        config.core.circuit_obfuscation,
        "Circuit fingerprinting (Kwon et al.)",
    );
    add_bool(
        &mut t,
        "flow_correlation_defense",
        config.core.flow_correlation_defense,
        "Flow correlation (DeepCorr)",
    );
    t.add_row(vec![
        Cell::new("target_rate"),
        Cell::new(format!("{:.1} cells/s", config.core.target_rate)),
        Cell::new("Cover traffic rate"),
    ]);
    t.add_row(vec![
        Cell::new("max_jitter_ms"),
        Cell::new(format!("{} ms", config.core.max_jitter_ms)),
        Cell::new("Timing noise ceiling"),
    ]);
    t.add_row(vec![
        Cell::new("batch_size"),
        Cell::new(config.core.batch_size.to_string()),
        Cell::new("Cell batching window"),
    ]);
    println!("{t}");
    println!();

    // Routing settings
    println!("{}", heading("Routing Defenses (routing)"));
    let mut t = base_table();
    t.set_header(vec!["Setting", "Value", "Defense"]);
    add_bool(
        &mut t,
        "bgp_protection",
        config.routing.bgp_protection,
        "BGP hijacking / RAPTOR (RPKI validation)",
    );
    add_bool(
        &mut t,
        "guard_management",
        config.routing.guard_management,
        "Guard discovery (vanguard architecture)",
    );
    add_bool(
        &mut t,
        "resource_protection",
        config.routing.resource_protection,
        "Sniper attacks (PoW + memory limits)",
    );
    add_bool(
        &mut t,
        "dns_protection",
        config.routing.dns_protection,
        "DNS leakage (DoH / DoT)",
    );
    add_bool(
        &mut t,
        "webrtc_protection",
        config.routing.webrtc_protection,
        "WebRTC leakage (ICE filtering)",
    );
    add_bool(
        &mut t,
        "sybil_defense",
        config.routing.sybil_defense,
        "Sybil attacks (reputation + stake)",
    );
    println!("{t}");
    println!();
}

// ── Diff table ────────────────────────────────────────────────────────────────

/// Print a table of pending changes: (key, old_value, new_value).
pub fn print_diff(changes: &[(String, String, String)]) {
    if changes.is_empty() {
        println!("  {}", dim("(no changes)"));
        return;
    }
    let mut t = base_table();
    t.set_header(vec!["Setting", "Current Value", "New Value"]);
    for (key, old, new) in changes {
        t.add_row(vec![Cell::new(key), value_cell(old), value_cell(new)]);
    }
    println!("{t}");
}

// ── Status checklist ──────────────────────────────────────────────────────────

/// Print the protection checklist used by `gptl status` and `gptl security status`.
pub fn print_protection_list(config: &GptlConfig) {
    let items: &[(&str, bool, &str)] = &[
        ("traffic_shaping", config.core.traffic_shaping, "core"),
        ("adaptive_padding", config.core.adaptive_padding, "core"),
        ("timing_protection", config.core.timing_protection, "core"),
        (
            "circuit_obfuscation",
            config.core.circuit_obfuscation,
            "core",
        ),
        (
            "flow_correlation_defense",
            config.core.flow_correlation_defense,
            "core",
        ),
        ("bgp_protection", config.routing.bgp_protection, "routing"),
        (
            "guard_management",
            config.routing.guard_management,
            "routing",
        ),
        (
            "resource_protection",
            config.routing.resource_protection,
            "routing",
        ),
        ("dns_protection", config.routing.dns_protection, "routing"),
        (
            "webrtc_protection",
            config.routing.webrtc_protection,
            "routing",
        ),
        ("sybil_defense", config.routing.sybil_defense, "routing"),
    ];

    for (name, enabled, module) in items {
        let (mark, label) = if *enabled {
            (ok("✔"), info_str("enabled"))
        } else {
            (err_str("✘"), err_str("disabled"))
        };
        println!(
            "  {}  {:<30}  {}  {}",
            mark,
            name,
            label,
            dim(&format!("({})", module))
        );
    }
}

// ── Audit findings ────────────────────────────────────────────────────────────

pub enum AuditSeverity {
    Pass,
    Warn,
    Fail,
}

/// Print a single audit finding line.
pub fn print_audit_line(sev: AuditSeverity, message: &str) {
    let tag = match sev {
        AuditSeverity::Pass => ok("[PASS]"),
        AuditSeverity::Warn => warn_str("[WARN]"),
        AuditSeverity::Fail => err_str("[FAIL]"),
    };
    println!("  {}  {}", tag, message);
}

// ── Confirmation prompt ───────────────────────────────────────────────────────

/// Ask the user to confirm. Returns `true` if the user said yes (or `--yes` was set).
/// Falls back to `false` on non-interactive terminals.
pub fn confirm(prompt: &str, yes: bool) -> bool {
    if yes {
        return true;
    }
    match dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
    {
        Ok(r) => r,
        Err(_) => {
            eprintln!(
                "  {} Non-interactive terminal — pass --yes / -y to skip confirmation.",
                warn_str("Note:")
            );
            false
        }
    }
}

// ── Warning / danger banners ──────────────────────────────────────────────────

pub fn print_warning(msg: &str) {
    println!();
    println!("  {}  {}", warn_str("WARNING:"), msg);
    println!();
}

pub fn print_danger(msg: &str) {
    println!();
    println!("  {}   {}", err_str("DANGER:"), msg);
    println!();
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn base_table() -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
    t
}

fn add_bool(table: &mut Table, key: &str, value: bool, description: &str) {
    table.add_row(vec![
        Cell::new(key),
        enabled_badge(value),
        Cell::new(description),
    ]);
}

fn value_cell(val: &str) -> Cell {
    match val.to_lowercase().as_str() {
        "true" => Cell::new(val).fg(Color::Green),
        "false" => Cell::new(val).fg(Color::Red),
        "standard" => Cell::new(val).fg(Color::Cyan),
        "enhanced" => Cell::new(val).fg(Color::Green),
        "maximum" => Cell::new(val).fg(Color::Yellow),
        _ => Cell::new(val),
    }
}
