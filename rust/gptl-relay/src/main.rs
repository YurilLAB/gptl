//! GPTL Relay - System Change Tracking and Management CLI
//!
//! This CLI tool provides commands to:
//! - Track all changes GPTL makes to the system
//! - List and filter changes by category, date, status
//! - Rollback specific changes
//! - Export changes for audit purposes
//! - Manage firewall rules with verification and rollback

use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use gptl_relay::auto_setup::{
    FirewallAutomation, FirewallError, FirewallResult, FirewallStatus, FirewallType,
};
use gptl_relay::changes::{
    ChangeCategory, ChangeFilter, ChangeStatus, ChangeTracker, ChangeTrackerConfig,
    PlatformDetails, SystemChange,
};
use std::path::PathBuf;
use std::process;
use tracing::{error, info, warn};
use uuid::Uuid;

/// CLI arguments for gptl-relay
#[derive(Parser)]
#[command(name = "gptl-relay")]
#[command(about = "GPTL System Change Tracking and Management")]
#[command(version = "0.1.0")]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Path to change log directory
    #[arg(short, long, global = true)]
    change_dir: Option<PathBuf>,

    /// Subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands
#[derive(Subcommand)]
enum Commands {
    /// List all system changes made by GPTL
    Changes {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,

        /// Show changes since this date (YYYY-MM-DD)
        #[arg(long)]
        since: Option<String>,

        /// Show changes until this date (YYYY-MM-DD)
        #[arg(long)]
        until: Option<String>,

        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,

        /// Filter by component
        #[arg(short, long)]
        component: Option<String>,

        /// Show only changes requiring admin
        #[arg(long)]
        admin_only: bool,

        /// Search in description
        #[arg(short, long)]
        search: Option<String>,

        /// Output format
        #[arg(short, long, value_enum, default_value = "table")]
        format: OutputFormat,

        /// Limit number of results
        #[arg(short, long)]
        limit: Option<usize>,
    },

    /// Show detailed information about a specific change
    Show {
        /// Change ID (UUID)
        change_id: String,
    },

    /// Rollback a specific change
    Rollback {
        /// Change ID (UUID)
        #[arg(short, long)]
        change_id: String,

        /// Force rollback even if dangerous
        #[arg(short, long)]
        force: bool,
    },

    /// Export changes for audit
    ExportChanges {
        /// Export format
        #[arg(short, long, value_enum, default_value = "json")]
        format: ExportFormat,

        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Filter by category
        #[arg(long)]
        category: Option<String>,

        /// Export changes since this date (YYYY-MM-DD)
        #[arg(long)]
        since: Option<String>,

        /// Export changes until this date (YYYY-MM-DD)
        #[arg(long)]
        until: Option<String>,
    },

    /// Show statistics about system changes
    Stats {
        /// Show detailed category breakdown
        #[arg(short, long)]
        detailed: bool,
    },

    /// Simulate recording a change (for testing)
    #[command(hide = true)]
    Simulate {
        /// Category of the change
        category: String,
        /// Description of the change
        description: String,
    },

    /// Clean up old changes
    Cleanup {
        /// Remove changes older than this many days
        #[arg(short, long, default_value = "90")]
        older_than: u32,

        /// Dry run - show what would be deleted
        #[arg(long)]
        dry_run: bool,
    },

    /// Open a port through the firewall
    FirewallOpen {
        /// Port number to open
        port: u16,

        /// Protocol (tcp or udp)
        #[arg(short, long, default_value = "tcp")]
        protocol: String,

        /// Description for the rule
        #[arg(short, long, default_value = "GPTL Relay")]
        description: String,

        /// Skip confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },

    /// Check firewall status and current rules
    FirewallStatus {
        /// Show detailed output
        #[arg(short, long)]
        detailed: bool,

        /// Show tracked rules only
        #[arg(short, long)]
        tracked: bool,
    },

    /// Verify firewall rules are working
    FirewallVerify {
        /// Port to verify (if not specified, verifies all tracked rules)
        #[arg(short, long)]
        port: Option<u16>,

        /// Protocol
        #[arg(short, long, default_value = "tcp")]
        protocol: String,
    },

    /// Rollback firewall rules added by GPTL
    FirewallRollback {
        /// Rule ID to rollback (if not specified, rolls back all tracked rules)
        #[arg(short, long)]
        rule_id: Option<String>,

        /// Force rollback without confirmation
        #[arg(short, long)]
        force: bool,
    },
}

/// Output format for listing changes
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputFormat {
    /// Table format for terminal display
    Table,
    /// JSON format
    Json,
    /// CSV format
    Csv,
    /// Simple list format
    List,
}

/// Export format
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ExportFormat {
    /// JSON format
    Json,
    /// CSV format
    Csv,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set logger");

    // Create change tracker
    let config = if let Some(dir) = cli.change_dir {
        ChangeTrackerConfig {
            log_dir: dir,
            ..Default::default()
        }
    } else {
        ChangeTrackerConfig::default()
    };

    let tracker = ChangeTracker::with_config(config);

    if let Err(e) = tracker.initialize().await {
        error!("Failed to initialize change tracker: {}", e);
        process::exit(1);
    }

    // Execute command
    let result = match cli.command {
        Commands::Changes {
            category,
            since,
            until,
            status,
            component,
            admin_only,
            search,
            format,
            limit,
        } => {
            cmd_changes(
                &tracker, category, since, until, status, component, admin_only, search, format,
                limit,
            )
            .await
        }
        Commands::Show { change_id } => cmd_show(&tracker, change_id).await,
        Commands::Rollback { change_id, force } => cmd_rollback(&tracker, change_id, force).await,
        Commands::ExportChanges {
            format,
            output,
            category,
            since,
            until,
        } => cmd_export(&tracker, format, output, category, since, until).await,
        Commands::Stats { detailed } => cmd_stats(&tracker, detailed).await,
        Commands::Simulate {
            category,
            description,
        } => cmd_simulate(&tracker, category, description).await,
        Commands::Cleanup {
            older_than,
            dry_run,
        } => cmd_cleanup(&tracker, older_than, dry_run).await,
        Commands::FirewallOpen {
            port,
            protocol,
            description,
            yes,
        } => cmd_firewall_open(port, &protocol, &description, yes).await,
        Commands::FirewallStatus { detailed, tracked } => {
            cmd_firewall_status(detailed, tracked).await
        }
        Commands::FirewallVerify { port, protocol } => cmd_firewall_verify(port, &protocol).await,
        Commands::FirewallRollback { rule_id, force } => {
            cmd_firewall_rollback(rule_id, force).await
        }
    };

    if let Err(e) = result {
        error!("Command failed: {}", e);
        process::exit(1);
    }
}

/// Execute the 'changes' command
async fn cmd_changes(
    tracker: &ChangeTracker,
    category: Option<String>,
    since: Option<String>,
    until: Option<String>,
    status: Option<String>,
    component: Option<String>,
    admin_only: bool,
    search: Option<String>,
    format: OutputFormat,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build filter
    let mut filter = ChangeFilter::new();

    if let Some(cat_str) = category {
        match ChangeCategory::parse(&cat_str) {
            Some(cat) => filter = filter.with_category(cat),
            None => {
                eprintln!("Error: Unknown category '{}'. Valid categories:", cat_str);
                eprintln!(
                    "  network, security, service, configuration, system, filesystem, usergroup"
                );
                process::exit(1);
            }
        }
    }

    if let Some(since_str) = since {
        let since_date = parse_date(&since_str)?;
        filter = filter.with_since(since_date);
    }

    if let Some(until_str) = until {
        let until_date = parse_date(&until_str)?;
        // Set to end of day
        let until_date = until_date + chrono::Duration::days(1) - chrono::Duration::seconds(1);
        filter = filter.with_until(until_date);
    }

    if let Some(status_str) = status {
        match parse_status(&status_str) {
            Some(s) => filter = filter.with_status(s),
            None => {
                eprintln!("Error: Unknown status '{}'. Valid statuses:", status_str);
                eprintln!("  pending, applied, failed, rolledback, rollbackfailed");
                process::exit(1);
            }
        }
    }

    if let Some(comp) = component {
        filter = filter.with_component(comp);
    }

    if admin_only {
        filter = filter.with_requires_admin(true);
    }

    if let Some(search_str) = search {
        filter = filter.with_search(search_str);
    }

    // Get changes
    let mut changes = tracker.get_filtered(&filter).await;

    // Apply limit
    if let Some(lim) = limit {
        changes.truncate(lim);
    }

    // Output in requested format
    match format {
        OutputFormat::Table => print_changes_table(&changes),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&changes)?;
            println!("{}", json);
        }
        OutputFormat::Csv => {
            print_changes_csv(&changes)?;
        }
        OutputFormat::List => {
            for change in changes {
                println!(
                    "{} | {} | {} | {}",
                    change.id.to_string().split('-').next().unwrap_or(""),
                    change.timestamp.format("%Y-%m-%d %H:%M"),
                    change.category,
                    change.description
                );
            }
        }
    }

    Ok(())
}

/// Execute the 'show' command
async fn cmd_show(
    tracker: &ChangeTracker,
    change_id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = Uuid::parse_str(&change_id)?;

    match tracker.get(id).await {
        Some(change) => print_change_detail(&change),
        None => {
            eprintln!("Error: Change with ID '{}' not found", change_id);
            process::exit(1);
        }
    }

    Ok(())
}

/// Execute the 'rollback' command
async fn cmd_rollback(
    tracker: &ChangeTracker,
    change_id: String,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = Uuid::parse_str(&change_id)?;

    // Get change details first
    let change = match tracker.get(id).await {
        Some(c) => c,
        None => {
            eprintln!("Error: Change with ID '{}' not found", change_id);
            process::exit(1);
        }
    };

    // Check if rollback is available
    if change.rollback_command.is_none() && !force {
        eprintln!("Error: Rollback is not available for this change");
        eprintln!("Use --force to attempt rollback anyway (may be dangerous)");
        process::exit(1);
    }

    println!("Rolling back change:");
    println!("  ID: {}", change.id);
    println!("  Description: {}", change.description);
    println!("  Category: {}", change.category);

    if let Some(ref cmd) = change.rollback_command {
        println!("  Rollback command: {}", cmd);
    }

    if !force {
        print!("\nAre you sure? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled");
            return Ok(());
        }
    }

    match tracker.rollback(id).await {
        Ok(_) => {
            println!("\n✓ Successfully rolled back change {}", change_id);
        }
        Err(e) => {
            eprintln!("\n✗ Rollback failed: {}", e);
            process::exit(1);
        }
    }

    Ok(())
}

/// Execute the 'export-changes' command
async fn cmd_export(
    tracker: &ChangeTracker,
    format: ExportFormat,
    output: Option<PathBuf>,
    category: Option<String>,
    since: Option<String>,
    until: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build filter
    let mut filter = ChangeFilter::new();

    if let Some(cat_str) = category {
        match ChangeCategory::parse(&cat_str) {
            Some(cat) => filter = filter.with_category(cat),
            None => {
                eprintln!("Error: Unknown category '{}'", cat_str);
                process::exit(1);
            }
        }
    }

    if let Some(since_str) = since {
        let since_date = parse_date(&since_str)?;
        filter = filter.with_since(since_date);
    }

    if let Some(until_str) = until {
        let until_date = parse_date(&until_str)?;
        let until_date = until_date + chrono::Duration::days(1) - chrono::Duration::seconds(1);
        filter = filter.with_until(until_date);
    }

    // Export
    let content = match format {
        ExportFormat::Json => tracker.export_json(&filter).await?,
        ExportFormat::Csv => tracker.export_csv(&filter).await?,
    };

    // Output
    if let Some(path) = output {
        tokio::fs::write(&path, content).await?;
        println!("Exported changes to {}", path.display());
    } else {
        println!("{}", content);
    }

    Ok(())
}

/// Execute the 'stats' command
async fn cmd_stats(
    tracker: &ChangeTracker,
    detailed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let stats = tracker.get_statistics().await;

    println!("GPTL System Changes Statistics");
    println!("==============================\n");

    println!("Total Changes:    {}", stats.total_changes);
    println!("Applied:          {}", stats.applied_count);
    println!("Failed:           {}", stats.failed_count);
    println!("Rolled Back:      {}", stats.rolled_back_count);
    println!("Rollback Failed:  {}", stats.rollback_failed_count);
    println!("Pending:          {}", stats.pending_count);

    if detailed {
        println!("\nChanges by Category:");
        println!("--------------------");
        for (category, count) in &stats.by_category {
            println!("  {:15} {}", category.to_string(), count);
        }
    }

    Ok(())
}

/// Execute the 'simulate' command (hidden, for testing)
async fn cmd_simulate(
    tracker: &ChangeTracker,
    category: String,
    description: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let cat = match ChangeCategory::parse(&category) {
        Some(c) => c,
        None => {
            eprintln!("Error: Unknown category '{}'", category);
            process::exit(1);
        }
    };

    let change = SystemChange::new(cat, description, "simulated command", "cli/simulate")
        .with_rollback("echo 'rollback simulated'")
        .with_admin();

    let id = tracker.record_applied(change).await?;
    println!("Recorded simulated change with ID: {}", id);

    Ok(())
}

/// Execute the 'cleanup' command
async fn cmd_cleanup(
    tracker: &ChangeTracker,
    older_than: u32,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let cutoff = Utc::now() - chrono::Duration::days(older_than as i64);

    let filter = ChangeFilter::new().with_until(cutoff);
    let old_changes = tracker.get_filtered(&filter).await;

    println!(
        "Found {} changes older than {} days",
        old_changes.len(),
        older_than
    );

    if dry_run {
        println!("\nDry run - would delete the following changes:");
        for change in &old_changes {
            println!(
                "  {} - {} - {}",
                change.id.to_string().split('-').next().unwrap_or(""),
                change.timestamp.format("%Y-%m-%d"),
                change.description
            );
        }
    } else if !old_changes.is_empty() {
        print!("\nDelete these changes? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().eq_ignore_ascii_case("y") {
            // Remove old changes
            let all_changes = tracker.get_all().await;
            let to_keep: Vec<_> = all_changes
                .into_iter()
                .filter(|c| c.timestamp > cutoff)
                .collect();

            // Clear and re-add kept changes
            tracker.clear().await?;
            for change in to_keep {
                tracker.record(change).await?;
            }

            println!("Deleted {} old changes", old_changes.len());
        } else {
            println!("Cancelled");
        }
    }

    Ok(())
}

/// Parse a date string (YYYY-MM-DD) into DateTime<Utc>
fn parse_date(date_str: &str) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    let naive = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")?;
    Ok(DateTime::from_naive_utc_and_offset(
        naive.and_hms_opt(0, 0, 0).unwrap(),
        Utc,
    ))
}

/// Parse a status string into ChangeStatus
fn parse_status(status_str: &str) -> Option<ChangeStatus> {
    match status_str.to_lowercase().as_str() {
        "pending" => Some(ChangeStatus::Pending),
        "applied" => Some(ChangeStatus::Applied),
        "failed" => Some(ChangeStatus::Failed),
        "rolledback" => Some(ChangeStatus::RolledBack),
        "rollbackfailed" => Some(ChangeStatus::RollbackFailed),
        _ => None,
    }
}

/// Print changes in table format
fn print_changes_table(changes: &[SystemChange]) {
    if changes.is_empty() {
        println!("No changes found matching the criteria.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["ID", "Timestamp", "Category", "Status", "Description"]);

    for change in changes {
        let id_short = change.id.to_string();
        let id_short = id_short.split('-').next().unwrap_or(&id_short);

        table.add_row(vec![
            id_short.to_string(),
            change.timestamp.format("%Y-%m-%d %H:%M").to_string(),
            change.category.to_string(),
            change.status.to_string(),
            truncate(&change.description, 40),
        ]);
    }

    println!("{}", table);
    println!("\nTotal: {} changes", changes.len());
}

/// Print changes in CSV format
fn print_changes_csv(changes: &[SystemChange]) -> Result<(), Box<dyn std::error::Error>> {
    println!("id,timestamp,category,status,description,command,requires_admin,component");

    for change in changes {
        println!(
            "{},{},{},{},\"{}\",\"{}\",{},{}",
            change.id,
            change.timestamp.to_rfc3339(),
            change.category,
            change.status,
            change.description.replace('"', "\"\""),
            change.command_or_action.replace('"', "\"\""),
            change.requires_admin,
            change.component
        );
    }

    Ok(())
}

/// Print detailed information about a change
fn print_change_detail(change: &SystemChange) {
    println!("Change Details");
    println!("==============\n");

    println!("ID:               {}", change.id);
    println!("Timestamp:        {}", change.timestamp.to_rfc3339());
    println!("Category:         {}", change.category);
    println!("Status:           {}", change.status);
    println!("Component:        {}", change.component);
    println!("GPTL Version:     {}", change.gptl_version);
    println!(
        "Requires Admin:   {}",
        if change.requires_admin { "Yes" } else { "No" }
    );

    println!("\nDescription:      {}", change.description);
    println!("Command/Action:   {}", change.command_or_action);

    if let Some(ref cmd) = change.rollback_command {
        println!("Rollback Command: {}", cmd);
    } else {
        println!("Rollback Command: (not available)");
    }

    if !change.files_affected.is_empty() {
        println!("\nFiles Affected:");
        for file in &change.files_affected {
            println!("  - {}", file.display());
        }
    }

    if let Some(ref error) = change.error_message {
        println!("\nError Message:    {}", error);
    }

    if !change.metadata.is_empty() {
        println!("\nMetadata:");
        for (key, value) in &change.metadata {
            println!("  {}: {}", key, value);
        }
    }

    // Platform-specific details
    match &change.platform_details {
        PlatformDetails::Windows {
            registry_keys,
            services,
            firewall_rules,
        } => {
            if !registry_keys.is_empty() {
                println!("\nRegistry Keys:");
                for key in registry_keys {
                    println!("  - {}", key);
                }
            }
            if !services.is_empty() {
                println!("\nWindows Services:");
                for svc in services {
                    println!("  - {}", svc);
                }
            }
            if !firewall_rules.is_empty() {
                println!("\nFirewall Rules:");
                for rule in firewall_rules {
                    println!("  - {}", rule);
                }
            }
        }
        PlatformDetails::Linux {
            systemd_units,
            sysctl_params,
            net_namespaces,
            iptables_rules,
        } => {
            if !systemd_units.is_empty() {
                println!("\nSystemd Units:");
                for unit in systemd_units {
                    println!("  - {}", unit);
                }
            }
            if !sysctl_params.is_empty() {
                println!("\nSysctl Parameters:");
                for param in sysctl_params {
                    println!("  - {}", param);
                }
            }
            if !net_namespaces.is_empty() {
                println!("\nNetwork Namespaces:");
                for ns in net_namespaces {
                    println!("  - {}", ns);
                }
            }
            if !iptables_rules.is_empty() {
                println!("\niptables Rules:");
                for rule in iptables_rules {
                    println!("  - {}", rule);
                }
            }
        }
        PlatformDetails::MacOS {
            launchd_plists,
            pf_rules,
        } => {
            if !launchd_plists.is_empty() {
                println!("\nLaunchd Plists:");
                for plist in launchd_plists {
                    println!("  - {}", plist);
                }
            }
            if !pf_rules.is_empty() {
                println!("\nPF Rules:");
                for rule in pf_rules {
                    println!("  - {}", rule);
                }
            }
        }
        PlatformDetails::Generic => {}
    }
}

/// Truncate a string to a maximum length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Execute the 'firewall-open' command
async fn cmd_firewall_open(
    port: u16,
    protocol: &str,
    description: &str,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut automation = if yes {
        FirewallAutomation::new().with_auto_confirm(true)
    } else {
        FirewallAutomation::new()
    };

    println!("Opening port {}/{} through firewall...", port, protocol);
    println!("Detected firewall: {}", automation.firewall_type());
    println!();

    if !automation.has_admin() {
        eprintln!("Error: Administrator privileges required");
        eprintln!();

        #[cfg(windows)]
        eprintln!("Please run this command as Administrator:");

        #[cfg(target_os = "linux")]
        eprintln!("Please run with sudo:");

        #[cfg(target_os = "macos")]
        eprintln!("Please run with sudo:");

        eprintln!("  sudo gptl-relay firewall-open {}", port);
        process::exit(1);
    }

    // Ask for confirmation if not auto-confirmed
    if !yes {
        print!("\nDo you want to proceed? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled");
            return Ok(());
        }
    }

    match automation.open_port(port, protocol, description).await {
        Ok(result) => {
            println!("\n✓ {}", result.message);

            if let Some(ref rule_id) = result.rule_id {
                println!(
                    "  Rule ID: {}",
                    rule_id.split('-').next().unwrap_or(rule_id)
                );
            }

            if result.verification_passed {
                println!("  ✓ Rule verified successfully");
            } else {
                println!("  ⚠ Rule added but verification pending");
            }

            if !result.warnings.is_empty() {
                println!("\n  Warnings:");
                for warning in &result.warnings {
                    println!("    - {}", warning);
                }
            }

            println!("\nTo rollback this change:");
            if let Some(ref rule_id) = result.rule_id {
                println!("  gptl-relay firewall-rollback --rule-id {}", rule_id);
            }
        }
        Err(FirewallError::PermissionDenied(msg)) => {
            eprintln!("\n✗ Permission denied: {}", msg);
            process::exit(1);
        }
        Err(FirewallError::NoFirewall) => {
            eprintln!("\n✗ No supported firewall detected");
            eprintln!("  Supported firewalls:");
            eprintln!("    Linux: UFW, firewalld, nftables, iptables");
            eprintln!("    Windows: Windows Defender Firewall");
            eprintln!("    macOS: PF (Packet Filter)");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("\n✗ Failed to open port: {}", e);
            process::exit(1);
        }
    }

    Ok(())
}

/// Execute the 'firewall-status' command
async fn cmd_firewall_status(
    detailed: bool,
    tracked_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let automation = FirewallAutomation::new();

    println!("Firewall Status");
    println!("===============");
    println!();

    if tracked_only {
        // Show only tracked rules
        let tracked = automation.get_tracked_rules();

        if tracked.is_empty() {
            println!("No tracked firewall rules found.");
            println!();
            println!("Rules are tracked when you use: gptl-relay firewall-open <port>");
        } else {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    "ID",
                    "Port",
                    "Protocol",
                    "Firewall",
                    "Verified",
                    "Description",
                ]);

            for rule in tracked {
                let id_short = rule.id.split('-').next().unwrap_or(&rule.id);
                let verified = if rule.verified { "✓" } else { "✗" };

                table.add_row(vec![
                    id_short.to_string(),
                    rule.port.to_string(),
                    rule.protocol.clone(),
                    format!("{:?}", rule.firewall_type),
                    verified.to_string(),
                    truncate(&rule.description, 30),
                ]);
            }

            println!("{}", table);
            println!("\nTotal tracked rules: {}", tracked.len());
        }
    } else {
        // Get full firewall status
        match automation.get_status().await {
            Ok(status) => {
                println!("Detected Firewall: {}", status.firewall_type);
                println!(
                    "Status: {}",
                    if status.is_active {
                        "Active ✓"
                    } else {
                        "Inactive ✗"
                    }
                );
                println!(
                    "Admin Privileges: {}",
                    if status.has_admin {
                        "Yes ✓"
                    } else {
                        "No ✗"
                    }
                );
                println!("Tracked Rules: {}", status.tracked_rules_count);
                println!();

                if !status.rules.is_empty() {
                    println!("Current Firewall Rules:");
                    println!("----------------------");

                    let mut table = Table::new();
                    table
                        .load_preset(UTF8_FULL)
                        .apply_modifier(UTF8_ROUND_CORNERS)
                        .set_header(vec!["Port", "Protocol", "Action", "Source"]);

                    for rule in &status.rules {
                        // Only show GPTL-related rules unless detailed mode
                        if !detailed {
                            if let Some(ref desc) = rule.description {
                                if !desc.to_lowercase().contains("gptl") {
                                    continue;
                                }
                            }
                        }

                        table.add_row(vec![
                            rule.port.to_string(),
                            rule.protocol.clone(),
                            rule.action.clone(),
                            rule.source.as_deref().unwrap_or("Any").to_string(),
                        ]);
                    }

                    println!("{}", table);
                } else {
                    println!("No firewall rules found.");
                }

                if detailed {
                    println!();
                    println!("Platform-specific Notes:");

                    match status.firewall_type {
                        FirewallType::Ufw => {
                            println!("  - UFW Status: sudo ufw status verbose");
                            println!("  - Enable: sudo ufw enable");
                            println!("  - Disable: sudo ufw disable");
                        }
                        FirewallType::Firewalld => {
                            println!("  - Firewalld Status: sudo systemctl status firewalld");
                            println!("  - Start: sudo systemctl start firewalld");
                            println!("  - Enable: sudo systemctl enable firewalld");
                        }
                        FirewallType::Iptables => {
                            println!("  - View rules: sudo iptables -L -n -v");
                            println!("  - For persistence, install iptables-persistent");
                        }
                        FirewallType::WindowsNetsh | FirewallType::WindowsPowerShell => {
                            println!(
                                "  - View all rules: netsh advfirewall firewall show rule name=all"
                            );
                            println!("  - Windows Firewall is controlled via Windows Security");
                        }
                        _ => {
                            println!("  No specific notes for this firewall type.");
                        }
                    }
                }
            }
            Err(FirewallError::NoFirewall) => {
                eprintln!("No supported firewall detected on this system.");
                eprintln!();
                eprintln!("Supported firewalls:");
                eprintln!("  Linux: UFW, firewalld, nftables, iptables");
                eprintln!("  Windows: Windows Defender Firewall");
                eprintln!("  macOS: PF (Packet Filter)");
            }
            Err(e) => {
                eprintln!("Error getting firewall status: {}", e);
                process::exit(1);
            }
        }
    }

    Ok(())
}

/// Execute the 'firewall-verify' command
async fn cmd_firewall_verify(
    port: Option<u16>,
    protocol: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let automation = FirewallAutomation::new();

    println!("Verifying Firewall Rules");
    println!("========================\n");

    if let Some(p) = port {
        // Verify specific port
        print!("Checking port {}/{}... ", p, protocol);

        match automation.get_status().await {
            Ok(status) => {
                let rule_exists = status
                    .rules
                    .iter()
                    .any(|r| r.port == p && r.protocol.to_lowercase() == protocol.to_lowercase());

                if rule_exists {
                    println!("✓ Rule found");
                } else {
                    println!("✗ Rule not found");
                    println!();
                    println!("The port may not be open through the firewall.");
                    println!("To open it, run: gptl-relay firewall-open {}", p);
                }
            }
            Err(e) => {
                eprintln!("✗ Error: {}", e);
                process::exit(1);
            }
        }
    } else {
        // Verify all tracked rules
        let tracked = automation.get_tracked_rules();

        if tracked.is_empty() {
            println!("No tracked rules to verify.");
            println!("Use 'gptl-relay firewall-open <port>' to open ports.");
            return Ok(());
        }

        let mut all_verified = true;

        for rule in tracked {
            print!(
                "Verifying {} ({}/{})... ",
                rule.description, rule.port, rule.protocol
            );

            match automation.get_status().await {
                Ok(status) => {
                    let rule_exists = status.rules.iter().any(|r| {
                        r.port == rule.port
                            && r.protocol.to_lowercase() == rule.protocol.to_lowercase()
                    });

                    if rule_exists {
                        println!("✓");
                    } else {
                        println!("✗ (rule missing)");
                        all_verified = false;
                    }
                }
                Err(_) => {
                    println!("✗ (check failed)");
                    all_verified = false;
                }
            }
        }

        println!();
        if all_verified {
            println!("✓ All tracked rules are in place");
        } else {
            println!("⚠ Some rules are missing or could not be verified");
            println!("  Run 'gptl-relay firewall-status --tracked' for details");
        }
    }

    Ok(())
}

/// Execute the 'firewall-rollback' command
async fn cmd_firewall_rollback(
    rule_id: Option<String>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut automation = FirewallAutomation::new();

    println!("Firewall Rollback");
    println!("=================\n");

    if !automation.has_admin() {
        eprintln!("Error: Administrator privileges required for rollback");
        eprintln!();

        #[cfg(unix)]
        eprintln!("Please run with sudo: sudo gptl-relay firewall-rollback");

        #[cfg(windows)]
        eprintln!("Please run as Administrator");

        process::exit(1);
    }

    match rule_id {
        Some(id) => {
            // Rollback specific rule
            println!(
                "Rolling back rule: {}...",
                id.split('-').next().unwrap_or(&id)
            );

            if !force {
                print!("\nAre you sure? [y/N] ");
                use std::io::Write;
                std::io::stdout().flush()?;

                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;

                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled");
                    return Ok(());
                }
            }

            match automation.rollback_rule(&id).await {
                Ok(result) => {
                    println!("\n✓ {}", result.message);
                    if !result.warnings.is_empty() {
                        println!("\n  Warnings:");
                        for warning in &result.warnings {
                            println!("    - {}", warning);
                        }
                    }
                }
                Err(FirewallError::RuleNotFound(_)) => {
                    eprintln!("✗ Rule not found: {}", id);
                    eprintln!("\nUse 'gptl-relay firewall-status --tracked' to see tracked rules.");
                    process::exit(1);
                }
                Err(e) => {
                    eprintln!("✗ Rollback failed: {}", e);
                    process::exit(1);
                }
            }
        }
        None => {
            // Rollback all tracked rules
            let tracked = automation.get_tracked_rules();

            if tracked.is_empty() {
                println!("No tracked rules to rollback.");
                return Ok(());
            }

            println!("Found {} tracked rule(s) to rollback:", tracked.len());
            for rule in tracked {
                println!("  - {} ({}/{})", rule.description, rule.port, rule.protocol);
            }

            if !force {
                print!("\nRollback all these rules? [y/N] ");
                use std::io::Write;
                std::io::stdout().flush()?;

                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;

                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled");
                    return Ok(());
                }
            }

            println!();
            let results = automation.rollback_all().await;

            let mut success_count = 0;
            let mut fail_count = 0;

            for result in results {
                match result {
                    Ok(r) => {
                        println!("✓ {}", r.message);
                        success_count += 1;
                    }
                    Err(e) => {
                        println!("✗ Failed: {}", e);
                        fail_count += 1;
                    }
                }
            }

            println!();
            println!(
                "Results: {} succeeded, {} failed",
                success_count, fail_count
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_date() {
        let result = parse_date("2024-01-15").unwrap();
        assert_eq!(result.format("%Y-%m-%d").to_string(), "2024-01-15");
    }

    #[test]
    fn test_parse_status() {
        assert!(matches!(
            parse_status("applied"),
            Some(ChangeStatus::Applied)
        ));
        assert!(matches!(parse_status("failed"), Some(ChangeStatus::Failed)));
        assert!(matches!(parse_status("unknown"), None));
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
    }
}
