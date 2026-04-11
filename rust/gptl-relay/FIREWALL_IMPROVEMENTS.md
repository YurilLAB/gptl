# Firewall Automation Improvements

This document summarizes the comprehensive firewall automation improvements made to the GPTL Relay project.

## Summary of Changes

### New File: `src/auto_setup.rs`

Created a complete firewall automation module with the following features:

#### 1. Cross-Platform Firewall Support

##### Linux
- **UFW** (Uncomplicated Firewall): Primary for Ubuntu/Debian
  - Check status before adding rules
  - Add allow rules with port/protocol
  - Verify rules after addition
  - Warn if UFW is disabled

- **firewalld** (RHEL/CentOS/Fedora):
  - Check if service is running
  - Add permanent rules
  - Reload configuration after changes
  - Handle service not running gracefully

- **nftables** (Modern Linux):
  - Check existing rules
  - Create table and chain if needed
  - Add rules with comments
  - Handle missing infrastructure

- **iptables** (Legacy Linux):
  - Add INPUT chain rules
  - Support for comments
  - Persistence warnings
  - Rule verification

##### Windows
- **netsh advfirewall**:
  - Admin privilege detection
  - Add inbound rules with descriptions
  - Check existing rules
  - Service status verification

- **PowerShell** (alternative):
  - New-NetFirewallRule support
  - Rule enumeration
  - Verification support

##### macOS
- **pfctl** (Packet Filter):
  - Anchor-based rule management
  - SIP (System Integrity Protection) awareness
  - Manual configuration guidance
  - Rule reload support

- **socketfilterfw** (Application Firewall):
  - Detection support
  - Manual configuration notes

#### 2. Rule Verification

After adding a rule, the system:
1. Waits briefly for firewall to apply changes
2. Checks if rule exists in firewall configuration
3. Retries up to 3 times if needed
4. Tests port availability locally
5. Reports verification status to user

#### 3. Error Handling

Comprehensive error types:
```rust
pub enum FirewallError {
    NoFirewall,           // No supported firewall found
    InvalidPort(u16),     // Port out of range
    InvalidProtocol(String), // Invalid protocol
    PermissionDenied(String), // Missing admin rights
    CommandFailed(String), // Firewall command failed
    RuleNotFound(String), // Rollback target missing
    RuleConflict,         // Rule conflicts with existing
    Unsupported(String),  // Operation not supported
    SerializationError(String), // State file error
    IoError(String),      // I/O error
    VerificationFailed,   // Rule verification failed
}
```

Each error includes helpful context and suggestions for resolution.

#### 4. Rollback Support

Automatic rule tracking:
- Each rule gets a unique UUID
- Tracked in persistent JSON file (`~/.config/gptl-relay/firewall_rules.json`)
- Tracks: port, protocol, firewall type, add command, remove command
- Verification status tracking
- Timestamps for audit trail

Rollback methods:
- Rollback specific rule by ID
- Rollback all tracked rules
- Automatic rollback command generation per firewall type

#### 5. Safety Features

- **Admin Privilege Checking**: Detects and reports missing privileges with platform-specific instructions
- **Security Warnings**: Displays warnings about security implications before opening ports
- **Rule Conflicts**: Detects and handles existing rules gracefully
- **Confirmation Prompts**: Requires user confirmation unless `--yes` flag is used
- **Never Removes Existing Rules**: Only removes rules explicitly added by GPTL

#### 6. Diagnostic Commands

Added three new CLI commands:

##### `gptl-relay firewall-open <port>`
```bash
# Open port with defaults (tcp protocol)
gptl-relay firewall-open 8443

# Open with specific protocol
gptl-relay firewall-open 8443 --protocol udp

# Open with description
gptl-relay firewall-open 8443 --description "My Service"

# Skip confirmation
gptl-relay firewall-open 8443 --yes
```

Output includes:
- Detected firewall type
- Rule ID for rollback
- Verification status
- Warnings (e.g., firewall disabled)
- Rollback instructions

##### `gptl-relay firewall-status`
```bash
# Basic status
gptl-relay firewall-status

# Detailed output with platform-specific notes
gptl-relay firewall-status --detailed

# Show only tracked rules
gptl-relay firewall-status --tracked
```

Displays:
- Detected firewall
- Active/inactive status
- Admin privilege status
- Current firewall rules
- Tracked rules count

##### `gptl-relay firewall-verify`
```bash
# Verify all tracked rules
gptl-relay firewall-verify

# Verify specific port
gptl-relay firewall-verify --port 8443
```

Checks:
- Rule exists in firewall configuration
- Port/protocol match
- Reports any missing or broken rules

##### `gptl-relay firewall-rollback`
```bash
# Rollback all tracked rules (with confirmation)
gptl-relay firewall-rollback

# Rollback specific rule
gptl-relay firewall-rollback --rule-id <uuid>

# Force without confirmation
gptl-relay firewall-rollback --force
```

Features:
- Interactive confirmation
- Force option for automation
- Individual or bulk rollback
- Success/failure reporting

### Updated Files

#### `src/lib.rs`
- Added `pub mod auto_setup`
- Re-exported all auto_setup types
- Added missing error variants to `RelayError`
- Enhanced `SecurityContext` with additional fields

#### `src/main.rs`
- Added firewall subcommands to CLI
- Implemented command handlers for:
  - `cmd_firewall_open`
  - `cmd_firewall_status`
  - `cmd_firewall_verify`
  - `cmd_firewall_rollback`
- Platform-specific privilege error messages
- User-friendly output formatting

#### `Cargo.toml`
- Added `which = "6.0"` for command detection
- Added `hex = "0.4"` for encoding
- Added platform-specific `libc` dependency for Unix

#### `src/relay.rs`
- Fixed `mut self` in builder methods
- Added proper mutability for configuration methods

#### `src/session/mod.rs`
- Fixed Debug implementation for `SessionManager`
- Redacted sensitive key material from debug output

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  FirewallAutomation                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Detection  │  │  Rule Mgmt   │  │  Verification │  │
│  │   Engine    │  │              │  │    Engine     │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │   Rollback  │  │    Status    │  │  Persistence  │  │
│  │    Store    │  │   Reporting  │  │   (JSON)      │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   ┌─────────┐       ┌──────────┐       ┌──────────┐
   │  Linux  │       │ Windows  │       │  macOS   │
   │UFW/FW/nft│       │  netsh   │       │  pfctl   │
   │/iptables│       │   PS     │       │socketfw  │
   └─────────┘       └──────────┘       └──────────┘
```

## Usage Examples

### Basic Workflow

```bash
# 1. Check current firewall status
gptl-relay firewall-status

# 2. Open a port for your service
gptl-relay firewall-open 8443 --description "GPTL Relay Server"

# 3. Verify the rule was applied
gptl-relay firewall-verify

# 4. Later, rollback if needed
gptl-relay firewall-rollback
```

### Automation/Scripting

```bash
# Non-interactive port opening
gptl-relay firewall-open 8443 --yes

# Check if rules are still in place
gptl-relay firewall-verify || echo "Rules need attention"
```

## Testing Recommendations

1. **Linux (Ubuntu/Debian)**: Test with UFW enabled/disabled
2. **Linux (RHEL/CentOS)**: Test with firewalld running/stopped
3. **Windows**: Test as Administrator and regular user
4. **macOS**: Test with SIP enabled (expect warnings)

## Future Improvements

Potential enhancements:
- IPv6 support
- IP range restrictions
- Integration with cloud provider security groups
- Rule priority management
- Automatic rule expiration
- Integration with system change tracking

## Security Considerations

1. **Never runs without admin privileges** - Requires explicit user elevation
2. **Preserves existing rules** - Only modifies rules it created
3. **Tracks all changes** - Full audit trail in JSON file
4. **Warns about implications** - Users informed about security risks
5. **Easy rollback** - Can quickly undo any changes
6. **Redacts sensitive data** - Keys not exposed in debug output
