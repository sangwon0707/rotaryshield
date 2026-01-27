# RotaryShield Project Structure

## Current Clean Architecture (CLI-Only)

```
RotaryShield/
├── CORE APPLICATION
│   ├── src/rotaryshield/           # Main application code
│   │   ├── monitoring/             # Log monitoring & pattern matching
│   │   ├── database/               # Database management
│   │   ├── firewall/               # Firewall integration
│   │   ├── security/               # Security engine
│   │   ├── cli.py                  # Main CLI with Rich formatting
│   │   ├── cli/                    # CLI command modules
│   │   │   ├── monitor.py          # Real-time log monitoring
│   │   │   ├── list_blocked.py     # List blocked IPs
│   │   │   ├── unblock.py          # Unblock IP addresses
│   │   │   └── stats.py            # System statistics
│   │   └── utils/                  # Utilities & validators
│   ├── run_live_monitoring.py      # Live monitoring service
│   └── rotaryshield_live.db        # Main application database
│
├── TESTING & VALIDATION
│   ├── tests/                      # Unit and integration tests
│   ├── test_*.py                   # Various test scripts
│   ├── validate_real_functionality.py  # Real attack validation
│   └── run_security_tests.py       # Security test suite
│
├── CONFIGURATION & SETUP
│   ├── configs/                    # Configuration files
│   ├── systemd/                    # systemd integration
│   ├── install.sh                  # Installation script
│   └── setup.py                    # Python package setup
│
├── DOCUMENTATION
│   ├── docs/                       # Documentation
│   ├── Readme.md                   # Main README
│   └── SECURITY_ASSESSMENT_REPORT.md
│
└── ARCHIVE
    └── archive/                    # Archived development files
```

## Key Components

### Main Application
- **`run_live_monitoring.py`** - Live attack detection service
- **`rotaryshield_live.db`** - Main database with security events
- **`src/rotaryshield/`** - Core monitoring components

### CLI Commands (Rich-Enhanced)
| Command | Description |
|---------|-------------|
| `rotaryshield-status` | Service status with colored tables |
| `rotaryshield-control` | Start/stop/restart service |
| `rotaryshield-monitor` | Real-time log viewing |
| `rotaryshield-list-blocked` | Blocked IPs with expiry times |
| `rotaryshield-unblock` | Unblock specific IP |
| `rotaryshield-stats` | System statistics |
| `rotaryshield top-attackers` | Top attacker IPs with threat levels |
| `rotaryshield events` | Recent security events |
| `rotaryshield watch` | Live terminal dashboard |
| `rotaryshield ban` | Manual IP banning |

### Testing
- **Real attack validation** - Proves system works with authentic attacks
- **Security test suite** - Comprehensive security testing
- **Platform compatibility** - Tests across different systems

## Quick Start

### 1. Start Main Monitoring
```bash
sudo systemctl start rotaryshield
# or directly:
python run_live_monitoring.py
```

### 2. Monitor with CLI
```bash
# Check status
rotaryshield-status

# View live stats
rotaryshield watch

# Monitor logs
rotaryshield-monitor -f
```

### 3. View Statistics
```bash
# System stats with colored output
rotaryshield-stats

# Top attackers with threat levels
rotaryshield top-attackers

# Recent security events
rotaryshield events --limit 20
```

## Design Philosophy

### CLI-Only Approach Benefits
- **Reduced Attack Surface** - No web server to exploit
- **Minimal Dependencies** - Only Rich library for formatting
- **Resource Efficient** - No Flask/SocketIO overhead
- **Secure by Default** - No network ports for dashboard
- **Terminal Native** - Works over SSH, no browser needed

### Rich Library Features
- Beautiful colored tables
- Real-time watch mode with auto-refresh
- Progress indicators and spinners
- Severity-based color coding
- Human-readable time formatting
