# RotaryShield Project Structure

## 📁 Current Clean Architecture

```
RotaryShield/
├── 🛡️  CORE APPLICATION
│   ├── src/rotaryshield/           # Main application code
│   │   ├── monitoring/             # Log monitoring & pattern matching
│   │   ├── database/               # Database management
│   │   ├── firewall/               # Firewall integration
│   │   ├── security/               # Security engine
│   │   └── utils/                  # Utilities & validators
│   ├── run_live_monitoring.py      # 🔥 Live monitoring service
│   └── rotaryshield_live.db        # 📊 Main application database
│
├── 🌐 WEB DASHBOARD (ISOLATED)
│   ├── dashboard/                  # Isolated web dashboard
│   │   ├── app.py                  # Standalone dashboard server
│   │   ├── config.py               # Dashboard configuration
│   │   ├── templates/index.html    # Dashboard UI
│   │   ├── data/dashboard.db       # Dashboard cache
│   │   └── run.sh                  # Quick launcher
│   └── 🔗 Reads from: rotaryshield_live.db
│
├── 🧪 TESTING & VALIDATION
│   ├── tests/                      # Unit and integration tests
│   ├── test_*.py                   # Various test scripts
│   ├── validate_real_functionality.py  # Real attack validation
│   └── run_security_tests.py       # Security test suite
│
├── ⚙️  CONFIGURATION & SETUP
│   ├── configs/                    # Configuration files
│   ├── systemd/                    # systemd integration
│   ├── install.sh                  # Installation script
│   └── setup.py                    # Python package setup
│
├── 📚 DOCUMENTATION
│   ├── docs/                       # Documentation
│   ├── Readme.md                   # Main README
│   ├── DASHBOARD_ISOLATION.md      # Dashboard isolation guide
│   └── SECURITY_ASSESSMENT_REPORT.md
│
└── 📦 ARCHIVE
    └── archive/                    # Archived development files
        └── dashboard-development/  # Old dashboard iterations
```

## 🎯 Key Components

### Main Application
- **`run_live_monitoring.py`** - Live attack detection service
- **`rotaryshield_live.db`** - Main database with security events
- **`src/rotaryshield/`** - Core monitoring components

### Isolated Dashboard  
- **`dashboard/app.py`** - Standalone web server (port 8080)
- **`dashboard/data/dashboard.db`** - Dashboard cache
- **Reads from**: Main application database
- **Independent**: Can run separately from monitoring

### Testing
- **Real attack validation** - Proves system works with authentic attacks
- **Security test suite** - Comprehensive security testing
- **Platform compatibility** - Tests across different systems

## 🚀 Quick Start

### 1. Start Main Monitoring
```bash
python run_live_monitoring.py
```

### 2. Start Web Dashboard  
```bash
cd dashboard && python app.py
```

### 3. Access Dashboard
- **URL**: http://127.0.0.1:8080
- **Features**: Real-time attack monitoring, IP bans, security events

## 🧹 Cleanup Completed

The following development files have been archived to keep the project root clean:

### Moved to `archive/dashboard-development/`
- Old dashboard implementations
- Demo databases and setup scripts  
- Development logs and test files
- Legacy database files

### Remaining in Root
- ✅ **Active monitoring service**
- ✅ **Live database** 
- ✅ **Test and validation scripts**
- ✅ **Core documentation**
- ✅ **Installation and setup files**

This structure provides clear separation between:
- **Production code** (main monitoring)
- **User interface** (isolated dashboard)  
- **Testing** (validation scripts)
- **Archive** (development history)