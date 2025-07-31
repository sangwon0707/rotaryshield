# Dashboard Development Archive

This folder contains files from the RotaryShield dashboard development process.

## Archived Files

### Dashboard Implementations (Development Iterations)
- **`run_dashboard.py`** - Final version before isolation (used live DB)
- **`simple_dashboard.py`** - Early standalone dashboard implementation  
- **`launch_dashboard.py`** - Dashboard launcher script
- **`test_dashboard.py`** - Dashboard testing script

### Database Setup Scripts
- **`setup_dashboard_demo.py`** - Created demo database with sample data
- **`simple_demo_setup.py`** - Simple demo data generator
- **`setup_real_attack_data.py`** - Created database with real attack patterns

### Development Databases
- **`rotaryshield_demo.db`** - Demo database with sample security events
- **`rotaryshield_real.db`** - Database with authentic attack patterns  
- **`test_real_attacks.db`** - Database from real attack validation tests

### Logs
- **`dashboard.log`** - Log from dashboard development/testing

## Migration to Isolated Dashboard

These files were replaced by the isolated dashboard system:

**Current Active System:**
- **Main monitoring**: `../../run_live_monitoring.py`
- **Live database**: `../../rotaryshield_live.db`  
- **Isolated dashboard**: `../../dashboard/` folder

## Development History

1. **Phase 1**: Created `simple_dashboard.py` for basic web interface
2. **Phase 2**: Developed `run_dashboard.py` with live database integration
3. **Phase 3**: Added real attack pattern validation with specialized databases
4. **Phase 4**: **Final isolation** - moved to dedicated `dashboard/` folder

## Safe to Remove

These files can be safely deleted if disk space is needed. The current isolated dashboard in `../../dashboard/` provides all functionality with better architecture.