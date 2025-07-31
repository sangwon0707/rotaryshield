# RotaryShield Archive

This folder contains files from the development process that are no longer needed in the main project but are kept for reference.

## Contents

### dashboard-development/
Files from the dashboard development and testing phase before the final isolated dashboard was created.

- **Old dashboard servers**: Various iterations of dashboard implementations
- **Demo databases**: Test databases with sample data  
- **Setup scripts**: Scripts used to create demo/test data
- **Development logs**: Log files from testing

## Current Active Files

The active RotaryShield system now uses:

- **Main monitoring**: `run_live_monitoring.py` + `rotaryshield_live.db`
- **Web dashboard**: `dashboard/` folder (isolated)
- **Core application**: `src/rotaryshield/`

## Note

These archived files can be safely removed if disk space is needed, but are kept for reference during development.