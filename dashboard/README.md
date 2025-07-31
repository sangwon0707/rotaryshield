# RotaryShield Web Dashboard

This folder contains the isolated web dashboard for RotaryShield security monitoring.

## Structure

```
dashboard/
├── app.py              # Main dashboard application
├── config.py           # Dashboard configuration
├── requirements.txt    # Dashboard dependencies
├── data/
│   └── dashboard.db    # Dashboard-specific database
├── static/
│   ├── css/           # CSS files
│   ├── js/            # JavaScript files
│   └── images/        # Images and icons
└── templates/
    └── index.html     # Main dashboard template
```

## Features

- 🛡️ Real-time security monitoring
- 📊 Live attack statistics and visualizations
- 🚫 IP ban management and tracking
- 📈 Security event timeline
- 🎯 Top attackers analysis
- 📱 Responsive design for all devices

## Quick Start

1. **Install dependencies:**
   ```bash
   cd dashboard
   pip install -r requirements.txt
   ```

2. **Run dashboard:**
   ```bash
   python app.py
   ```

3. **Access dashboard:**
   Open http://127.0.0.1:8080 in your browser

## Database

The dashboard uses its own SQLite database (`data/dashboard.db`) to store:
- Security events from the main RotaryShield application
- IP ban records and statistics  
- Dashboard configuration and settings

## Integration

The dashboard integrates with the main RotaryShield application by:
- Reading security events from the monitoring service
- Displaying real-time attack data and statistics
- Providing a web interface for system management

## Configuration

Edit `config.py` to customize:
- Database path
- Dashboard port and host
- Refresh intervals
- Display settings