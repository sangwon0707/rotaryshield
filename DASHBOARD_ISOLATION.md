# RotaryShield Dashboard Isolation

## 🎯 Overview

The RotaryShield web dashboard has been **completely isolated** from the main application into its own dedicated folder structure. This separation provides better organization, security, and maintainability.

## 📁 Folder Structure

```
RotaryShield/
├── src/rotaryshield/          # Main application (monitoring, detection, blocking)  
├── dashboard/                 # 🆕 ISOLATED Web Dashboard
│   ├── app.py                # Standalone dashboard server
│   ├── config.py             # Dashboard configuration  
│   ├── requirements.txt      # Dashboard dependencies
│   ├── run.sh               # Quick launcher script
│   ├── data/
│   │   └── dashboard.db     # Dashboard cache database
│   ├── templates/
│   │   └── index.html       # Dashboard HTML template
│   └── static/              # CSS, JS, images (future)
├── run_live_monitoring.py    # Main monitoring service
└── rotaryshield_live.db     # Main application database
```

## 🔗 How It Works

### Main Application
- **`run_live_monitoring.py`** - Live attack detection service
- **`rotaryshield_live.db`** - Main database with security events
- **`src/rotaryshield/`** - Core monitoring components

### Isolated Dashboard  
- **`dashboard/app.py`** - Standalone web server
- **`dashboard/data/dashboard.db`** - Dashboard cache (optional)
- **Reads from**: `../rotaryshield_live.db` (main database)
- **Runs on**: http://127.0.0.1:8080 (separate port)

## 🚀 Usage

### Start Main Monitoring (Terminal 1)
```bash
python run_live_monitoring.py
```

### Start Isolated Dashboard (Terminal 2)  
```bash
cd dashboard
python app.py
# OR
./run.sh
```

### Access Dashboard
Open http://127.0.0.1:8080 in your browser

## ✅ Benefits of Isolation

### 🔒 **Security**
- Dashboard has its own process and database
- Main application continues if dashboard fails
- Separate configuration and dependencies

### 📊 **Organization**  
- Clear separation between monitoring and UI
- Independent development and updates
- Easier to deploy dashboard separately

### ⚡ **Performance**
- Dashboard doesn't impact monitoring performance
- Can scale dashboard independently
- Separate resource usage

### 🛠️ **Maintenance**
- Dashboard can be updated without touching main app
- Different teams can work on different components
- Easier testing and debugging

## 📋 API Endpoints

The isolated dashboard provides these REST APIs:

- **`GET /api/stats`** - Dashboard statistics
- **`GET /api/top-attackers`** - Top attacking IPs (24h)
- **`GET /api/blocked-ips`** - Currently blocked IPs  
- **`GET /api/recent-events`** - Recent security events
- **`GET /api/health`** - Dashboard health check

## 🔧 Configuration

Edit `dashboard/config.py` to customize:

```python
DASHBOARD_HOST = '127.0.0.1'
DASHBOARD_PORT = 8080
ROTARYSHIELD_DB_PATH = '../rotaryshield_live.db'
AUTO_REFRESH_INTERVAL = 10
```

## 🎯 Integration

The dashboard integrates with the main RotaryShield application by:

1. **Reading** from the main database (`rotaryshield_live.db`)
2. **Displaying** real-time attack data and statistics
3. **Auto-refreshing** every 10 seconds
4. **Operating independently** from the main monitoring service

## 📈 Real-Time Data

The dashboard shows **live data** from the main monitoring service:

- ✅ **Active IP bans** - Currently blocked attackers
- ✅ **Recent events** - Live attack detections  
- ✅ **Top attackers** - Most active attacking IPs
- ✅ **Statistics** - Hourly and daily attack counts

## 🛡️ Status

**✅ COMPLETE**: Dashboard isolation is fully implemented and tested.

The isolated dashboard successfully reads live attack data from the main RotaryShield monitoring service while operating as a completely separate component.