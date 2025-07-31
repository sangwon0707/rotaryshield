#!/bin/bash
# RotaryShield Isolated Dashboard Launcher

echo "🛡️  RotaryShield Isolated Dashboard"
echo "📊 Starting isolated web interface..."
echo ""

# Check if RotaryShield database exists
if [ ! -f "../rotaryshield_live.db" ]; then
    echo "⚠️  WARNING: RotaryShield live database not found!"
    echo "   Expected: ../rotaryshield_live.db"
    echo "   Dashboard will show empty data until monitoring starts."
    echo ""
    echo "💡 To start live monitoring:"
    echo "   cd .. && python run_live_monitoring.py"
    echo ""
fi

# Start dashboard
python app.py