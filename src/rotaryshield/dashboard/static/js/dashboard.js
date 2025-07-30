/* RotaryShield Dashboard JavaScript
   Real-time security monitoring dashboard
   Phase 2 Complete - Enterprise Ready
*/

class RotaryShieldDashboard {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.updateInterval = null;
        this.isConnected = false;
        this.isPaused = false;
        
        // Chart color schemes
        this.colors = {
            primary: '#00d4aa',
            secondary: '#0099cc',
            danger: '#dc3545',
            warning: '#ffc107',
            success: '#28a745',
            info: '#17a2b8'
        };
        
        this.chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff'
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#b0b0b0'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                y: {
                    ticks: {
                        color: '#b0b0b0'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            }
        };
    }
    
    // Initialize dashboard
    async initialize() {
        console.log('Initializing RotaryShield Dashboard...');
        
        try {
            // Initialize WebSocket connection
            this.initializeWebSocket();
            
            // Initialize charts
            this.initializeCharts();
            
            // Load initial data
            await this.loadInitialData();
            
            // Start periodic updates
            this.startPeriodicUpdates();
            
            console.log('Dashboard initialized successfully');
            
        } catch (error) {
            console.error('Dashboard initialization failed:', error);
            this.showError('Failed to initialize dashboard');
        }
    }
    
    // Initialize WebSocket connection
    initializeWebSocket() {
        try {
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('WebSocket connected');
                this.isConnected = true;
                this.updateConnectionStatus(true);
                this.socket.emit('request_stats');
            });
            
            this.socket.on('disconnect', () => {
                console.log('WebSocket disconnected');
                this.isConnected = false;
                this.updateConnectionStatus(false);
            });
            
            this.socket.on('stats_update', (data) => {
                if (!this.isPaused) {
                    this.updateStatistics(data);
                    this.updateCharts(data);
                }
            });
            
            this.socket.on('error', (error) => {
                console.error('WebSocket error:', error);
                this.showError('Connection error: ' + error.message);
            });
            
        } catch (error) {
            console.error('WebSocket initialization failed:', error);
        }
    }
    
    // Initialize charts
    initializeCharts() {
        // Timeline Chart
        const timelineCtx = document.getElementById('timeline-chart');
        if (timelineCtx) {
            this.charts.timeline = new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => i + ':00'),
                    datasets: [{
                        label: 'Security Events',
                        data: new Array(24).fill(0),
                        borderColor: this.colors.primary,
                        backgroundColor: this.colors.primary + '20',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    ...this.chartOptions,
                    plugins: {
                        ...this.chartOptions.plugins,
                        title: {
                            display: false
                        }
                    }
                }
            });
        }
        
        // Attack Types Chart
        const attackTypesCtx = document.getElementById('attack-types-chart');
        if (attackTypesCtx) {
            this.charts.attackTypes = new Chart(attackTypesCtx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            this.colors.danger,
                            this.colors.warning,
                            this.colors.info,
                            this.colors.success,
                            this.colors.secondary
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#ffffff',
                                padding: 15
                            }
                        }
                    }
                }
            });
        }
        
        // Top Attackers Chart
        const topAttackersCtx = document.getElementById('top-attackers-chart');
        if (topAttackersCtx) {
            this.charts.topAttackers = new Chart(topAttackersCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Attack Attempts',
                        data: [],
                        backgroundColor: this.colors.danger + '80',
                        borderColor: this.colors.danger,
                        borderWidth: 1
                    }]
                },
                options: {
                    ...this.chartOptions,
                    indexAxis: 'y',
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
    }
    
    // Load initial data
    async loadInitialData() {
        try {
            // Load statistics
            const statsResponse = await fetch('/api/stats');
            if (statsResponse.ok) {
                const statsData = await statsResponse.json();
                if (statsData.success) {
                    this.updateStatistics(statsData.data);
                    this.updateCharts(statsData.data);
                }
            }
            
            // Load blocked IPs
            await this.loadBlockedIPs();
            
            // Load recent events
            await this.loadRecentEvents();
            
            // Load attack patterns
            await this.loadAttackPatterns();
            
        } catch (error) {
            console.error('Failed to load initial data:', error);
            this.showError('Failed to load dashboard data');
        }
    }
    
    // Update statistics display
    updateStatistics(data) {
        try {
            document.getElementById('active-bans').textContent = this.formatNumber(data.active_bans || 0);
            document.getElementById('events-24h').textContent = this.formatNumber(data.events_24h || 0);
            document.getElementById('events-1h').textContent = this.formatNumber(data.events_1h || 0);
            document.getElementById('total-bans').textContent = this.formatNumber(data.total_bans || 0);
            
            // Update last updated time
            const now = new Date();
            document.getElementById('last-update').textContent = now.toLocaleTimeString();
            
            // Update system status
            const statusText = document.getElementById('status-text');
            const statusDot = document.getElementById('status-dot');
            
            if (data.system_status === 'active') {
                statusText.textContent = 'System Active';
                statusDot.className = 'status-dot active';
            } else {
                statusText.textContent = 'System Error';
                statusDot.className = 'status-dot';
            }
            
        } catch (error) {
            console.error('Error updating statistics:', error);
        }
    }
    
    // Update charts with new data
    updateCharts(data) {
        try {
            // Update timeline chart
            if (this.charts.timeline && data.hourly_trend) {
                const hours = Array.from({length: 24}, (_, i) => i);
                const counts = new Array(24).fill(0);
                
                data.hourly_trend.forEach(item => {
                    if (item.hour >= 0 && item.hour < 24) {
                        counts[item.hour] = item.count;
                    }
                });
                
                this.charts.timeline.data.datasets[0].data = counts;
                this.charts.timeline.update('none');
            }
            
            // Update attack types chart
            if (this.charts.attackTypes && data.attack_types) {
                const labels = data.attack_types.map(item => item.type);
                const counts = data.attack_types.map(item => item.count);
                
                this.charts.attackTypes.data.labels = labels;
                this.charts.attackTypes.data.datasets[0].data = counts;
                this.charts.attackTypes.update('none');
            }
            
            // Update top attackers chart
            if (this.charts.topAttackers && data.top_attackers) {
                const labels = data.top_attackers.slice(0, 10).map(item => item.ip);
                const counts = data.top_attackers.slice(0, 10).map(item => item.attempts);
                
                this.charts.topAttackers.data.labels = labels;
                this.charts.topAttackers.data.datasets[0].data = counts;
                this.charts.topAttackers.update('none');
            }
            
        } catch (error) {
            console.error('Error updating charts:', error);
        }
    }
    
    // Load blocked IPs
    async loadBlockedIPs() {
        try {
            const response = await fetch('/api/blocked-ips?limit=50');
            if (!response.ok) throw new Error('Failed to fetch blocked IPs');
            
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'API error');
            
            const tbody = document.getElementById('blocked-ips-tbody');
            if (data.data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="loading">No blocked IPs</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.data.map(ip => `
                <tr class="fade-in">
                    <td><strong>${this.escapeHtml(ip.ip_address)}</strong></td>
                    <td>${this.escapeHtml(ip.reason)}</td>
                    <td><span class="badge">${ip.attempts}</span></td>
                    <td>${this.formatDateTime(ip.created_at)}</td>
                    <td><span class="status-${ip.status.toLowerCase()}">${ip.status}</span></td>
                </tr>
            `).join('');
            
        } catch (error) {
            console.error('Error loading blocked IPs:', error);
            const tbody = document.getElementById('blocked-ips-tbody');
            tbody.innerHTML = '<tr><td colspan="5" class="loading">Error loading data</td></tr>';
        }
    }
    
    // Load recent events
    async loadRecentEvents() {
        try {
            const response = await fetch('/api/recent-events?limit=30');
            if (!response.ok) throw new Error('Failed to fetch recent events');
            
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'API error');
            
            const tbody = document.getElementById('recent-events-tbody');
            if (data.data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="loading">No recent events</td></tr>';
                return;
            }
            
            tbody.innerHTML = data.data.map(event => `
                <tr class="fade-in">
                    <td>${this.formatDateTime(event.created_at)}</td>
                    <td><span class="event-type">${this.escapeHtml(event.event_type)}</span></td>
                    <td><strong>${this.escapeHtml(event.ip_address)}</strong></td>
                    <td><span class="severity-${event.severity.toLowerCase()}">${event.severity}</span></td>
                    <td>${this.escapeHtml(event.description)}</td>
                </tr>
            `).join('');
            
        } catch (error) {
            console.error('Error loading recent events:', error);
            const tbody = document.getElementById('recent-events-tbody');
            tbody.innerHTML = '<tr><td colspan="5" class="loading">Error loading data</td></tr>';
        }
    }
    
    // Load attack patterns
    async loadAttackPatterns() {
        try {
            const response = await fetch('/api/attack-patterns');
            if (!response.ok) throw new Error('Failed to fetch attack patterns');
            
            const data = await response.json();
            if (!data.success) throw new Error(data.error || 'API error');
            
            document.getElementById('total-patterns').textContent = this.formatNumber(data.data.total_patterns || 0);
            document.getElementById('total-matches').textContent = this.formatNumber(data.data.total_matches || 0);
            document.getElementById('avg-match-time').textContent = 
                this.formatNumber((data.data.average_match_time || 0) * 1000, 2) + ' ms';
            
        } catch (error) {
            console.error('Error loading attack patterns:', error);
        }
    }
    
    // Start periodic updates
    startPeriodicUpdates() {
        this.updateInterval = setInterval(() => {
            if (!this.isPaused && this.isConnected) {
                this.socket.emit('request_stats');
            }
        }, 10000); // Update every 10 seconds
    }
    
    // Pause updates (when page is hidden)
    pauseUpdates() {
        this.isPaused = true;
        console.log('Dashboard updates paused');
    }
    
    // Resume updates
    resumeUpdates() {
        this.isPaused = false;
        console.log('Dashboard updates resumed');
        
        // Request immediate update
        if (this.isConnected) {
            this.socket.emit('request_stats');
        }
    }
    
    // Update connection status indicator
    updateConnectionStatus(connected) {
        const dot = document.getElementById('connection-dot');
        const status = document.getElementById('connection-status');
        
        if (connected) {
            dot.className = 'connection-dot connected';
            status.textContent = 'Connected';
        } else {
            dot.className = 'connection-dot';
            status.textContent = 'Disconnected';
        }
    }
    
    // Utility functions
    formatNumber(num, decimals = 0) {
        if (num === null || num === undefined) return '--';
        return new Intl.NumberFormat('en-US', {
            minimumFractionDigits: decimals,
            maximumFractionDigits: decimals
        }).format(num);
    }
    
    formatDateTime(timestamp) {
        if (!timestamp) return '--';
        try {
            const date = new Date(timestamp);
            return date.toLocaleString('en-US', {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (error) {
            return '--';
        }
    }
    
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    showError(message) {
        console.error('Dashboard error:', message);
        // Could implement a toast notification system here
    }
    
    // Public methods for button handlers
    async refreshData() {
        console.log('Refreshing dashboard data...');
        await this.loadInitialData();
    }
}

// Global dashboard instance
let dashboard = null;

// Initialize dashboard
function initializeDashboard() {
    dashboard = new RotaryShieldDashboard();
    dashboard.initialize();
}

// Button handlers
function loadBlockedIPs() {
    if (dashboard) {
        dashboard.loadBlockedIPs();
    }
}

function loadRecentEvents() {
    if (dashboard) {
        dashboard.loadRecentEvents();
    }
}

// Page visibility handlers
function pauseUpdates() {
    if (dashboard) {
        dashboard.pauseUpdates();
    }
}

function resumeUpdates() {
    if (dashboard) {
        dashboard.resumeUpdates();
    }
}

// Export for use in HTML
window.initializeDashboard = initializeDashboard;
window.loadBlockedIPs = loadBlockedIPs;
window.loadRecentEvents = loadRecentEvents;
window.pauseUpdates = pauseUpdates;
window.resumeUpdates = resumeUpdates;