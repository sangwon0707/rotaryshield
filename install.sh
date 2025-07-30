#!/bin/bash
#
# RotaryShield Installation Script
# Production-ready installer with comprehensive security hardening
#
# Security Features:
# - Input validation and sanitization for all user inputs
# - Permission checks and privilege validation
# - Comprehensive error handling and rollback capability
# - Security warnings and recommendations
# - Audit logging of installation actions
# - Secure file permissions and ownership
# - Defense against common installation attacks
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/tmp/rotaryshield_install_$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="/tmp/rotaryshield_backup_$(date +%Y%m%d_%H%M%S)"

# Installation paths (following FHS standards)
readonly INSTALL_USER="rotaryshield"
readonly INSTALL_GROUP="rotaryshield"
readonly CONFIG_DIR="/etc/rotaryshield"
readonly DATA_DIR="/var/lib/rotaryshield"
readonly LOG_DIR="/var/log/rotaryshield"
readonly RUN_DIR="/run/rotaryshield"
readonly SERVICE_FILE="/lib/systemd/system/rotaryshield.service"

# Colors for output (disabled if not a terminal)
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly NC='\033[0m' # No Color
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly BLUE=''
    readonly NC=''
fi

# Installation state tracking
INSTALLATION_STEPS_COMPLETED=()
ROLLBACK_REQUIRED=false

# Trap for cleanup on script exit
trap cleanup_on_exit EXIT
trap handle_interrupt INT TERM

#
# Security and logging functions
#

log_message() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    # Sanitize message for security
    local sanitized_message="${message//[^a-zA-Z0-9 ._\/-]/}"
    
    echo "[${timestamp}] [${level}] ${sanitized_message}" | tee -a "${LOG_FILE}"
}

log_info() {
    log_message "INFO" "$1"
    echo -e "${BLUE}INFO:${NC} $1"
}

log_warning() {
    log_message "WARNING" "$1"
    echo -e "${YELLOW}WARNING:${NC} $1" >&2
}

log_error() {
    log_message "ERROR" "$1"
    echo -e "${RED}ERROR:${NC} $1" >&2
}

log_success() {
    log_message "SUCCESS" "$1"
    echo -e "${GREEN}SUCCESS:${NC} $1"
}

# Validate input against dangerous patterns
validate_input() {
    local input="$1"
    local field_name="$2"
    
    # Check for command injection attempts
    if [[ "$input" =~ [\;\&\|\`\$\(\)] ]]; then
        log_error "Invalid characters detected in ${field_name}: ${input}"
        return 1
    fi
    
    # Check for path traversal attempts
    if [[ "$input" =~ \.\./|\.\.\\ ]]; then
        log_error "Path traversal attempt detected in ${field_name}: ${input}"
        return 1
    fi
    
    return 0
}

# Check if running with appropriate privileges
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for system installation"
        log_info "Usage: sudo $0"
        exit 1
    fi
    
    # Warn about root execution
    log_warning "Running as root. Installation will create dedicated user '$INSTALL_USER'"
}

# Validate system requirements
validate_system() {
    log_info "Validating system requirements..."
    
    # Check OS compatibility
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version. This installer supports Linux distributions only."
        exit 1
    fi
    
    # Check for systemd
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is required but not found"
        exit 1
    fi
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not found"
        exit 1
    fi
    
    local python_version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
        log_error "Python 3.8 or higher is required. Found: ${python_version}"
        exit 1
    fi
    
    log_success "System requirements validated (Python ${python_version})"
}

# Create system user and group
create_system_user() {
    log_info "Creating system user and group..."
    
    if getent group "$INSTALL_GROUP" &> /dev/null; then
        log_info "Group '$INSTALL_GROUP' already exists"
    else
        if ! groupadd --system "$INSTALL_GROUP"; then
            log_error "Failed to create group '$INSTALL_GROUP'"
            return 1
        fi
        log_success "Created group '$INSTALL_GROUP'"
    fi
    
    if getent passwd "$INSTALL_USER" &> /dev/null; then
        log_info "User '$INSTALL_USER' already exists"
    else
        if ! useradd --system --gid "$INSTALL_GROUP" --home-dir "$DATA_DIR" \
                     --shell /bin/false --comment "RotaryShield Security Daemon" \
                     "$INSTALL_USER"; then
            log_error "Failed to create user '$INSTALL_USER'"
            return 1
        fi
        log_success "Created user '$INSTALL_USER'"
    fi
    
    INSTALLATION_STEPS_COMPLETED+=("create_system_user")
    return 0
}

# Create directory structure with secure permissions
create_directories() {
    log_info "Creating directory structure..."
    
    local directories=(
        "$CONFIG_DIR:755:root:$INSTALL_GROUP"
        "$DATA_DIR:750:$INSTALL_USER:$INSTALL_GROUP"
        "$LOG_DIR:750:$INSTALL_USER:$INSTALL_GROUP"
        "$RUN_DIR:755:$INSTALL_USER:$INSTALL_GROUP"
    )
    
    for dir_spec in "${directories[@]}"; do
        IFS=':' read -r dir mode owner group <<< "$dir_spec"
        
        if [[ ! -d "$dir" ]]; then
            if ! mkdir -p "$dir"; then
                log_error "Failed to create directory: $dir"
                return 1
            fi
            log_info "Created directory: $dir"
        else
            log_info "Directory already exists: $dir"
        fi
        
        # Set permissions
        if ! chmod "$mode" "$dir"; then
            log_error "Failed to set permissions for: $dir"
            return 1
        fi
        
        # Set ownership
        if ! chown "$owner:$group" "$dir"; then
            log_error "Failed to set ownership for: $dir"
            return 1
        fi
        
        log_success "Configured directory: $dir (${mode}, ${owner}:${group})"
    done
    
    INSTALLATION_STEPS_COMPLETED+=("create_directories")
    return 0
}

# Install Python dependencies
install_dependencies() {
    log_info "Installing Python dependencies..."
    
    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required but not found. Install with: apt-get install python3-pip"
        return 1
    fi
    
    # Install system packages
    local system_packages=(
        "python3-venv"
        "python3-dev"
        "iptables"
        "systemd"
    )
    
    log_info "Installing system packages..."
    for package in "${system_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            log_info "Package already installed: $package"
        else
            log_info "Installing package: $package"
            if ! apt-get update && apt-get install -y "$package"; then
                log_warning "Failed to install package: $package (continuing anyway)"
            fi
        fi
    done
    
    # Install RotaryShield package
    log_info "Installing RotaryShield Python package..."
    if ! pip3 install -e "$SCRIPT_DIR"; then
        log_error "Failed to install RotaryShield package"
        return 1
    fi
    
    log_success "Dependencies installed successfully"
    INSTALLATION_STEPS_COMPLETED+=("install_dependencies")
    return 0
}

# Install configuration files
install_configuration() {
    log_info "Installing configuration files..."
    
    local config_file="$CONFIG_DIR/config.yml"
    local example_config="$SCRIPT_DIR/configs/config.example.yml"
    
    if [[ ! -f "$example_config" ]]; then
        log_error "Example configuration file not found: $example_config"
        return 1
    fi
    
    # Backup existing configuration
    if [[ -f "$config_file" ]]; then
        local backup_file="$BACKUP_DIR/config.yml.backup"
        mkdir -p "$BACKUP_DIR"
        if ! cp "$config_file" "$backup_file"; then
            log_error "Failed to backup existing configuration"
            return 1
        fi
        log_info "Backed up existing configuration to: $backup_file"
    fi
    
    # Install new configuration
    if ! cp "$example_config" "$config_file"; then
        log_error "Failed to install configuration file"
        return 1
    fi
    
    # Set secure permissions
    if ! chmod 640 "$config_file"; then
        log_error "Failed to set configuration file permissions"
        return 1
    fi
    
    if ! chown "root:$INSTALL_GROUP" "$config_file"; then
        log_error "Failed to set configuration file ownership"
        return 1
    fi
    
    log_success "Configuration installed: $config_file"
    INSTALLATION_STEPS_COMPLETED+=("install_configuration")
    return 0
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."
    
    local service_source="$SCRIPT_DIR/systemd/rotaryshield.service"
    
    if [[ ! -f "$service_source" ]]; then
        log_error "Systemd service file not found: $service_source"
        return 1
    fi
    
    # Backup existing service file
    if [[ -f "$SERVICE_FILE" ]]; then
        local backup_file="$BACKUP_DIR/rotaryshield.service.backup"
        mkdir -p "$BACKUP_DIR"
        if ! cp "$SERVICE_FILE" "$backup_file"; then
            log_error "Failed to backup existing service file"
            return 1
        fi
        log_info "Backed up existing service file to: $backup_file"
    fi
    
    # Install service file
    if ! cp "$service_source" "$SERVICE_FILE"; then
        log_error "Failed to install systemd service file"
        return 1
    fi
    
    # Set permissions
    if ! chmod 644 "$SERVICE_FILE"; then
        log_error "Failed to set service file permissions"
        return 1
    fi
    
    if ! chown root:root "$SERVICE_FILE"; then
        log_error "Failed to set service file ownership"
        return 1
    fi
    
    # Reload systemd
    if ! systemctl daemon-reload; then
        log_error "Failed to reload systemd daemon"
        return 1
    fi
    
    log_success "Systemd service installed: $SERVICE_FILE"
    INSTALLATION_STEPS_COMPLETED+=("install_systemd_service")
    return 0
}

# Test configuration
test_configuration() {
    log_info "Testing configuration..."
    
    # Test using the installed CLI
    if command -v rotaryshield-config &> /dev/null; then
        if rotaryshield-config "$CONFIG_DIR/config.yml"; then
            log_success "Configuration test passed"
        else
            log_warning "Configuration test failed - please review $CONFIG_DIR/config.yml"
        fi
    else
        log_warning "CLI tools not available yet - skipping configuration test"
    fi
    
    INSTALLATION_STEPS_COMPLETED+=("test_configuration")
    return 0
}

# Show post-installation information
show_post_install_info() {
    echo
    echo "======================================================================"
    echo "                    RotaryShield Installation Complete"
    echo "======================================================================"
    echo
    echo "Installation Summary:"
    echo "  - User created: $INSTALL_USER"
    echo "  - Configuration: $CONFIG_DIR/config.yml"
    echo "  - Log directory: $LOG_DIR"
    echo "  - Data directory: $DATA_DIR"
    echo "  - Service file: $SERVICE_FILE"
    echo
    echo "Next Steps:"
    echo "  1. Review and customize configuration:"
    echo "     sudo nano $CONFIG_DIR/config.yml"
    echo
    echo "  2. Test configuration:"
    echo "     rotaryshield-config"
    echo
    echo "  3. Enable and start service:"
    echo "     sudo systemctl enable rotaryshield"
    echo "     sudo systemctl start rotaryshield"
    echo
    echo "  4. Check service status:"
    echo "     rotaryshield-status"
    echo
    echo "Available Commands:"
    echo "  - rotaryshield          # Main daemon (usually run via systemd)"
    echo "  - rotaryshield-status   # Check service status"
    echo "  - rotaryshield-config   # Test configuration"
    echo "  - rotaryshield-control  # Start/stop/restart service"
    echo
    echo "Documentation:"
    echo "  - Configuration file: $CONFIG_DIR/config.yml"
    echo "  - Log files: $LOG_DIR/"
    echo "  - Installation log: $LOG_FILE"
    if [[ -d "$BACKUP_DIR" ]]; then
        echo "  - Backup files: $BACKUP_DIR/"
    fi
    echo
    echo "Security Recommendations:"
    echo "  - Review firewall rules after configuration"
    echo "  - Monitor logs in $LOG_DIR/"
    echo "  - Keep configuration file secure (640 permissions)"
    echo "  - Regularly update RotaryShield for security patches"
    echo
    echo "======================================================================"
}

# Cleanup function
cleanup_on_exit() {
    if [[ "$ROLLBACK_REQUIRED" == true ]]; then
        log_warning "Installation failed, attempting rollback..."
        perform_rollback
    fi
}

# Handle interruption signals
handle_interrupt() {
    log_warning "Installation interrupted by user"
    ROLLBACK_REQUIRED=true
    exit 130
}

# Perform rollback of installation steps
perform_rollback() {
    log_info "Performing installation rollback..."
    
    # Reverse order of completed steps
    for ((i=${#INSTALLATION_STEPS_COMPLETED[@]}-1; i>=0; i--)); do
        local step="${INSTALLATION_STEPS_COMPLETED[i]}"
        case "$step" in
            "install_systemd_service")
                log_info "Rolling back systemd service..."
                systemctl stop rotaryshield 2>/dev/null || true
                systemctl disable rotaryshield 2>/dev/null || true
                rm -f "$SERVICE_FILE"
                systemctl daemon-reload 2>/dev/null || true
                ;;
            "install_configuration")
                log_info "Rolling back configuration..."
                rm -f "$CONFIG_DIR/config.yml"
                ;;
            "create_directories")
                log_info "Rolling back directories..."
                rm -rf "$DATA_DIR" "$LOG_DIR" "$RUN_DIR" 2>/dev/null || true
                ;;
            "create_system_user")
                log_info "Rolling back system user..."
                userdel "$INSTALL_USER" 2>/dev/null || true
                groupdel "$INSTALL_GROUP" 2>/dev/null || true
                ;;
        esac
    done
    
    log_info "Rollback completed"
}

# Main installation function
main() {
    log_info "Starting RotaryShield installation..."
    log_info "Installation log: $LOG_FILE"
    
    # Initial security checks
    check_privileges
    validate_system
    
    # Confirm installation
    echo
    echo -e "${YELLOW}This will install RotaryShield security system on your server.${NC}"
    echo -e "${YELLOW}The installation will create system user '$INSTALL_USER' and modify system configuration.${NC}"
    echo
    read -p "Do you want to continue? [y/N]: " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installation cancelled by user"
        exit 0
    fi
    
    # Validate user input
    if ! validate_input "$REPLY" "user_confirmation"; then
        log_error "Invalid input detected"
        exit 1
    fi
    
    # Perform installation steps
    local steps=(
        "create_system_user"
        "create_directories"
        "install_dependencies"
        "install_configuration"
        "install_systemd_service"
        "test_configuration"
    )
    
    for step in "${steps[@]}"; do
        log_info "Executing step: $step"
        if ! "$step"; then
            log_error "Installation step failed: $step"
            ROLLBACK_REQUIRED=true
            exit 1
        fi
    done
    
    # Show completion information
    show_post_install_info
    log_success "RotaryShield installation completed successfully!"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi