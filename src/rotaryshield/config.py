#!/usr/bin/env python3
"""
RotaryShield Configuration Management System
Secure configuration loading and validation with enterprise-grade security measures.

Security Features:
- Input validation and sanitization
- File permission verification
- Path traversal protection
- Configuration integrity checks
- Secure default values
"""

import os
import stat
import yaml
import logging
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import re


class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""
    pass


class SecurityError(Exception):
    """Custom exception for security-related configuration issues."""
    pass


@dataclass
class DetectionConfig:
    """Detection layer configuration with validation."""
    max_retry: int = 5
    ban_threshold: int = 10
    time_window: int = 600
    log_files: List[str] = field(default_factory=lambda: [
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/httpd/access_log',
        '/var/log/nginx/access.log'
    ])
    patterns: Dict[str, str] = field(default_factory=lambda: {
        'ssh_failed': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
        'ssh_invalid': r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)',
        'http_brute': r'(\d+\.\d+\.\d+\.\d+).*POST.*login.*40[13]',
        'ftp_failed': r'FAIL LOGIN.*from (\d+\.\d+\.\d+\.\d+)'
    })
    
    def validate(self) -> None:
        """Validate detection configuration parameters."""
        if not isinstance(self.max_retry, int) or self.max_retry < 1 or self.max_retry > 100:
            raise ConfigurationError("max_retry must be an integer between 1 and 100")
        
        if not isinstance(self.ban_threshold, int) or self.ban_threshold < 1 or self.ban_threshold > 1000:
            raise ConfigurationError("ban_threshold must be an integer between 1 and 1000")
        
        if not isinstance(self.time_window, int) or self.time_window < 60 or self.time_window > 86400:
            raise ConfigurationError("time_window must be an integer between 60 and 86400 seconds")
        
        # Validate log file paths for security
        for log_file in self.log_files:
            if not self._is_safe_path(log_file):
                raise SecurityError(f"Unsafe log file path detected: {log_file}")
        
        # Validate regex patterns
        for name, pattern in self.patterns.items():
            try:
                re.compile(pattern)
            except re.error as e:
                raise ConfigurationError(f"Invalid regex pattern '{name}': {e}")
    
    def _is_safe_path(self, path: str) -> bool:
        """Check if path is safe from traversal attacks."""
        # Normalize path and check for traversal attempts
        normalized = os.path.normpath(path)
        if '..' in normalized or normalized.startswith('/..'):
            return False
        
        # Only allow absolute paths in specific directories
        allowed_dirs = ['/var/log', '/opt/rotaryshield/logs', '/tmp/rotaryshield']
        return any(normalized.startswith(allowed_dir) for allowed_dir in allowed_dirs)


@dataclass
class ThrottlingConfig:
    """Throttling layer configuration with validation."""
    ssh_delay: float = 1.0
    http_rate_limit: int = 10
    http_rate_window: int = 60
    max_connections: int = 100
    enable_captcha: bool = False
    
    def validate(self) -> None:
        """Validate throttling configuration parameters."""
        if not isinstance(self.ssh_delay, (int, float)) or self.ssh_delay < 0 or self.ssh_delay > 10:
            raise ConfigurationError("ssh_delay must be a number between 0 and 10 seconds")
        
        if not isinstance(self.http_rate_limit, int) or self.http_rate_limit < 1 or self.http_rate_limit > 1000:
            raise ConfigurationError("http_rate_limit must be an integer between 1 and 1000")
        
        if not isinstance(self.http_rate_window, int) or self.http_rate_window < 1 or self.http_rate_window > 3600:
            raise ConfigurationError("http_rate_window must be an integer between 1 and 3600 seconds")
        
        if not isinstance(self.max_connections, int) or self.max_connections < 1 or self.max_connections > 10000:
            raise ConfigurationError("max_connections must be an integer between 1 and 10000")


@dataclass
class BanConfig:
    """Ban layer configuration with validation."""
    ban_time: int = 3600
    max_ban_time: int = 86400
    escalation_factor: float = 2.0
    enable_honeypot: bool = False
    honeypot_port: int = 2222
    notification: bool = True
    whitelist_ips: List[str] = field(default_factory=lambda: ['127.0.0.1', '::1'])
    firewall_backend: str = 'iptables'
    
    def validate(self) -> None:
        """Validate ban configuration parameters."""
        if not isinstance(self.ban_time, int) or self.ban_time < 60 or self.ban_time > 604800:
            raise ConfigurationError("ban_time must be an integer between 60 and 604800 seconds")
        
        if not isinstance(self.max_ban_time, int) or self.max_ban_time < self.ban_time:
            raise ConfigurationError("max_ban_time must be greater than or equal to ban_time")
        
        if not isinstance(self.escalation_factor, (int, float)) or self.escalation_factor < 1 or self.escalation_factor > 10:
            raise ConfigurationError("escalation_factor must be a number between 1 and 10")
        
        if not isinstance(self.honeypot_port, int) or self.honeypot_port < 1024 or self.honeypot_port > 65535:
            raise ConfigurationError("honeypot_port must be an integer between 1024 and 65535")
        
        if self.firewall_backend not in ['iptables', 'firewalld', 'ufw']:
            raise ConfigurationError("firewall_backend must be one of: iptables, firewalld, ufw")
        
        # Validate whitelist IPs
        for ip in self.whitelist_ips:
            if not self._is_valid_ip(ip):
                raise ConfigurationError(f"Invalid IP address in whitelist: {ip}")
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


@dataclass
class DatabaseConfig:
    """Database configuration with security validation."""
    db_path: str = '/var/lib/rotaryshield/rotaryshield.db'
    backup_enabled: bool = True
    backup_interval: int = 3600
    max_backup_files: int = 10
    vacuum_interval: int = 86400
    
    def validate(self) -> None:
        """Validate database configuration parameters."""
        # Validate database path
        if not self._is_safe_db_path(self.db_path):
            raise SecurityError(f"Unsafe database path: {self.db_path}")
        
        if not isinstance(self.backup_interval, int) or self.backup_interval < 300:
            raise ConfigurationError("backup_interval must be at least 300 seconds")
        
        if not isinstance(self.max_backup_files, int) or self.max_backup_files < 1 or self.max_backup_files > 100:
            raise ConfigurationError("max_backup_files must be between 1 and 100")
    
    def _is_safe_db_path(self, path: str) -> bool:
        """Check if database path is secure."""
        normalized = os.path.normpath(path)
        if '..' in normalized:
            return False
        
        allowed_dirs = ['/var/lib/rotaryshield', '/opt/rotaryshield/data', '/tmp/rotaryshield']
        return any(normalized.startswith(allowed_dir) for allowed_dir in allowed_dirs)


@dataclass
class NotificationConfig:
    """Notification system configuration."""
    email_enabled: bool = False
    email_smtp_server: str = ''
    email_smtp_port: int = 587
    email_username: str = ''
    email_password: str = ''
    email_recipients: List[str] = field(default_factory=list)
    email_use_tls: bool = True
    
    slack_enabled: bool = False
    slack_webhook_url: str = ''
    
    def validate(self) -> None:
        """Validate notification configuration."""
        if self.email_enabled:
            if not self.email_smtp_server or not self.email_username:
                raise ConfigurationError("Email notifications require smtp_server and username")
            
            if not isinstance(self.email_smtp_port, int) or self.email_smtp_port < 1 or self.email_smtp_port > 65535:
                raise ConfigurationError("email_smtp_port must be between 1 and 65535")
            
            for email in self.email_recipients:
                if not self._is_valid_email(email):
                    raise ConfigurationError(f"Invalid email address: {email}")
        
        if self.slack_enabled:
            if not self.slack_webhook_url or not self.slack_webhook_url.startswith('https://'):
                raise ConfigurationError("Slack webhook URL must be a valid HTTPS URL")
    
    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None


@dataclass
class RotaryShieldConfig:
    """Main RotaryShield configuration."""
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    throttling: ThrottlingConfig = field(default_factory=ThrottlingConfig)
    ban: BanConfig = field(default_factory=BanConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    notification: NotificationConfig = field(default_factory=NotificationConfig)
    
    # Global settings
    log_level: str = 'INFO'
    log_file: str = '/var/log/rotaryshield/rotaryshield.log'
    pid_file: str = '/var/run/rotaryshield/rotaryshield.pid'
    daemon_mode: bool = True
    user: str = 'rotaryshield'
    group: str = 'rotaryshield'
    
    def validate(self) -> None:
        """Validate all configuration sections."""
        # Validate all subsections
        self.detection.validate()
        self.throttling.validate()
        self.ban.validate()
        self.database.validate()
        self.notification.validate()
        
        # Validate global settings
        if self.log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ConfigurationError("log_level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")
        
        # Validate file paths
        for path_attr in ['log_file', 'pid_file']:
            path = getattr(self, path_attr)
            if not self._is_safe_path(path):
                raise SecurityError(f"Unsafe path for {path_attr}: {path}")
    
    def _is_safe_path(self, path: str) -> bool:
        """Check if path is safe from traversal attacks."""
        normalized = os.path.normpath(path)
        if '..' in normalized:
            return False
        
        allowed_dirs = ['/var/log', '/var/run', '/opt/rotaryshield', '/tmp/rotaryshield']
        return any(normalized.startswith(allowed_dir) for allowed_dir in allowed_dirs)


class ConfigManager:
    """Secure configuration manager with validation and integrity checks."""
    
    def __init__(self, config_path: str = '/etc/rotaryshield/config.yml'):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self._config: Optional[RotaryShieldConfig] = None
        self._config_hash: Optional[str] = None
    
    def load_config(self) -> RotaryShieldConfig:
        """Load and validate configuration from file."""
        try:
            # Security checks on config file
            self._verify_config_file_security()
            
            # Load configuration
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            if not isinstance(config_data, dict):
                raise ConfigurationError("Configuration file must contain a YAML dictionary")
            
            # Calculate configuration hash for integrity monitoring
            config_content = Path(self.config_path).read_text()
            self._config_hash = hashlib.sha256(config_content.encode()).hexdigest()
            
            # Build configuration object
            self._config = self._build_config(config_data)
            
            # Validate complete configuration
            self._config.validate()
            
            self.logger.info(f"Configuration loaded successfully from {self.config_path}")
            return self._config
            
        except FileNotFoundError:
            self.logger.warning(f"Configuration file not found: {self.config_path}, using defaults")
            self._config = RotaryShieldConfig()
            self._config.validate()
            return self._config
            
        except (yaml.YAMLError, ConfigurationError, SecurityError) as e:
            self.logger.error(f"Configuration error: {e}")
            raise
        
        except Exception as e:
            self.logger.error(f"Unexpected error loading configuration: {e}")
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def _verify_config_file_security(self) -> None:
        """Verify configuration file has secure permissions."""
        if not os.path.exists(self.config_path):
            return
        
        stat_info = os.stat(self.config_path)
        
        # Check file permissions (should be 600 or 640)
        mode = stat_info.st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO) & ~(stat.S_IRGRP):
            raise SecurityError(f"Configuration file {self.config_path} has insecure permissions")
        
        # Check ownership (should be owned by root or rotaryshield user)
        if stat_info.st_uid != 0:  # Not root
            import pwd
            try:
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
                if owner != 'rotaryshield':
                    self.logger.warning(f"Configuration file owned by {owner}, expected root or rotaryshield")
            except KeyError:
                raise SecurityError(f"Configuration file owned by unknown UID {stat_info.st_uid}")
    
    def _build_config(self, config_data: Dict[str, Any]) -> RotaryShieldConfig:
        """Build configuration object from dictionary data."""
        config = RotaryShieldConfig()
        
        # Detection configuration
        if 'detection' in config_data:
            detection_data = config_data['detection']
            config.detection = DetectionConfig(
                max_retry=detection_data.get('max_retry', config.detection.max_retry),
                ban_threshold=detection_data.get('ban_threshold', config.detection.ban_threshold),
                time_window=detection_data.get('time_window', config.detection.time_window),
                log_files=detection_data.get('log_files', config.detection.log_files),
                patterns=detection_data.get('patterns', config.detection.patterns)
            )
        
        # Throttling configuration
        if 'throttling' in config_data:
            throttling_data = config_data['throttling']
            config.throttling = ThrottlingConfig(
                ssh_delay=throttling_data.get('ssh_delay', config.throttling.ssh_delay),
                http_rate_limit=throttling_data.get('http_rate_limit', config.throttling.http_rate_limit),
                http_rate_window=throttling_data.get('http_rate_window', config.throttling.http_rate_window),
                max_connections=throttling_data.get('max_connections', config.throttling.max_connections),
                enable_captcha=throttling_data.get('enable_captcha', config.throttling.enable_captcha)
            )
        
        # Ban configuration
        if 'ban' in config_data:
            ban_data = config_data['ban']
            config.ban = BanConfig(
                ban_time=ban_data.get('ban_time', config.ban.ban_time),
                max_ban_time=ban_data.get('max_ban_time', config.ban.max_ban_time),
                escalation_factor=ban_data.get('escalation_factor', config.ban.escalation_factor),
                enable_honeypot=ban_data.get('enable_honeypot', config.ban.enable_honeypot),
                honeypot_port=ban_data.get('honeypot_port', config.ban.honeypot_port),
                notification=ban_data.get('notification', config.ban.notification),
                whitelist_ips=ban_data.get('whitelist_ips', config.ban.whitelist_ips),
                firewall_backend=ban_data.get('firewall_backend', config.ban.firewall_backend)
            )
        
        # Database configuration
        if 'database' in config_data:
            db_data = config_data['database']
            config.database = DatabaseConfig(
                db_path=db_data.get('db_path', config.database.db_path),
                backup_enabled=db_data.get('backup_enabled', config.database.backup_enabled),
                backup_interval=db_data.get('backup_interval', config.database.backup_interval),
                max_backup_files=db_data.get('max_backup_files', config.database.max_backup_files),
                vacuum_interval=db_data.get('vacuum_interval', config.database.vacuum_interval)
            )
        
        # Notification configuration
        if 'notification' in config_data:
            notif_data = config_data['notification']
            config.notification = NotificationConfig(
                email_enabled=notif_data.get('email_enabled', config.notification.email_enabled),
                email_smtp_server=notif_data.get('email_smtp_server', config.notification.email_smtp_server),
                email_smtp_port=notif_data.get('email_smtp_port', config.notification.email_smtp_port),
                email_username=notif_data.get('email_username', config.notification.email_username),
                email_password=notif_data.get('email_password', config.notification.email_password),
                email_recipients=notif_data.get('email_recipients', config.notification.email_recipients),
                email_use_tls=notif_data.get('email_use_tls', config.notification.email_use_tls),
                slack_enabled=notif_data.get('slack_enabled', config.notification.slack_enabled),
                slack_webhook_url=notif_data.get('slack_webhook_url', config.notification.slack_webhook_url)
            )
        
        # Global settings
        config.log_level = config_data.get('log_level', config.log_level)
        config.log_file = config_data.get('log_file', config.log_file)
        config.pid_file = config_data.get('pid_file', config.pid_file)
        config.daemon_mode = config_data.get('daemon_mode', config.daemon_mode)
        config.user = config_data.get('user', config.user)
        config.group = config_data.get('group', config.group)
        
        return config
    
    def save_config(self, config: RotaryShieldConfig) -> None:
        """Save configuration to file with secure permissions."""
        try:
            # Create directory if it doesn't exist
            config_dir = os.path.dirname(self.config_path)
            os.makedirs(config_dir, mode=0o755, exist_ok=True)
            
            # Convert config to dictionary
            config_dict = self._config_to_dict(config)
            
            # Write configuration with secure permissions
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2, sort_keys=True)
            
            # Set secure file permissions
            os.chmod(self.config_path, 0o600)
            
            self.logger.info(f"Configuration saved to {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def _config_to_dict(self, config: RotaryShieldConfig) -> Dict[str, Any]:
        """Convert configuration object to dictionary."""
        return {
            'detection': {
                'max_retry': config.detection.max_retry,
                'ban_threshold': config.detection.ban_threshold,
                'time_window': config.detection.time_window,
                'log_files': config.detection.log_files,
                'patterns': config.detection.patterns
            },
            'throttling': {
                'ssh_delay': config.throttling.ssh_delay,
                'http_rate_limit': config.throttling.http_rate_limit,
                'http_rate_window': config.throttling.http_rate_window,
                'max_connections': config.throttling.max_connections,
                'enable_captcha': config.throttling.enable_captcha
            },
            'ban': {
                'ban_time': config.ban.ban_time,
                'max_ban_time': config.ban.max_ban_time,
                'escalation_factor': config.ban.escalation_factor,
                'enable_honeypot': config.ban.enable_honeypot,
                'honeypot_port': config.ban.honeypot_port,
                'notification': config.ban.notification,
                'whitelist_ips': config.ban.whitelist_ips,
                'firewall_backend': config.ban.firewall_backend
            },
            'database': {
                'db_path': config.database.db_path,
                'backup_enabled': config.database.backup_enabled,
                'backup_interval': config.database.backup_interval,
                'max_backup_files': config.database.max_backup_files,
                'vacuum_interval': config.database.vacuum_interval
            },
            'notification': {
                'email_enabled': config.notification.email_enabled,
                'email_smtp_server': config.notification.email_smtp_server,
                'email_smtp_port': config.notification.email_smtp_port,
                'email_username': config.notification.email_username,
                'email_password': config.notification.email_password,
                'email_recipients': config.notification.email_recipients,
                'email_use_tls': config.notification.email_use_tls,
                'slack_enabled': config.notification.slack_enabled,
                'slack_webhook_url': config.notification.slack_webhook_url
            },
            'log_level': config.log_level,
            'log_file': config.log_file,
            'pid_file': config.pid_file,
            'daemon_mode': config.daemon_mode,
            'user': config.user,
            'group': config.group
        }
    
    def check_config_integrity(self) -> bool:
        """Check if configuration file has been modified."""
        if not self._config_hash or not os.path.exists(self.config_path):
            return False
        
        try:
            current_content = Path(self.config_path).read_text()
            current_hash = hashlib.sha256(current_content.encode()).hexdigest()
            return current_hash == self._config_hash
        except Exception:
            return False
    
    def get_config(self) -> RotaryShieldConfig:
        """Get current configuration, loading if necessary."""
        if self._config is None:
            return self.load_config()
        return self._config


# Global configuration manager instance
config_manager = ConfigManager()