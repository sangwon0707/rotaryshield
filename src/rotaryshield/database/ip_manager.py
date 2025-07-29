#!/usr/bin/env python3
"""
RotaryShield IP Manager
High-performance IP ban management with SQLite persistence.

Security Features:
- IP address validation and normalization
- SQL injection prevention through parameterized queries
- Thread-safe operations for concurrent access
- Comprehensive audit logging
- Performance optimization for 100,000+ IPs
- Automatic cleanup of expired bans
"""

import time
import threading
import logging
import ipaddress
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
import json

from .manager import DatabaseManager
from .models import IPBanRecord, AuditLogRecord, BanStatus, AuditAction


@dataclass
class IPStatistics:
    """Statistics for IP management operations."""
    total_bans: int = 0
    active_bans: int = 0
    expired_bans: int = 0
    manually_removed_bans: int = 0
    unique_ips_banned: int = 0
    total_ban_time: float = 0.0
    average_ban_duration: float = 0.0
    most_banned_ips: List[Tuple[str, int]] = None
    
    def __post_init__(self):
        if self.most_banned_ips is None:
            self.most_banned_ips = []


class IPManagerError(Exception):
    """Exception for IP manager errors."""
    pass


class IPManager:
    """
    High-performance IP ban management system.
    
    This class provides efficient management of IP bans with SQLite persistence,
    supporting large numbers of banned IPs with automatic cleanup and
    comprehensive audit logging.
    """
    
    def __init__(self, database_manager: DatabaseManager):
        """
        Initialize IP manager.
        
        Args:
            database_manager: Database manager instance
        """
        self.db_manager = database_manager
        self.logger = logging.getLogger(__name__)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Cache for active bans (for performance)
        self._active_bans_cache: Dict[str, IPBanRecord] = {}
        self._cache_last_update = 0.0
        self._cache_ttl = 300  # 5 minutes
        
        # Statistics
        self._operations_count = 0
        self._cache_hits = 0
        self._cache_misses = 0
        
        # Background cleanup
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_interval = 3600  # 1 hourly
        self._stop_cleanup = threading.Event()
        
        self.logger.info("IPManager initialized")
    
    def start_background_cleanup(self) -> None:
        """Start background cleanup thread for expired bans."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        self._stop_cleanup.clear()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="ip-manager-cleanup",
            daemon=True
        )
        self._cleanup_thread.start()
        self.logger.info("Background cleanup thread started")
    
    def stop_background_cleanup(self) -> None:
        """Stop background cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=5)
            self.logger.info("Background cleanup thread stopped")
    
    def _cleanup_loop(self) -> None:
        """Background cleanup loop for expired bans."""
        while not self._stop_cleanup.is_set():
            try:
                self.cleanup_expired_bans()
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
            
            # Wait for next cleanup or stop signal
            self._stop_cleanup.wait(self._cleanup_interval)
    
    def ban_ip(self, ip_address: str, ban_duration: int, reason: str, 
               offense_type: str = "", created_by: str = "rotaryshield") -> bool:
        """
        Ban an IP address with comprehensive validation and logging.
        
        Args:
            ip_address: IP address to ban
            ban_duration: Ban duration in seconds
            reason: Reason for the ban
            offense_type: Type of offense (e.g., "ssh_brute_force")
            created_by: System/user that created the ban
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            try:
                # Validate IP address
                normalized_ip = self._validate_ip_address(ip_address)
                
                # Validate ban duration
                if ban_duration <= 0 or ban_duration > 31536000:  # Max 1 year
                    raise IPManagerError(f"Invalid ban duration: {ban_duration}")
                
                # Check if IP is already banned
                existing_ban = self.get_ban_record(normalized_ip)
                if existing_ban and existing_ban.is_active():
                    # Extend existing ban if it's active
                    return self._extend_existing_ban(existing_ban, ban_duration, reason)
                
                # Create new ban record
                current_time = time.time()
                ban_record = IPBanRecord(
                    ip_address=normalized_ip,
                    ban_reason=reason,
                    ban_duration=ban_duration,
                    created_at=current_time,
                    expires_at=current_time + ban_duration,
                    updated_at=current_time,
                    status=BanStatus.ACTIVE,
                    ban_count=1 if not existing_ban else existing_ban.ban_count + 1,
                    last_offense_type=offense_type,
                    created_by=created_by
                )
                
                # Insert into database
                success = self._insert_ban_record(ban_record)
                
                if success:
                    # Update cache
                    self._active_bans_cache[normalized_ip] = ban_record
                    
                    # Log audit record
                    self._log_audit_action(
                        action=AuditAction.IP_BANNED,
                        ip_address=normalized_ip,
                        description=f"IP banned: {reason}",
                        details=json.dumps({
                            "ban_duration": ban_duration,
                            "offense_type": offense_type,
                            "ban_count": ban_record.ban_count
                        }),
                        user_id=created_by
                    )
                    
                    self.logger.info(
                        f"IP banned successfully: {normalized_ip} "
                        f"(duration: {ban_duration}s, reason: {reason})"
                    )
                    
                    self._operations_count += 1
                    return True
                else:
                    self.logger.error(f"Failed to insert ban record for IP: {normalized_ip}")
                    return False
                
            except Exception as e:
                self.logger.error(f"Error banning IP {ip_address}: {e}")
                return False
    
    def _extend_existing_ban(self, existing_ban: IPBanRecord, additional_duration: int, reason: str) -> bool:
        """Extend existing ban duration."""
        try:
            # Calculate new expiration time
            new_expires_at = max(existing_ban.expires_at, time.time()) + additional_duration
            
            # Update ban record
            update_query = '''
                UPDATE ip_bans 
                SET expires_at = ?, 
                    updated_at = ?, 
                    ban_reason = ?,
                    ban_count = ban_count + 1,
                    status = 'active'
                WHERE ip_address = ? AND id = ?
            '''
            
            current_time = time.time()
            params = (new_expires_at, current_time, f"{existing_ban.ban_reason} | Extended: {reason}",
                     existing_ban.ip_address, existing_ban.id)
            
            result = self.db_manager.execute_query(update_query, params)
            
            if result and result > 0:
                # Update cache
                existing_ban.expires_at = new_expires_at
                existing_ban.updated_at = current_time
                existing_ban.ban_reason = f"{existing_ban.ban_reason} | Extended: {reason}"
                existing_ban.ban_count += 1
                existing_ban.status = BanStatus.ACTIVE
                
                self._active_bans_cache[existing_ban.ip_address] = existing_ban
                
                self.logger.info(f"Extended ban for IP {existing_ban.ip_address} by {additional_duration}s")
                return True
            else:
                self.logger.error(f"Failed to extend ban for IP: {existing_ban.ip_address}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error extending ban for IP {existing_ban.ip_address}: {e}")
            return False
    
    def unban_ip(self, ip_address: str, reason: str = "Manual unban", 
                 removed_by: str = "rotaryshield") -> bool:
        """
        Unban an IP address.
        
        Args:
            ip_address: IP address to unban
            reason: Reason for unbanning
            removed_by: System/user that removed the ban
            
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            try:
                # Validate IP address
                normalized_ip = self._validate_ip_address(ip_address)
                
                # Get existing ban record
                ban_record = self.get_ban_record(normalized_ip)
                if not ban_record:
                    self.logger.warning(f"No ban record found for IP: {normalized_ip}")
                    return True  # Consider it successful if already not banned
                
                if not ban_record.is_active():
                    self.logger.info(f"IP {normalized_ip} is already not active")
                    return True
                
                # Update ban record to manually removed
                update_query = '''
                    UPDATE ip_bans 
                    SET status = 'manually_removed',
                        updated_at = ?,
                        removed_reason = ?
                    WHERE ip_address = ? AND status = 'active'
                '''
                
                current_time = time.time()
                params = (current_time, reason, normalized_ip)
                
                result = self.db_manager.execute_query(update_query, params)
                
                if result and result > 0:
                    # Remove from cache
                    self._active_bans_cache.pop(normalized_ip, None)
                    
                    # Log audit record
                    self._log_audit_action(
                        action=AuditAction.IP_UNBANNED,
                        ip_address=normalized_ip,
                        description=f"IP unbanned: {reason}",
                        details=json.dumps({"removed_reason": reason}),
                        user_id=removed_by
                    )
                    
                    self.logger.info(f"IP unbanned successfully: {normalized_ip} (reason: {reason})")
                    self._operations_count += 1
                    return True
                else:
                    self.logger.error(f"Failed to unban IP: {normalized_ip}")
                    return False
                
            except Exception as e:
                self.logger.error(f"Error unbanning IP {ip_address}: {e}")
                return False
    
    def is_banned(self, ip_address: str) -> bool:
        """
        Check if an IP address is currently banned.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if banned, False otherwise
        """
        try:
            # Validate IP address
            normalized_ip = self._validate_ip_address(ip_address)
            
            # Check cache first
            if normalized_ip in self._active_bans_cache:
                ban_record = self._active_bans_cache[normalized_ip]
                if ban_record.is_active():
                    self._cache_hits += 1
                    return True
                else:
                    # Remove expired record from cache
                    self._active_bans_cache.pop(normalized_ip, None)
            
            # Check database
            ban_record = self.get_ban_record(normalized_ip)
            self._cache_misses += 1
            
            if ban_record and ban_record.is_active():
                # Update cache
                self._active_bans_cache[normalized_ip] = ban_record
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking if IP {ip_address} is banned: {e}")
            return False  # Fail open for security
    
    def get_ban_record(self, ip_address: str) -> Optional[IPBanRecord]:
        """
        Get ban record for an IP address.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            IPBanRecord if found, None otherwise
        """
        try:
            # Validate IP address
            normalized_ip = self._validate_ip_address(ip_address)
            
            # Query database for most recent ban record
            query = '''
                SELECT * FROM ip_bans 
                WHERE ip_address = ? 
                ORDER BY created_at DESC 
                LIMIT 1
            '''
            
            row = self.db_manager.execute_query(query, (normalized_ip,))
            
            if row:
                return self._row_to_ban_record(row)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting ban record for IP {ip_address}: {e}")
            return None
    
    def get_active_bans(self) -> List[str]:
        """
        Get list of all currently active banned IP addresses.
        
        Returns:
            List of banned IP addresses
        """
        try:
            query = '''
                SELECT ip_address FROM ip_bans 
                WHERE status = 'active' AND expires_at > ?
                ORDER BY created_at DESC
            '''
            
            current_time = time.time()
            rows = self.db_manager.execute_query(query, (current_time,), fetch_all=True)
            
            if rows:
                return [row['ip_address'] for row in rows]
            
            return []
            
        except Exception as e:
            self.logger.error(f"Error getting active bans: {e}")
            return []
    
    def get_ban_history(self, ip_address: Optional[str] = None, limit: int = 100) -> List[IPBanRecord]:
        """
        Get ban history records.
        
        Args:
            ip_address: Specific IP to get history for, or None for all
            limit: Maximum number of records to return
            
        Returns:
            List of ban records
        """
        try:
            if ip_address:
                # Validate IP address
                normalized_ip = self._validate_ip_address(ip_address)
                
                query = '''
                    SELECT * FROM ip_bans 
                    WHERE ip_address = ? 
                    ORDER BY created_at DESC 
                    LIMIT ?
                '''
                params = (normalized_ip, limit)
            else:
                query = '''
                    SELECT * FROM ip_bans 
                    ORDER BY created_at DESC 
                    LIMIT ?
                '''
                params = (limit,)
            
            rows = self.db_manager.execute_query(query, params, fetch_all=True)
            
            if rows:
                return [self._row_to_ban_record(row) for row in rows]
            
            return []
            
        except Exception as e:
            self.logger.error(f"Error getting ban history: {e}")
            return []
    
    def cleanup_expired_bans(self, max_cleanup: int = 1000) -> int:
        """
        Clean up expired ban records by marking them as expired.
        
        Args:
            max_cleanup: Maximum number of records to update in one operation
            
        Returns:
            Number of records cleaned up
        """
        try:
            current_time = time.time()
            
            # Update expired bans
            update_query = '''
                UPDATE ip_bans 
                SET status = 'expired', updated_at = ?
                WHERE status = 'active' AND expires_at <= ?
                LIMIT ?
            '''
            
            result = self.db_manager.execute_query(
                update_query, 
                (current_time, current_time, max_cleanup)
            )
            
            cleanup_count = result if result else 0
            
            if cleanup_count > 0:
                # Clear cache to force refresh
                self._active_bans_cache.clear()
                self._cache_last_update = 0
                
                self.logger.info(f"Cleaned up {cleanup_count} expired ban records")
            
            return cleanup_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up expired bans: {e}")
            return 0
    
    def get_statistics(self) -> IPStatistics:
        """
        Get comprehensive IP management statistics.
        
        Returns:
            IPStatistics object with current statistics
        """
        try:
            # Get basic counts
            stats_query = '''
                SELECT 
                    status,
                    COUNT(*) as count,
                    AVG(ban_duration) as avg_duration
                FROM ip_bans 
                GROUP BY status
            '''
            
            rows = self.db_manager.execute_query(stats_query, fetch_all=True)
            
            stats = IPStatistics()
            
            if rows:
                for row in rows:
                    count = row['count']
                    avg_duration = row['avg_duration'] or 0
                    
                    if row['status'] == 'active':
                        stats.active_bans = count
                        stats.average_ban_duration = avg_duration
                    elif row['status'] == 'expired':
                        stats.expired_bans = count
                    elif row['status'] == 'manually_removed':
                        stats.manually_removed_bans = count
                
                stats.total_bans = sum([stats.active_bans, stats.expired_bans, stats.manually_removed_bans])
            
            # Get unique IPs count
            unique_ips_query = 'SELECT COUNT(DISTINCT ip_address) as count FROM ip_bans'
            unique_row = self.db_manager.execute_query(unique_ips_query)
            if unique_row:
                stats.unique_ips_banned = unique_row['count']
            
            # Get most banned IPs
            most_banned_query = '''
                SELECT ip_address, COUNT(*) as ban_count 
                FROM ip_bans 
                GROUP BY ip_address 
                ORDER BY ban_count DESC 
                LIMIT 10
            '''
            
            most_banned_rows = self.db_manager.execute_query(most_banned_query, fetch_all=True)
            if most_banned_rows:
                stats.most_banned_ips = [(row['ip_address'], row['ban_count']) for row in most_banned_rows]
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting IP statistics: {e}")
            return IPStatistics()
    
    def _validate_ip_address(self, ip_address: str) -> str:
        """Validate and normalize IP address."""
        if not ip_address or not isinstance(ip_address, str):
            raise IPManagerError("IP address must be a non-empty string")
        
        try:
            ip_obj = ipaddress.ip_address(ip_address.strip())
            return str(ip_obj)
        except ValueError:
            raise IPManagerError(f"Invalid IP address format: {ip_address}")
    
    def _insert_ban_record(self, ban_record: IPBanRecord) -> bool:
        """Insert ban record into database."""
        try:
            insert_query = '''
                INSERT INTO ip_bans (
                    ip_address, ban_reason, ban_duration, created_at, expires_at,
                    updated_at, status, ban_count, last_offense_type, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            '''
            
            params = (
                ban_record.ip_address,
                ban_record.ban_reason,
                ban_record.ban_duration,
                ban_record.created_at,
                ban_record.expires_at,
                ban_record.updated_at,
                ban_record.status.value,
                ban_record.ban_count,
                ban_record.last_offense_type,
                ban_record.created_by
            )
            
            result = self.db_manager.execute_query(insert_query, params)
            return result and result > 0
            
        except Exception as e:
            self.logger.error(f"Error inserting ban record: {e}")
            return False
    
    def _row_to_ban_record(self, row) -> IPBanRecord:
        """Convert database row to IPBanRecord."""
        return IPBanRecord(
            id=row['id'],
            ip_address=row['ip_address'],
            ban_reason=row['ban_reason'],
            ban_duration=row['ban_duration'],
            created_at=row['created_at'],
            expires_at=row['expires_at'],
            updated_at=row['updated_at'],
            status=BanStatus(row['status']),
            ban_count=row['ban_count'],
            last_offense_type=row['last_offense_type'] or '',
            created_by=row['created_by'],
            removed_reason=row['removed_reason'] or ''
        )
    
    def _log_audit_action(self, action: AuditAction, ip_address: str, description: str,
                         details: str = "", user_id: str = "system") -> None:
        """Log audit action to database."""
        try:
            audit_record = AuditLogRecord(
                action=action,
                user_id=user_id,
                ip_address=ip_address,
                description=description,
                details=details,
                component="ip_manager"
            )
            
            insert_query = '''
                INSERT INTO audit_logs (
                    timestamp, action, user_id, ip_address, description,
                    details, result, component
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            '''
            
            params = (
                audit_record.timestamp,
                audit_record.action.value,
                audit_record.user_id,
                audit_record.ip_address,
                audit_record.description,
                audit_record.details,
                audit_record.result,
                audit_record.component
            )
            
            self.db_manager.execute_query(insert_query, params)
            
        except Exception as e:
            self.logger.error(f"Error logging audit action: {e}")
    
    def get_performance_stats(self) -> Dict[str, any]:
        """Get performance statistics for the IP manager."""
        cache_hit_rate = (
            self._cache_hits / max(self._cache_hits + self._cache_misses, 1) * 100
        )
        
        return {
            'operations_count': self._operations_count,
            'cache_size': len(self._active_bans_cache), 
            'cache_hits': self._cache_hits,
            'cache_misses': self._cache_misses,
            'cache_hit_rate_percent': cache_hit_rate,
            'cache_last_update': self._cache_last_update,
            'cleanup_thread_active': self._cleanup_thread and self._cleanup_thread.is_alive()
        }
    
    def cleanup(self) -> None:
        """Clean up IP manager resources."""
        try:
            # Stop background cleanup
            self.stop_background_cleanup()
            
            # Clear cache
            self._active_bans_cache.clear()
            
            self.logger.info("IPManager cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during IPManager cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.start_background_cleanup()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()