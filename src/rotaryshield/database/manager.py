#!/usr/bin/env python3
"""
RotaryShield Database Manager
SQLite database management with security and performance optimization.

Security Features:
- SQL injection prevention through parameterized queries
- Database file permission validation
- Transaction integrity and rollback support
- Connection pooling and resource management
- Query timeout and resource limits
- Comprehensive error handling and logging
"""

import sqlite3
import logging
import threading
import time
import os
import stat
from typing import List, Dict, Any, Optional, Tuple, Union
from pathlib import Path
from contextlib import contextmanager
import json

from .models import IPBanRecord, AuditLogRecord, SecurityEventRecord, BanStatus, AuditAction, EventSeverity


class DatabaseError(Exception):
    """Base exception for database errors."""
    pass


class DatabaseConnectionError(DatabaseError):
    """Exception for database connection errors."""
    pass


class DatabaseIntegrityError(DatabaseError):
    """Exception for database integrity violations."""
    pass


class DatabaseManager:
    """
    SQLite database manager with security and performance optimization.
    
    This class manages all database operations for RotaryShield with
    enterprise-grade security measures and performance optimization.
    """
    
    # Database configuration
    DB_VERSION = 1
    DB_TIMEOUT = 30  # seconds
    MAX_CONNECTIONS = 10
    WAL_MODE = True  # Use WAL mode for better concurrency
    
    # SQL schema definitions
    SCHEMA_SQL = {
        'ip_bans': '''
            CREATE TABLE IF NOT EXISTS ip_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                ban_reason TEXT NOT NULL,
                ban_duration INTEGER NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                ban_count INTEGER NOT NULL DEFAULT 1,
                last_offense_type TEXT,
                created_by TEXT NOT NULL DEFAULT 'rotaryshield',
                removed_reason TEXT,
                
                -- UNIQUE constraint without WHERE clause for SQLite compatibility
                CONSTRAINT unique_ip_address UNIQUE(ip_address)
            )
        ''',
        
        'audit_logs': '''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                action TEXT NOT NULL,
                user_id TEXT NOT NULL,
                ip_address TEXT,
                description TEXT NOT NULL,
                details TEXT,
                result TEXT NOT NULL DEFAULT 'success',
                component TEXT NOT NULL DEFAULT 'rotaryshield',
                session_id TEXT
            )
        ''',
        
        'security_events': '''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp REAL NOT NULL,
                processed_at REAL NOT NULL,
                source_ip TEXT,
                source_port INTEGER,
                source_country TEXT,
                target_service TEXT,
                target_port INTEGER,
                description TEXT,
                raw_log_data TEXT,
                pattern_matched TEXT,
                threat_score INTEGER DEFAULT 0,
                false_positive BOOLEAN DEFAULT FALSE,
                actions_taken TEXT DEFAULT '[]',
                detection_source TEXT
            )
        ''',
        
        'database_metadata': '''
            CREATE TABLE IF NOT EXISTS database_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
        '''
    }
    
    # Index definitions for performance optimization
    INDEXES_SQL = [
        # Partial index to enforce unique active IP addresses (SQLite 3.8+ compatible)
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_bans_unique_active ON ip_bans(ip_address) WHERE status = \"active\"',
        'CREATE INDEX IF NOT EXISTS idx_ip_bans_ip_status ON ip_bans(ip_address, status)',
        'CREATE INDEX IF NOT EXISTS idx_ip_bans_expires_at ON ip_bans(expires_at)',
        'CREATE INDEX IF NOT EXISTS idx_ip_bans_created_at ON ip_bans(created_at)',
        'CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)',
        'CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip)',
        'CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type)',
        'CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity)'
    ]
    
    def __init__(self, db_path: str):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = os.path.abspath(db_path)
        self.logger = logging.getLogger(__name__)
        
        # Thread safety
        self._lock = threading.RLock()
        self._connection_pool: List[sqlite3.Connection] = []
        self._pool_lock = threading.Lock()
        
        # Statistics
        self._queries_executed = 0
        self._total_query_time = 0.0
        self._error_count = 0
        self._connections_created = 0
        
        # Database state
        self._is_initialized = False
        self._db_version = 0
        
        self.logger.info(f"DatabaseManager initialized for: {self.db_path}")
    
    def initialize(self) -> None:
        """
        Initialize database with schema creation and validation.
        
        Raises:
            DatabaseError: If initialization fails
        """
        try:
            with self._lock:
                # Validate database file path and permissions
                self._validate_database_path()
                
                # Create database directory if needed
                self._ensure_database_directory()
                
                # Initialize database schema
                self._initialize_schema()
                
                # Configure database settings
                self._configure_database()
                
                # Validate database integrity
                self._validate_database_integrity()
                
                self._is_initialized = True
                self.logger.info("Database initialization completed successfully")
        
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise DatabaseError(f"Failed to initialize database: {e}")
    
    def _validate_database_path(self) -> None:
        """Validate database file path for security with comprehensive protection."""
        # Import the robust path validator
        from ..utils.validators import validate_file_path
        
        # Define allowed directories for database files
        allowed_dirs = [
            '/var/lib/rotaryshield',
            '/opt/rotaryshield/data',
            '/tmp/rotaryshield',
            os.getcwd()  # Allow current working directory for development
        ]
        
        # Use the robust path validation function
        is_valid, error, normalized_path = validate_file_path(self.db_path, allowed_dirs)
        
        if not is_valid:
            raise DatabaseError(f"Invalid database path: {error}")
        
        # Update the database path to the validated, normalized version
        self.db_path = normalized_path
        
        # Additional database-specific security checks
        db_dir = os.path.dirname(self.db_path)
        
        # Ensure database filename doesn't contain suspicious characters
        db_filename = os.path.basename(self.db_path)
        if not db_filename or '..' in db_filename or '/' in db_filename or '\\' in db_filename:
            raise DatabaseError(f"Invalid database filename: {db_filename}")
        
        # Warn if database is in non-standard location
        standard_dirs = ['/var/lib/rotaryshield', '/opt/rotaryshield/data']
        if not any(self.db_path.startswith(std_dir) for std_dir in standard_dirs):
            self.logger.warning(f"Database path outside standard directories: {self.db_path}")
            
        self.logger.debug(f"Database path validated: {self.db_path}")
    
    def _ensure_database_directory(self) -> None:
        """Ensure database directory exists with proper permissions."""
        db_dir = os.path.dirname(self.db_path)
        
        if not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, mode=0o750, exist_ok=True)
                self.logger.info(f"Created database directory: {db_dir}")
            except OSError as e:
                raise DatabaseError(f"Cannot create database directory {db_dir}: {e}")
        
        # Validate directory permissions
        try:
            dir_stat = os.stat(db_dir)
            
            # Check if directory is writable
            if not os.access(db_dir, os.W_OK):
                raise DatabaseError(f"Database directory not writable: {db_dir}")
            
            # Warn about overly permissive permissions
            mode = stat.S_IMODE(dir_stat.st_mode)
            if mode & stat.S_IRWXO:  # Others have any permissions
                self.logger.warning(f"Database directory has overly permissive permissions: {oct(mode)}")
        
        except OSError as e:
            raise DatabaseError(f"Cannot validate database directory permissions: {e}")
    
    def _initialize_schema(self) -> None:
        """Initialize database schema and tables."""
        with self._get_connection() as conn:
            try:
                # Create tables
                for table_name, schema_sql in self.SCHEMA_SQL.items():
                    conn.execute(schema_sql)
                    self.logger.debug(f"Created/validated table: {table_name}")
                
                # Create indexes
                for index_sql in self.INDEXES_SQL:
                    conn.execute(index_sql)
                
                # Initialize metadata
                self._initialize_metadata(conn)
                
                conn.commit()
                self.logger.info("Database schema initialized successfully")
                
            except sqlite3.Error as e:
                conn.rollback()
                raise DatabaseError(f"Schema initialization failed: {e}")
    
    def _initialize_metadata(self, conn: sqlite3.Connection) -> None:
        """Initialize database metadata."""
        current_time = time.time()
        
        # Set database version
        conn.execute(
            '''INSERT OR REPLACE INTO database_metadata (key, value, updated_at)
               VALUES (?, ?, ?)''',
            ('db_version', str(self.DB_VERSION), current_time)
        )
        
        # Set creation timestamp if not exists
        conn.execute(
            '''INSERT OR IGNORE INTO database_metadata (key, value, updated_at)
               VALUES (?, ?, ?)''',
            ('created_at', str(current_time), current_time)
        )
        
        # Set last initialized timestamp
        conn.execute(
            '''INSERT OR REPLACE INTO database_metadata (key, value, updated_at)
               VALUES (?, ?, ?)''',
            ('last_initialized', str(current_time), current_time)
        )
    
    def _configure_database(self) -> None:
        """Configure database settings for performance and security."""
        with self._get_connection() as conn:
            try:
                # Enable WAL mode for better concurrency
                if self.WAL_MODE:
                    conn.execute('PRAGMA journal_mode=WAL')
                
                # Set synchronous mode for data safety
                conn.execute('PRAGMA synchronous=NORMAL')
                
                # Set reasonable cache size (in KB)
                conn.execute('PRAGMA cache_size=10000')
                
                # Enable foreign key constraints
                conn.execute('PRAGMA foreign_keys=ON')
                
                # Set query timeout
                conn.execute(f'PRAGMA busy_timeout={self.DB_TIMEOUT * 1000}')
                
                self.logger.debug("Database configuration applied")
                
            except sqlite3.Error as e:
                raise DatabaseError(f"Database configuration failed: {e}")
    
    def _validate_database_integrity(self) -> None:
        """Validate database integrity."""
        with self._get_connection() as conn:
            try:
                # Check database integrity
                result = conn.execute('PRAGMA integrity_check').fetchone()
                if result[0] != 'ok':
                    raise DatabaseIntegrityError(f"Database integrity check failed: {result[0]}")
                
                # Get database version
                version_row = conn.execute(
                    'SELECT value FROM database_metadata WHERE key = ?',
                    ('db_version',)
                ).fetchone()
                
                if version_row:
                    self._db_version = int(version_row[0])
                    if self._db_version > self.DB_VERSION:
                        self.logger.warning(
                            f"Database version ({self._db_version}) is newer than expected ({self.DB_VERSION})"
                        )
                
                self.logger.debug(f"Database integrity validated (version: {self._db_version})")
                
            except sqlite3.Error as e:
                raise DatabaseError(f"Database integrity validation failed: {e}")
    
    @contextmanager
    def _get_connection(self):
        """
        Get database connection with automatic cleanup.
        
        This context manager provides a database connection with proper
        resource management and error handling.
        """
        conn = None
        try:
            conn = self._create_connection()
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            self._error_count += 1
            self.logger.error(f"Database operation failed: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            if conn:
                self._return_connection(conn)
    
    def _create_connection(self) -> sqlite3.Connection:
        """Create new database connection with security settings."""
        try:
            # Try to get connection from pool first
            with self._pool_lock:
                if self._connection_pool:
                    return self._connection_pool.pop()
            
            # Create new connection
            conn = sqlite3.connect(
                self.db_path,
                timeout=self.DB_TIMEOUT,
                check_same_thread=False,
                isolation_level=None  # Enable autocommit mode
            )
            
            # Configure connection
            conn.row_factory = sqlite3.Row  # Enable column access by name
            conn.execute('PRAGMA foreign_keys=ON')
            
            self._connections_created += 1
            return conn
            
        except sqlite3.Error as e:
            raise DatabaseConnectionError(f"Cannot create database connection: {e}")
    
    def _return_connection(self, conn: sqlite3.Connection) -> None:
        """Return connection to pool or close it."""
        try:
            with self._pool_lock:
                if len(self._connection_pool) < self.MAX_CONNECTIONS:
                    self._connection_pool.append(conn)
                    return
            
            # Pool is full, close connection
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error returning connection to pool: {e}")
            try:
                conn.close()
            except:
                pass
    
    def execute_query(self, query: str, parameters: Tuple = (), fetch_all: bool = False) -> Optional[Union[List[sqlite3.Row], sqlite3.Row]]:
        """
        Execute SQL query with parameters and return results.
        
        Args:
            query: SQL query string
            parameters: Query parameters (prevents SQL injection)
            fetch_all: Whether to fetch all results or just one
            
        Returns:
            Query results or None
        """
        start_time = time.time()
        
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(query, parameters)
                
                if query.strip().upper().startswith('SELECT'):
                    result = cursor.fetchall() if fetch_all else cursor.fetchone()
                else:
                    conn.commit()
                    result = cursor.rowcount
                
                # Update statistics
                self._queries_executed += 1
                self._total_query_time += time.time() - start_time
                
                return result
                
        except Exception as e:
            self.logger.error(f"Query execution failed: {query[:100]}... Error: {e}")
            raise
    
    def execute_transaction(self, operations: List[Tuple[str, Tuple]]) -> bool:
        """
        Execute multiple operations in a single transaction.
        
        Args:
            operations: List of (query, parameters) tuples
            
        Returns:
            True if successful, False otherwise
        """
        start_time = time.time()
        
        try:
            with self._get_connection() as conn:
                conn.execute('BEGIN TRANSACTION')
                
                try:
                    for query, parameters in operations:
                        conn.execute(query, parameters)
                    
                    conn.commit()
                    
                    # Update statistics
                    self._queries_executed += len(operations)
                    self._total_query_time += time.time() - start_time
                    
                    return True
                    
                except Exception as e:
                    conn.rollback()
                    self.logger.error(f"Transaction failed: {e}")
                    raise
                    
        except Exception as e:
            self._error_count += 1
            self.logger.error(f"Transaction execution failed: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database manager statistics."""
        avg_query_time = (
            self._total_query_time / max(self._queries_executed, 1) * 1000  # Convert to ms
        )
        
        # Get database file size
        db_size = 0
        try:
            if os.path.exists(self.db_path):
                db_size = os.path.getsize(self.db_path)
        except OSError:
            pass
        
        return {
            'db_path': self.db_path,
            'is_initialized': self._is_initialized,
            'db_version': self._db_version,
            'queries_executed': self._queries_executed,
            'total_query_time': self._total_query_time,
            'average_query_time_ms': avg_query_time,
            'error_count': self._error_count,
            'connections_created': self._connections_created,
            'pool_size': len(self._connection_pool),
            'db_file_size_bytes': db_size
        }
    
    def vacuum_database(self) -> bool:
        """
        Vacuum database to reclaim space and optimize performance.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with self._get_connection() as conn:
                self.logger.info("Starting database vacuum operation...")
                conn.execute('VACUUM')
                self.logger.info("Database vacuum completed successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Database vacuum failed: {e}")
            return False
    
    def backup_database(self, backup_path: str) -> bool:
        """
        Create database backup.
        
        Args:
            backup_path: Path for backup file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate backup path
            backup_path = os.path.abspath(backup_path)
            backup_dir = os.path.dirname(backup_path)
            
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir, mode=0o750, exist_ok=True)
            
            # Create backup using SQLite backup API
            with self._get_connection() as source_conn:
                backup_conn = sqlite3.connect(backup_path)
                try:
                    source_conn.backup(backup_conn)
                    self.logger.info(f"Database backup created: {backup_path}")
                    return True
                finally:
                    backup_conn.close()
                    
        except Exception as e:
            self.logger.error(f"Database backup failed: {e}")
            return False
    
    def close(self) -> None:
        """Close database manager and cleanup resources."""
        try:
            with self._pool_lock:
                # Close all pooled connections
                while self._connection_pool:
                    conn = self._connection_pool.pop()
                    try:
                        conn.close()
                    except Exception as e:
                        self.logger.error(f"Error closing pooled connection: {e}")
            
            self.logger.info("Database manager closed successfully")
            
        except Exception as e:
            self.logger.error(f"Error closing database manager: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        if not self._is_initialized:
            self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()