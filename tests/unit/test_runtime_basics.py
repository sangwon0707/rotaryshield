"""Local regression checks: temporary SQLite/logs and an in-memory firewall only."""
import contextlib
import io
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from rotaryshield.config import ConfigManager, ConfigurationError, RotaryShieldConfig
from rotaryshield.database.manager import DatabaseManager
from rotaryshield.security.bans import BanController, BanOperationError, select_backend, remember_backend
from rotaryshield.security.engine import SecurityEngine
from rotaryshield.cli import RotaryShieldCLI
from rotaryshield.monitoring.log_monitor import LogFileWatcher
from rotaryshield.monitoring.pattern_matcher import PatternMatcher


class FakeFirewall:
    def __init__(self):
        self.blocked = set()
        self.fail_block = False
        self.fail_unblock = False
        self.calls = 0

    def initialize(self):
        pass

    def cleanup(self):
        pass

    def get_current_backend(self):
        return 'iptables'

    def block_ip(self, address, comment=None):
        self.calls += 1
        if self.fail_block:
            return False
        self.blocked.add(address)
        return True

    def unblock_ip(self, address):
        if self.fail_unblock:
            return False
        self.blocked.discard(address)
        return True


class RuntimeBasics(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.runtime-', dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = DatabaseManager(str(self.root / 'state.db'))
        self.db.initialize()
        self.addCleanup(self.db.close)
        self.fw = FakeFirewall()
        self.bans = BanController(self.db, self.fw, ['192.0.2.0/28'])

    def status(self, address='198.51.100.10'):
        return self.db.execute_query('SELECT * FROM ip_bans WHERE ip_address = ?', (address,))

    def test_firewall_failure_rolls_back_database(self):
        self.fw.fail_block = True
        with self.assertRaises(BanOperationError):
            self.bans.ban('198.51.100.10', 60, 'failed login')
        self.assertIsNone(self.status())

    def test_database_failure_after_block_compensates_firewall(self):
        with patch.object(self.bans, '_audit', side_effect=RuntimeError('write failed')):
            with self.assertRaises(RuntimeError):
                self.bans.ban('198.51.100.10', 60, 'failed login')
        self.assertIsNone(self.status())
        self.assertFalse(self.fw.blocked)

    def test_unblock_failure_preserves_record_for_retry(self):
        self.bans.ban('198.51.100.10', 60, 'failed login')
        self.fw.fail_unblock = True
        with self.assertRaises(BanOperationError):
            self.bans.unban('198.51.100.10')
        self.assertEqual(self.status()['status'], 'active')

    def test_expiry_removes_firewall_before_database_status(self):
        self.bans.ban('198.51.100.10', 60, 'failed login')
        self.db.execute_query('UPDATE ip_bans SET expires_at = ?', (time.time() - 1,))
        self.bans.reconcile()
        self.assertEqual(self.status()['status'], 'expired')
        self.assertFalse(self.fw.blocked)

    def test_failed_expiry_is_retried(self):
        self.bans.ban('198.51.100.10', 60, 'failed login')
        self.db.execute_query('UPDATE ip_bans SET expires_at = ?', (time.time() - 1,))
        self.fw.fail_unblock = True
        with self.assertRaises(BanOperationError):
            self.bans.reconcile()
        self.assertEqual(self.status()['status'], 'active')
        self.fw.fail_unblock = False
        self.bans.reconcile()
        self.assertEqual(self.status()['status'], 'expired')

    def test_one_expiry_failure_does_not_block_other_expiries(self):
        for address in ['198.51.100.10', '198.51.100.11']:
            self.bans.ban(address, 60, 'failed login')
        self.db.execute_query('UPDATE ip_bans SET expires_at = ?', (time.time() - 1,))
        remove = self.fw.unblock_ip
        def fail_one(address):
            return False if address.endswith('.11') else remove(address)
        with patch.object(self.fw, 'unblock_ip', side_effect=fail_one):
            with self.assertRaises(BanOperationError):
                self.bans.reconcile()
        self.assertEqual(self.status()['status'], 'expired')

    def test_restart_restores_without_extending_ban(self):
        self.bans.ban('198.51.100.10', 60, 'failed login')
        expiry = self.status()['expires_at']
        self.fw.blocked.clear()
        self.bans.reconcile(restore=True)
        self.assertIn('198.51.100.10', self.fw.blocked)
        self.assertEqual(expiry, self.status()['expires_at'])

    def test_reban_after_manual_removal(self):
        self.bans.ban('198.51.100.10', 60, 'failed login')
        self.bans.unban('198.51.100.10')
        self.bans.ban('198.51.100.10', 60, 'repeat login')
        self.assertEqual(self.status()['status'], 'active')
        self.assertEqual(self.status()['ban_count'], 2)

    def test_cidr_and_loopback_whitelist(self):
        for address in ['192.0.2.2', '127.0.0.2', '::1']:
            self.assertFalse(self.bans.ban(address, 60, 'failed login'))
        self.assertEqual(self.fw.calls, 0)

    def test_database_failure_is_not_an_empty_ban_list(self):
        with patch.object(self.db, 'execute_query', side_effect=RuntimeError('unavailable')):
            with self.assertRaises(RuntimeError):
                self.bans.records()

    def test_legacy_and_canonical_config(self):
        manager = ConfigManager()
        old = manager._build_config({'detection': {'thresholds': {'warning': 3, 'blocking': 7}},
                                     'blocking': {'ban_time': 120, 'firewall': 'auto', 'whitelist_ips': ['192.0.2.0/24']}})
        old.validate()
        self.assertEqual(old.ban.ban_time, 120)
        self.assertEqual(old.detection.ban_threshold, 7)
        new = manager._build_config({'ban': {'firewall_backend': 'ufw'}})
        self.assertEqual(new.ban.firewall_backend, 'ufw')
        with self.assertRaises(ConfigurationError):
            manager._build_config({'ban': {}, 'blocking': {}})

    def test_shipped_configuration_loads(self):
        path = self.root / 'config.yml'
        path.write_text(Path('configs/config.example.yml').read_text())
        path.chmod(0o600)
        config = ConfigManager(str(path)).load_config()
        matcher = PatternMatcher()
        for name, pattern in config.detection.patterns.items():
            self.assertTrue(matcher.add_pattern(name, pattern))
        self.assertTrue(matcher.match_line('Failed password for user from 2001:db8::1 port 22 ssh2'))

    def test_missing_config_fails(self):
        with self.assertRaises(ConfigurationError):
            ConfigManager(str(self.root / 'missing.yml')).load_config()

    def test_backend_change_is_refused_while_bans_exist(self):
        remember_backend(self.db, 'iptables')
        self.bans.ban('198.51.100.10', 60, 'failed login')
        self.assertEqual(select_backend(self.db, 'auto'), 'iptables')
        with self.assertRaises(BanOperationError):
            select_backend(self.db, 'ufw')

    def test_engine_log_to_ban_and_shutdown_drains_queue(self):
        log = self.root / 'auth.log'
        log.write_text('')
        config = RotaryShieldConfig()
        config.database.db_path = str(self.root / 'engine.db')
        config.detection.log_files = [str(log)]
        config.detection.patterns = {'ssh_failed': r'Failed password for \S+ from (\d+\.\d+\.\d+\.\d+)'}
        config.detection.max_retry = 2
        config.detection.ban_threshold = 3
        with patch('rotaryshield.security.engine.ConfigManager.load_config', return_value=config), \
             patch('rotaryshield.security.engine.FirewallManager', return_value=self.fw):
            engine = SecurityEngine()
            engine.initialize()
            self.assertEqual(len(engine.log_monitor.file_watchers), 1)
            engine.start()
            with log.open('a') as stream:
                for _ in range(3):
                    stream.write('Failed password for user from 198.51.100.10\n')
            engine.log_monitor._check_all_files()
            engine.shutdown()
            self.assertIn('198.51.100.10', self.fw.blocked)
            self.assertFalse(engine.is_running())
            self.assertEqual(engine.event_queue.unfinished_tasks, 0)
            self.assertFalse(any(t.is_alive() for t in engine._event_threads))
            database = DatabaseManager(config.database.db_path)
            self.addCleanup(database.close)
            events = database.execute_query('SELECT COUNT(*) AS n FROM security_events')['n']
            self.assertEqual(events, 3)
            self.assertEqual(engine.metrics.ips_throttled, 0)

    def test_cli_uses_real_schema_and_reports_errors(self):
        self.bans.ban('198.51.100.10', 60, 'failed login')
        cli = RotaryShieldCLI()
        @contextlib.contextmanager
        def db_context():
            yield RotaryShieldConfig(), self.db
        with patch.object(cli, '_database', db_context), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.list_blocked(), 0)
            self.assertEqual(cli.show_stats(), 0)
        self.assertIn('198.51.100.10', output.getvalue())
        self.assertIn('active: 1', output.getvalue())

    def test_cli_unblock_failure_returns_nonzero(self):
        self.bans.ban('198.51.100.10', 60, 'failed login')
        self.fw.fail_unblock = True
        cli = RotaryShieldCLI()
        @contextlib.contextmanager
        def db_context():
            yield RotaryShieldConfig(), self.db
        with patch.object(cli, '_database', db_context), \
             patch('rotaryshield.firewall.manager.FirewallManager', return_value=self.fw), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.unblock_ip('198.51.100.10'), 1)
        self.assertEqual(self.status()['status'], 'active')

    def test_rotated_log_is_read_from_start(self):
        path = self.root / 'rotate.log'
        path.write_text('')
        matcher = PatternMatcher()
        self.assertTrue(matcher.add_pattern('ssh_failed', r'Failed from (\S+)'))
        watcher = LogFileWatcher(str(path), matcher)
        watcher.initialize()
        self.addCleanup(watcher.close)
        path.rename(self.root / 'old.log')
        path.write_text('Failed from 198.51.100.10\n')
        watcher.check_for_changes()
        events = watcher.check_for_changes()
        self.assertEqual(len(events), 1)

    def test_partial_log_record_waits_for_newline(self):
        path = self.root / 'partial.log'
        path.write_text('')
        matcher = PatternMatcher()
        matcher.add_pattern('ssh_failed', r'Failed from (\S+)')
        watcher = LogFileWatcher(str(path), matcher)
        watcher.initialize()
        self.addCleanup(watcher.close)
        with path.open('a') as stream:
            stream.write('Failed from 198.51.')
        self.assertEqual(watcher.check_for_changes(), [])
        with path.open('a') as stream:
            stream.write('100.10\n')
        events = watcher.check_for_changes()
        self.assertEqual(events[0].matched_groups, ['198.51.100.10'])

    def test_firewalld_partial_removal_is_failure(self):
        from rotaryshield.firewall.firewalld_adapter import FirewalldAdapter
        adapter = FirewalldAdapter()
        with patch.object(adapter, '_execute_command', side_effect=[('', 'denied', 1), ('', '', 0)]):
            self.assertFalse(adapter.unblock_ip('198.51.100.10'))

    def test_firewalld_partial_block_is_failure(self):
        from rotaryshield.firewall.firewalld_adapter import FirewalldAdapter
        adapter = FirewalldAdapter()
        with patch.object(adapter, '_execute_command', side_effect=[('', '', 0), ('', 'denied', 1)]), \
             patch.object(adapter, 'unblock_ip', return_value=True) as undo:
            self.assertFalse(adapter.block_ip('198.51.100.10'))
            undo.assert_called_once()


if __name__ == '__main__':
    unittest.main()
