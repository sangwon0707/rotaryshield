"""Offline checks: synthetic pressure, SQLite, and intercepted nft subprocesses.

No sockets, real firewall commands, service management or ARTEX execution.
"""
import contextlib
import io
import json
import math
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from rotaryshield.config import ConfigManager, ConfigurationError, PumpConfig, PumpServiceConfig, RotaryShieldConfig
from rotaryshield.database.manager import DatabaseManager
from rotaryshield.pump.controller import PressureController, PressureSample, Stage, rate_for
from rotaryshield.pump.nftables import NftablesPump, PumpActuatorError, PumpLock, TABLE, marker, render_install, render_stage
from rotaryshield.pump.runtime import HostPressureSensor, PumpRuntime
from rotaryshield.pump.simulation import replay
from rotaryshield.pump.__main__ import main


def configuration(mode='observe'):
    return PumpConfig(mode=mode, sample_interval=1, recovery_seconds=3,
                      smoothing_seconds=1, services=[PumpServiceConfig()])


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.config = configuration()
        self.controller = PressureController(self.config)

    def update(self, second, cpu=0.2, memory=0.2, queue=0):
        return self.controller.update(PressureSample(second, cpu, memory, queue))

    def warm_up(self):
        for second in range(7):
            self.update(second)
        self.assertEqual(self.controller.stage, Stage.NOMINAL)

    def test_slow_start_and_one_stage_per_recovery_window(self):
        stages = [self.update(second).stage for second in range(7)]
        self.assertEqual(stages, [Stage.RELIEF] * 3 + [Stage.REGULATED] * 3 + [Stage.NOMINAL])

    def test_critical_raw_pressure_bypasses_smoothing(self):
        self.warm_up()
        decision = self.update(7, queue=0.99)
        self.assertEqual(decision.stage, Stage.RELIEF)
        self.assertIn('queue', decision.reason)

    def test_sustained_high_pressure_restricts_without_ip_attribution(self):
        self.warm_up()
        for second in range(7, 12):
            decision = self.update(second, cpu=0.85)
        self.assertEqual(decision.stage, Stage.REGULATED)

    def test_hysteresis_and_interrupted_recovery(self):
        for second, pressure in enumerate([0.2, 0.2, 0.6, 0.2, 0.2, 0.6, 0.2, 0.2]):
            self.update(second, pressure)
        self.assertEqual(self.controller.stage, Stage.RELIEF)

    def test_invalid_samples_and_gap_do_not_count_as_recovery(self):
        self.update(0)
        self.update(1)
        for value in [math.nan, math.inf, -0.1, 1.1]:
            with self.assertRaises(ValueError):
                self.update(2, value)
        self.assertEqual(self.update(100).stage, Stage.RELIEF)
        self.assertEqual(self.update(101).stage, Stage.RELIEF)
        self.assertEqual(self.update(200).stage, Stage.RELIEF)

    def test_out_of_order_samples_reset_recovery(self):
        self.update(10)
        self.update(11)
        with self.assertRaises(ValueError):
            self.update(10)
        self.assertEqual(self.update(12).stage, Stage.RELIEF)

    def test_failed_sensor_resets_recovery(self):
        self.update(0)
        self.update(1)
        self.controller.sensor_failed()
        self.assertEqual(self.update(2).stage, Stage.RELIEF)
        self.assertEqual(self.update(3).stage, Stage.RELIEF)

    def test_capacity_never_zero_and_restricts_monotonically(self):
        service = PumpServiceConfig(rate=7, minimum_rate=2, per_source_rate=1)
        self.assertEqual([rate_for(service, stage) for stage in Stage], [7, 3, 2])

    def test_offline_replay_visits_pressure_and_recovery_stages(self):
        rows = replay()
        transitions = [row['stage'] for row in rows if row['changed']]
        self.assertEqual(transitions, ['regulated', 'nominal', 'regulated', 'relief', 'regulated', 'nominal'])
        self.assertEqual(rows[-1]['rate'], 20)


class ConfigurationTests(unittest.TestCase):
    def test_round_trip_and_legacy_default(self):
        manager = ConfigManager()
        config = RotaryShieldConfig(pump=configuration())
        loaded = manager._build_config(manager._config_to_dict(config))
        self.assertEqual(loaded.pump, config.pump)
        self.assertEqual(manager._build_config({}).pump.mode, 'off')

    def test_invalid_rates_thresholds_and_names_fail_before_render(self):
        for field, value in [('mode', 'enable'), ('high_pressure', 0.2), ('relief_pressure', float('nan')),
                             ('sample_interval', True), ('recovery_seconds', 0.5), ('max_sources', 0),
                             ('services', []), ('source_timeout', 1)]:
            config = configuration()
            setattr(config, field, value)
            with self.subTest(field=field), self.assertRaises(ConfigurationError):
                config.validate()
        for field, value in [('name', 'ssh; flush ruleset'), ('port', 0), ('rate', True),
                             ('minimum_rate', 200), ('per_source_rate', 30), ('burst', 0)]:
            config = configuration()
            setattr(config.services[0], field, value)
            with self.subTest(field=field), self.assertRaises(ConfigurationError):
                render_install(config, [])

    def test_duplicate_ports_and_unknown_options_are_rejected(self):
        config = configuration()
        config.services.append(PumpServiceConfig(name='other'))
        with self.assertRaises(ConfigurationError):
            config.validate()
        with self.assertRaises(ConfigurationError):
            ConfigManager()._build_config({'pump': {'rate_typo': 3}})
        with self.assertRaises(ConfigurationError):
            ConfigManager()._build_config({'pump': {'services': [{'port_typo': 80}]}})


class NftablesTests(unittest.TestCase):
    def setUp(self):
        self.config = configuration('enforce')
        self.adapter = NftablesPump(self.config, ['192.0.2.0/24', '2001:db8::/32'])

    def table(self, stage=Stage.RELIEF):
        counts = {'input': 6, 'source_0': 3, 'ceiling_0': 2,
                  **{'flow_0_' + level.name.lower(): 2 for level in Stage}}
        return json.dumps({'nftables': [
            {'table': {'family': 'inet', 'name': TABLE, 'comment': marker(self.config, self.adapter.whitelist)}},
            {'chain': {'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': -10, 'policy': 'accept'}},
            *[{'rule': {'chain': name, 'expr': []}} for name, count in counts.items() for _ in range(count)],
            {'rule': {'chain': 'gate_0', 'expr': [{'goto': {'target': 'flow_0_' + stage.name.lower()}}]}},
            *[{'counter': {'name': name + '_0', 'packets': 3}}
              for name in ('passed', 'source_dropped', 'capacity_dropped')]
        ]})

    def test_plan_covers_both_families_and_only_new_syn_host_ports(self):
        script = render_install(self.config, self.adapter.whitelist)
        for required in ['type ipv4_addr;', 'type ipv6_addr;', 'size 4096;', 'timeout 60s;',
                         'ct state new tcp flags & (fin | syn | rst | ack) == syn tcp dport 22',
                         'ip saddr 192.0.2.0/24 return', 'ip6 saddr 2001:db8::/32 return',
                         'hook input priority -10', 'goto ceiling_0', 'ceiling_0 goto gate_0', 'source_dropped_0 drop',
                         'ceiling_0 limit rate over 20/second burst 10 packets',
                         'flow_0_relief limit rate over 2/second']:
            self.assertIn(required, script)
        self.assertNotIn('flush ruleset', script)
        self.assertNotIn('hook forward', script)
        self.assertNotIn('jump gate_0', script)  # would fall through and DROP admitted traffic

    def test_stage_changes_do_not_recreate_buckets_or_counters(self):
        script = render_stage(self.config, Stage.REGULATED)
        self.assertEqual(script.count('\n'), 2)
        self.assertIn('flush chain inet rotaryshield_pump gate_0', script)
        for forbidden in ('delete table', 'flush table', 'flush set', 'add set', 'limit rate', 'counter'):
            self.assertNotIn(forbidden, script)
        with patch.object(self.adapter, '_run') as run:
            self.adapter.applied = Stage.RELIEF
            self.adapter.apply(Stage.REGULATED)
            self.adapter.apply(Stage.REGULATED)
        run.assert_called_once_with(['--file', '-'], script)

    def test_failed_apply_is_not_recorded_as_success_and_is_retried(self):
        self.adapter.applied = Stage.NOMINAL
        with patch.object(self.adapter, '_run', side_effect=PumpActuatorError('denied')):
            with self.assertRaises(PumpActuatorError):
                self.adapter.apply(Stage.RELIEF)
        self.assertIsNone(self.adapter.applied)
        with patch.object(self.adapter, '_run') as run:
            self.adapter.apply(Stage.RELIEF)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(self.adapter.applied, Stage.RELIEF)

    def test_unowned_collision_refuses_replacement(self):
        foreign = json.dumps({'nftables': [{'table': {'name': TABLE, 'comment': 'someone else'}}]})
        with patch.object(self.adapter, '_exists', return_value=True), \
             patch.object(self.adapter, '_run', return_value=foreign) as run:
            with self.assertRaises(PumpActuatorError):
                self.adapter.initialize()
        self.assertTrue(all('--file' not in call.args[0] for call in run.call_args_list))

    def test_start_checks_before_atomic_replacement(self):
        with patch.object(self.adapter, '_exists', return_value=True), \
             patch.object(self.adapter, '_table', return_value=json.loads(self.table())), \
             patch.object(self.adapter, '_run') as run:
            self.adapter.initialize()
        self.assertEqual(run.call_args_list[0].args[0], ['--check', '--file', '-'])
        self.assertEqual(run.call_args_list[1].args[0], ['--file', '-'])
        script = run.call_args_list[1].args[1]
        self.assertTrue(script.startswith('delete table inet rotaryshield_pump\ncreate table'))
        self.assertEqual(self.adapter.applied, Stage.RELIEF)

    def test_counter_read_detects_deleted_or_changed_selector(self):
        self.adapter.applied = Stage.RELIEF
        with patch.object(self.adapter, '_run', return_value=self.table()):
            self.assertEqual(self.adapter.read_counters()['ssh']['passed'], 3)
        with patch.object(self.adapter, '_run', return_value=self.table(Stage.NOMINAL)):
            with self.assertRaises(PumpActuatorError):
                self.adapter.read_counters()

    def test_flushed_input_is_not_reported_as_enforced(self):
        self.adapter.applied = Stage.RELIEF
        data = json.loads(self.table())
        data['nftables'] = [entry for entry in data['nftables'] if entry.get('rule', {}).get('chain') != 'input']
        with patch.object(self.adapter, '_run', return_value=json.dumps(data)):
            with self.assertRaises(PumpActuatorError):
                self.adapter.read_counters()

    def test_failed_replacement_does_not_remove_previous_rules(self):
        with patch.object(self.adapter, '_exists', return_value=True), \
             patch.object(self.adapter, '_table', return_value=json.loads(self.table())), \
             patch.object(self.adapter, '_run', side_effect=['', PumpActuatorError('commit failed')]) as run:
            with self.assertRaises(PumpActuatorError):
                self.adapter.initialize()
            self.adapter.cleanup()
        self.assertEqual(run.call_count, 2)
        self.assertFalse(self.adapter.installed)

    def test_cleanup_only_removes_owned_table(self):
        self.adapter.installed = True
        with patch.object(self.adapter, '_exists', return_value=True), \
             patch.object(self.adapter, '_table', return_value=json.loads(self.table())), \
             patch.object(self.adapter, '_run') as run:
            self.adapter.cleanup()
        run.assert_called_once_with(['--file', '-'], 'delete table inet rotaryshield_pump\n')

    def test_process_errors_and_timeouts_are_visible(self):
        import subprocess
        self.adapter.binary = '/mock/nft'
        for failure in [subprocess.TimeoutExpired('nft', 5), OSError('unavailable')]:
            with patch('rotaryshield.pump.nftables.subprocess.run', side_effect=failure):
                with self.assertRaises(PumpActuatorError):
                    self.adapter._run(['--file', '-'], 'mock script')

    def test_lock_refuses_second_controller_and_releases(self):
        with tempfile.TemporaryDirectory() as root:
            first, second = PumpLock(root + '/pump.lock'), PumpLock(root + '/pump.lock')
            first.acquire()
            try:
                with self.assertRaises(PumpActuatorError):
                    second.acquire()
            finally:
                first.close()
            second.acquire()
            second.close()


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.pump-test-', dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.config = RotaryShieldConfig(pump=configuration())
        self.config.database.db_path = self.temp.name + '/state.db'
        self.db = DatabaseManager(self.config.database.db_path)
        self.db.initialize()
        self.addCleanup(self.db.close)
        self.sensor = Mock()
        self.sensor.read.return_value = PressureSample(0, 0.2, 0.2, 0)

    def test_observation_has_no_enforcement_or_fabricated_counters(self):
        with patch('rotaryshield.pump.runtime.NftablesPump') as factory:
            runtime = PumpRuntime(self.config, self.db, self.sensor)
            runtime.initialize()
            runtime.tick()
            factory.assert_not_called()
        self.assertEqual(runtime.snapshot['status'], 'observing')
        self.assertIsNone(runtime.snapshot['applied_stage'])
        self.assertIsNone(runtime.snapshot['services'][0]['counters'])
        runtime.cleanup()

    def test_apply_failure_visible_and_retried_instead_of_silent_success(self):
        self.config.pump.mode = 'enforce'
        actuator = Mock(applied=Stage.RELIEF)
        actuator.apply.side_effect = PumpActuatorError('denied')
        runtime = PumpRuntime(self.config, self.db, self.sensor, actuator=actuator, lock=Mock())
        runtime.initialize()
        runtime.tick()
        self.assertEqual(runtime.snapshot['status'], 'degraded')
        self.assertIsNone(runtime.snapshot['applied_stage'])
        self.assertIsNone(runtime.snapshot['services'][0]['counters'])
        actuator.apply.side_effect = lambda stage: setattr(actuator, 'applied', stage)
        actuator.read_counters.return_value = {'ssh': {'passed': 10, 'source_dropped': 4, 'capacity_dropped': 2}}
        self.sensor.read.return_value = PressureSample(1, 0.2, 0.2, 0)
        runtime.tick()
        self.assertEqual(runtime.snapshot['status'], 'enforced')
        self.assertEqual(runtime.snapshot['services'][0]['counters']['source_dropped'], 4)

    def test_sensor_failure_holds_capacity_and_reports_degradation(self):
        runtime = PumpRuntime(self.config, self.db, self.sensor)
        runtime.initialize()
        runtime.tick()
        self.sensor.read.side_effect = RuntimeError('sensor unavailable')
        runtime.tick()
        self.assertEqual(runtime.snapshot['status'], 'degraded')
        self.assertEqual(runtime.snapshot['desired_stage'], 'relief')
        self.assertIsNone(runtime.snapshot['signals'])

    def test_cleanup_failure_is_persisted_and_lock_released(self):
        self.config.pump.mode = 'enforce'
        actuator, lock = Mock(applied=Stage.RELIEF), Mock()
        actuator.cleanup.side_effect = PumpActuatorError('remove denied')
        runtime = PumpRuntime(self.config, self.db, self.sensor, actuator=actuator, lock=lock)
        runtime.initialize()
        with self.assertRaises(PumpActuatorError):
            runtime.cleanup()
        self.assertEqual(runtime.snapshot['status'], 'cleanup_failed')
        lock.close.assert_called_once()

    def test_start_failure_preserves_error_and_does_not_clean_twice(self):
        self.config.pump.mode = 'enforce'
        actuator, lock = Mock(applied=None), Mock()
        actuator.initialize.side_effect = PumpActuatorError('cannot install')
        runtime = PumpRuntime(self.config, self.db, self.sensor, actuator=actuator, lock=lock)
        with self.assertRaises(PumpActuatorError):
            runtime.initialize()
        runtime.cleanup()
        self.assertEqual(runtime.snapshot['status'], 'initialization_failed')
        actuator.cleanup.assert_called_once()
        lock.close.assert_called_once()

    def test_daemon_starts_pressure_thread_and_joins_it_before_database_close(self):
        import threading
        from rotaryshield.security.engine import SecurityEngine
        from tests.unit.test_runtime_basics import FakeFirewall
        log = Path(self.temp.name) / 'auth.log'
        log.write_text('')
        self.config.detection.log_files = [str(log)]
        self.config.detection.patterns = {'ssh_failed': r'Failed from (\S+)'}
        seen = threading.Event()
        def sample():
            seen.set()
            return PressureSample(time.monotonic(), 0.2, 0.2, 0)
        with patch('rotaryshield.security.engine.ConfigManager.load_config', return_value=self.config), \
             patch('rotaryshield.security.engine.FirewallManager', return_value=FakeFirewall()), \
             patch('rotaryshield.pump.runtime.HostPressureSensor.read', side_effect=sample), \
             patch('rotaryshield.pump.runtime.NftablesPump') as actuator:
            engine = SecurityEngine()
            engine.initialize()
            try:
                engine.start()
                self.assertTrue(seen.wait(1))
            finally:
                engine.shutdown()
            self.assertFalse(engine._pump_thread.is_alive())
            actuator.assert_not_called()
        row = self.db.execute_query("SELECT value FROM database_metadata WHERE key = 'pump_status'")
        self.assertEqual(json.loads(row['value'])['status'], 'stopped')

    def test_cli_shows_stale_status_and_returns_failure(self):
        runtime = PumpRuntime(self.config, self.db, self.sensor)
        runtime.initialize()
        runtime.tick()
        with patch('rotaryshield.pump.__main__.ConfigManager.load_config', return_value=self.config), \
             patch('rotaryshield.pump.__main__.time.time', return_value=time.time() + 60), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(['status', '--json'])
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(output.getvalue())['stale'])

    def test_host_sensor_uses_host_cpu_and_queue_pressure(self):
        queue = Mock(maxsize=100)
        queue.qsize.return_value = 90
        with patch('rotaryshield.pump.runtime.psutil.cpu_percent', return_value=25), \
             patch('rotaryshield.pump.runtime.psutil.virtual_memory', return_value=Mock(percent=50)):
            sample = HostPressureSensor(queue).read()
        self.assertEqual((sample.cpu, sample.memory, sample.queue), (0.25, 0.5, 0.9))


if __name__ == '__main__':
    unittest.main()
