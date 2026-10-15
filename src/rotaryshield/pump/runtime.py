"""Connect the pure controller to host sensors, nftables and persisted status."""
import json
import logging
import time

import psutil

from .controller import PressureController, PressureSample, rate_for
from .nftables import NftablesPump, PumpLock

LOCK_PATH = '/run/rotaryshield/pump.lock'


class HostPressureSensor:
    def __init__(self, event_queue):
        self.event_queue = event_queue

    def read(self):
        # Measure the HOST, not this Python process. A short explicit interval
        # avoids psutil's meaningless first non-blocking CPU sample.
        cpu = psutil.cpu_percent(interval=0.1) / 100
        memory = psutil.virtual_memory().percent / 100
        occupancy = self.event_queue.qsize() / self.event_queue.maxsize
        return PressureSample(time.monotonic(), cpu, memory, min(1.0, occupancy))


class PumpRuntime:
    def __init__(self, config, database, sensor, actuator=None, lock=None):
        self.config = config.pump
        self.database = database
        self.sensor = sensor
        self.controller = PressureController(self.config)
        self.actuator = actuator if actuator is not None else (
            NftablesPump(self.config, config.ban.whitelist_ips) if self.config.mode == 'enforce' else None)
        self.lock = lock if lock is not None else PumpLock(LOCK_PATH)
        self.logger = logging.getLogger(__name__)
        self.snapshot = {}
        self._last_status = None
        self._last_stage = None
        self._closed = False

    def initialize(self):
        if self.config.mode == 'enforce':
            try:
                self.lock.acquire()
            except Exception:
                # Do not overwrite the running controller's status or clean up
                # its table when a second process fails to acquire ownership.
                self._closed = True
                raise
            try:
                self._publish('starting', 'slow start; application unconfirmed')
                self.actuator.initialize(self.controller.stage)
            except Exception as error:
                try:
                    self.actuator.cleanup()
                finally:
                    self.lock.close()
                    self._closed = True
                    self.actuator.applied = None
                    self._publish('initialization_failed', str(error) + '; residual owned rules may remain')
                raise
        else:
            self._publish('off' if self.config.mode == 'off' else 'starting', 'slow start; application unconfirmed')

    def tick(self):
        if self.config.mode == 'off':
            return
        sample = None
        counters = None
        try:
            sample = self.sensor.read()
            decision = self.controller.update(sample)
            if self.actuator is not None:
                self.actuator.apply(decision.stage)
                counters = self.actuator.read_counters()
            status = 'enforced' if self.config.mode == 'enforce' else 'observing'
            reason = decision.reason
        except Exception as error:
            self.controller.sensor_failed()
            status, reason = 'degraded', str(error)
            # Never report unconfirmed application or count failed calls as drops.
            if self.actuator is not None:
                self.actuator.applied = None
        self._publish(status, reason, sample, counters)

    def _publish(self, status, reason, sample=None, counters=None):
        applied = self.actuator.applied if self.actuator is not None else None
        self.snapshot = {
            'mode': self.config.mode, 'status': status, 'updated_at': time.time(),
            'sample_interval': self.config.sample_interval,
            'desired_stage': self.controller.stage.name.lower(),
            'applied_stage': applied.name.lower() if applied is not None else None,
            'pressure': self.controller.pressure, 'reason': reason,
            'signals': ({key: getattr(sample, key) for key in ('cpu', 'memory', 'queue')}
                        if sample is not None and status != 'degraded' else None),
            'services': [{
                'name': service.name, 'port': service.port,
                'desired_rate': rate_for(service, self.controller.stage),
                'applied_rate': rate_for(service, applied) if applied is not None else None,
                'burst': service.burst, 'per_source_rate': service.per_source_rate,
                'counters': counters.get(service.name) if counters is not None else None,
            } for service in self.config.services],
        }
        value = json.dumps(self.snapshot, allow_nan=False)
        self.database.execute_query(
            "INSERT OR REPLACE INTO database_metadata (key, value, updated_at) VALUES ('pump_status', ?, ?)",
            (value, self.snapshot['updated_at']))
        if status != self._last_status or self.controller.stage != self._last_stage:
            self.logger.log(logging.ERROR if status == 'degraded' else logging.INFO,
                            'Pump %s: desired=%s applied=%s; %s', status,
                            self.snapshot['desired_stage'], self.snapshot['applied_stage'], reason)
            self._last_status, self._last_stage = status, self.controller.stage

    def cleanup(self):
        if self._closed:
            return
        try:
            if self.actuator is not None:
                try:
                    self.actuator.cleanup()
                except Exception as error:
                    self.actuator.applied = None
                    self._publish('cleanup_failed', str(error))
                    raise
            self._publish('stopped', 'controller stopped; pump rules removed' if self.actuator else 'controller stopped')
        finally:
            self.lock.close()
            self._closed = True
