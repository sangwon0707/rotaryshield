"""Pure pressure controller. No network, firewall or wall-clock dependencies.

The pump analogy is a design aid: displacement becomes bounded admission,
pressure becomes measured saturation, and relief sheds excess work. A rotary
pump alone does not provide this feedback controller.
"""
import math
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class Stage(IntEnum):
    NOMINAL = 0
    REGULATED = 1
    RELIEF = 2


@dataclass(frozen=True)
class PressureSample:
    timestamp: float  # monotonic seconds
    cpu: float        # fractions in [0, 1], whole host
    memory: float
    queue: float      # RotaryShield's event queue occupancy

    def validate(self):
        if not math.isfinite(self.timestamp):
            raise ValueError("Invalid sample timestamp")
        for name in ("cpu", "memory", "queue"):
            value = getattr(self, name)
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("Invalid pressure signal: " + name)


@dataclass(frozen=True)
class Decision:
    stage: Stage
    pressure: float
    reason: str
    changed: bool


class PressureController:
    def __init__(self, config):
        self.config = config
        # Slow start also prevents a restart from relaxing an old relief limit.
        self.stage = Stage.RELIEF
        self.pressure = 0.0
        self._last_sample: Optional[float] = None
        self._low_since: Optional[float] = None

    def sensor_failed(self):
        # Missing samples are not evidence of recovery.
        self._low_since = None
        self._last_sample = None

    def update(self, sample: PressureSample) -> Decision:
        try:
            sample.validate()
            if self._last_sample is not None and sample.timestamp <= self._last_sample:
                raise ValueError("Pressure samples must advance monotonically")
        except (TypeError, ValueError):
            self.sensor_failed()
            raise
        raw = max(sample.cpu, sample.memory, sample.queue)
        previous = self.stage
        elapsed = None if self._last_sample is None else sample.timestamp - self._last_sample
        if elapsed is None or elapsed > self.config.sample_interval * 3:
            self.pressure = raw
            self._low_since = None
        else:
            # Time-based smoothing is independent of the configured sample rate.
            alpha = 1 - math.exp(-elapsed / self.config.smoothing_seconds)
            self.pressure += alpha * (raw - self.pressure)
        self._last_sample = sample.timestamp

        if raw >= self.config.relief_pressure:
            self.stage = Stage.RELIEF
            self._low_since = None
            reason = "critical pressure: " + max(
                ("cpu", "memory", "queue"), key=lambda key: getattr(sample, key))
        elif self.pressure >= self.config.high_pressure:
            self.stage = max(self.stage, Stage.REGULATED)
            self._low_since = None
            reason = "sustained high pressure"
        elif raw <= self.config.low_pressure and self.pressure <= self.config.low_pressure:
            if self._low_since is None:
                self._low_since = sample.timestamp
            if self.stage > Stage.NOMINAL and sample.timestamp - self._low_since >= self.config.recovery_seconds:
                self.stage = Stage(self.stage - 1)
                self._low_since = sample.timestamp
                reason = "stable low pressure: recover one stage"
            else:
                reason = "healthy" if self.stage == Stage.NOMINAL else "waiting for stable recovery"
        else:
            self._low_since = None
            reason = "holding within hysteresis band"
        return Decision(self.stage, self.pressure, reason, previous != self.stage)


def rate_for(service, stage: Stage) -> int:
    if stage == Stage.RELIEF:
        return service.minimum_rate
    if stage == Stage.REGULATED:
        return max(service.minimum_rate, service.rate // 2)
    return service.rate
