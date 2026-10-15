"""Deterministic offline pressure replay. This is not a network benchmark."""
from ..config import PumpConfig, PumpServiceConfig
from .controller import PressureController, PressureSample, rate_for


def replay():
    config = PumpConfig(mode='observe', sample_interval=2, recovery_seconds=6,
                        smoothing_seconds=2, services=[PumpServiceConfig()])
    config.validate()
    controller = PressureController(config)
    rows = []
    for second in range(0, 66, 2):
        cpu = 0.25 if second < 18 or second >= 40 else (0.85 if second < 28 else 0.98)
        decision = controller.update(PressureSample(float(second), cpu, 0.30, 0.0))
        rows.append({'second': second, 'cpu': cpu, 'pressure': round(decision.pressure, 3),
                     'stage': decision.stage.name.lower(), 'changed': decision.changed,
                     'rate': rate_for(config.services[0], decision.stage), 'reason': decision.reason})
    return rows
