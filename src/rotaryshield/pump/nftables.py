"""nftables actuator for new inbound TCP SYNs to explicitly selected host ports.

Only our inet table is changed. Transactions cover both IP families. Persistent
source buckets and stage chains survive stage changes; selecting a stage never
flushes their tokens or counters. Rules are derived from Netfilter's documented
dynamic sets, limit statements, and atomic `nft -f` batches.
"""
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict

from .controller import Stage, rate_for

TABLE = 'rotaryshield_pump'
OWNER = 'rotaryshield:pump:v1:'


class PumpActuatorError(RuntimeError):
    pass


def _networks(whitelist):
    return sorted({str(ipaddress.ip_network(address, strict=False))
                   for address in list(whitelist) + ['127.0.0.0/8', '::1/128']})


def marker(config, whitelist):
    data = json.dumps({'config': asdict(config), 'whitelist': _networks(whitelist)}, sort_keys=True)
    return OWNER + hashlib.sha256(data.encode()).hexdigest()[:20]


def render_install(config, whitelist, stage=Stage.RELIEF, replace=False):
    """Pure renderer: no system calls, no shell interpolation, validated scalars."""
    config.validate()
    stage = Stage(stage)
    prefix = 'inet ' + TABLE
    lines = ['delete table ' + prefix] if replace else []
    lines.append('create table %s { comment "%s"; }' % (prefix, marker(config, whitelist)))
    lines.append('add chain %s input { type filter hook input priority -10; policy accept; }' % prefix)
    # Whitelisting returns to the remaining system firewall; it is not an ACCEPT
    # exception for bans or another firewall's access policy.
    lines.append('add rule %s input iifname "lo" return' % prefix)
    for address in _networks(whitelist):
        family = 'ip' if ipaddress.ip_network(address).version == 4 else 'ip6'
        lines.append('add rule %s input %s saddr %s return' % (prefix, family, address))

    for index, service in enumerate(config.services):
        for counter in ('passed', 'source_dropped', 'capacity_dropped'):
            lines.append('add counter %s %s_%d' % (prefix, counter, index))
        for chain in ('source_%d' % index, 'ceiling_%d' % index, 'gate_%d' % index):
            lines.append('add chain %s %s' % (prefix, chain))
        # This bucket is shared across all stages, so cycling stage-specific
        # buckets cannot exceed the configured overall rate + burst envelope.
        lines.append('add rule %s ceiling_%d limit rate over %d/second burst %d packets '
                     'counter name capacity_dropped_%d drop' %
                     (prefix, index, service.rate, service.burst, index))
        lines.append('add rule %s ceiling_%d goto gate_%d' % (prefix, index, index))
        for level in Stage:
            chain = 'flow_%d_%s' % (index, level.name.lower())
            lines.append('add chain %s %s' % (prefix, chain))
            lines.append('add rule %s %s limit rate over %d/second burst %d packets '
                         'counter name capacity_dropped_%d drop' %
                         (prefix, chain, rate_for(service, level), service.burst, index))
            lines.append('add rule %s %s counter name passed_%d return' % (prefix, chain, index))
        lines.append('add rule %s gate_%d goto flow_%d_%s' % (prefix, index, index, stage.name.lower()))
        for version, family, addrtype in ((4, 'ip', 'ipv4_addr'), (6, 'ip6', 'ipv6_addr')):
            name = 'sources%d_%d' % (version, index)
            lines.append('add set %s %s { type %s; flags dynamic,timeout; timeout %ds; size %d; }' %
                         (prefix, name, addrtype, config.source_timeout, config.max_sources))
            # Match UNDER the limit and goto; an exhausted/full set falls through
            # to DROP, never bypassing the global cap or allocating unboundedly.
            lines.append('add rule %s source_%d meta nfproto ipv%d update @%s '
                         '{ %s saddr limit rate %d/second burst %d packets } goto ceiling_%d' %
                         (prefix, index, version, name, family, service.per_source_rate,
                          service.per_source_burst, index))
        lines.append('add rule %s source_%d counter name source_dropped_%d drop' % (prefix, index, index))
        lines.append('add rule %s input ct state new tcp flags & (fin | syn | rst | ack) == syn '
                     'tcp dport %d jump source_%d' % (prefix, service.port, index))
    return '\n'.join(lines) + '\n'


def render_stage(config, stage):
    stage = Stage(stage)
    lines = []
    for index, _ in enumerate(config.services):
        lines.extend(['flush chain inet %s gate_%d' % (TABLE, index),
                      'add rule inet %s gate_%d goto flow_%d_%s' % (TABLE, index, index, stage.name.lower())])
    return '\n'.join(lines) + '\n'


class PumpLock:
    """One pump controller per daemon PID path, including the release command."""
    def __init__(self, path):
        self.path = path
        self.fd = None

    def acquire(self):
        import fcntl
        if self.fd is not None:
            raise PumpActuatorError('Pump lock already acquired')
        # Parent is the configured, administrator-owned runtime directory.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(fd)
            raise PumpActuatorError('Another pump controller holds ' + self.path) from error
        self.fd = fd

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class NftablesPump:
    def __init__(self, config, whitelist):
        self.config = config
        self.whitelist = whitelist
        self.applied = None
        self.installed = False
        self.binary = None

    def _run(self, args, script=None):
        if self.binary is None:
            if sys.platform != 'linux':
                raise PumpActuatorError('Pump enforcement requires Linux and nftables')
            self.binary = shutil.which('nft')
            if not self.binary:
                raise PumpActuatorError('nft executable not found')
        try:
            result = subprocess.run([self.binary] + args, input=script, text=True,
                                    capture_output=True, timeout=5, check=False,
                                    env={**os.environ, 'LC_ALL': 'C'})
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PumpActuatorError('nft command failed or timed out; applied state may be unknown') from error
        if result.returncode:
            raise PumpActuatorError('nft failed: ' + result.stderr.strip()[:500])
        return result.stdout

    def _exists(self):
        result = json.loads(self._run(['-j', '-t', 'list', 'tables', 'inet']))
        return any(entry.get('table', {}).get('name') == TABLE for entry in result['nftables'])

    def _table(self):
        result = json.loads(self._run(['-j', '-t', 'list', 'table', 'inet', TABLE]))
        table = next((entry['table'] for entry in result['nftables'] if 'table' in entry), {})
        if not table.get('comment', '').startswith(OWNER):
            raise PumpActuatorError('Refusing to modify a table without RotaryShield ownership marker')
        return result

    def initialize(self, stage=Stage.RELIEF):
        exists = self._exists()
        if exists:
            self._table()  # Refuse unrelated tables with a colliding name.
        script = render_install(self.config, self.whitelist, stage, replace=exists)
        self._run(['--check', '--file', '-'], script)
        # On failure, retain any pre-existing rules. A timeout is ambiguous; do
        # not delete an old protective table just because startup did not finish.
        self._run(['--file', '-'], script)
        self.installed = True
        self.applied = Stage(stage)
        self.read_counters()

    def apply(self, stage):
        stage = Stage(stage)
        if stage == self.applied:
            return
        try:
            self._run(['--file', '-'], render_stage(self.config, stage))
        except Exception:
            self.applied = None
            raise
        self.applied = stage

    def read_counters(self):
        data = self._table()
        table = next(entry['table'] for entry in data['nftables'] if 'table' in entry)
        if table.get('comment') != marker(self.config, self.whitelist):
            raise PumpActuatorError('Pump table configuration changed externally')
        rules = [entry['rule'] for entry in data['nftables'] if 'rule' in entry]
        base = next((entry['chain'] for entry in data['nftables']
                     if entry.get('chain', {}).get('name') == 'input'), {})
        if any(base.get(key) != value for key, value in
               {'type': 'filter', 'hook': 'input', 'prio': -10, 'policy': 'accept'}.items()):
            raise PumpActuatorError('Pump input hook missing or changed externally')
        # Detect accidental flushes of the entry or limiting chains, even when
        # named counters and the stage selector survived.
        expected = {'input': 1 + len(_networks(self.whitelist)) + len(self.config.services)}
        for index in range(len(self.config.services)):
            expected.update({'source_%d' % index: 3, 'ceiling_%d' % index: 2})
            expected.update({'flow_%d_%s' % (index, level.name.lower()): 2 for level in Stage})
        for chain, count in expected.items():
            if sum(rule['chain'] == chain for rule in rules) != count:
                raise PumpActuatorError('Pump rule count changed externally: ' + chain)
        counters = {entry['counter']['name']: entry['counter'] for entry in data['nftables'] if 'counter' in entry}
        result = {}
        for index, service in enumerate(self.config.services):
            selector = [rule for rule in rules if rule['chain'] == 'gate_%d' % index]
            target = 'flow_%d_%s' % (index, self.applied.name.lower()) if self.applied is not None else None
            if len(selector) != 1 or selector[0]['expr'] != [{'goto': {'target': target}}]:
                raise PumpActuatorError('Pump selector missing or changed externally')
            result[service.name] = {}
            for name in ('passed', 'source_dropped', 'capacity_dropped'):
                key = '%s_%d' % (name, index)
                if key not in counters:
                    raise PumpActuatorError('Pump counter missing: ' + key)
                result[service.name][name] = counters[key]['packets']
        return result

    def release(self):
        if self._exists():
            self._table()
            self._run(['--file', '-'], 'delete table inet %s\n' % TABLE)
        self.applied = None
        self.installed = False

    def cleanup(self):
        if self.installed:
            self.release()
