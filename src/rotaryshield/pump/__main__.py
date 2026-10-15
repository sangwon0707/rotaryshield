"""CLI for pump status, offline rules/replay and explicit stale-rule removal."""
import argparse
import json
import sys
import time
from pathlib import Path

from ..config import ConfigManager
from ..database.manager import DatabaseManager
from .controller import Stage
from .nftables import NftablesPump, PumpLock, render_install
from .runtime import LOCK_PATH
from .simulation import replay


def main(argv=None):
    parser = argparse.ArgumentParser(description='RotaryShield pump admission controller')
    parser.add_argument('command', choices=['status', 'plan', 'demo', 'release'])
    parser.add_argument('--config', '-c')
    parser.add_argument('--json', action='store_true', help='Machine-readable status or demo')
    parser.add_argument('--stage', choices=['nominal', 'regulated', 'relief'], default='relief',
                        help='Stage for the offline plan (default: slow start)')
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            rows = replay()
            if args.json:
                print(json.dumps(rows, indent=2))
            else:
                print('RotaryShield pump | OFFLINE pressure replay (no packets or firewall changes)')
                print(' time   CPU   pressure   stage       proposed SYN/s')
                for row in rows:
                    if row['changed'] or row['second'] % 10 == 0:
                        print('%4ds   %3d%%     %3d%%     %-10s  %3d  %s' %
                              (row['second'], row['cpu'] * 100, row['pressure'] * 100,
                               row['stage'], row['rate'], row['reason']))
                print('Synthetic inputs; 6s recovery windows for demonstration. Not an effectiveness benchmark.')
            return 0
        config = ConfigManager(args.config).load_config()
        if args.command == 'plan':
            if not config.pump.services:
                raise ValueError('Configure pump.services before rendering rules')
            print(render_install(config.pump, config.ban.whitelist_ips, Stage[args.stage.upper()]), end='')
            return 0
        if args.command == 'release':
            lock = PumpLock(LOCK_PATH)
            lock.acquire()
            try:
                NftablesPump(config.pump, config.ban.whitelist_ips).release()
            finally:
                lock.close()
            print('Owned pump table removed. Existing ban rules remain managed by the ban engine.')
            return 0
        if not Path(config.database.db_path).is_file():
            raise ValueError('No daemon database; no recorded pump status')
        database = DatabaseManager(config.database.db_path)
        try:
            row = database.execute_query("SELECT value FROM database_metadata WHERE key = 'pump_status'")
        finally:
            database.close()
        if not row:
            raise ValueError('No pump status recorded; start the daemon first')
        snapshot = json.loads(row['value'])
        age = time.time() - snapshot['updated_at']
        snapshot['stale'] = age < 0 or age > max(15, 3 * snapshot['sample_interval'])
        snapshot['age_seconds'] = round(age, 1)
        if args.json:
            print(json.dumps(snapshot, indent=2))
        else:
            print('Recorded pump status (no live firewall query):')
            print('mode=%s status=%s%s age=%.1fs' % (snapshot['mode'], snapshot['status'],
                  ' STALE' if snapshot['stale'] else '', age))
            print('desired=%s applied=%s pressure=%.0f%%; %s' % (snapshot['desired_stage'],
                  snapshot['applied_stage'] or 'unconfirmed', 100 * snapshot['pressure'], snapshot['reason']))
            for service in snapshot['services']:
                print('%s tcp/%d: proposed=%d SYN/s applied=%s burst=%d source=%d/s counters=%s' % (
                    service['name'], service['port'], service['desired_rate'],
                    service['applied_rate'] if service['applied_rate'] is not None else 'unconfirmed',
                    service['burst'], service['per_source_rate'], service['counters']))
        return 1 if snapshot['stale'] or snapshot['status'] in ('degraded', 'cleanup_failed', 'initialization_failed') else 0
    except Exception as error:
        print('Pump: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
