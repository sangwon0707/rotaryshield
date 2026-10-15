"""Coordinate persistent bans with the firewall, shared by the daemon and CLI.

SQLite's write lock serializes mutations across processes. Firewall operations
cannot be part of a SQLite transaction, so failures roll back the database and
commit failures trigger a compensating firewall operation. Reconciliation retries
unfinished expiry/removal and restores active rules after restart.
"""

import ipaddress
import logging
import time


class BanOperationError(RuntimeError):
    pass


def select_backend(database, configured):
    """Keep pending rules on the backend that originally enforced them."""
    saved = database.execute_query("SELECT value FROM database_metadata WHERE key = 'firewall_backend'")
    pending = database.execute_query("SELECT COUNT(*) AS n FROM ip_bans WHERE status = 'active'")['n']
    if saved and pending:
        if configured != 'auto' and configured != saved['value']:
            raise BanOperationError("Active bans belong to backend " + saved['value'])
        return saved['value']
    return None if configured == 'auto' else configured


def remember_backend(database, backend):
    database.execute_query(
        "INSERT OR REPLACE INTO database_metadata (key, value, updated_at) VALUES ('firewall_backend', ?, ?)",
        (backend, time.time()))


class BanController:
    def __init__(self, database, firewall, whitelist=()):
        self.database = database
        self.firewall = firewall
        self.whitelist = tuple(ipaddress.ip_network(ip, strict=False)
                               for ip in list(whitelist) + ['127.0.0.0/8', '::1/128'])
        self.logger = logging.getLogger(__name__)

    def is_whitelisted(self, address):
        ip = ipaddress.ip_address(address)
        return any(ip in network for network in self.whitelist)

    def records(self):
        # Do not hide database failures behind an empty (apparently safe) result.
        rows = self.database.execute_query(
            "SELECT * FROM ip_bans ORDER BY created_at DESC", fetch_all=True)
        return [dict(row) for row in rows]

    def ban(self, address, duration, reason):
        address = str(ipaddress.ip_address(address))
        if self.is_whitelisted(address):
            return False
        if not isinstance(duration, int) or not 0 < duration <= 31536000:
            raise ValueError("Invalid ban duration")
        changed = False
        was_active = False
        with self.database._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM ip_bans WHERE ip_address = ?", (address,)).fetchone()
                now = time.time()
                was_active = row is not None and row['status'] == 'active' and row['expires_at'] > now
                if not was_active:
                    count = row['ban_count'] + 1 if row else 1
                    conn.execute(
                        """INSERT OR REPLACE INTO ip_bans
                        (ip_address, ban_reason, ban_duration, created_at, expires_at,
                         updated_at, status, ban_count, created_by)
                        VALUES (?, ?, ?, ?, ?, ?, 'active', ?, 'rotaryshield')""",
                        (address, reason, duration, now, now + duration, now, count))
                if not self.firewall.block_ip(address, comment="RotaryShield"):
                    raise BanOperationError("Firewall did not confirm blocking " + address)
                changed = True
                self._audit(conn, address, 'ip_banned', reason)
                conn.commit()
                return True
            except Exception:
                conn.rollback()
                if changed and not was_active and not self.firewall.unblock_ip(address):
                    self.logger.critical("Database rollback left a firewall rule for %s", address)
                raise

    def unban(self, address, reason="Manual unban", expired=False):
        address = str(ipaddress.ip_address(address))
        changed = False
        restore = False
        with self.database._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM ip_bans WHERE ip_address = ?", (address,)).fetchone()
                if row is None:
                    conn.commit()
                    return True
                # Re-read under the write lock: a CLI action may have renewed the ban.
                if expired and (row['status'] != 'active' or row['expires_at'] > time.time()):
                    conn.commit()
                    return True
                restore = row['status'] == 'active'
                if not self.firewall.unblock_ip(address):
                    raise BanOperationError("Firewall did not confirm unblocking " + address)
                changed = True
                status = 'expired' if expired else 'manually_removed'
                conn.execute(
                    "UPDATE ip_bans SET status = ?, updated_at = ?, removed_reason = ? WHERE ip_address = ?",
                    (status, time.time(), reason, address))
                self._audit(conn, address, 'ip_unbanned', reason)
                conn.commit()
                return True
            except Exception:
                conn.rollback()
                if changed and restore and not self.firewall.block_ip(address, comment="RotaryShield"):
                    self.logger.critical("Could not restore firewall rule after database failure: %s", address)
                raise

    def reconcile(self, restore=False):
        """Expire due bans; optionally restore active rules. Return enforced IPs."""
        failures = []
        for row in self.records():
            try:
                address = row['ip_address']
                if row['status'] != 'active':
                    continue
                if self.is_whitelisted(address):
                    self.unban(address, "Whitelisted IP")
                elif row['expires_at'] <= time.time():
                    self.unban(address, "Ban expired", expired=True)
                elif restore:
                    # Re-check under the write lock; never renew a removed/expired ban.
                    with self.database._get_connection() as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        try:
                            current = conn.execute(
                                "SELECT status, expires_at FROM ip_bans WHERE ip_address = ?", (address,)).fetchone()
                            if current and current['status'] == 'active' and current['expires_at'] > time.time():
                                if not self.firewall.block_ip(address, comment="RotaryShield"):
                                    raise BanOperationError("Could not restore ban: " + address)
                            conn.commit()
                        except Exception:
                            conn.rollback()
                            raise
            except Exception as error:
                failures.append(str(error))
                self.logger.error("Ban reconciliation failed: %s", error)
        if failures:
            raise BanOperationError("; ".join(failures))
        return {row['ip_address'] for row in self.records()
                if row['status'] == 'active' and row['expires_at'] > time.time()}

    @staticmethod
    def _audit(conn, address, action, description):
        conn.execute(
            """INSERT INTO audit_logs (timestamp, action, user_id, ip_address, description)
            VALUES (?, ?, 'rotaryshield', ?, ?)""",
            (time.time(), action, address, description))
