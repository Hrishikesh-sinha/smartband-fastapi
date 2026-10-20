"""Storage: readings, per-device sequence state, security events, dashboard users.

PostgreSQL is used when the DATABASE_URL environment variable is set (Render cloud);
otherwise a local SQLite file is used (laptop development).

Device HMAC secrets are NOT stored here (see device_auth.py), so a copy of this
database never contains the keys that sign readings.
"""
import os
import sqlite3
import time

DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
SQLITE_PATH = os.environ.get("SMARTBAND_DB", os.path.join(os.path.dirname(__file__), "smartband.db"))

if USE_PG:
    import psycopg
    from psycopg.rows import dict_row

ID = "BIGSERIAL PRIMARY KEY" if USE_PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
SCHEMA = [
    f"""CREATE TABLE IF NOT EXISTS readings (
        id          {ID},
        device_id   TEXT    NOT NULL,
        seq         BIGINT  NOT NULL,
        pulse_bpm   INTEGER,
        mq135_raw   INTEGER NOT NULL,
        received_at BIGINT  NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS device_state (
        device_id   TEXT PRIMARY KEY,
        last_seq    BIGINT NOT NULL DEFAULT 0,
        last_seen   BIGINT)""",
    f"""CREATE TABLE IF NOT EXISTS security_events (
        id          {ID},
        at          BIGINT NOT NULL,
        event_type  TEXT   NOT NULL,
        device_id   TEXT,
        detail      TEXT,
        client_ip   TEXT)""",
    """CREATE TABLE IF NOT EXISTS dashboard_users (
        username    TEXT PRIMARY KEY,
        token_hash  TEXT NOT NULL UNIQUE)""",
    "CREATE INDEX IF NOT EXISTS idx_readings_dev ON readings(device_id, id)",
]


class Conn:
    """Thin wrapper so the same SQL (with ? placeholders) runs on SQLite and PostgreSQL."""

    def __init__(self):
        if USE_PG:
            self.c = psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=False)
        else:
            self.c = sqlite3.connect(SQLITE_PATH, timeout=10, isolation_level=None)
            self.c.row_factory = sqlite3.Row

    def execute(self, sql, params=()):
        if USE_PG:
            sql = sql.replace("?", "%s")
        return self.c.execute(sql, params)

    def begin(self):
        if not USE_PG:
            self.c.execute("BEGIN IMMEDIATE")   # SQLite: take the write lock up front

    def commit(self):
        if USE_PG:
            self.c.commit()
        else:
            self.c.execute("COMMIT")

    def rollback(self):
        if USE_PG:
            self.c.rollback()
        elif self.c.in_transaction:
            self.c.execute("ROLLBACK")

    def close(self):
        if USE_PG:
            self.c.commit()   # end the implicit transaction PostgreSQL opens for every statement
        self.c.close()


def connect():
    return Conn()


def init_db():
    con = connect()
    for stmt in SCHEMA:
        con.execute(stmt)
    con.close()


def log_event(event_type, device_id=None, detail=None, client_ip=None):
    """Record a security event. Never pass secrets or full sensor payloads here."""
    con = connect()
    con.execute(
        "INSERT INTO security_events(at, event_type, device_id, detail, client_ip) VALUES (?,?,?,?,?)",
        (int(time.time()), event_type, (device_id or "")[:64] or None, (detail or "")[:200] or None, client_ip),
    )
    con.close()


def store_reading_if_new(device_id, seq, pulse_bpm, mq135_raw):
    """Atomically accept a new sequence number and store the reading.

    The conditional UPDATE (... WHERE last_seq < seq) is one atomic step in both databases:
    PostgreSQL locks the row, SQLite holds the write lock. Two simultaneous requests with the
    same sequence number therefore cannot both succeed.
    Returns (True, seq) if stored, (False, last_seq) if rejected as a replay.
    """
    con = connect()
    now = int(time.time())
    try:
        con.begin()
        con.execute("INSERT INTO device_state(device_id, last_seq) VALUES (?, 0) ON CONFLICT(device_id) DO NOTHING",
                    (device_id,))
        cur = con.execute("UPDATE device_state SET last_seq=?, last_seen=? WHERE device_id=? AND last_seq<?",
                          (seq, now, device_id, seq))
        if cur.rowcount != 1:
            row = con.execute("SELECT last_seq FROM device_state WHERE device_id=?", (device_id,)).fetchone()
            con.rollback()
            return False, row["last_seq"]
        con.execute("INSERT INTO readings(device_id, seq, pulse_bpm, mq135_raw, received_at) VALUES (?,?,?,?,?)",
                    (device_id, seq, pulse_bpm, mq135_raw, now))
        con.commit()
        return True, seq
    except Exception:
        con.rollback()
        raise
    finally:
        con.c.close()
