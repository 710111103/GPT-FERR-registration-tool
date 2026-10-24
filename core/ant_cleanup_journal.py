"""Durable retry queue for cleanup explicitly requested by the owning task.
Never infers abandoned tasks from browser names, age, or account state.
"""
import sqlite3
import time
import threading
import os
from contextlib import closing
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "ant_cleanup.sqlite3"
_LOCK = threading.Lock()
_STARTED = False

def connect():
    c = sqlite3.connect(str(_PATH), timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS cleanup (base TEXT, profile_id TEXT, state TEXT, attempts INTEGER DEFAULT 0, due REAL DEFAULT 0, error TEXT DEFAULT '', owner_pid INTEGER DEFAULT 0, PRIMARY KEY(base,profile_id))")
    columns = {row[1] for row in c.execute("PRAGMA table_info(cleanup)")}
    if "owner_pid" not in columns:
        c.execute("ALTER TABLE cleanup ADD COLUMN owner_pid INTEGER DEFAULT 0")
    c.commit()
    return c

def record_owned(base, pid):
    """Persist ownership immediately after create so a process crash can be recovered."""
    with closing(connect()) as c, c:
        c.execute(
            "INSERT INTO cleanup(base,profile_id,state,owner_pid,due,error) VALUES(?,?,'active',?,0,'') "
            "ON CONFLICT(base,profile_id) DO UPDATE SET state='active',owner_pid=excluded.owner_pid,due=0,error=''",
            (base, pid, os.getpid()),
        )

def recover_previous_process():
    """Queue Ant profiles owned by an earlier application process for deletion."""
    with closing(connect()) as c, c:
        cur = c.execute(
            "UPDATE cleanup SET state='pending',due=0,error='owner_process_exited' "
            "WHERE state='active' AND owner_pid!=?",
            (os.getpid(),),
        )
        return int(cur.rowcount or 0)

def claim(base, pid):
    with closing(connect()) as c, c:
        c.execute("BEGIN IMMEDIATE")
        c.execute("INSERT OR IGNORE INTO cleanup(base,profile_id,state) VALUES(?,?,'pending')",(base,pid))
        row=c.execute("SELECT * FROM cleanup WHERE base=? AND profile_id=?",(base,pid)).fetchone()
        if row["state"] == "done" or (row["state"] == "working" and row["due"] > time.time()):
            return False
        c.execute("UPDATE cleanup SET state='working',attempts=attempts+1,due=? WHERE base=? AND profile_id=?",(time.time()+900,base,pid))
        return True

def finish(base,pid,error=None):
    with closing(connect()) as c, c:
        c.execute("UPDATE cleanup SET state=?,error=?,due=? WHERE base=? AND profile_id=?",("pending" if error else "done",type(error).__name__ if error else "",time.time()+60 if error else 0,base,pid))

def pending():
    """Return only cleanup work explicitly queued by an owner.

    ``active`` means the current process still owns and may be using the Ant
    profile.  Treating it as pending allowed the recovery worker to close a
    live login browser every 60 seconds while it was waiting for email OTP.
    """
    with closing(connect()) as c:
        return [
            dict(r)
            for r in c.execute(
                "SELECT base,profile_id FROM cleanup "
                "WHERE state IN ('pending','working') AND due<=? LIMIT 10",
                (time.time(),),
            )
        ]

def retry_pending():
    from types import SimpleNamespace
    from core.antbrowser_driver import cleanup_ant_profile
    for row in pending():
        try:
            cleanup_ant_profile(SimpleNamespace(raw={"ephemeral":True,"api_base":row["base"],"profile_id":row["profile_id"]}))
        except Exception:
            pass  # Error state is retained durably by cleanup_ant_profile.

def start_recovery():
    global _STARTED
    with _LOCK:
        if _STARTED:
            return
        _STARTED=True
    recovered = recover_previous_process()
    if recovered:
        import logging
        logging.getLogger(__name__).warning("[AntCleanup] queued %s orphan profiles from previous process", recovered)
    retry_pending()
    def worker():
        import logging
        while True:
            try:
                retry_pending()
            except Exception as exc:
                logging.getLogger(__name__).warning("[AntCleanup] retry worker error: %s",type(exc).__name__)
            time.sleep(60)
    threading.Thread(target=worker,name="ant-cleanup-recovery",daemon=True).start()
