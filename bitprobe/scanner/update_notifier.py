from datetime import datetime, timedelta
import json
import os
from pathlib import Path

from scanner.cve_updater import needs_update, update_cve_db


_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
META_PATH = str(_DATA_DIR / "cve_meta.json")
REMINDER_DAYS = 14


def _load_meta():
    if not os.path.exists(META_PATH):
        return {}
    with open(META_PATH, "r") as f:
        return json.load(f)


def check_and_notify(auto_update: bool = True):
    """
    Runs at startup.
    - Auto-updates if internet is available and DB is stale
    - Otherwise prints a loud reminder
    """

    if needs_update():
        print("\n" + "=" * 70)
        print("⚠ CVE DATABASE OUT OF DATE ⚠")
        print("=" * 70)

        if auto_update:
            try:
                updated = update_cve_db()
                if updated:
                    return
            except Exception:
                pass

        meta = _load_meta()
        last_update = meta.get("last_update", "UNKNOWN")

        print(f"Last update: {last_update}")
        print("New vulnerabilities may be missing.")
        print("Run: bitprobe update-cves")
        print("=" * 70 + "\n")
        return

    meta = _load_meta()
    last_update = meta.get("last_update")

    if not last_update:
        return

    last_dt = datetime.fromisoformat(last_update)
    if datetime.utcnow() - last_dt > timedelta(days=REMINDER_DAYS):
        print("\n[!] Reminder: CVE database has not been updated recently.")
