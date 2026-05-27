import json
import os
from pathlib import Path

from scanner.cve_db_manager import (
    cve_db_needs_update,
    update_cve_database,
    bootstrap_cve_state,
    get_stats,
)


_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
META_PATH = str(_DATA_DIR / "cve_meta.json")
REMINDER_DAYS = 14
# Fast bootstrap on scan startup (not the full NVD corpus)
SCAN_BOOTSTRAP_DAYS = 7


def _load_meta():
    if not os.path.exists(META_PATH):
        return {}
    with open(META_PATH, "r") as f:
        return json.load(f)


def check_and_notify(auto_update: bool = True, bootstrap_days: int = SCAN_BOOTSTRAP_DAYS):
    """
    Runs at scan startup.
    - Auto-updates via SQLite + incremental NVD (lastMod) when possible
    - Empty DB: windowed bootstrap (last N days), never unfiltered 350k+ sync
    - Otherwise prints a loud reminder
    """

    if not cve_db_needs_update():
        return

    print("\n" + "=" * 70)
    print("⚠ CVE DATABASE OUT OF DATE ⚠")
    print("=" * 70)

    if auto_update:
        try:
            stats = get_stats()
            total = stats.get("total_cves", 0) if isinstance(stats, dict) else 0
            bootstrap_cve_state()
            state_ts = None
            try:
                from scanner.update_state import get_state_timestamp

                state_ts = get_state_timestamp("cve", "last_modified")
            except Exception:
                pass

            if total == 0 or not state_ts:
                print(
                    f"[*] Bootstrapping CVE DB (last {bootstrap_days} days of NVD publishes)..."
                )
                update_cve_database(
                    days=bootstrap_days,
                    incremental=False,
                    force=False,
                )
            else:
                print("[*] Incremental CVE sync (modified since last cursor)...")
                update_cve_database(
                    days=bootstrap_days,
                    incremental=True,
                    force=False,
                )
            print("=" * 70 + "\n")
            return
        except Exception as exc:
            print(f"[!] Auto CVE update failed: {exc}")

    meta = _load_meta()
    last_update = meta.get("last_update", "UNKNOWN")

    print(f"Last update: {last_update}")
    print("New vulnerabilities may be missing.")
    print("Run: bitsentry update-cve-db   (or: bitprobe update-cve-db)")
    print("Set NVD_API_KEY for faster NVD rate limits.")
    print("=" * 70 + "\n")
