import json
import os
from pathlib import Path
from typing import List, Dict, Any

_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CVE_DB_PATH = str(_DATA_DIR / "cve_db.json")


def load_cve_db() -> Dict[str, Any]:
    """
    Load CVE database from disk.

    Expected format:
    {
        "metadata": {...},
        "entries": [ {...}, {...} ]
    }
    """

    if not os.path.exists(CVE_DB_PATH):
        raise FileNotFoundError("CVE database not found")

    with open(CVE_DB_PATH, "r") as f:
        data = json.load(f)

    # Backward compatibility: raw list → wrap
    if isinstance(data, list):
        return {
            "metadata": {},
            "entries": data,
        }

    if not isinstance(data, dict):
        raise ValueError("Invalid CVE database format")

    if "entries" not in data or not isinstance(data["entries"], list):
        raise ValueError("CVE database missing 'entries' list")

    return data
