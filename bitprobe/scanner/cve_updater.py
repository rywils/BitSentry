import json
import os
import time
import requests
from datetime import datetime, timedelta
from pathlib import Path
from scanner.update_state import get_state_timestamp, set_state_timestamp


_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CVE_DB_PATH = str(_DATA_DIR / "cve_db.json")
CVE_META_PATH = str(_DATA_DIR / "cve_meta.json")

NVD_FEED_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_UPDATE_DAYS = 7


def _format_nvd_datetime(dt: datetime) -> str:
    """Return NVD-compatible timestamp with milliseconds."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _load_meta():
    if not os.path.exists(CVE_META_PATH):
        return {}
    with open(CVE_META_PATH, "r") as f:
        return json.load(f)


def _save_meta(meta):
    os.makedirs(os.path.dirname(CVE_META_PATH), exist_ok=True)
    with open(CVE_META_PATH, "w") as f:
        json.dump(meta, f, indent=2)


def _save_db(entries):
    os.makedirs(os.path.dirname(CVE_DB_PATH), exist_ok=True)
    with open(CVE_DB_PATH, "w") as f:
        json.dump(entries, f, indent=2)


def needs_update(force: bool = False) -> bool:
    if force:
        return True

    meta = _load_meta()
    last_update = meta.get("last_update")

    if not last_update:
        return True

    last_dt = datetime.fromisoformat(last_update)
    return datetime.utcnow() - last_dt > timedelta(days=DEFAULT_UPDATE_DAYS)


def update_cve_db(force: bool = False, incremental: bool = True, verbose: bool = False) -> bool:
    if not force and not needs_update(force):
        return False

    print("[*] Updating CVE database from NVD...")
    print("[*] Timeout per request: 60s | Results per page: 2000")
    if verbose:
        print(f"[VERBOSE] NVD API URL: {NVD_FEED_URL}")

    # Load existing DB for incremental updates
    existing_db = {}
    if incremental and os.path.exists(CVE_DB_PATH) and not force:
        try:
            with open(CVE_DB_PATH, "r") as f:
                existing_data = json.load(f)
                existing_db = {entry["cve_id"]: entry for entry in existing_data}
            print(f"[*] Loaded {len(existing_db)} existing CVEs for incremental update")
        except Exception as e:
            print(f"[!] Failed to load existing CVE DB for incremental update: {e}")

    params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    # For incremental updates, only fetch CVEs modified since last state timestamp
    state_last_modified = get_state_timestamp("cve", "last_modified") if incremental else None
    update_end = _format_nvd_datetime(datetime.utcnow())
    if state_last_modified and not force:
        params["lastModStartDate"] = state_last_modified
        params["lastModEndDate"] = update_end
        print("[*] Incremental CVE update:")
        print(f"    from: {state_last_modified}")
        print(f"    to:   {update_end}")
    elif incremental and not force:
        print("[!] No CVE state timestamp found; performing initial full sync.")

    all_entries = list(existing_db.values()) if existing_db else []
    batch_num = 0
    updated_count = 0
    skipped_count = 0
    overall_start_time = time.time()
    last_progress_time = overall_start_time

    latest_last_modified: str | None = None
    api_failed = False
    saw_vulnerabilities = False
    while True:
        batch_num += 1
        request_start = time.time()

        if verbose:
            print(f"[VERBOSE] [Batch {batch_num}] Requesting startIndex={params['startIndex']} with params: {params}")
        print(f"  [Batch {batch_num}] Requesting startIndex={params['startIndex']}...", end=" ", flush=True)

        try:
            resp = requests.get(
                NVD_FEED_URL,
                params=params,
                timeout=60,
                headers={"User-Agent": "BitSentry/1.0"},
            )
            request_time = time.time() - request_start
            print(f"({request_time:.1f}s)")

            if resp.status_code != 200:
                print(f"[!] Failed to fetch CVE feed: HTTP {resp.status_code}")
                print(f"[!] URL: {resp.url}")
                print(f"[!] Response: {resp.text}")
                api_failed = True
                raise RuntimeError(f"NVD API request failed with HTTP {resp.status_code}")

            data = resp.json()
            if "vulnerabilities" not in data:
                print(f"[!] Invalid NVD response (missing 'vulnerabilities') from: {resp.url}")
                print(f"[!] Response body: {resp.text}")
                raise RuntimeError("NVD response missing 'vulnerabilities'")
            vulns = data.get("vulnerabilities", [])

            if not vulns:
                if state_last_modified and incremental and not force:
                    print("[+] CVE DB already up to date (no changes)")
                else:
                    print(f"  [!] No vulnerabilities returned, ending.")
                if verbose:
                    print(f"[VERBOSE] Empty vulnerabilities list at startIndex={params['startIndex']}")
                break

            saw_vulnerabilities = True
            parse_start = time.time()
            # Build lookup of existing entries for fast deduplication
            existing_ids = {e["cve_id"] for e in all_entries}

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                cve_last_modified = cve.get("lastModified")
                if cve_last_modified and (
                    latest_last_modified is None or cve_last_modified > latest_last_modified
                ):
                    latest_last_modified = cve_last_modified
                if not cve_id:
                    if verbose:
                        print(f"[VERBOSE] Skipping entry without CVE ID")
                    continue

                # Quick check if already exists (skip re-processing)
                if cve_id in existing_ids and incremental:
                    skipped_count += 1
                    if verbose and skipped_count % 100 == 0:
                        print(f"[VERBOSE] Skipped {skipped_count} existing CVEs so far")
                    continue

                descs = cve.get("descriptions", [])
                summary = ""
                for d in descs:
                    if d.get("lang") == "en":
                        summary = d.get("value", "")
                        break

                metrics = cve.get("metrics", {})
                cvss = None
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

                affected = cve.get("configurations", [])

                entry = {
                    "cve_id": cve_id,
                    "summary": summary,
                    "cvss": cvss,
                    "raw": affected,
                }

                if cve_id in existing_ids:
                    # Replace existing entry
                    for i, e in enumerate(all_entries):
                        if e["cve_id"] == cve_id:
                            all_entries[i] = entry
                            break
                else:
                    all_entries.append(entry)
                    existing_ids.add(cve_id)

                updated_count += 1
            parse_time = time.time() - parse_start

            total = data.get("totalResults", 0)
            params["startIndex"] += len(vulns)

            elapsed = time.time() - overall_start_time
            rate = params["startIndex"] / elapsed if elapsed > 0 else 0
            remaining = total - params["startIndex"]
            eta_seconds = remaining / rate if rate > 0 else 0
            eta_str = f"{int(eta_seconds//60)}m{int(eta_seconds%60):02d}s" if rate > 0 else "unknown"

            print(f"  Progress: {params['startIndex']}/{total} CVEs | "
                  f"New/Updated: {updated_count} | Skipped: {skipped_count} | "
                  f"Rate: {rate:.1f}/s | ETA: {eta_str}")

            last_progress_time = time.time()

            if params["startIndex"] >= total:
                break

            # Reduced delay for incremental updates (NVD allows faster with API key)
            if not state_last_modified:
                time.sleep(0.5)  # Full update - be polite
            else:
                time.sleep(0.2)  # Incremental - faster

        except requests.exceptions.Timeout:
            print(f"\n[!] Request timeout after 60s - possible hang detected at batch {batch_num}")
            api_failed = True
            break
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Request failed: {e}")
            api_failed = True
            break

    if api_failed:
        raise RuntimeError("CVE update failed before completion; state not updated.")

    _save_db(all_entries)

    meta = {
        "last_update": datetime.utcnow().isoformat(),
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "entry_count": len(all_entries),
        "incremental": bool(last_update and not force),
    }
    _save_meta(meta)
    if saw_vulnerabilities:
        set_state_timestamp("cve", "last_modified", latest_last_modified or update_end)

    mode_str = "incrementally" if (state_last_modified and not force) else "fully"
    print(f"[+] CVE database updated {mode_str}: {updated_count} new/updated, {len(all_entries)} total entries")
    return True
