#!/usr/bin/env python3
"""
CVE Database Manager

Manages SQLite database for CVE tracking with NVD feed integration.
"""

import sqlite3
import json
import os
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from packaging import version
from pathlib import Path
from scanner.update_state import get_state_timestamp, set_state_timestamp, merge_section


_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CVE_DB_PATH = str(_DATA_DIR / "cve_db.sqlite")
CVE_META_PATH = str(_DATA_DIR / "cve_meta.json")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_STALE_DAYS = 7
# Below this count, local DB is treated as a short publication window bootstrap, not full coverage.
MIN_PRODUCTION_CVE_COUNT = 50_000
# NVD bulk-download pacing (https://nvd.nist.gov/developers/start-here)
NVD_SLEEP_NO_KEY = 6.0
NVD_SLEEP_WITH_KEY = 2.0
NVD_MAX_RETRIES = 6
NVD_RETRY_HTTP = frozenset({404, 429, 500, 502, 503, 504})


def _format_nvd_datetime(dt: datetime) -> str:
    """Return NVD-compatible timestamp with milliseconds."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _normalize_nvd_timestamp(value: str) -> str:
    """Coerce stored timestamps to NVD lastMod format (yyyy-MM-ddTHH:mm:ss.000)."""
    value = (value or "").strip()
    if not value:
        return value
    try:
        parsed = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(parsed)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return _format_nvd_datetime(dt)
    except ValueError:
        pass
    if "T" in value and "." in value:
        base, frac = value.split(".", 1)
        frac_digits = "".join(c for c in frac if c.isdigit())[:3].ljust(3, "0")
        return f"{base}.{frac_digits}"
    return value


def _nvd_inter_request_sleep(api_key: Optional[str], *, full_sync: bool) -> float:
    """Seconds to wait between NVD requests (rate-limit safe)."""
    if full_sync:
        return NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_NO_KEY
    return 0.65 if not api_key else 0.25


def _nvd_get(
    params: Dict[str, Any],
    headers: Dict[str, str],
    *,
    timeout: int = 60,
    verbose: bool = False,
) -> requests.Response:
    """GET NVD CVE API with retries on transient HTTP errors."""
    last: Optional[requests.Response] = None
    for attempt in range(1, NVD_MAX_RETRIES + 1):
        response = requests.get(
            NVD_API_URL, params=params, headers=headers, timeout=timeout
        )
        last = response
        if response.status_code == 200:
            return response
        if response.status_code not in NVD_RETRY_HTTP:
            return response
        wait = (NVD_SLEEP_WITH_KEY if headers.get("apiKey") else NVD_SLEEP_NO_KEY) * attempt
        print(
            f"  [!] NVD HTTP {response.status_code} "
            f"(attempt {attempt}/{NVD_MAX_RETRIES}); retrying in {wait:.0f}s..."
        )
        if verbose:
            print(f"[VERBOSE] URL: {response.url}")
            body = (response.text or "").strip()
            if body:
                print(f"[VERBOSE] Body: {body[:500]}")
        time.sleep(wait)
    assert last is not None
    return last


def _normalize_severity(
    raw: Optional[str], cvss_score: Optional[float]
) -> Optional[str]:
    """
    Map NVD/CVSS severity strings to DB enum values.
    Returns None when severity cannot be classified (allowed by schema).
    """
    allowed = frozenset({"critical", "high", "medium", "low"})
    aliases = {
        "moderate": "medium",
        "none": None,
        "unknown": None,
        "": None,
    }

    if raw:
        normalized = str(raw).strip().lower()
        normalized = aliases.get(normalized, normalized)
        if normalized in allowed:
            return normalized

    if cvss_score is not None:
        try:
            score = float(cvss_score)
        except (TypeError, ValueError):
            return None
        if score <= 0:
            return None
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    return None


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(CVE_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _load_legacy_meta() -> dict:
    if not os.path.exists(CVE_META_PATH):
        return {}
    with open(CVE_META_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def bootstrap_cve_state() -> str | None:
    """
    Seed ~/.bitsentry/state.json cve.last_modified from DB or legacy meta
    so incremental NVD sync works after upgrades or empty state files.
    """
    existing = get_state_timestamp("cve", "last_modified")
    if existing:
        return existing

    if os.path.exists(CVE_DB_PATH):
        conn = _connect()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cve_entries")
            if cursor.fetchone()[0] == 0:
                return None
            cursor.execute(
                "SELECT MAX(last_modified) FROM cve_entries "
                "WHERE last_modified IS NOT NULL AND last_modified != ''"
            )
            row = cursor.fetchone()
            if row and row[0]:
                set_state_timestamp("cve", "last_modified", row[0])
                return row[0]
        finally:
            conn.close()

    # Do not seed from legacy meta when SQLite is empty — that cursor is too
    # stale and triggers huge lastMod incremental pulls (~40k+ CVEs).
    meta = _load_legacy_meta()
    if meta.get("entry_count", 0) == 0:
        return None

    last_update = meta.get("last_update")
    if isinstance(last_update, str) and last_update:
        try:
            dt = datetime.fromisoformat(last_update.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            seeded = _format_nvd_datetime(dt)
        except ValueError:
            seeded = last_update
        set_state_timestamp("cve", "last_modified", seeded)
        return seeded

    return None


def cve_db_needs_update(stale_days: int = DEFAULT_STALE_DAYS) -> bool:
    """True when the local CVE store is missing or older than stale_days."""
    if os.environ.get("BITSENTRY_SKIP_CVE_UPDATE", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }:
        return False

    if not os.path.exists(CVE_DB_PATH):
        return True

    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        count = cursor.fetchone()[0]
        if count == 0:
            return True

        cursor.execute("SELECT value FROM metadata WHERE key = 'last_updated'")
        row = cursor.fetchone()
        if not row or not row[0]:
            meta = _load_legacy_meta()
            last_update = meta.get("last_update")
            if not last_update:
                return True
            last_dt = datetime.fromisoformat(last_update)
        else:
            last_dt = datetime.fromisoformat(row[0])
    finally:
        conn.close()

    return datetime.utcnow() - last_dt > timedelta(days=stale_days)


def describe_cve_db_local_status() -> str:
    """
    Short status string for installers / diagnostics (no network).
    """
    if not os.path.exists(CVE_DB_PATH):
        return "missing (never built)"
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        count = cursor.fetchone()[0]
    finally:
        conn.close()
    if count == 0:
        return "empty (0 CVEs; bootstrap required before reliable correlation)"
    if count < MIN_PRODUCTION_CVE_COUNT:
        return (
            f"partial ({count} CVEs; run update-cve-db --full or --years 15 "
            "for complete product coverage)"
        )
    if cve_db_needs_update():
        return f"stale or incomplete ({count} CVEs; refresh recommended)"
    return f"ok ({count} CVEs loaded)"


def init_cve_database():
    """Initialize SQLite database with CVE schema."""
    os.makedirs(os.path.dirname(CVE_DB_PATH), exist_ok=True)
    
    conn = _connect()
    cursor = conn.cursor()
    
    # Main CVE entries table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low')),
            cvss_score REAL CHECK(cvss_score >= 0 AND cvss_score <= 10),
            cvss_vector TEXT,
            published_date TEXT,
            last_modified TEXT,
            "references" TEXT
        )
    """)
    
    # Product mappings for version matching
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT REFERENCES cve_entries(cve_id),
            vendor TEXT,
            product TEXT NOT NULL,
            version_start TEXT,
            version_end TEXT,
            version_start_including BOOLEAN DEFAULT 1,
            version_end_including BOOLEAN DEFAULT 1,
            UNIQUE(cve_id, vendor, product, version_start, version_end)
        )
    """)
    
    # CPE mappings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cpes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT REFERENCES cve_entries(cve_id),
            cpe_uri TEXT NOT NULL,
            is_vulnerable BOOLEAN DEFAULT 1
        )
    """)
    
    # Metadata table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    # Create indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_entries(cvss_score)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_product_lookup ON cve_products(vendor, product)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_product_version ON cve_products(product, version_start, version_end)")
    
    conn.commit()
    conn.close()
    
    print(f"[+] CVE database initialized at {CVE_DB_PATH}")


def update_cve_database(
    days: int = 30,
    years: Optional[int] = None,
    full_sync: bool = False,
    api_key: Optional[str] = None,
    incremental: bool = True,
    force: bool = False,
    verbose: bool = False,
) -> int:
    """
    Update CVE database from NVD feeds.

    Args:
        days: Days of *publication* window when bootstrapping (not scan coverage)
        years: Alternative bootstrap: CVEs published in the last N years
        full_sync: Download entire NVD corpus (slow; use for first-time DB build)
        api_key: Optional NVD API key for higher rate limits
        incremental: If True, only fetch CVEs modified since last update
        force: Force update even if not needed
        verbose: Enable verbose output

    Returns:
        Number of CVEs added/updated
    """
    init_cve_database()
    bootstrap_cve_state()

    headers = {
        "User-Agent": "BitSentry/1.0",
    }
    api_key = api_key or os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params: Dict[str, Any] = {
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    conn = _connect()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        existing_count = cursor.fetchone()[0]
    finally:
        conn.close()

    # Determine update strategy from persistent state
    state_last_modified = get_state_timestamp("cve", "last_modified")
    update_end = _format_nvd_datetime(datetime.utcnow())

    if full_sync:
        merge_section("cve", {"last_modified": None})
        state_last_modified = None
        print("[*] Full sync requested: ignoring incremental cursor and date windows")
    elif existing_count == 0:
        merge_section("cve", {"last_modified": None})
        state_last_modified = None

    use_incremental = (
        incremental and state_last_modified and not force and not full_sync
    )

    if use_incremental:
        # Incremental: only fetch CVEs modified since last update
        mod_start = _normalize_nvd_timestamp(state_last_modified)
        params['lastModStartDate'] = mod_start
        params['lastModEndDate'] = update_end
        print("[*] Incremental CVE update:")
        print(f"    from: {mod_start}")
        print(f"    to:   {update_end}")
        if verbose:
            print(f"[VERBOSE] Using lastModStartDate filter: {mod_start}")
    else:
        if full_sync:
            if incremental and not state_last_modified and not force:
                print(
                    "[!] CVE DB empty: building full local NVD mirror "
                    "(~350k CVEs; may take 30–90+ min without NVD_API_KEY)."
                )
            print("[*] Full NVD corpus sync (no date filter)")
        else:
            end_date = datetime.now()
            if years is not None and years > 0:
                window_days = years * 365
                label = f"{years} year(s)"
            else:
                window_days = days
                label = f"{days} days"
            start_date = end_date - timedelta(days=window_days)
            params['pubStartDate'] = _format_nvd_datetime(start_date)
            params['pubEndDate'] = _format_nvd_datetime(end_date)
            if incremental and not state_last_modified and not force:
                print(
                    f"[!] CVE DB empty: bootstrapping publications from last {label}. "
                    "For complete product coverage run: update-cve-db --full "
                    "(or --years 15)."
                )
            print(f"[*] Windowed update: CVEs published in last {label}")
            if verbose:
                print(f"[VERBOSE] Using pubStartDate filter: {params['pubStartDate']}")
    
    total_updated = 0
    start_index = 0
    batch_num = 0
    batch_cves = []  # Collect CVEs for batch insert
    overall_start_time = time.time()
    latest_last_modified: str | None = None
    saw_vulnerabilities = False
    api_failed = False
    expected_total: Optional[int] = None

    if use_incremental:
        update_type = "incremental"
    elif full_sync:
        update_type = "full corpus"
    elif years:
        update_type = f"last {years} year(s) of publications"
    else:
        update_type = f"last {days} days of publications"
    print(f"[*] Fetching CVEs from NVD ({update_type})...")
    print(f"[*] Timeout per request: 60s | Results per page: {params['resultsPerPage']}")

    while True:
        batch_num += 1
        params['startIndex'] = start_index
        request_start = time.time()

        try:
            print(f"[Batch {batch_num}] startIndex={start_index}", flush=True)
            response = _nvd_get(params, headers, timeout=60, verbose=verbose)
            request_time = time.time() - request_start
            print(f"({request_time:.1f}s)")
            if response.status_code != 200:
                print(f"[!] NVD API request failed: HTTP {response.status_code}")
                print(f"[!] URL: {response.url}")
                print(f"[!] Response: {response.text}")
                raise RuntimeError(
                    f"NVD API request failed with HTTP {response.status_code}"
                )
            data = response.json()
            if "vulnerabilities" not in data:
                print(f"[!] Invalid NVD response (missing 'vulnerabilities') from: {response.url}")
                print(f"[!] Response body: {response.text}")
                raise RuntimeError("NVD response missing 'vulnerabilities'")

            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                if use_incremental:
                    print("[+] CVE DB already up to date (no changes)")
                else:
                    print(f"  [!] No vulnerabilities returned, ending.")
                break

            saw_vulnerabilities = True
            store_start = time.time()
            # Collect CVE data for batch processing
            for vuln in vulnerabilities:
                cve_data = vuln.get('cve', {})
                if cve_data.get('id'):
                    batch_cves.append(cve_data)
                    cve_last_modified = cve_data.get("lastModified")
                    if cve_last_modified and (
                        latest_last_modified is None
                        or cve_last_modified > latest_last_modified
                    ):
                        latest_last_modified = cve_last_modified
                    if verbose and len(batch_cves) % 100 == 0:
                        print(f"[VERBOSE] Collected {len(batch_cves)} CVEs in current batch")

            # Batch insert every 1000 CVEs or at end
            if len(batch_cves) >= 1000:
                if verbose:
                    print(f"[VERBOSE] Storing batch of {len(batch_cves)} CVEs...")
                _store_cves_batch(batch_cves)
                total_updated += len(batch_cves)
                if verbose:
                    print(f"[VERBOSE] Batch stored. Total updated so far: {total_updated}")
                batch_cves = []

            store_time = time.time() - store_start

            total_results = int(data.get("totalResults", 0))
            if expected_total is None:
                expected_total = total_results
            page_stride = int(
                data.get("resultsPerPage") or params["resultsPerPage"]
            )
            start_index += page_stride

            elapsed = time.time() - overall_start_time
            rate = start_index / elapsed if elapsed > 0 else 0
            remaining = total_results - start_index
            eta_seconds = remaining / rate if rate > 0 else 0
            eta_str = f"{int(eta_seconds//60)}m{int(eta_seconds%60):02d}s" if rate > 0 else "unknown"

            print(f"  Progress: {start_index}/{total_results} CVEs | "
                  f"Rate: {rate:.1f}/s | ETA: {eta_str} | "
                  f"Store: {store_time:.1f}s")

            if start_index >= total_results:
                break

            time.sleep(_nvd_inter_request_sleep(api_key, full_sync=full_sync))

        except requests.exceptions.Timeout:
            print(f"\n[!] Request timeout after 60s - possible hang detected at batch {batch_num}")
            api_failed = True
            break
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Request failed: {e}")
            api_failed = True
            break
        except Exception as e:
            print(f"\n[!] Error processing CVEs: {e}")
            api_failed = True
            break

    # Store any remaining CVEs in the batch
    if batch_cves:
        if verbose:
            print(f"[VERBOSE] Storing final batch of {len(batch_cves)} CVEs...")
        _store_cves_batch(batch_cves)
        total_updated += len(batch_cves)
        if verbose:
            print(f"[VERBOSE] Final batch stored.")

    if api_failed:
        raise RuntimeError("CVE update failed before completion; state not updated.")

    if (
        full_sync
        and expected_total
        and start_index < expected_total
        and saw_vulnerabilities
    ):
        raise RuntimeError(
            f"Incomplete full NVD sync: reached index {start_index} of "
            f"{expected_total} CVEs. Re-run: bitsentry update-cve-db --full"
        )

    conn = _connect()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        total_in_db = cursor.fetchone()[0]
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ('last_updated', datetime.now().isoformat()),
        )
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ('total_entries', str(total_in_db)),
        )
        conn.commit()
    finally:
        conn.close()

    os.makedirs(os.path.dirname(CVE_META_PATH), exist_ok=True)
    with open(CVE_META_PATH, "w", encoding="utf-8") as f:
        json.dump(
            {
                "last_update": datetime.utcnow().isoformat(),
                "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "entry_count": total_in_db,
                "incremental": bool(use_incremental),
            },
            f,
            indent=2,
        )

    if saw_vulnerabilities:
        set_state_timestamp("cve", "last_modified", latest_last_modified or update_end)
    
    print(
        f"[+] CVE database updated: {total_updated} CVEs added/updated "
        f"({total_in_db} total in DB)"
    )
    return total_updated


def _extract_cve_data(cve_data: Dict) -> Optional[Dict]:
    """Extract normalized CVE data from NVD format."""
    cve_id = cve_data.get('id')
    if not cve_id:
        return None

    # Extract severity and CVSS
    severity = None
    cvss_score = None
    cvss_vector = None

    metrics = cve_data.get('metrics', {})
    for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if cvss_version in metrics and metrics[cvss_version]:
            metric = metrics[cvss_version][0]
            cvss_data = metric.get('cvssData', {})
            cvss_score = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
            severity = _normalize_severity(metric.get('baseSeverity'), cvss_score)
            break

    # Extract description
    description = ""
    for desc in cve_data.get('descriptions', []):
        if desc.get('lang') == 'en':
            description = desc.get('value', '')
            break

    # Extract references
    references = []
    for ref in cve_data.get('references', []):
        if ref.get('url'):
            references.append(ref['url'])

    # Extract products
    products = []
    for config in cve_data.get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if match.get('vulnerable'):
                    criteria = match.get('criteria', '')
                    parts = criteria.split(':')
                    if len(parts) >= 5:
                        vendor = parts[3] if len(parts) > 3 else ''
                        product = parts[4] if len(parts) > 4 else ''
                        version_str = parts[5] if len(parts) > 5 else '*'

                        products.append({
                            'vendor': vendor.lower(),
                            'product': product.lower(),
                            'version_start': match.get('versionStartIncluding', version_str if version_str != '*' else None),
                            'version_end': match.get('versionEndIncluding', version_str if version_str != '*' else None),
                            'version_start_including': 1 if match.get('versionStartIncluding') else 0,
                            'version_end_including': 1 if match.get('versionEndIncluding') else 0,
                        })

    return {
        'cve_id': cve_id,
        'description': description,
        'severity': severity,
        'cvss_score': cvss_score,
        'cvss_vector': cvss_vector,
        'published_date': cve_data.get('published'),
        'last_modified': cve_data.get('lastModified'),
        'references': json.dumps(references),
        'products': products,
    }


def _store_cves_batch(cve_data_list: List[Dict]):
    """Store multiple CVEs in a single batch transaction (much faster)."""
    if not cve_data_list:
        return

    conn = _connect()
    cursor = conn.cursor()

    try:
        # Prepare batch data
        cve_entries = []
        product_entries = []

        for cve_data in cve_data_list:
            normalized = _extract_cve_data(cve_data)
            if not normalized:
                continue

            cve_entries.append((
                normalized['cve_id'], normalized['description'],
                normalized['severity'], normalized['cvss_score'],
                normalized['cvss_vector'], normalized['published_date'],
                normalized['last_modified'], normalized['references']
            ))

            for prod in normalized['products']:
                product_entries.append((
                    normalized['cve_id'], prod['vendor'], prod['product'],
                    prod['version_start'], prod['version_end'],
                    prod['version_start_including'], prod['version_end_including']
                ))

        # Batch insert CVEs
        if cve_entries:
            cursor.executemany("""
                INSERT OR REPLACE INTO cve_entries
                (cve_id, description, severity, cvss_score, cvss_vector,
                 published_date, last_modified, "references")
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, cve_entries)

        # Batch insert products (delete old first to avoid duplicates)
        cve_ids = [c[0] for c in cve_entries]
        if cve_ids:
            cursor.execute(
                "DELETE FROM cve_products WHERE cve_id IN ({})".format(
                    ','.join('?' * len(cve_ids))
                ), cve_ids
            )

        if product_entries:
            seen_products: set[tuple] = set()
            unique_products = []
            for row in product_entries:
                if row in seen_products:
                    continue
                seen_products.add(row)
                unique_products.append(row)
            cursor.executemany("""
                INSERT OR IGNORE INTO cve_products
                (cve_id, vendor, product, version_start, version_end,
                 version_start_including, version_end_including)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, unique_products)

        conn.commit()
    finally:
        conn.close()


def _store_cve(cve_data: Dict):
    """Store a single CVE in the database (deprecated, use batch)."""
    _store_cves_batch([cve_data])


def query_cves(
    product: str,
    vendor: Optional[str] = None,
    version: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Query CVEs affecting a specific product/version via exact CPE name matching.
    
    Uses PRODUCT_ALIASES from cve_matcher to resolve detected technology names
    to their known CPE product identifiers, avoiding false positives from
    substring matching (e.g., 'astro' no longer matches 'astrocam').
    
    Args:
        product: Product name (e.g., "nginx", "wordpress")
        version: Version string (e.g., "1.18.0")
        vendor: Vendor name (optional)
        
    Returns:
        List of CVE dictionaries
    """
    if not os.path.exists(CVE_DB_PATH):
        raise FileNotFoundError("CVE database not found. Run 'bitprobe update-cve-db' first.")
    
    from scanner.cve_matcher import _get_cpe_names, _get_expected_vendor
    
    cpe_names = _get_cpe_names(product)
    if not cpe_names:
        return []
    
    expected_vendor = vendor or _get_expected_vendor(product)
    
    conn = _connect()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Map cpe_names to their expected vendor strings for filtering
        placeholders = ','.join('?' * len(cpe_names))
        query = f"""
            SELECT DISTINCT 
                c.cve_id, c.description, c.severity, 
                c.cvss_score, c."references", c.published_date
            FROM cve_entries c
            JOIN cve_products p ON c.cve_id = p.cve_id
            WHERE p.product IN ({placeholders})
        """
        params: list = list(cpe_names)
        
        # Auto-filter by known vendor when the product has ambiguous vendors.
        # E.g. product="astro" has vendor="astro" (real Astro web framework)
        # and vendor="saxum2003" (Saxum Astro Joomla component).
        if expected_vendor:
            query += " AND p.vendor = ?"
            params.append(expected_vendor)
        
        # Version matching if provided
        if version:
            query += """
                AND (
                    (p.version_start IS NULL OR ? >= p.version_start)
                    AND (p.version_end IS NULL OR ? <= p.version_end)
                )
            """
            params.extend([version, version])
        
        query += " ORDER BY c.cvss_score DESC NULLS LAST"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        cves = []
        for row in rows:
            cve = {
                'cve_id': row['cve_id'],
                'description': row['description'],
                'severity': row['severity'],
                'cvss_score': row['cvss_score'],
                'published_date': row['published_date'],
                'references': json.loads(row['references'] or '[]')
            }
            cves.append(cve)
        
        return cves
        
    finally:
        conn.close()


def get_stats() -> Dict[str, Any]:
    """Get database statistics."""
    if not os.path.exists(CVE_DB_PATH):
        return {'error': 'Database not found'}
    
    conn = _connect()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM cve_entries")
        total_cves = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cve_products")
        total_products = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT severity, COUNT(*) FROM cve_entries 
            WHERE severity IS NOT NULL
            GROUP BY severity
        """)
        severity_counts = dict(cursor.fetchall())
        
        cursor.execute("SELECT value FROM metadata WHERE key = 'last_updated'")
        last_updated = cursor.fetchone()
        
        return {
            'total_cves': total_cves,
            'total_products': total_products,
            'severity_counts': severity_counts,
            'last_updated': last_updated[0] if last_updated else None
        }
        
    finally:
        conn.close()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'update':
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        update_cve_database(days=days)
    elif len(sys.argv) > 1 and sys.argv[1] == 'stats':
        print(json.dumps(get_stats(), indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == 'query':
        product = sys.argv[2] if len(sys.argv) > 2 else 'nginx'
        version = sys.argv[3] if len(sys.argv) > 3 else None
        results = query_cves(product, version=version)
        print(json.dumps(results, indent=2))
    else:
        print("Usage: python cve_db_manager.py [update|stats|query]")
