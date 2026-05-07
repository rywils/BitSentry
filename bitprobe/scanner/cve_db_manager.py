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
from scanner.update_state import get_state_timestamp, set_state_timestamp


_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CVE_DB_PATH = str(_DATA_DIR / "cve_db.sqlite")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _format_nvd_datetime(dt: datetime) -> str:
    """Return NVD-compatible timestamp with milliseconds."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def init_cve_database():
    """Initialize SQLite database with CVE schema."""
    os.makedirs(os.path.dirname(CVE_DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(CVE_DB_PATH)
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


def update_cve_database(days: int = 30, api_key: Optional[str] = None,
                        incremental: bool = True, force: bool = False,
                        verbose: bool = False) -> int:
    """
    Update CVE database from NVD feeds.

    Args:
        days: Number of days back to fetch CVEs (for initial/full updates)
        api_key: Optional NVD API key for higher rate limits
        incremental: If True, only fetch CVEs modified since last update
        force: Force update even if not needed
        verbose: Enable verbose output

    Returns:
        Number of CVEs added/updated
    """
    init_cve_database()

    headers = {
        "User-Agent": "BitSentry/1.0",
    }
    if api_key:
        headers['apiKey'] = api_key

    params = {
        'resultsPerPage': 2000,
        'startIndex': 0,
    }

    # Determine update strategy from persistent state
    state_last_modified = get_state_timestamp("cve", "last_modified")
    update_end = _format_nvd_datetime(datetime.utcnow())

    if incremental and state_last_modified and not force:
        # Incremental: only fetch CVEs modified since last update
        mod_start = state_last_modified
        params['lastModStartDate'] = mod_start
        params['lastModEndDate'] = update_end
        print("[*] Incremental CVE update:")
        print(f"    from: {mod_start}")
        print(f"    to:   {update_end}")
        if verbose:
            print(f"[VERBOSE] Using lastModStartDate filter: {mod_start}")
    else:
        # Full update: fetch CVEs published in the last N days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        params['pubStartDate'] = _format_nvd_datetime(start_date)
        params['pubEndDate'] = _format_nvd_datetime(end_date)
        if incremental and not state_last_modified and not force:
            print(
                "[!] No CVE state timestamp found; performing initial full sync."
            )
        print(f"[*] Full update: fetching CVEs published in last {days} days")
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

    update_type = "incremental" if (incremental and state_last_modified and not force) else f"last {days} days"
    print(f"[*] Fetching CVEs from NVD ({update_type})...")
    print(f"[*] Timeout per request: 60s | Results per page: {params['resultsPerPage']}")

    while True:
        batch_num += 1
        params['startIndex'] = start_index
        request_start = time.time()

        try:
            print(f"[Batch {batch_num}] startIndex={start_index}", flush=True)
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=60
            )
            request_time = time.time() - request_start
            print(f"({request_time:.1f}s)")
            if response.status_code != 200:
                print(f"[!] NVD API request failed: HTTP {response.status_code}")
                print(f"[!] URL: {response.url}")
                print(f"[!] Response: {response.text}")
                raise RuntimeError(f"NVD API request failed with HTTP {response.status_code}")
            data = response.json()
            if "vulnerabilities" not in data:
                print(f"[!] Invalid NVD response (missing 'vulnerabilities') from: {response.url}")
                print(f"[!] Response body: {response.text}")
                raise RuntimeError("NVD response missing 'vulnerabilities'")

            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                if incremental and state_last_modified and not force:
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

            total_results = data.get('totalResults', 0)
            start_index += len(vulnerabilities)

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

    # Update metadata
    conn = sqlite3.connect(CVE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ('last_updated', datetime.now().isoformat())
    )
    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ('total_entries', str(total_updated))
    )
    conn.commit()
    conn.close()

    if saw_vulnerabilities:
        set_state_timestamp("cve", "last_modified", latest_last_modified or update_end)
    
    print(f"[+] CVE database updated: {total_updated} CVEs added/updated")
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
            severity = metric.get('baseSeverity', '').lower()
            if not severity and cvss_score:
                if cvss_score >= 9.0:
                    severity = 'critical'
                elif cvss_score >= 7.0:
                    severity = 'high'
                elif cvss_score >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'
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

    conn = sqlite3.connect(CVE_DB_PATH)
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
            cursor.executemany("""
                INSERT INTO cve_products
                (cve_id, vendor, product, version_start, version_end,
                 version_start_including, version_end_including)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, product_entries)

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
    Query CVEs affecting a specific product/version.
    
    Args:
        product: Product name (e.g., "nginx", "wordpress")
        version: Version string (e.g., "1.18.0")
        vendor: Vendor name (optional)
        
    Returns:
        List of CVE dictionaries
    """
    if not os.path.exists(CVE_DB_PATH):
        raise FileNotFoundError("CVE database not found. Run 'bitprobe update-cve-db' first.")
    
    conn = sqlite3.connect(CVE_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Base query
        query = """
            SELECT DISTINCT 
                c.cve_id, c.description, c.severity, 
                c.cvss_score, c."references", c.published_date
            FROM cve_entries c
            JOIN cve_products p ON c.cve_id = p.cve_id
            WHERE p.product LIKE ?
        """
        params = [f'%{product.lower()}%']
        
        if vendor:
            query += " AND (p.vendor = ? OR p.vendor = '')"
            params.append(vendor.lower())
        
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
    
    conn = sqlite3.connect(CVE_DB_PATH)
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
