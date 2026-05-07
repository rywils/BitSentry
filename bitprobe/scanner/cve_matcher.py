"""
Enhanced CVE Matching with CPE parsing and semantic versioning.
"""

import re
from typing import Dict, List, Optional, Tuple
from packaging import version as pkg_version


def parse_cpe(cpe_string: str) -> Optional[Dict]:
    """
    Parse CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:lang:...
    Returns dict with vendor, product, version, etc.
    """
    if not cpe_string or not cpe_string.startswith("cpe:"):
        return None
    
    parts = cpe_string.split(":")
    if len(parts) < 6:
        return None
    
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    return {
        "part": parts[2] if len(parts) > 2 else "a",  # a=app, o=os, h=hardware
        "vendor": parts[3] if len(parts) > 3 else "",
        "product": parts[4] if len(parts) > 4 else "",
        "version": parts[5] if len(parts) > 5 else "",
        "update": parts[6] if len(parts) > 6 else "",
        "edition": parts[7] if len(parts) > 7 else "",
    }


def normalize_product_name(name: str) -> str:
    """Normalize product name for matching."""
    name = name.lower().strip()
    # Remove common suffixes/prefixes
    name = re.sub(r'\s+(web\s+)?server$', '', name)
    name = re.sub(r'^apache\s+', 'apache_', name)
    return name


def product_names_match(detected: str, cve_product: str) -> bool:
    """Check if detected product matches CVE product name."""
    detected = normalize_product_name(detected)
    cve_product = normalize_product_name(cve_product)
    
    # Direct match
    if detected == cve_product:
        return True
    
    # Common aliases - strict mapping only
    aliases = {
        "wordpress": ["wordpress", "wp"],
        "apache": ["apache", "apache_http_server", "httpd", "apache_httpd"],
        "nginx": ["nginx", "nginx_proxy", "nginx_plus"],
        "mysql": ["mysql", "oracle_mysql", "mariadb"],
        "mariadb": ["mariadb", "mysql"],
        "postgresql": ["postgresql", "postgres"],
        "mongodb": ["mongodb", "mongo_db"],
        "redis": ["redis", "redis_server"],
        "laravel": ["laravel"],
        "django": ["django"],
        "rails": ["rails", "ruby_on_rails"],
        "nodejs": ["nodejs", "node.js", "node_js"],
        "php": ["php", "php_fpm", "php_cli"],
        "python": ["python"],
        "java": ["java", "oracle_java", "openjdk", "jdk", "jre"],
    }
    
    detected_aliases = aliases.get(detected, [detected])
    cve_aliases = aliases.get(cve_product, [cve_product])
    
    # Only exact matches within alias lists
    return any(d == c for d in detected_aliases for c in cve_aliases)


def parse_version_range(cpe: Dict) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract version range from CPE data.
    Returns (min_version, max_version) where None means unbounded.
    """
    version = cpe.get("version", "")
    
    # Handle special version strings
    if version in ["*", "-", "any", ""]:
        return (None, None)
    
    # Check for range patterns in update field
    update = cpe.get("update", "")
    
    # before/after patterns
    if update.startswith("before_"):
        return (None, update.replace("before_", ""))
    if update.startswith("after_"):
        return (update.replace("after_", ""), None)
    
    return (version, version)


def version_in_range(detected: str, min_ver: Optional[str], max_ver: Optional[str]) -> bool:
    """Check if detected version falls within the range."""
    if not detected:
        # No version detected - can't determine vulnerability
        # Only match if CVE affects all versions (no version constraints)
        return min_ver is None and max_ver is None
    
    try:
        detected_v = pkg_version.parse(detected)
        
        if min_ver and max_ver:
            # Specific version or range
            if min_ver == max_ver:
                return detected_v == pkg_version.parse(min_ver)
            return pkg_version.parse(min_ver) <= detected_v <= pkg_version.parse(max_ver)
        
        elif min_ver:
            return detected_v >= pkg_version.parse(min_ver)
        
        elif max_ver:
            return detected_v <= pkg_version.parse(max_ver)
        
        else:
            # No version constraints - any version matches
            return True
            
    except Exception:
        # Fallback to string comparison
        if min_ver and max_ver and min_ver == max_ver:
            return detected == min_ver
        return True


def extract_cve_info(cve_entry: Dict) -> List[Dict]:
    """
    Extract product and version info from CVE entry.
    Returns list of affected products with version ranges.
    """
    products = []
    raw = cve_entry.get("raw", [])
    
    for config in raw:
        nodes = config.get("nodes", [])
        for node in nodes:
            matches = node.get("cpeMatch", [])
            for match in matches:
                if not match.get("vulnerable", False):
                    continue
                
                criteria = match.get("criteria", "")
                cpe = parse_cpe(criteria)
                if not cpe:
                    continue
                
                # Check for version range in versionEndExcluding/versionEndIncluding
                version_start = match.get("versionStartIncluding")
                version_end = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                
                if version_start or version_end:
                    min_ver = version_start
                    max_ver = version_end
                else:
                    min_ver, max_ver = parse_version_range(cpe)
                
                products.append({
                    "vendor": cpe.get("vendor", ""),
                    "product": cpe.get("product", ""),
                    "min_version": min_ver,
                    "max_version": max_ver,
                    "version": cpe.get("version"),
                })
    
    return products


def match_technology_to_cve(tech_name: str, tech_version: Optional[str], cve_entry: Dict) -> Optional[Dict]:
    """
    Match a detected technology to a CVE entry.
    Returns match details if vulnerable, None if not.
    """
    affected_products = extract_cve_info(cve_entry)
    
    for product in affected_products:
        if product_names_match(tech_name, product["product"]):
            # Product matches, check version
            if version_in_range(tech_version, product["min_version"], product["max_version"]):
                return {
                    "matched_product": product["product"],
                    "detected_version": tech_version,
                    "affected_versions": f"{product['min_version'] or 'any'} - {product['max_version'] or 'any'}",
                }
    
    return None


def calculate_severity(cvss_score: Optional[float], cve_id: str = "") -> str:
    """Calculate severity from CVSS score or CVE ID patterns."""
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    # Try to extract year from CVE ID for prioritization
    if cve_id.startswith("CVE-"):
        try:
            year = int(cve_id.split("-")[1])
            # Older CVEs are more likely to have exploits
            if year < 2015:
                return "high"  # Assume high for old CVEs without score
            elif year < 2020:
                return "medium"
            else:
                return "low"
        except:
            pass
    
    return "medium"


# Export for use in plugins
__all__ = [
    "parse_cpe",
    "product_names_match",
    "version_in_range",
    "extract_cve_info",
    "match_technology_to_cve",
    "calculate_severity",
]
