#!/usr/bin/env python3
"""
Advanced Technology Fingerprinting

Detects web technologies, frameworks, servers, CDNs, and analytics
from HTTP responses.
"""

from typing import Dict, Optional, List, Tuple
import re


# Technology signatures for detection
TECH_SIGNATURES = {
    # Web Frameworks
    "frameworks": {
        "WordPress": {
            "body_patterns": [r"wp-content", r"wp-includes", r"wordpress", r'generator"? content="[^"]*WordPress'],
            "headers": {"X-Powered-By": r"PHP/[\d.]+"},
            "meta": [r'WordPress [\d.]+'],
        },
        "Laravel": {
            "body_patterns": [r"laravel", r"csrf-token"],
            "cookies": [r"laravel_session"],
        },
        "Django": {
            "body_patterns": [r"csrfmiddlewaretoken", r"django"],
            "headers": {"Server": r"WSGIServer"},
            "cookies": [r"csrftoken", r"django_sessionid"],
        },
        "Rails": {
            "body_patterns": [r"csrf-param", r"csrf-token", r"ruby-on-rails"],
            "cookies": [r"_session_id", r"_rails"],
        },
        "Express": {
            "headers": {"X-Powered-By": r"Express"},
        },
        "Next.js": {
            "body_patterns": [r"__NEXT_DATA__", r"_next/static"],
            "headers": {"X-Powered-By": r"Next.js"},
        },
        "React": {
            "body_patterns": [r'reactroot', r'data-reactroot', r'react\.js', r'react\.production\.min\.js'],
        },
        "Angular": {
            "body_patterns": [r"ng-app", r"ng-controller", r"angular\.js"],
        },
        "Vue.js": {
            "body_patterns": [r"vue\.js", r"v-app", r"data-v-"],
        },
        "Astro": {
            "body_patterns": [r"astro@", r"data-astro-cid"],
        },
    },
    
    # Web Servers
    "servers": {
        "Apache": {
            "headers": {"Server": r"Apache[/\s]?[\d.]*"},
        },
        "Nginx": {
            "headers": {"Server": r"nginx[/\s]?[\d.]*"},
        },
        "IIS": {
            "headers": {"Server": r"Microsoft-IIS[/\s]?[\d.]*"},
        },
        "Caddy": {
            "headers": {"Server": r"Caddy"},
        },
        "LiteSpeed": {
            "headers": {"Server": r"LiteSpeed"},
        },
    },
    
    # CDNs and Cloud
    "cdn": {
        "Cloudflare": {
            "headers": {"CF-RAY": r".+", "Server": r"cloudflare"},
            "body_patterns": [r"cloudflare"],
        },
        "AWS CloudFront": {
            "headers": {"X-Amz-Cf-Id": r".+", "Via": r"[\d.]+ cloudfront"},
        },
        "Fastly": {
            "headers": {"X-Served-By": r"cache-", "X-Cache": r"."},
        },
        "Akamai": {
            "headers": {"X-Akamai-Request-ID": r".+", "X-Cache": r"TCP_"},
        },
        "MaxCDN": {
            "headers": {"X-CDN-Provider": r"MaxCDN"},
        },
    },
    
    # Programming Languages
    "languages": {
        "PHP": {
            "headers": {"X-Powered-By": r"PHP[/\s]?[\d.]*"},
            "body_patterns": [r"\.php", r"<?php"],
            "cookies": [r"PHPSESSID"],
        },
        "Python": {
            "headers": {"Server": r"WSGIServer|Python/[\d.]+"},
        },
        "Node.js": {
            "headers": {"X-Powered-By": r"Express|Node\.js"},
        },
        "Ruby": {
            "headers": {"Server": r"WEBrick|Puma|Unicorn|Passenger"},
        },
        "ASP.NET": {
            "headers": {"X-AspNet-Version": r".+", "X-Powered-By": r"ASP\.NET"},
            "cookies": [r"ASPSESSIONID", r"ASP\.NET_SessionId"],
        },
        "Java": {
            "headers": {"Server": r"Apache-Coyote|Tomcat|Jetty|JBoss"},
            "cookies": [r"JSESSIONID"],
        },
    },
    
    # Analytics
    "analytics": {
        "Google Analytics": {
            "body_patterns": [r"google-analytics", r"googletagmanager", r"gtag", r"ga\("],
        },
        "Google Tag Manager": {
            "body_patterns": [r"googletagmanager\.com/gtm\.js"],
        },
        "Mixpanel": {
            "body_patterns": [r"mixpanel", r"mixpanel\.track"],
        },
        "Segment": {
            "body_patterns": [r"segment\.com", r"analytics\.track"],
        },
        "Hotjar": {
            "body_patterns": [r"hotjar", r"hj\("],
        },
        "Cloudflare Insights": {
            "body_patterns": [r"cloudflareinsights"],
        },
    },
    
    # Databases (indirect detection)
    "databases": {
        "MySQL": {
            "body_patterns": [r"mysql", r"mysqli"],
        },
        "PostgreSQL": {
            "body_patterns": [r"postgresql", r"postgres"],
        },
        "MongoDB": {
            "body_patterns": [r"mongodb", r"mongoose"],
        },
        "Redis": {
            "body_patterns": [r"redis"],
        },
    },
    
    # JavaScript Libraries
    "js_libraries": {
        "jQuery": {
            "body_patterns": [r"jquery[.-]?([\d.]+)?", r"jquery\.min\.js"],
        },
        "Bootstrap": {
            "body_patterns": [r"bootstrap[.-]?([\d.]+)?", r"bootstrap\.min\.css"],
        },
        "React": {
            "body_patterns": [r"react[.-]?([\d.]+)?", r"react\.production\.min\.js"],
        },
        "Vue": {
            "body_patterns": [r"vue[.-]?([\d.]+)?", r"vue\.min\.js"],
        },
        "Angular": {
            "body_patterns": [r"angular[.-]?([\d.]+)?"],
        },
        "Lodash": {
            "body_patterns": [r"lodash", r"_\."],
        },
        "Axios": {
            "body_patterns": [r"axios", r"axios\.min\.js"],
        },
    },
}


def extract_version(text: str, pattern: str) -> Optional[str]:
    """Extract version number from text using pattern."""
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        return match.group(1) if match.groups() else match.group(0)
    return None


def check_body_patterns(body: str, patterns: List[str]) -> Tuple[bool, Optional[str]]:
    """Check if any pattern matches in body. Returns (found, version)."""
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            version = None
            if match.groups():
                version = match.group(1)
            return True, version
    return False, None


def check_headers(headers: Dict, signatures: Dict) -> Tuple[bool, Optional[str]]:
    """Check if header signatures match."""
    for header_name, pattern in signatures.items():
        header_value = headers.get(header_name, "")
        if header_value:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                return True, version
    return False, None


def check_cookies(headers: Dict, patterns: List[str]) -> bool:
    """Check if any cookie pattern matches."""
    cookie_header = headers.get("Set-Cookie", "") or headers.get("Cookie", "")
    for pattern in patterns:
        if re.search(pattern, cookie_header, re.IGNORECASE):
            return True
    return False


def fingerprint_technologies(response) -> Dict:
    """
    Perform comprehensive technology fingerprinting on HTTP response.
    
    Args:
        response: requests.Response object
        
    Returns:
        Dictionary of detected technologies with versions where available
    """
    tech = {
        "frameworks": [],
        "servers": [],
        "cdn": [],
        "languages": [],
        "analytics": [],
        "databases": [],
        "js_libraries": [],
        "other": [],
    }
    
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text.lower() if response.text else ""
    
    # Check each technology category
    for category, technologies in TECH_SIGNATURES.items():
        for tech_name, signatures in technologies.items():
            detected = False
            version = None
            
            # Check body patterns
            if "body_patterns" in signatures:
                found, ver = check_body_patterns(body, signatures["body_patterns"])
                if found:
                    detected = True
                    version = ver
            
            # Check headers
            if not detected and "headers" in signatures:
                # Normalize header keys for comparison
                normalized_headers = {k.lower(): v for k, v in response.headers.items()}
                found, ver = check_headers(normalized_headers, 
                    {k.lower(): v for k, v in signatures["headers"].items()})
                if found:
                    detected = True
                    version = ver
            
            # Check cookies
            if not detected and "cookies" in signatures:
                if check_cookies(response.headers, signatures["cookies"]):
                    detected = True
            
            # Check meta tags (simplified - just search in body)
            if not detected and "meta" in signatures:
                found, ver = check_body_patterns(body, signatures["meta"])
                if found:
                    detected = True
                    version = ver
            
            if detected:
                tech_item = {"name": tech_name}
                if version:
                    tech_item["version"] = version
                tech[category].append(tech_item)
    
    # Additional simple checks
    server = response.headers.get("Server", "")
    if server and not any(s["name"] in str(server) for s in tech["servers"]):
        tech["other"].append({"name": server})
    
    powered_by = response.headers.get("X-Powered-By", "")
    if powered_by:
        tech["other"].append({"name": powered_by})
    
    # Flatten for backward compatibility
    flattened = {}
    for category, items in tech.items():
        if items:
            if category == "frameworks" and items:
                flattened["framework"] = items[0]["name"]
                if "version" in items[0]:
                    flattened["framework_version"] = items[0]["version"]
            elif category == "servers" and items:
                flattened["server"] = items[0]["name"]
            elif category == "languages" and items:
                flattened["language"] = items[0]["name"]
            elif category == "cdn" and items:
                flattened["cdn"] = items[0]["name"]
            elif category == "analytics" and items:
                flattened["analytics"] = items[0]["name"]
    
    # Add detailed breakdown
    flattened["_detailed"] = tech
    
    return flattened


def get_technology_summary(tech: Dict) -> str:
    """Generate human-readable technology summary."""
    parts = []
    
    if "framework" in tech:
        fw = tech["framework"]
        ver = tech.get("framework_version", "")
        parts.append(f"Framework: {fw} {ver}".strip())
    
    if "server" in tech:
        parts.append(f"Server: {tech['server']}")
    
    if "language" in tech:
        parts.append(f"Language: {tech['language']}")
    
    if "cdn" in tech:
        parts.append(f"CDN: {tech['cdn']}")
    
    if "_detailed" in tech:
        detailed = tech["_detailed"]
        if detailed.get("js_libraries"):
            libs = [lib["name"] for lib in detailed["js_libraries"][:3]]
            parts.append(f"JS Libraries: {', '.join(libs)}")
    
    return " | ".join(parts) if parts else "No technologies detected"


# Backward compatibility
if __name__ == "__main__":
    import requests
    
    # Test fingerprinting
    test_urls = [
        "https://wordpress.com",
        "https://github.com",
    ]
    
    for url in test_urls:
        try:
            resp = requests.get(url, timeout=10)
            tech = fingerprint_technologies(resp)
            print(f"\n{url}:")
            print(get_technology_summary(tech))
            print(f"Detailed: {tech.get('_detailed', {})}")
        except Exception as e:
            print(f"\n{url}: Error - {e}")
