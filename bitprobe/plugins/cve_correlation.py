"""
Enhanced CVE Correlation Plugin

Correlates detected technologies with CVEs using:
- CPE parsing for accurate product matching
- Semantic versioning for version ranges
- Multiple product name aliases
"""

from plugins.base_plugin import BasePlugin, Finding
from typing import Dict, List

from scanner.cve_db import load_cve_db
from scanner.fingerprints import fingerprint_technologies
from scanner.cve_matcher import (
    match_technology_to_cve,
    calculate_severity,
)


class CVECorrelationPlugin(BasePlugin):

    def get_name(self) -> str:
        return "cve_correlation"

    def get_description(self) -> str:
        return "Correlates detected technologies with CVEs using CPE matching"

    def _extract_all_technologies(self, tech: Dict) -> List[Dict]:
        """Extract all detected technologies with their versions."""
        technologies = []
        
        # Get detailed breakdown
        detailed = tech.get("_detailed", {})
        
        for category, items in detailed.items():
            for item in items:
                tech_entry = {
                    "name": item["name"],
                    "category": category,
                    "version": item.get("version"),
                }
                technologies.append(tech_entry)
        
        # Also add flattened versions
        if "framework" in tech:
            technologies.append({
                "name": tech["framework"],
                "category": "framework",
                "version": tech.get("framework_version"),
            })
        
        if "server" in tech:
            technologies.append({
                "name": tech["server"],
                "category": "server",
                "version": None,
            })
        
        if "language" in tech:
            technologies.append({
                "name": tech["language"],
                "category": "language",
                "version": None,
            })
        
        return technologies

    def _generate_contextual_guidance(self, tech_name: str, cve_id: str) -> Dict[str, str]:
        """Generate attack/defense/mitigation specific to the technology."""
        
        tech_lower = tech_name.lower()
        
        # Database-specific guidance
        if any(db in tech_lower for db in ["mysql", "postgres", "mongodb", "redis", "mariadb"]):
            return {
                "attack": (
                    f"Attackers can exploit {tech_name} vulnerabilities to extract, modify, or "
                    f"delete database contents. Common attacks include SQL injection, authentication "
                    f"bypass, and remote code execution through database features."
                ),
                "defense": (
                    "Implement network segmentation with databases in private subnets. Use VPN or "
                    "bastion hosts for administrative access. Enable query logging and intrusion "
                    "detection. Regularly patch and upgrade database software."
                ),
                "mitigation": (
                    "1. Identify all database instances and their versions\n"
                    "2. Check vendor security advisories for this CVE\n"
                    "3. Test patches in staging environment\n"
                    "4. Apply updates during maintenance window\n"
                    "5. Verify remediation through re-scanning"
                ),
            }
        
        # Web framework guidance
        if any(fw in tech_lower for fw in ["wordpress", "laravel", "django", "rails", "drupal", "joomla"]):
            return {
                "attack": (
                    f"Web framework vulnerabilities can lead to remote code execution, privilege "
                    f"escalation, or data breaches. Attackers may exploit plugin/addon vulnerabilities "
                    f"or core framework weaknesses."
                ),
                "defense": (
                    "Keep frameworks and all plugins/themes updated. Use Web Application Firewall (WAF) "
                    "rules specific to the framework. Implement proper input validation and output "
                    "encoding. Enable security headers and CSRF protection."
                ),
                "mitigation": (
                    "1. Inventory all framework plugins/extensions\n"
                    "2. Remove unused plugins\n"
                    "3. Enable automatic security updates if available\n"
                    "4. Implement WAF rules\n"
                    "5. Schedule regular security scans"
                ),
            }
        
        # Server software guidance
        if any(srv in tech_lower for srv in ["apache", "nginx", "iis", "tomcat"]):
            return {
                "attack": (
                    f"Web server vulnerabilities can allow attackers to bypass access controls, "
                    f"execute arbitrary code, or cause denial of service. Misconfigurations are "
                    f"commonly exploited alongside software vulnerabilities."
                ),
                "defense": (
                    "Follow server hardening guides. Remove default pages and unnecessary modules. "
                    "Implement proper access controls and logging. Use mod_security or equivalent "
                    "for additional protection."
                ),
                "mitigation": (
                    "1. Review server configuration against CIS benchmarks\n"
                    "2. Apply security patches\n"
                    "3. Remove unnecessary modules/extensions\n"
                    "4. Enable comprehensive logging\n"
                    "5. Configure fail2ban for brute force protection"
                ),
            }
        
        # Language/runtime guidance
        if any(lang in tech_lower for lang in ["php", "python", "nodejs", "ruby", "java"]):
            return {
                "attack": (
                    f"Runtime vulnerabilities can lead to code execution, memory corruption, or "
                    f"denial of service. Applications running on vulnerable runtimes are at risk "
                    f"regardless of application code quality."
                ),
                "defense": (
                    "Use current supported versions of languages/runtimes. Implement application "
                    "sandboxing and resource limits. Monitor for unusual process behavior. Use "
                    "dependency scanning for known vulnerable libraries."
                ),
                "mitigation": (
                    "1. Inventory all applications using this runtime\n"
                    "2. Plan runtime version upgrades\n"
                    "3. Test application compatibility\n"
                    "4. Deploy updates\n"
                    "5. Implement runtime monitoring"
                ),
            }
        
        # Default guidance
        return {
            "attack": (
                f"This vulnerability in {tech_name} could allow attackers to compromise system "
                f"confidentiality, integrity, or availability. Review the CVE details for specific "
                f"attack vectors."
            ),
            "defense": (
                "Apply defense in depth principles. Restrict network exposure. Monitor for "
                "suspicious activity. Maintain regular backups."
            ),
            "mitigation": (
                "1. Identify affected systems\n"
                "2. Review vendor security advisories\n"
                "3. Test patches in non-production\n"
                "4. Deploy fixes\n"
                "5. Verify remediation"
            ),
        }

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []

        if url_info.get("depth", 0) > 0:
            return findings

        url = url_info["url"]
        response = request_handler.get(url)
        if response is None:
            return findings

        tech = fingerprint_technologies(response)
        if not tech:
            return findings

        try:
            db = load_cve_db()
        except Exception:
            return findings

        entries = db.get("entries", [])
        if not entries:
            return findings

        # Sort entries by CVSS score (highest first) to prioritize critical CVEs
        entries = sorted(
            entries,
            key=lambda e: e.get("cvss") or 0,
            reverse=True
        )

        # Get all detected technologies
        detected_techs = self._extract_all_technologies(tech)
        
        # Track unique CVEs to avoid duplicates
        found_cves = set()
        cves_per_tech = {}  # Limit CVEs per technology
        MAX_CVES_PER_TECH = 10  # Cap at 10 CVEs per technology

        for tech_entry in detected_techs:
            tech_name = tech_entry["name"]
            tech_version = tech_entry.get("version")
            
            # Track CVEs per technology
            if tech_name not in cves_per_tech:
                cves_per_tech[tech_name] = 0
            
            for cve_entry in entries:
                cve_id = cve_entry.get("cve_id", "UNKNOWN")
                
                # Skip if we've already found this CVE for this technology
                cache_key = f"{tech_name}:{cve_id}"
                if cache_key in found_cves:
                    continue
                
                # Skip if we've hit the limit for this technology
                if cves_per_tech[tech_name] >= MAX_CVES_PER_TECH:
                    break
                
                # Try to match
                match = match_technology_to_cve(tech_name, tech_version, cve_entry)
                if not match:
                    continue
                
                found_cves.add(cache_key)
                cves_per_tech[tech_name] += 1
                
                # Get severity
                cvss = cve_entry.get("cvss")
                severity = calculate_severity(cvss, cve_id)
                
                # Get contextual guidance
                guidance = self._generate_contextual_guidance(tech_name, cve_id)
                
                finding = Finding(
                    plugin_name=self.get_name(),
                    severity=severity,
                    title=f"CVE-{cve_id}: {tech_name} vulnerability",
                    description=cve_entry.get("summary", "No description available."),
                    url=url,
                    evidence={
                        "technology": tech_name,
                        "detected_version": tech_version,
                        "cve_id": cve_id,
                        "cvss_score": cvss,
                        "affected_versions": match["affected_versions"],
                        "references": cve_entry.get("references", [])[:3],  # Top 3 refs
                    },
                    remediation=f"Upgrade {tech_name} to a patched version. See CVE details for specific fixed versions.",
                    attack_scenario=guidance["attack"],
                    defense_strategy=guidance["defense"],
                    mitigation_plan=guidance["mitigation"],
                )
                
                findings.append(finding)

        return findings
