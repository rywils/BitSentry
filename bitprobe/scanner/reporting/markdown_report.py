import os
from datetime import datetime
from pathlib import Path


class MarkdownReportGenerator:
    def __init__(
        self,
        report_data: dict,
        output_directory: str,
        client_name: str,
        output_name: str = "report",
    ):
        self.report_data = report_data
        self.output_directory = output_directory
        self.client_name = client_name
        self.output_name = output_name
        self.timestamp = self._resolve_timestamp()

    def _resolve_timestamp(self) -> str:
        timestamp = self.report_data.get("timestamp") or self.report_data.get(
            "generated_at"
        )
        if timestamp:
            try:
                clean = timestamp.replace("Z", "")
                return datetime.fromisoformat(clean).strftime("%B %d, %Y")
            except ValueError:
                pass
        return datetime.now().strftime("%B %d, %Y")

    def _generate_attack_scenario(self, finding: dict) -> str:
        """Generate attack scenario based on finding type."""
        if finding.get("attack_scenario"):
            return finding["attack_scenario"]
        
        title = finding.get("title", "").lower()
        severity = finding.get("severity", "medium")
        
        if "sql" in title or "mysql" in title or "postgres" in title:
            return (
                "An attacker could connect directly to the exposed database server. "
                "They may attempt default credentials, brute force authentication, "
                "or exploit known database vulnerabilities. Once authenticated, "
                "they can exfiltrate, modify, or destroy sensitive data."
            )
        elif "ssh" in title:
            return (
                "Attackers can attempt to brute force SSH credentials or exploit "
                "vulnerabilities in the SSH service. Successful compromise provides "
                "full server access, allowing data theft, malware installation, or "
                "use as a pivot point for lateral movement."
            )
        elif "ftp" in title:
            return (
                "Anonymous or weak FTP authentication may allow unauthorized file "
                "access. Attackers can upload malicious files, download sensitive "
                "data, or use the server for storing/distributing illegal content."
            )
        elif "redis" in title or "mongo" in title:
            return (
                "Exposed NoSQL databases often lack authentication by default. "
                "Attackers can dump entire databases, modify data, or use the "
                "server for cryptocurrency mining (cryptojacking)."
            )
        elif "telnet" in title:
            return (
                "Telnet transmits credentials in plaintext. Attackers can sniff "
                "traffic or connect directly to gain unauthorized access to the "
                "system with the privileges of authenticated users."
            )
        elif "sensitive file" in title or ".env" in title or ".git" in title:
            return (
                "Attackers can access exposed sensitive files containing credentials, "
                "API keys, or source code. This information enables further attacks "
                "on the application, database, or cloud infrastructure."
            )
        elif "tls" in title or "ssl" in title or "certificate" in title:
            return (
                "Weak TLS configurations allow man-in-the-middle attacks. Attackers "
                "can intercept, read, and modify encrypted traffic between users "
                "and the server, potentially stealing session cookies or credentials."
            )
        elif "header" in title and "security" in title:
            return (
                "Missing security headers enable various attacks including XSS, "
                "clickjacking, and MIME-type sniffing. Attackers can inject malicious "
                "scripts or trick users into performing unintended actions."
            )
        elif "cve" in title or "vulnerability" in title:
            return (
                "Attackers can exploit the known vulnerability using publicly "
                "available exploit code. This may lead to remote code execution, "
                "data breaches, or complete system compromise depending on the CVE."
            )
        elif "port" in title:
            return (
                "Exposed network services provide attack surface. Attackers can "
                "probe for version-specific vulnerabilities, attempt authentication "
                "bypass, or use the service for reconnaissance and lateral movement."
            )
        else:
            return (
                f"An attacker may exploit this {severity}-severity issue to compromise "
                f"system confidentiality, integrity, or availability. The specific "
                f"impact depends on the vulnerability type and attacker objectives."
            )

    def _generate_defense_strategy(self, finding: dict) -> str:
        """Generate defense strategy based on finding type."""
        if finding.get("defense_strategy"):
            return finding["defense_strategy"]
        
        title = finding.get("title", "").lower()
        
        if "sql" in title or "mysql" in title or "postgres" in title or "redis" in title or "mongo" in title:
            return (
                "Implement network segmentation with databases in isolated subnets. "
                "Use VPN or private connectivity for database access. Enable "
                "strong authentication, encryption at rest and in transit, and "
                "regular automated backups. Monitor database connections for "
                "unusual patterns or unauthorized access attempts."
            )
        elif "ssh" in title:
            return (
                "Disable password authentication; use key-based authentication only. "
                "Implement fail2ban to block brute force attempts. Restrict SSH "
                "access to specific IP ranges or require VPN. Use non-standard "
                "ports and monitor login attempts with alerting for suspicious activity."
            )
        elif "ftp" in title:
            return (
                "Replace FTP with SFTP or FTPS for encrypted file transfers. "
                "Implement IP-based access restrictions. Use strong authentication "
                "and chroot jails to limit user access. Monitor file access logs "
                "and implement file integrity monitoring."
            )
        elif "telnet" in title:
            return (
                "Immediately disable Telnet service. Replace with SSH for secure "
                "remote access. Remove Telnet from startup services and firewall "
                "rules. Audit systems for any Telnet dependencies before removal."
            )
        elif "sensitive file" in title or ".env" in title or ".git" in title:
            return (
                "Implement proper file permissions and access controls. Use '.gitignore' "
                "to prevent committing sensitive files. Store secrets in secure "
                "vaults (HashiCorp Vault, AWS Secrets Manager). Implement Web "
                "Application Firewall (WAF) rules to block access to sensitive paths."
            )
        elif "tls" in title or "ssl" in title or "certificate" in title:
            return (
                "Enable TLS 1.2 or higher only. Disable weak ciphers and protocols. "
                "Use certificate pinning for mobile applications. Implement "
                "automated certificate renewal (Let's Encrypt with certbot). "
                "Monitor certificate expiration with automated alerts."
            )
        elif "header" in title and "security" in title:
            return (
                "Implement security headers at the web server or application level: "
                "Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, "
                "Strict-Transport-Security, X-XSS-Protection. Use security headers "
                "scanning tools to validate configuration. Include headers in "
                "automated deployment pipelines."
            )
        elif "cve" in title or "vulnerability" in title:
            return (
                "Establish a vulnerability management program with regular scanning. "
                "Maintain an asset inventory with software versions. Subscribe to "
                "security advisories for critical components. Implement automated "
                "patching where possible and maintain a patching SLA based on severity."
            )
        elif "port" in title:
            return (
                "Implement host-based and network-based firewalls with default-deny "
                "policies. Use port knocking or jump hosts for administrative access. "
                "Regularly audit exposed ports with automated scanning. Implement "
                "network segmentation to limit lateral movement potential."
            )
        else:
            return (
                "Implement defense in depth with multiple security layers. Apply "
                "the principle of least privilege. Monitor logs for suspicious "
                "activity. Maintain regular backups and have an incident response "
                "plan ready. Conduct regular security assessments and penetration tests."
            )

    def _generate_mitigation_plan(self, finding: dict) -> str:
        """Generate mitigation plan with priorities and timelines."""
        if finding.get("mitigation_plan"):
            return finding["mitigation_plan"]
        
        severity = finding.get("severity", "medium")
        remediation = finding.get("remediation", "")
        
        timelines = {
            "critical": "Immediate (within 24 hours)",
            "high": "Urgent (within 1 week)",
            "medium": "Short-term (within 1 month)",
            "low": "Long-term (next maintenance cycle)",
            "info": "As needed (informational only)",
        }
        
        timeline = timelines.get(severity, "As appropriate")
        
        plan = f"""**Priority:** {severity.upper()}
**Timeline:** {timeline}

**Immediate Actions:**
1. Assess the scope of exposure and identify affected systems
2. Implement temporary controls (firewall rules, access restrictions)
3. Review logs for signs of exploitation or unauthorized access

**Remediation Steps:**
{remediation}

**Verification:**
- Re-scan after remediation to confirm issue is resolved
- Implement automated monitoring to prevent regression
- Document changes in configuration management system

**Long-term Improvements:**
- Include this check in continuous security monitoring
- Update security baselines and hardening guides
- Train development/operations teams on secure configuration"""
        
        return plan

    def generate(self):
        output_root = Path(self.output_directory).resolve()
        output_root.mkdir(parents=True, exist_ok=True)
        output_path = output_root / f"{self.output_name}.md"

        md = []

        # COVER
        md.append("# BitProbe Security Assessment Report\n\n")
        md.append(f"**Client:** {self.client_name}  \n")
        md.append(f"**Target:** {self.report_data.get('target')}  \n")
        md.append(f"**Date:** {self.timestamp}  \n")
        md.append(f"**Scan ID:** {self.report_data.get('scan_id')}  \n")
        md.append("\n---\n")

        stats = self.report_data.get("statistics", {})
        severity_stats = stats.get("findings_by_severity", {})
        risk = stats.get("risk", {})
        raw_risk = risk.get("raw_score", 0)
        adjusted_risk = risk.get("adjusted_score", risk.get("normalized_score", 0))
        normalized_risk = risk.get("normalized_score", adjusted_risk)

        # EXEC SUMMARY
        md.append("## Executive Summary\n\n")
        md.append(
            "This report presents the findings of an automated security assessment performed using **BitProbe**. "
            "The objective of this assessment was to identify security weaknesses, misconfigurations, and known "
            "vulnerabilities that could impact the confidentiality, integrity, or availability of the target system.\n\n"
        )

        md.append("### Overall Risk Posture\n\n")
        md.append(
            f"- **Overall Risk Level:** `{risk.get('level', 'unknown').upper()}`  \n"
        )
        md.append(
            f"- **Risk Score (Post-Edge):** {normalized_risk} / 100 "
            f"(pre-edge: {raw_risk})  \n"
        )
        md.append(f"- **Edge-Adjusted Total (uncapped):** {adjusted_risk}  \n\n")

        md.append("### Risk Overview by Severity\n\n")
        for sev, count in severity_stats.items():
            if count > 0:
                md.append(f"- **{sev.upper()}**: {count}\n")

        md.append(f"\n**Total Findings:** {stats.get('total_findings', 0)}  \n")
        md.append(f"**URLs Scanned:** {stats.get('urls_scanned')}  \n")
        md.append(f"**Scan Duration:** {stats.get('duration_seconds')} seconds  \n")

        md.append("\n---\n")

        # DETAILED FINDINGS
        md.append("## Detailed Findings\n\n")

        if not self.report_data.get("findings"):
            md.append("✅ No security issues were detected during this scan.\n")
        else:
            for idx, finding in enumerate(self.report_data["findings"], 1):
                md.append(f"### {idx}. {finding['title']}\n")
                md.append(f"**Severity:** `{finding['severity'].upper()}`  \n")

                edge_flag = finding.get("edge_infrastructure", False)
                raw_score = finding.get("raw_risk_score", finding.get("risk_score"))
                adjusted_score = finding.get("adjusted_risk_score", raw_score)

                md.append(
                    f"**Edge Infrastructure:** {'YES' if edge_flag else 'NO'}  \n"
                )

                if raw_score is not None:
                    md.append(f"**Risk Score (pre-edge):** {raw_score}  \n")

                if adjusted_score is not None:
                    md.append(f"**Risk Score (post-edge):** {adjusted_score}  \n")

                md.append(f"**Affected URL:** {finding['url']}  \n\n")

                md.append("**Description:**\n")
                md.append(f"{finding['description']}\n\n")

                md.append("**Evidence:**\n")
                md.append("```json\n")
                md.append(f"{finding.get('evidence', {})}\n")
                md.append("```\n\n")

                # Generate and include attack/defense/mitigation content
                md.append("### Attack Strategy\n")
                md.append(f"{self._generate_attack_scenario(finding)}\n\n")

                md.append("### Defense Strategy\n")
                md.append(f"{self._generate_defense_strategy(finding)}\n\n")

                md.append("### Mitigation Plan\n")
                md.append(f"{self._generate_mitigation_plan(finding)}\n\n")

                md.append("**Remediation:**\n")
                md.append(f"{finding['remediation']}\n\n")
                md.append("---\n\n")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("".join(md))
        assert output_path.exists(), f"Failed to write {output_path}"

        return str(output_path)
