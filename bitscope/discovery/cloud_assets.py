"""
Cloud asset discovery (S3, CloudFront, Azure Blob, etc.)
"""

import re
from typing import Dict, List, Set
import requests


class CloudDiscovery:
    """Discover cloud assets associated with a domain."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "BitScope/1.0 (Security Research)"
        })
    
    def scan(self, domain: str) -> Dict[str, List[Dict]]:
        """Scan for all cloud asset types."""
        results = {}
        
        # AWS S3 buckets
        results["s3_buckets"] = self._find_s3_buckets(domain)
        
        # CloudFront distributions
        results["cloudfront"] = self._find_cloudfront(domain)
        
        # Azure Blob storage
        results["azure_blob"] = self._find_azure_blobs(domain)
        
        # Google Cloud Storage
        results["gcs"] = self._find_gcs_buckets(domain)
        
        return results
    
    def _find_s3_buckets(self, domain: str) -> List[Dict]:
        """Find potential S3 buckets from various sources."""
        found = []
        base_name = domain.replace(".", "-").lower()
        
        # Common bucket naming patterns
        patterns = [
            base_name,
            f"{base_name}-assets",
            f"{base_name}-static",
            f"{base_name}-media",
            f"{base_name}-uploads",
            f"{base_name}-backup",
            f"{base_name}-data",
            domain.replace(".", "").lower(),
        ]
        
        for bucket in patterns:
            for region in ["us-east-1", "us-west-2", "eu-west-1"]:
                url = f"https://{bucket}.s3.{region}.amazonaws.com"
                try:
                    response = self.session.head(url, timeout=5)
                    if response.status_code == 200:
                        found.append({
                            "bucket": bucket,
                            "region": region,
                            "url": url,
                            "state": "exists",
                            "public": True,
                        })
                        break
                    elif response.status_code == 403:
                        found.append({
                            "bucket": bucket,
                            "region": region,
                            "url": url,
                            "state": "exists",
                            "public": False,
                        })
                        break
                except Exception:
                    continue
        
        return found
    
    def _find_cloudfront(self, domain: str) -> List[Dict]:
        """Find CloudFront distributions."""
        found = []
        
        # Common CloudFront patterns in DNS
        # Would need DNS lookup integration for real implementation
        # This is a placeholder
        
        return found
    
    def _find_azure_blobs(self, domain: str) -> List[Dict]:
        """Find Azure Blob storage accounts."""
        found = []
        base = domain.replace(".", "").replace("-", "").lower()[:24]
        
        patterns = [
            base,
            f"{base}storage",
            f"{base}data",
            f"{base}assets",
        ]
        
        for account in patterns:
            url = f"https://{account}.blob.core.windows.net"
            try:
                response = self.session.head(url, timeout=5)
                if response.status_code != 404:
                    found.append({
                        "account": account,
                        "url": url,
                        "exists": True,
                    })
            except Exception:
                continue
        
        return found
    
    def _find_gcs_buckets(self, domain: str) -> List[Dict]:
        """Find Google Cloud Storage buckets."""
        found = []
        base_name = domain.replace(".", "-").lower()
        
        patterns = [
            base_name,
            f"{base_name}-assets",
        ]
        
        for bucket in patterns:
            url = f"https://storage.googleapis.com/{bucket}"
            try:
                response = self.session.head(url, timeout=5)
                if response.status_code == 200:
                    found.append({
                        "bucket": bucket,
                        "url": url,
                        "public": True,
                    })
            except Exception:
                continue
        
        return found
