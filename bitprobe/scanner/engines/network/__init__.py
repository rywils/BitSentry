"""
High-performance network scanner.

Tries to use Go native scanner if available and compiled.
Falls back to pure-Python async implementation.

Usage:
    from scanner.engines.network import scan_target, quick_scan
    
    # Full scan with metadata
    result = scan_target("example.com", ports="top100")
    
    # Quick list of open ports
    open_ports = quick_scan("example.com")
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

# Path to Go scanner
GO_SOURCE = Path(__file__).parent / "scanner.go"
BINARY_NAME = "network_scanner"


def _get_binary_path() -> Optional[Path]:
    """Get path to compiled binary if it exists."""
    binary_dir = GO_SOURCE.parent
    binary_path = binary_dir / BINARY_NAME
    
    if binary_path.exists():
        return binary_path
    
    # Try to compile if Go is available
    if shutil.which("go"):
        try:
            _compile_scanner(binary_path)
            return binary_path
        except Exception:
            pass
    
    return None


def _compile_scanner(output_path: Path) -> None:
    """Compile the Go scanner binary."""
    cmd = ["go", "build", "-o", str(output_path), str(GO_SOURCE)]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=GO_SOURCE.parent)
    
    if result.returncode != 0:
        raise RuntimeError(f"Failed to compile Go scanner: {result.stderr}")


def _use_go_scanner() -> bool:
    """Check if Go scanner is available."""
    return _get_binary_path() is not None


def scan_target_go(
    target: str,
    ports: str = "top100",
    scan_type: str = "connect",
    timeout_ms: int = 2000,
    concurrency: int = 0,
    grab_banners: bool = False,
) -> Dict:
    """Scan using Go binary."""
    binary = _get_binary_path()
    
    cmd = [
        str(binary),
        "-target", target,
        "-ports", ports,
        "-type", scan_type,
        "-timeout", str(timeout_ms),
        "-json",
    ]
    
    if concurrency > 0:
        cmd.extend(["-concurrency", str(concurrency)])
    
    if grab_banners:
        cmd.append("-banners")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        return {
            "error": result.stderr,
            "target": target,
            "results": [],
        }
    
    return json.loads(result.stdout)


def scan_target_native(
    target: str,
    ports: str = "top100",
    timeout_ms: int = 2000,
    concurrency: int = 100,
    grab_banners: bool = False,
) -> Dict:
    """Scan using pure Python implementation."""
    from .native import scan_target as native_scan
    return native_scan(target, ports, timeout_ms, concurrency, grab_banners)


def scan_target(
    target: str,
    ports: str = "top100",
    scan_type: str = "connect",
    timeout_ms: int = 2000,
    concurrency: int = 0,
    grab_banners: bool = False,
) -> Dict:
    """
    Scan target using best available scanner.
    
    Args:
        target: Hostname or IP to scan
        ports: "top100", "top1000", or list of ports
        scan_type: "connect", "syn", or "udp"
        timeout_ms: Connection timeout
        concurrency: Workers (0 = auto)
        grab_banners: Grab service banners
    
    Returns:
        Dict with scan results
    """
    # Use Go scanner if available
    if _use_go_scanner():
        return scan_target_go(
            target, ports, scan_type, timeout_ms, concurrency, grab_banners
        )
    
    # Fall back to native Python scanner
    return scan_target_native(
        target, ports, timeout_ms, concurrency or 100, grab_banners
    )


def quick_scan(target: str, ports: str = "top100") -> List[Dict]:
    """Quick scan returning just open ports."""
    result = scan_target(target, ports=ports)
    return result.get("results", [])


class NetworkScanner:
    """Unified network scanner interface."""
    
    def __init__(
        self,
        ports: str = "top100",
        timeout_ms: int = 2000,
        concurrency: int = 0,
        grab_banners: bool = False,
    ):
        self.ports = ports
        self.timeout_ms = timeout_ms
        self.concurrency = concurrency
        self.grab_banners = grab_banners
        self._using_go = _use_go_scanner()
    
    def scan(self, target: str) -> List[Dict]:
        """Scan a single target."""
        result = scan_target(
            target=target,
            ports=self.ports,
            timeout_ms=self.timeout_ms,
            concurrency=self.concurrency,
            grab_banners=self.grab_banners,
        )
        
        if "error" in result:
            raise RuntimeError(result["error"])
        
        # Return list of open port dicts
        return [
            {
                "port": r["port"],
                "protocol": r["protocol"],
                "state": r["state"],
                "service": r.get("service", ""),
                "banner": r.get("banner", ""),
                "response_time_ms": r.get("response_time_ms", 0),
            }
            for r in result.get("results", [])
            if r.get("state") == "open"
        ]
    
    def scan_many(self, targets: List[str]) -> Dict[str, List[Dict]]:
        """Scan multiple targets."""
        results = {}
        for target in targets:
            try:
                results[target] = self.scan(target)
            except Exception as e:
                results[target] = [{"error": str(e)}]
        return results
    
    @property
    def engine(self) -> str:
        """Return which engine is being used."""
        return "go" if self._using_go else "python-native"


__all__ = [
    "scan_target",
    "quick_scan",
    "NetworkScanner",
]
