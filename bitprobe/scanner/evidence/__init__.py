"""Evidence collection for BitProbe security scanner."""

from .screenshotter import (
    Screenshotter,
    EvidenceCollector,
    capture_screenshot_sync,
)

__all__ = [
    "Screenshotter",
    "EvidenceCollector",
    "capture_screenshot_sync",
]
