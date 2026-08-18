from __future__ import annotations

import sys
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

import pytest


_BITPROBE = Path(__file__).resolve().parents[1] / "bitprobe"
if str(_BITPROBE) not in sys.path:
    sys.path.insert(0, str(_BITPROBE))


def test_lock_is_reentrant_and_released_after_exception(tmp_path: Path) -> None:
    from scanner.update_lock import bitsentry_update_lock

    lock_path = tmp_path / ".update.lock"
    with pytest.raises(RuntimeError):
        with bitsentry_update_lock(lock_path=lock_path):
            with bitsentry_update_lock(lock_path=lock_path):
                raise RuntimeError("boom")

    with bitsentry_update_lock(lock_path=lock_path):
        assert lock_path.exists()


def test_lock_contention_fails_without_waiting(tmp_path: Path) -> None:
    from scanner.update_lock import UpdateLockError, bitsentry_update_lock

    lock_path = tmp_path / ".update.lock"
    with bitsentry_update_lock(lock_path=lock_path):
        with pytest.raises(UpdateLockError):
            with bitsentry_update_lock(lock_path=lock_path, _allow_reentry=False):
                pass


def test_cve_update_uses_shared_lock(monkeypatch, tmp_path: Path) -> None:
    import scanner.cve_db_manager as manager

    monkeypatch.setattr(manager, "CVE_DB_PATH", str(tmp_path / "cve.sqlite"))
    monkeypatch.setattr(manager, "CVE_META_PATH", str(tmp_path / "meta.json"))
    monkeypatch.setattr(manager, "migrate_legacy_cve_database", lambda: False)
    lock = mock.Mock(return_value=nullcontext())
    monkeypatch.setattr(manager, "bitsentry_update_lock", lock)
    response = mock.Mock(status_code=200)
    response.json.return_value = {"vulnerabilities": [], "totalResults": 0}
    monkeypatch.setattr(manager, "_nvd_get", lambda *args, **kwargs: response)

    manager.update_cve_database(incremental=False)

    lock.assert_called_once_with()
