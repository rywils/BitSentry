from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BITPROBE = ROOT / "bitprobe"
if str(BITPROBE) not in sys.path:
    sys.path.insert(0, str(BITPROBE))


def _cli():
    spec = importlib.util.spec_from_file_location("bitprobe_cli_for_test", BITPROBE / "bitprobe.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_default_update_uses_snapshot_policy(monkeypatch) -> None:
    cli = _cli()
    policy = mock.Mock(return_value=4)
    direct = mock.Mock()
    monkeypatch.setattr(cli, "update_with_snapshot_policy", policy)
    monkeypatch.setattr(cli, "update_cve_database", direct)
    monkeypatch.setattr(sys, "argv", ["bitprobe", "update-cve-db"])

    assert cli.main() == 0
    policy.assert_called_once_with(snapshot_only=False, verbose=False)
    direct.assert_not_called()


def test_explicit_years_skips_snapshot(monkeypatch) -> None:
    cli = _cli()
    policy = mock.Mock()
    direct = mock.Mock(return_value=2)
    monkeypatch.setattr(cli, "update_with_snapshot_policy", policy)
    monkeypatch.setattr(cli, "update_cve_database", direct)
    monkeypatch.setattr(sys, "argv", ["bitprobe", "update-cve-db", "--years", "2"])

    assert cli.main() == 0
    policy.assert_not_called()
    assert direct.call_args.kwargs["years"] == 2


def test_snapshot_only_uses_snapshot_without_direct_nvd(monkeypatch) -> None:
    cli = _cli()
    policy = mock.Mock(return_value=0)
    direct = mock.Mock()
    monkeypatch.setattr(cli, "update_with_snapshot_policy", policy)
    monkeypatch.setattr(cli, "update_cve_database", direct)
    monkeypatch.setattr(sys, "argv", ["bitprobe", "update-cve-db", "--snapshot-only"])

    assert cli.main() == 0
    policy.assert_called_once_with(snapshot_only=True, verbose=False)
    direct.assert_not_called()


def test_raw_full_exposes_best_effort_unfiltered_escape_hatch(monkeypatch) -> None:
    cli = _cli()
    direct = mock.Mock(return_value=1)
    monkeypatch.setattr(cli, "update_cve_database", direct)
    monkeypatch.setattr(sys, "argv", ["bitprobe", "update-cve-db", "--raw-full"])

    assert cli.main() == 0
    assert direct.call_args.kwargs["full_sync"] is True
    assert direct.call_args.kwargs["raw_full_sync"] is True
