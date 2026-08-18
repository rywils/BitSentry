from pathlib import Path


def test_cve_workflow_has_safe_producer_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/update-cve-db.yml").read_text(encoding="utf-8")

    assert 'cron: "17 6 * * *"' in workflow
    assert "full_rebuild:" in workflow
    assert "contents: write" in workflow
    assert "group: cve-db-producer" in workflow
    assert 'python-version: "3.13"' in workflow
    assert "NVD_API_KEY" in workflow
    assert workflow.index("Restore previous snapshot") < workflow.index("Update canonical database")
    assert "build_cve_snapshot.py" in workflow
    assert "update_cve_snapshot_release.sh" in workflow


def test_release_script_keeps_database_releases_out_of_latest() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts/update_cve_snapshot_release.sh").read_text(encoding="utf-8")
    assert "cve-db-latest" in script
    assert "--latest=false" in script
    assert "--clobber" in script
