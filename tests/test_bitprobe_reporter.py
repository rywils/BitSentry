import pytest

from scanner.reporting.reporter import Reporter


def failing_writer(*_args):
    raise RuntimeError("reportlab missing")


def test_reporter_preserves_json_when_pdf_fails(tmp_path, monkeypatch):
    writers = Reporter.WRITERS.copy()
    writers["pdf"] = failing_writer
    monkeypatch.setattr(Reporter, "WRITERS", writers)

    artifacts = Reporter.write(
        {"scan_id": "scan_1"},
        "scan_1",
        ["json", "pdf"],
        str(tmp_path),
    )

    assert artifacts == [str((tmp_path / "scan_1.json").resolve())]
    assert (tmp_path / "scan_1.json").is_file()


def test_reporter_fails_when_every_requested_format_fails(tmp_path, monkeypatch):
    writers = Reporter.WRITERS.copy()
    writers["pdf"] = failing_writer
    monkeypatch.setattr(Reporter, "WRITERS", writers)

    with pytest.raises(RuntimeError, match="PDF report generation failed"):
        Reporter.write(
            {"scan_id": "scan_1"},
            "scan_1",
            ["pdf"],
            str(tmp_path),
        )
