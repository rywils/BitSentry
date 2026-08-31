from scanner.engines import network


def test_rust_binary_must_run_on_the_current_host(tmp_path, monkeypatch):
    incompatible = tmp_path / "bitprobe-engine"
    incompatible.write_bytes(b"not a native executable")
    incompatible.chmod(0o755)
    monkeypatch.setattr(network, "RUST_BINARY", incompatible)

    assert network._get_rust_binary() is None


def test_network_scanner_falls_back_when_rust_is_incompatible(tmp_path, monkeypatch):
    incompatible = tmp_path / "bitprobe-engine"
    incompatible.write_bytes(b"not a native executable")
    incompatible.chmod(0o755)
    monkeypatch.setattr(network, "RUST_BINARY", incompatible)
    monkeypatch.setattr(network, "_get_go_binary", lambda: None)

    scanner = network.NetworkScanner()

    assert scanner.engine == "python-native"
