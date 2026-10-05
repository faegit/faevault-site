from pathlib import Path


def test_sanitize_windows_runtime_removes_path_polluted_icu(tmp_path: Path):
    from tools.sanitize_windows_runtime import sanitize_windows_runtime

    app = tmp_path / "FAEVault"
    internal = app / "_internal"
    pyside = internal / "PySide6"
    pyside.mkdir(parents=True)
    (internal / "icuuc.dll").write_bytes(b"third-party-versioned-icu")
    (internal / "icudt78.dll").write_bytes(b"third-party-icu-data")
    (internal / "python312.dll").write_bytes(b"keep")
    (pyside / "Qt6Core.dll").write_bytes(b"keep")

    removed = sanitize_windows_runtime(app)

    assert removed == ("icudt78.dll", "icuuc.dll")
    assert not (internal / "icuuc.dll").exists()
    assert not (internal / "icudt78.dll").exists()
    assert (internal / "python312.dll").read_bytes() == b"keep"
    assert (pyside / "Qt6Core.dll").read_bytes() == b"keep"

