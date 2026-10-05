from core import updates


def _release(version="3.7.0"):
    # PC 端 Release 使用 pc/ 前缀，与 Android 端（android/）在同一仓库内隔离。
    tag = f"pc/v{version}"
    return {
        "tag_name": tag, "draft": False, "prerelease": False,
        "html_url": f"https://github.com/faegit/faevault-site/releases/tag/{tag}",
        "body": "changes",
        "assets": [{
            "name": f"FAEVault_v{version}_Setup.exe",
            "browser_download_url": f"https://github.com/faegit/faevault-site/releases/download/{tag}/FAEVault_v{version}_Setup.exe",
        }],
    }


def test_select_pc_release_ignores_android_tags_and_picks_newest():
    releases = [
        _release("4.6.2"),
        {"tag_name": "android/v9.9.9", "draft": False, "prerelease": False,
         "html_url": "https://github.com/faegit/faevault-site/releases/tag/android/v9.9.9",
         "assets": [{"name": "app-universal-release.apk",
                     "browser_download_url": "https://github.com/faegit/faevault-site/releases/download/android/v9.9.9/app-universal-release.apk"}]},
        _release("4.1.0"),
        {"tag_name": "pc/v5.0.0", "draft": True, "prerelease": False, "assets": []},
    ]
    picked = updates.select_pc_release(releases)
    assert picked["tag_name"] == "pc/v4.6.2"


def test_select_pc_release_requires_pc_releases():
    import pytest
    only_android = [{"tag_name": "android/v1.0.0", "assets": []}]
    with pytest.raises(ValueError):
        updates.select_pc_release(only_android)


def test_parse_release_selects_exact_windows_installer():
    info = updates.parse_release(_release())
    assert info.version == "3.7.0"
    assert info.download_url.endswith("FAEVault_v3.7.0_Setup.exe")


def test_version_comparison_is_numeric():
    assert updates.is_newer("3.10.0", "3.9.9")
    assert not updates.is_newer("3.6.2", "3.6.2")


def test_parse_release_rejects_untrusted_asset_url():
    payload = _release()
    payload["assets"][0]["browser_download_url"] = "https://example.com/setup.exe"
    try:
        updates.parse_release(payload)
    except ValueError as exc:
        assert "Windows 安装包" in str(exc)
    else:
        raise AssertionError("untrusted asset URL accepted")


def _info(checksum=""):
    return updates.UpdateInfo(
        version="4.6.5",
        notes="n",
        page_url="https://github.com/faegit/faevault-site/releases/tag/pc/v4.6.5",
        download_url=(
            "https://github.com/faegit/faevault-site/releases/download/pc/v4.6.5/"
            "FAEVault_v4.6.5_Setup.exe"
        ),
        checksum_url=checksum,
    )


def test_download_update_reports_every_stage_in_order(tmp_path, monkeypatch):
    """阶段回调让 UI 能把「下载」切成「校验」再切成「安装」。

    回归点：原先下载与校验是同一次调用里的两步，界面只能停在 100%，用户
    分不清是在下载、在校验还是已经开始装。
    """
    monkeypatch.setattr(updates, "download_file", lambda url, dest, progress=None: dest.write_bytes(b"x"))
    monkeypatch.setattr(updates, "fetch_text", lambda url: f"{'a' * 64}  FAEVault_v4.6.5_Setup.exe")
    monkeypatch.setattr(updates, "verify_checksum", lambda path, expected: None)

    seen: list = []
    out = updates.download_update(
        _info(checksum="https://example/SHA256SUMS.txt"),
        dest_dir=tmp_path,
        on_stage=seen.append,
    )
    assert out.exists()
    assert seen == [
        updates.InstallStage.DOWNLOADING,
        updates.InstallStage.VERIFYING,
        updates.InstallStage.INSTALLING,
    ]


def test_download_update_skips_verifying_without_a_checksum_file(tmp_path, monkeypatch):
    monkeypatch.setattr(updates, "download_file", lambda url, dest, progress=None: dest.write_bytes(b"x"))

    def _boom(url):
        raise AssertionError("没有校验文件时不该去取")

    monkeypatch.setattr(updates, "fetch_text", _boom)
    seen: list = []
    updates.download_update(_info(), dest_dir=tmp_path, on_stage=seen.append)
    assert updates.InstallStage.VERIFYING not in seen
    assert seen[-1] is updates.InstallStage.INSTALLING


def test_install_update_launches_the_installer_silently(tmp_path, monkeypatch):
    """安装器必须静默启动，且调用方拿得到句柄以便观察成败。"""
    recorded = {}

    class _Proc:
        pid = 4321

    def _popen(command, creationflags=0):
        recorded["command"] = command
        recorded["creationflags"] = creationflags
        return _Proc()

    monkeypatch.setattr(updates.subprocess, "Popen", _popen)
    setup = tmp_path / "FAEVault_v4.6.5_Setup.exe"
    setup.write_bytes(b"x")
    proc = updates.install_update(setup)
    assert proc.pid == 4321
    assert recorded["command"][0] == str(setup)
    for flag in ("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"):
        assert flag in recorded["command"]


def test_wait_for_install_returns_the_installer_exit_code(monkeypatch):
    class _Proc:
        def __init__(self, codes):
            self._codes = list(codes)

        def poll(self):
            return self._codes.pop(0) if self._codes else None

    monkeypatch.setattr(updates.time, "sleep", lambda _s: None)
    # 先返回 None（还在跑），再返回 0：必须等到真正的结束，不能只看第一次。
    assert updates.wait_for_install(_Proc([None, None, 0]), poll_interval=0) == 0
    assert updates.wait_for_install(_Proc([5]), poll_interval=0) == 5
