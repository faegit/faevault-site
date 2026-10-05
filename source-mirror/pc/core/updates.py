"""GitHub Releases update metadata with strict, testable parsing."""

from __future__ import annotations

import enum
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

RELEASES_API = "https://api.github.com/repos/faegit/faevault-site/releases?per_page=50"
# Release tag 前缀。Android 与 PC 共用 faegit/faevault-site 仓库但各自发版，
# 因此不能用 releases/latest（会命中另一端的最新发布）；改为按前缀筛选。
RELEASE_TAG_PREFIX = "pc/"
_VERSION_RE = re.compile(r"^(?:v)?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    notes: str
    page_url: str
    download_url: str
    checksum_url: str = ""


def version_tuple(value: str) -> tuple[int, int, int]:
    match = _VERSION_RE.fullmatch(value.strip())
    if not match:
        raise ValueError("无效版本号")
    return tuple(int(part) for part in match.groups())


def parse_release(payload: object) -> UpdateInfo:
    if not isinstance(payload, dict) or payload.get("draft") or payload.get("prerelease"):
        raise ValueError("没有可用的正式版本")
    # tag 形如 pc/v4.6.2：先去掉端前缀，再去掉 v 前缀。
    version = str(payload.get("tag_name") or "").removeprefix(RELEASE_TAG_PREFIX).removeprefix("v")
    version_tuple(version)
    page_url = str(payload.get("html_url") or "")
    if not page_url.startswith("https://github.com/faegit/faevault-site/releases/"):
        raise ValueError("发布页面地址无效")
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise ValueError("发布资产无效")
    expected = f"FAEVault_v{version}_Setup.exe"
    asset = next((item for item in assets if isinstance(item, dict) and item.get("name") == expected), None)
    download_url = str((asset or {}).get("browser_download_url") or "")
    if not download_url.startswith("https://github.com/faegit/faevault-site/releases/download/"):
        raise ValueError("未找到 Windows 安装包")
    checksum = next(
        (item for item in assets if isinstance(item, dict) and item.get("name") == "SHA256SUMS.txt"), None
    )
    checksum_url = str((checksum or {}).get("browser_download_url") or "")
    if checksum_url and not checksum_url.startswith("https://github.com/faegit/faevault-site/releases/download/"):
        raise ValueError("校验文件地址无效")
    return UpdateInfo(version, str(payload.get("body") or "").strip(), page_url, download_url, checksum_url)


def select_pc_release(releases: object) -> dict:
    """从 releases 列表里挑出本端最新的正式发布：tag 带 pc/ 前缀，按版本号从高到低。"""
    if not isinstance(releases, list):
        raise ValueError("发布列表无效")
    candidates = [
        item
        for item in releases
        if isinstance(item, dict)
        and str(item.get("tag_name") or "").startswith(RELEASE_TAG_PREFIX)
        and not item.get("draft")
        and not item.get("prerelease")
    ]
    if not candidates:
        raise ValueError("没有找到可用的正式版本")

    def version_key(release: dict) -> int:
        version = (
            str(release.get("tag_name") or "")
            .removeprefix(RELEASE_TAG_PREFIX)
            .removeprefix("v")
        )
        try:
            major, minor, patch = version_tuple(version)
        except ValueError:
            return 0
        return major * 1_000_000 + minor * 1_000 + patch

    return max(candidates, key=version_key)


def check_latest(*, timeout: float = 10.0) -> UpdateInfo:
    request = urllib.request.Request(
        RELEASES_API,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "FAEVault-UpdateChecker"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise OSError(f"更新服务返回 HTTP {response.status}")
        payload = json.loads(response.read(4_000_001))
    return parse_release(select_pc_release(payload))


def is_newer(latest: str, current: str) -> bool:
    return version_tuple(latest) > version_tuple(current)


def _checksum_map(text: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            mapping[parts[1].lstrip("*")] = parts[0].lower()
    return mapping


def parse_checksums(text: str, filename: str) -> str:
    mapping = _checksum_map(text)
    if filename not in mapping:
        raise ValueError(f"校验文件中未找到 {filename}")
    return mapping[filename]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(path: Path, expected: str) -> None:
    if sha256_of(path) != expected.lower():
        raise ValueError("下载文件校验失败，可能与发布内容不一致")


def download_file(
    url: str,
    dest: Path,
    *,
    timeout: float = 30.0,
    progress: Callable[[int, int], None] | None = None,
) -> Path:
    """流式下载到 dest，按需回调 (已下载字节, 总字节)。"""
    request = urllib.request.Request(url, headers={"User-Agent": "FAEVault-UpdateDownloader"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise OSError(f"下载服务返回 HTTP {response.status}")
        total = int(response.headers.get("Content-Length") or 0)
        received = 0
        with dest.open("wb") as handle:
            while True:
                chunk = response.read(1 << 16)
                if not chunk:
                    break
                handle.write(chunk)
                received += len(chunk)
                if progress:
                    progress(received, total)
    if progress:
        progress(received, received)
    return dest


def fetch_text(url: str, *, timeout: float = 30.0) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "FAEVault-UpdateChecker"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise OSError(f"更新服务返回 HTTP {response.status}")
        return response.read(1 << 20).decode("utf-8", errors="replace")


class InstallStage(enum.Enum):
    """安装更新的阶段。UI 据此切换文案与进度条形态。

    分成这四段是因为它们的风险不同：下载失败可以重来，校验失败说明包被篡改
    必须停下换渠道，而安装阶段一旦启动外部进程，用户就再也回不到「取消」——
    那时候唯一能做的只有等，或者去官网手动下载。
    """

    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    INSTALLING = "installing"
    DONE = "done"


def download_update(
    info: UpdateInfo,
    *,
    dest_dir: Path | None = None,
    progress: Callable[[int, int], None] | None = None,
    on_stage: Callable[[InstallStage], None] | None = None,
) -> Path:
    """下载并校验最新安装包，返回本地 Setup.exe 路径。

    on_stage 会在进入校验与安装阶段时回调，让 UI 把「下载 XX MB」换成
    「正在校验…」——此前这两个阶段混在同一次调用里，界面只能停在 100%。
    """
    def _stage(value: InstallStage) -> None:
        if on_stage is not None:
            on_stage(value)

    _stage(InstallStage.DOWNLOADING)
    dest_dir = dest_dir or Path(tempfile.gettempdir()) / "faevault-update"
    dest_dir.mkdir(parents=True, exist_ok=True)
    setup_name = Path(info.download_url).name
    setup_path = dest_dir / setup_name
    download_file(info.download_url, setup_path, progress=progress)
    if info.checksum_url:
        _stage(InstallStage.VERIFYING)
        text = fetch_text(info.checksum_url)
        expected = parse_checksums(text, setup_name)
        verify_checksum(setup_path, expected)
    _stage(InstallStage.INSTALLING)
    return setup_path


def install_update(setup_path: Path) -> subprocess.Popen:
    """以静默模式启动安装包；安装器会自动关闭占用进程并卸载旧版。

    返回 Popen 是为了让调用方能观察到安装器的存活状态：原先返回值被直接丢弃，
    UI 打印一句「安装程序将立即在后台运行」就退出，而安装器到底成没成功，
    应用这边无从得知。
    """
    command = [str(setup_path), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | 0x00000008  # DETACHED_PROCESS
    return subprocess.Popen(command, creationflags=creationflags)


def wait_for_install(proc: subprocess.Popen, *, poll_interval: float = 0.5) -> int | None:
    """等待安装器结束，返回其退出码。

    注意 Inno Setup 用 `/VERYSILENT` 启动时，退出码 0 表示安装器自身跑完；它
    内部会调用旧版卸载与文件替换，那些失败会以非 0 传出。超时返回 None 表示
    「安装器还活着但迟迟不退出」——通常是它正在等用户确认 UAC 或被占用文件
    卡住，此时不该报失败，而应提示用户去「程序和功能」里看。
    """
    while True:
        code = proc.poll()
        if code is not None:
            return code
        time.sleep(poll_interval)
