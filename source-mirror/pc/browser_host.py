"""Executable Native Messaging host for Vault browser autofill."""

from __future__ import annotations

import os
import sys
import time
from core import config, autofill_exclusions
from core import crypto
from core import log as log_module
from core.browser_autofill import (
    CHROMIUM_EXTENSION_ID,
    FIREFOX_EXTENSION_ID,
    ProtocolError,
    failure,
    parse_request,
    read_message,
    success,
    write_message,
    origin_is_excluded,
)
from core.browser_host import BrowserAutofillController, SaveSelection
from core.storage import Vault, vault_dir

ALLOWED_CALLERS = {
    f"chrome-extension://{CHROMIUM_EXTENSION_ID}/",
    FIREFOX_EXTENSION_ID,
}

_log = log_module.get("browser_host")
_qt_app = None
def _caller_allowed(arguments: list[str]) -> bool:
    if os.environ.get("VAULT_AUTOFILL_ALLOW_TEST_CALLER") == "1":
        return True
    normalized = {arg.strip() for arg in arguments if isinstance(arg, str)}
    return bool(normalized & ALLOWED_CALLERS)


def _application():
    global _qt_app
    if _qt_app is None:
        from PySide6.QtCore import QLocale
        from PySide6.QtWidgets import QApplication

        from ui import i18n, theme, widgets

        _qt_app = QApplication.instance() or QApplication(["Vault Browser Autofill"])
        widgets.install_combobox_wheel_guard()
        _qt_app.setQuitOnLastWindowClosed(False)
        i18n.install(_qt_app, config.language_mode(), QLocale.system().name())
        _qt_app.setWindowIcon(widgets.app_icon())
        _qt_app.setStyleSheet(theme.stylesheet(config.theme_mode()))
    return _qt_app


def _unlock_vault() -> Vault | None:
    from PySide6.QtWidgets import QDialog

    from ui.dialogs import UnlockDialog
    from ui import widgets

    _application()
    dialog = UnlockDialog()
    dialog.setWindowTitle("浏览器自动填充 - 解锁保险库")
    dialog.setWindowIcon(widgets.app_icon())
    if dialog.exec() != QDialog.Accepted:
        return None
    if dialog.vault is not None:
        autofill_exclusions.sync_local_config(dialog.vault, migrate=True)
    return dialog.vault


def _unlock_vault_with_password(password: str) -> Vault:
    current_user = config.get_current_user()
    record = next((item for item in config.list_users() if item.get("name") == current_user), None)
    if record is None:
        raise ProtocolError("NO_ACCOUNT", "请先在保险库主程序中选择当前账户")

    remaining = int(config.password_cooling_remaining() + 0.999)
    if remaining > 0:
        raise ProtocolError("RATE_LIMITED", f"尝试次数过多，请在 {remaining} 秒后重试", retryable=True)

    try:
        vault = Vault.open(config.user_vault_path(record), password)
    except crypto.DecryptError as exc:
        new_count, delay, entered_cooldown, cooldown = config.record_password_failure()
        if entered_cooldown:
            raise ProtocolError(
                "RATE_LIMITED",
                f"主密码错误次数过多，请等待约 {cooldown} 秒后重试",
                retryable=True,
            ) from exc
        time.sleep(delay)
        attempts_left = config.PASSWORD_MAX_ATTEMPTS - new_count
        raise ProtocolError(
            "WRONG_PASSWORD",
            f"主密码不正确，还可尝试 {attempts_left} 次",
            retryable=True,
        ) from exc
    except (OSError, ValueError) as exc:
        raise ProtocolError("VAULT_UNAVAILABLE", "无法打开当前账户的保险库", retryable=True) from exc

    config.set_current_user(str(record["name"]))
    config.clear_password_lockout()
    autofill_exclusions.sync_local_config(vault, migrate=True)
    return vault


def _is_ip_origin_authorized(origin: str) -> bool:
    allowed, signature_valid = config.browser_private_origins()
    if not signature_valid:
        _log.warning("IP 地址自动填充授权签名无效，已拒绝已有授权")
        config.set_browser_private_origins([])
        return False
    return origin in allowed


def _authorize_ip_origin(origin: str) -> bool:
    if _is_ip_origin_authorized(origin):
        return True
    allowed, _signature_valid = config.browser_private_origins()

    from ui import widgets

    _application()
    approved = widgets.confirm(
        None,
        "授权 IP 地址自动填充",
        f"是否允许 FAEVault 在以下 IP 来源自动填充？\n\n{origin}\n\n"
        "授权仅匹配此 IP 和端口。确认这是你信任的设备或服务；地址归属变化时请立即在设置中撤销授权。",
        kind="warn",
    )
    if not approved:
        return False
    config.set_browser_private_origins([*allowed[-63:], origin])
    _log.info("已授权 IP 地址自动填充来源：%s", origin)
    return True


def _is_origin_excluded(origin: str) -> bool:
    return origin_is_excluded(origin, config.get("browser_autofill_excluded_hosts", []))


def _confirm_word_match(origin: str, entry) -> bool:
    from ui import i18n, widgets

    _application()
    return widgets.confirm(
        None,
        "确认自动填充来源",
        i18n.tr("所选条目仅名称与此网页有单词匹配。\n\n"
                "条目：{title}\n保存的网站：{url}\n当前网页：{origin}\n\n"
                "确认信任当前网页后，允许仅本次填充所选条目？").format(
                    title=entry.title, url=entry.url or i18n.tr("未设置"), origin=origin,
                ),
        kind="warn",
    )


def _confirm_save(request, matches) -> SaveSelection:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QPushButton

    from ui import i18n, widgets

    _application()
    dialog = widgets.ShadowDialog("保存登录凭据", width=400)
    title = widgets.icon_text("保存到保险库", "vault", object_name="DetailTitle", icon_size=24)
    dialog.body.addWidget(title)
    site = QLabel(
        f"网站：{request.origin}\n账户：{request.username or i18n.tr('未填写用户名')}",
    )
    site.setWordWrap(True)
    site.setTextInteractionFlags(Qt.TextSelectableByMouse)
    dialog.body.addWidget(site)
    note = QLabel("密码不会显示在确认窗口中。请选择更新现有条目或新建条目。")
    note.setObjectName("Empty")
    note.setWordWrap(True)
    dialog.body.addWidget(note)

    combo = None
    update_button = None
    result = SaveSelection("cancel")
    if matches:
        combo = QComboBox()
        for entry in matches:
            label = entry.title or entry.username or request.origin
            account = f" · {entry.username}" if entry.username else ""
            combo.addItem(f"{label}{account}", entry.id)
        dialog.body.addWidget(combo)

    buttons = QHBoxLayout()
    cancel = QPushButton("取消")
    cancel.clicked.connect(dialog.reject)
    buttons.addWidget(cancel)
    buttons.addStretch()

    def choose(selection: SaveSelection) -> None:
        nonlocal result
        result = selection
        dialog.accept()

    if combo is not None:
        update_button = QPushButton("更新所选条目")
        update_button.clicked.connect(lambda: choose(SaveSelection("update", str(combo.currentData() or ""))))
        buttons.addWidget(update_button)
    create = QPushButton("新建条目")
    create.setObjectName("Primary")
    create.clicked.connect(lambda: choose(SaveSelection("create")))
    buttons.addWidget(create)
    dialog.body.addLayout(buttons)
    if dialog.exec() != QDialog.Accepted:
        return SaveSelection("cancel")
    return result


def _configure_binary_stdio() -> None:
    if os.name != "nt":
        return
    import msvcrt

    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)


def main(arguments: list[str] | None = None) -> int:
    from ui import i18n

    args = sys.argv[1:] if arguments is None else arguments
    _configure_binary_stdio()
    # stdout is reserved exclusively for Native Messaging frames.
    log_module.setup(log_file=vault_dir() / "vault_browser_host.log", console=False)
    i18n.set_locale(i18n.resolve_locale(config.language_mode(), ""))
    if not _caller_allowed(args):
        _log.warning("拒绝未授权的浏览器扩展调用")
        return 2

    controller = BrowserAutofillController(
        _unlock_vault,
        _confirm_save,
        unlock_with_password=_unlock_vault_with_password,
        is_origin_authorized=_is_ip_origin_authorized,
        authorize_origin=_authorize_ip_origin,
        is_origin_excluded=_is_origin_excluded,
        confirm_word_match=_confirm_word_match,
        lock_after_seconds=config.lock_seconds,
    )
    input_stream = sys.stdin.buffer
    output_stream = sys.stdout.buffer
    try:
        while True:
            request_id = ""
            try:
                raw = read_message(input_stream)
                if raw is None:
                    break
                request_id = raw.get("requestId", "") if isinstance(raw, dict) else ""
                request = parse_request(raw)
                result = controller.handle(request)
                if isinstance(result, dict):
                    result["uiLocale"] = i18n.current_locale()
                response = success(request.request_id, result)
            except ProtocolError as exc:
                response = failure(
                    request_id,
                    ProtocolError(exc.code, i18n.tr_dynamic(exc.message), retryable=exc.retryable),
                )
            except Exception:
                _log.exception("浏览器自动填充请求处理失败")
                response = failure(
                    request_id,
                    ProtocolError(
                        "INTERNAL_ERROR",
                        i18n.tr("自动填充操作失败"),
                        retryable=True,
                    ),
                )
            try:
                write_message(output_stream, response)
            except (BrokenPipeError, OSError):
                break
    finally:
        controller.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
