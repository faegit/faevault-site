"""解锁校验异步化 + 旋转动画的行为守护。

重点验证：
- 主密码校验在后台线程完成，不再阻塞 UI 线程（``_UnlockVerifyWorker`` 信号契约）；
- ``SpinnerWidget`` 可正常 start/stop。
"""

import inspect
import threading
import time

import pytest
from PySide6.QtWidgets import QApplication
from PySide6.QtTest import QTest

from ui import dialogs, widgets


def _app():
    return QApplication.instance() or QApplication([])


def _pump_until(predicate):
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        QTest.qWait(10)
    assert predicate()


def test_unlock_worker_emits_succeeded(monkeypatch):
    _app()
    fake = object()

    class FakeVault:
        @staticmethod
        def open_with_password_buffer(path, pw):
            return fake

    monkeypatch.setattr(dialogs, "Vault", FakeVault)
    results = []
    worker = dialogs._UnlockVerifyWorker("p", bytearray(b"pw"))
    worker.succeeded.connect(lambda v: results.append(("ok", v)))
    worker.failed.connect(lambda k, m: results.append(("fail", k, m)))
    worker.run()
    assert results == [("ok", fake)]


def test_unlock_worker_emits_decrypt_on_wrong_password(monkeypatch):
    _app()

    class FakeVault:
        @staticmethod
        def open_with_password_buffer(path, pw):
            raise dialogs.crypto.DecryptError()

    monkeypatch.setattr(dialogs, "Vault", FakeVault)
    results = []
    worker = dialogs._UnlockVerifyWorker("p", bytearray(b"pw"))
    worker.succeeded.connect(lambda v: results.append(("ok", v)))
    worker.failed.connect(lambda k, m: results.append(("fail", k, m)))
    worker.run()
    assert results and results[0][0] == "fail" and results[0][1] == "decrypt"


def test_unlock_worker_zeroes_password_buffer(monkeypatch):
    _app()

    class FakeVault:
        @staticmethod
        def open_with_password_buffer(path, pw):
            return object()

    monkeypatch.setattr(dialogs, "Vault", FakeVault)
    buf = bytearray(b"secret-pw")
    worker = dialogs._UnlockVerifyWorker("p", buf)
    worker.run()
    assert buf == bytearray(len(buf))  # 缓冲区在用完后清零


def test_spinner_starts_and_stops():
    _app()
    spinner = widgets.SpinnerWidget()
    assert spinner._spinning is False
    spinner.start()
    assert spinner._spinning is True
    spinner.stop()
    assert spinner._spinning is False


def test_spinner_accepts_explicit_color_for_dark_buttons():
    _app()
    spinner = widgets.SpinnerWidget(color="#FFFFFF")
    assert spinner._color == "#FFFFFF"


def _unlock_dialog(monkeypatch):
    """构造一个带单个账户的解锁对话框，不触碰真实配置与密码库。"""
    _app()
    monkeypatch.setattr(dialogs.config, "list_users", lambda: [{"name": "FAE", "file": "fae.pmv"}])
    monkeypatch.setattr(dialogs.config, "get_current_user", lambda: "FAE")
    monkeypatch.setattr(dialogs.config, "set_current_user", lambda name: None)
    monkeypatch.setattr(dialogs.config, "user_vault_path", lambda _record: "fae.pmv")
    monkeypatch.setattr(dialogs.config, "password_cooling_remaining", lambda: 0)
    dialog = dialogs.UnlockDialog()
    dialog.show()
    _app().processEvents()
    return dialog


def test_slow_hello_probe_keeps_unlock_spinner_moving(monkeypatch):
    # Suppress the scheduled startup probe; exercise it explicitly below.
    with monkeypatch.context() as setup_patch:
        setup_patch.setattr(dialogs.UnlockDialog, "_load_hello_availability", lambda self: None)
        dialog = _unlock_dialog(monkeypatch)
    release = threading.Event()
    entered = threading.Event()
    finished = threading.Event()
    frame_changed = threading.Event()
    ui_thread = threading.get_ident()
    probe_threads = []

    def slow_probe():
        thread = threading.get_ident()
        probe_threads.append(thread)
        # Fail before blocking if the implementation regresses onto the UI thread.
        assert thread != ui_thread
        entered.set()
        release.wait()
        finished.set()
        return True

    def wait_for_ui(predicate):
        # This bounds a hung test, rather than measuring scheduling performance.
        deadline = time.monotonic() + 5
        while not predicate() and time.monotonic() < deadline:
            QTest.qWait(10)
        assert predicate()

    monkeypatch.setattr(dialogs.biometric, "available", slow_probe)
    monkeypatch.setattr(dialogs.biometric, "is_enabled", lambda _path: True)
    dialog._unlocking = True
    dialog.hello_btn.setEnabled(False)
    dialog.btn.start_busy("正在解锁…")
    dialog.btn._spinner._anim.valueChanged.connect(lambda _value: frame_changed.set())
    try:
        dialog._load_hello_availability()
        wait_for_ui(entered.is_set)
        assert len(probe_threads) == 1
        assert probe_threads[0] != ui_thread
        assert not dialog._hello_probe_future.done()
        assert not finished.is_set()
        assert dialog.btn._spinner._spinning
        assert dialog.btn._spinner.isVisible()
        frame_changed.clear()
        wait_for_ui(frame_changed.is_set)
        # A frame was delivered by the UI event loop while the worker was held.
        assert not finished.is_set()
        assert not dialog._hello_probe_future.done()
        assert not dialog.hello_btn.isEnabled()
        release.set()
        wait_for_ui(lambda: finished.is_set() and dialog._hello_ok)
        assert dialog._hello_probe_future.result() is True
        assert not dialog._hello_probe_timer.isActive()
        assert not dialog.hello_btn.isEnabled()
    finally:
        release.set()
        if dialog._hello_probe_future is not None:
            dialog._hello_probe_future.result(timeout=5)
        dialog._unlocking = False
        dialog.btn.stop_busy()
        dialog.close()


def test_unlock_dialog_keeps_its_height_when_hint_appears_and_clears(monkeypatch):
    app = _app()
    dialog = _unlock_dialog(monkeypatch)
    try:
        reserved = dialog.size()
        default_sub = dialog.sub_label.text()

        # 错误提示并入副标题（不再有独立 hint 占位行），窗口高度保持不变
        dialog._set_hint("主密码不正确（还可尝试 4 次）")
        app.processEvents()
        assert "主密码不正确" in dialog.sub_label.text()
        assert dialog.sub_label.objectName() == "FieldError"
        assert dialog.size() == reserved

        dialog._set_hint("")
        app.processEvents()
        assert dialog.sub_label.text() == default_sub
        assert dialog.size() == reserved
    finally:
        dialog.close()


def test_unlock_spinner_lives_inside_the_unlock_button(monkeypatch):
    app = _app()
    dialog = _unlock_dialog(monkeypatch)
    try:
        button = dialog.btn
        reserved = dialog.size()
        # 独立的“正在解锁…”一行已经移除，动画改为按钮子控件
        assert not [
            label for label in dialog.findChildren(dialogs.QLabel)
            if label.text().startswith("正在解锁")
        ]

        button.start_busy(dialogs.i18n.tr("正在解锁…"))
        app.processEvents()
        spinner = button._spinner
        assert spinner.isVisible()
        assert button.rect().contains(spinner.geometry())
        assert dialog.size() == reserved

        button.stop_busy()
        app.processEvents()
        assert button.text() == dialogs.i18n.tr("解锁")
        assert not spinner.isVisible()
        assert dialog.size() == reserved
    finally:
        dialog.close()


def test_wrong_password_hint_is_fully_localized():
    app = _app()

    class Harness(dialogs.LockoutMixin):
        def __init__(self):
            self.hint_text = ""
            self._lk_fields = []
            self._lk_button = dialogs.QPushButton()

        def _shake_fields(self):
            pass

        def _apply_delay(self, seconds):
            pass

        def _set_hint(self, text):
            self.hint_text = text

    original = dialogs.config.record_password_failure
    dialogs.config.record_password_failure = lambda: (1, 0.0, False, 0)
    dialogs.i18n.install(app, "en", "en_US")
    try:
        harness = Harness()
        harness.wrong_password()
        assert harness.hint_text == "Incorrect master password. (4 attempts remaining)"
        assert not any("一" <= char <= "鿿" for char in harness.hint_text)
    finally:
        dialogs.i18n.install(app, "zh-Hans", "zh_CN")
        dialogs.config.record_password_failure = original


def test_wrong_password_refocuses_unlock_input(monkeypatch):
    app = _app()
    dialog = _unlock_dialog(monkeypatch)
    monkeypatch.setattr(dialog, "_apply_delay", lambda _seconds: None)
    monkeypatch.setattr(dialogs.config, "record_password_failure", lambda: (1, 0.0, False, 0))
    try:
        dialog.pw.clear()
        dialog.btn.setFocus()
        dialog._on_unlock_failure("decrypt", "")
        app.processEvents()

        assert dialog.pw.hasFocus()
    finally:
        dialog.close()


def test_confirm_password_error_keeps_input_editable(monkeypatch):
    """对齐安卓：失败后输入框保持可编辑、焦点不夺走，允许就地重输。

    安卓侧 OutlinedTextField 的 enabled 只受 busy 影响，退避与冷却期不禁用；
    改一个字符即清掉错误提示。不做 shake，也强制抢焦点。
    """
    app = _app()
    monkeypatch.setattr(dialogs.config, "record_password_failure", lambda: (1, 0.0, False, 0))
    monkeypatch.setattr(dialogs.config, "password_cooling_remaining", lambda: 0.0)
    dialog = dialogs.ConfirmPasswordDialog(lambda _password: False, "确认", "请输入主密码")
    dialog.show()
    try:
        dialog._wrong_password()
        app.processEvents()
        assert dialog.pw.isEnabled(), "失败后输入框必须保持可编辑"
        assert dialog.hint.text() == "主密码不正确"
    finally:
        dialog.close()


def test_failure_backoff_blocks_submit_without_freezing_input(monkeypatch):
    _app()
    remaining = [0.0]
    monkeypatch.setattr(dialogs.config, "password_cooling_remaining", lambda: remaining[0])
    verified = []
    dialog = dialogs.ConfirmPasswordDialog(lambda pw: verified.append(pw) or True, "确认", "请输入主密码")
    try:
        remaining[0] = 0.5
        dialog._apply_delay(0.5)
        dialog.pw.setText("guess")
        dialog.accept()
        assert verified == []
        assert dialog.pw.isEnabled()
        assert not dialog.btn.isEnabled()
        remaining[0] = 0.0
        dialog._lk_tick()
        assert dialog.btn.isEnabled()
    finally:
        dialog.close()


# ── 敏感操作二次验证的失败计数与冷却 ──────────────────────────────
# 二次验证此前完全不做计数，可无限次重试；而 verify_password 的快速路径走
# hmac.compare_digest 不跑 Argon2id，单次成本接近零。以下用例守住补齐后的行为。


def test_confirm_password_mixes_in_lockout_and_counts_failures(monkeypatch):
    """二次验证必须复用与解锁页同一份计数机制。"""
    _app()
    assert isinstance(dialogs.ConfirmPasswordDialog(lambda _p: False, "t", "m"), dialogs.LockoutMixin)

    calls = []

    def _record():
        calls.append(1)
        return (len(calls), 0.0, False, 0)

    monkeypatch.setattr(dialogs.config, "record_password_failure", _record)
    dialog = dialogs.ConfirmPasswordDialog(lambda _p: False, "确认", "请输入主密码")
    dialog.show()
    try:
        dialog._wrong_password()
        assert len(calls) == 1, "输错主密码必须记一次失败"
        dialog._wrong_password()
        assert len(calls) == 2
    finally:
        dialog.close()


def test_confirm_password_hint_omits_remaining_attempts(monkeypatch):
    """对齐安卓：二次验证只提示「主密码不正确」，不显示剩余可尝试次数。

    「还可尝试 N 次」是解锁页独有的文案——那里用户本来就在锁态，需要知道还剩
    几次机会；二次验证出现在使用过程中，暴露计数等于帮攻击者做进度条。
    """
    _app()
    monkeypatch.setattr(dialogs.config, "record_password_failure", lambda: (3, 0.0, False, 0))
    dialog = dialogs.ConfirmPasswordDialog(lambda _p: False, "确认", "请输入主密码")
    dialog.show()
    try:
        dialog._wrong_password()
        assert dialog.hint.text() == "主密码不正确"
    finally:
        dialog.close()


def test_confirm_password_typing_clears_error_hint():
    """对齐安卓 onValueChange { error = null }：改一个字符即清掉错误提示。"""
    _app()
    dialog = dialogs.ConfirmPasswordDialog(lambda _p: False, "确认", "请输入主密码")
    dialog.show()
    try:
        dialog._set_hint("主密码不正确")
        # textEdited 只由用户输入触发，setText 不发；用 QTest.keyClick 模拟敲键。
        from PySide6.QtCore import Qt
        from PySide6.QtTest import QTest

        dialog.pw.setFocus()
        QTest.keyClick(dialog.pw, Qt.Key_A)
        assert dialog.hint.text() == ""
    finally:
        dialog.close()


def test_confirm_password_cooldown_disables_button_not_input(monkeypatch):
    """对齐安卓：冷却期只禁用确认键，输入框保持可编辑。"""
    _app()
    monkeypatch.setattr(dialogs.config, "record_password_failure", lambda: (5, 0.0, True, 30))
    monkeypatch.setattr(dialogs.config, "password_cooling_remaining", lambda: 30.0)
    dialog = dialogs.ConfirmPasswordDialog(lambda _p: False, "确认", "请输入主密码")
    dialog.show()
    try:
        dialog._wrong_password()
        assert not dialog.btn.isEnabled(), "冷却期确认键必须禁用"
        assert dialog.pw.isEnabled(), "冷却期输入框仍可编辑"
    finally:
        dialog._lk_timer.stop()
        dialog.close()


def test_confirm_password_lockout_blocks_further_attempts(monkeypatch):
    """记满上限后进入冷却，期间 accept() 必须直接拒绝而不是继续校验。"""
    _app()
    monkeypatch.setattr(dialogs.config, "record_password_failure", lambda: (5, 0.0, True, 30))
    monkeypatch.setattr(dialogs.config, "password_cooling_remaining", lambda: 30.0)
    verified = []
    dialog = dialogs.ConfirmPasswordDialog(lambda p: verified.append(p) or True, "确认", "请输入主密码")
    dialog.show()
    try:
        dialog._wrong_password()
        assert dialog.cooling_down, "记满上限必须进入冷却状态"
        dialog.pw.setText("guess")
        dialog.accept()
        assert verified == [], "冷却期间不得再调用校验函数"
        assert not dialog.unlocked
    finally:
        dialog._lk_timer.stop()
        dialog.close()


def test_confirm_password_lockout_closes_itself_and_reports_lock(monkeypatch):
    """记满上限时先收掉确认框，再通知主窗口锁定，避免两个模态框叠加。"""
    _app()
    monkeypatch.setattr(dialogs.config, "record_password_failure", lambda: (5, 0.0, True, 30))
    monkeypatch.setattr(dialogs.config, "password_cooling_remaining", lambda: 30.0)
    reasons = []
    dialog = dialogs.ConfirmPasswordDialog(
        lambda _p: False, "确认", "请输入主密码", on_lockout=reasons.append
    )
    dialog.show()
    try:
        dialog._wrong_password()
        assert dialog.result() == dialogs.QDialog.Rejected, "记满上限应关闭确认框"
        assert reasons == [], "锁定通知必须延后到 exec() 返回之后"
        _app().processEvents()
        assert len(reasons) == 1, "事件队列处理后必须发出锁定通知"
    finally:
        dialog._lk_timer.stop()
        dialog.close()


def test_confirm_password_success_clears_failure_count(monkeypatch):
    """验证通过必须清零计数，否则解锁页会无辜继承这次会话的失败次数。"""
    _app()
    # 本用例关心的是「成功后调用了 clear」，必须隔离冷却态，否则前序用例留下的
    # 真实 lockout_until 会让 accept() 直接早退。
    monkeypatch.setattr(dialogs.config, "password_cooling_remaining", lambda: 0.0)
    cleared = []
    monkeypatch.setattr(dialogs.config, "clear_password_lockout", lambda: cleared.append(1))
    dialog = dialogs.ConfirmPasswordDialog(lambda _p: True, "确认", "请输入主密码")
    dialog.show()
    try:
        dialog.pw.setText("correct")
        dialog.accept()
        assert cleared == [1]
        assert dialog.unlocked
    finally:
        dialog.close()


def test_cooldown_hint_shows_remaining_seconds(monkeypatch):
    """冷却期间必须显示剩余秒数，否则用户只看到确认键变灰、无法判断要等多久。"""
    _app()
    monkeypatch.setattr(dialogs.config, "password_cooling_remaining", lambda: 30.0)
    dialog = dialogs.ConfirmPasswordDialog(lambda _p: False, "确认", "请输入主密码")
    dialog.show()
    try:
        dialog.init_lockout(dialog.hint, [dialog.pw], dialog.btn)
        assert dialog.cooling_down
        dialog._lk_tick()
        assert "30" in dialog.hint.text(), "应显示剩余秒数"
        assert "验证已冷却" in dialog.hint.text()
    finally:
        dialog._lk_timer.stop()
        dialog.close()


def test_unlock_error_keeps_layout_and_single_user_disabled(monkeypatch):
    from ui import theme
    app = _app()
    old_sheet = app.styleSheet()
    app.setStyleSheet(theme.stylesheet("light"))
    monkeypatch.setattr(dialogs.biometric, "available", lambda: False)
    monkeypatch.setattr(dialogs.config, "record_password_failure", lambda: (1, 0.25, False, 0))
    dialog = _unlock_dialog(monkeypatch)
    try:
        size = dialog.size()
        positions = [widget.geometry() for widget in (dialog.sub_label, dialog.user_combo, dialog.btn)]
        dialog._unlocking = True
        dialog.btn.start_busy("正在解锁…")
        dialog._on_unlock_failure("decrypt", "")
        QTest.qWait(400)
        assert not dialog.user_combo.isEnabled(), "错误恢复后仍然只有一个用户，不能重新启用下拉"
        assert "down-arrow { image: none" in dialog.user_combo.styleSheet()
        assert dialog.size() == size
        assert [widget.geometry() for widget in (dialog.sub_label, dialog.user_combo, dialog.btn)] == positions
    finally:
        dialog.close()
        app.setStyleSheet(old_sheet)


def test_completion_hides_ring_and_keeps_geometry():
    _app()
    button = dialogs._BusyButton("解锁")
    button.resize(250, 40)
    button.show()
    button.start_busy("正在解锁…")
    size = button.size()
    from PySide6.QtTest import QSignalSpy
    finished = QSignalSpy(button._check._anim.finished)
    button.complete_busy()
    assert not button._spinner._spinning
    assert button._spinner.isHidden()
    assert not button._check.isHidden()
    assert button.size() == size
    assert "drawArc" not in inspect.getsource(widgets.CompletionCheckWidget)
    _pump_until(lambda: finished.count() == 1)
    assert button._check._progress == pytest.approx(1.0)
    button.stop_busy()
    assert button._check.isHidden()
    assert button.text() == "解锁"
    button.close()


def test_success_handoff_once_and_blocks_cancel_and_submit(monkeypatch):
    dialog = _unlock_dialog(monkeypatch)
    monkeypatch.setattr(dialog, "passed", lambda: None)
    prepared = []
    dialog._prepare_handoff = lambda dlg: prepared.append(dlg)
    vault = object()
    dialog._on_unlock_success({"name": "FAE"}, vault)
    dialog._on_unlock_success({"name": "FAE"}, vault)
    dialog.accept()
    dialog.reject()
    assert dialog.isVisible()
    assert not dialog.btn.isEnabled()
    assert not dialog.pw.isEnabled()
    assert not dialog.btn._spinner._spinning
    # Hold the drawing partway through; pumping past the former fixed delay
    # must not prepare the main window or accept the login.
    animation = dialog.btn._check._anim
    animation.pause()
    animation.setCurrentTime(120)
    QTest.qWait(360)
    assert dialog.btn._check._progress < 1.0
    assert prepared == []
    assert not dialog._completion_hold_timer.isActive()
    dialog.finish_handoff()
    assert dialog.isVisible()
    finished_states = []
    def on_finished():
        finished_states.append((dialog.btn._check._progress,
                                dialog._completion_hold_timer.isActive(), list(prepared)))
        # Duplicate finished delivery must not restart the hold or prepare twice.
        dialog._on_completion_drawn()
    animation.finished.connect(on_finished)
    animation.resume()
    _pump_until(lambda: len(prepared) == 1)
    assert finished_states == [(1.0, True, [])]
    assert dialog._completion_hold_timer.interval() == 80
    assert prepared == [dialog]
    assert dialog.isVisible()
    accepted = []
    dialog.accepted.connect(lambda: accepted.append(True))
    dialog.finish_handoff()
    dialog.finish_handoff()
    assert accepted == [True]


def test_handoff_failure_closes_vault_and_resets_completion(monkeypatch):
    dialog = _unlock_dialog(monkeypatch)
    monkeypatch.setattr(dialog, "passed", lambda: None)
    closed = []
    class Vault:
        def close(self):
            closed.append(True)
    def fail(dlg):
        raise RuntimeError("prepare failed")
    dialog._prepare_handoff = fail
    dialog._on_unlock_success({"name": "FAE"}, Vault())
    _pump_until(lambda: bool(closed))
    assert closed == [True]
    assert dialog.vault is None
    assert not dialog._unlocking
    assert dialog.btn._check.isHidden()
    assert dialog.btn._spinner.isHidden()
    assert dialog.btn.isEnabled()
    dialog.close()


def test_worker_pending_prevents_dialog_cancellation(monkeypatch):
    dialog = _unlock_dialog(monkeypatch)
    dialog._unlocking = True
    dialog.btn.start_busy("正在解锁…")
    dialog.reject()
    dialog.close()
    assert dialog.isVisible()
    dialog._on_unlock_failure("other", "cancelled")
    assert dialog.btn._spinner.isHidden()
    assert dialog.btn._check.isHidden()
    dialog.reject()
    assert not dialog.isVisible()


def test_direct_success_places_check_inside_button():
    _app()
    button = dialogs._BusyButton("解锁")
    button.resize(250, 40)
    button.complete_busy()
    assert button._check.y() == 11
    assert button._check.x() >= 8
    assert button._spinner.isHidden()
    button.stop_busy()


@pytest.mark.parametrize("label", ["正在验证主密码，请稍候…", "Verifying a very long master password label…"])
def test_waiting_dots_long_labels_do_not_overlap_or_clip(label):
    _app()
    button = dialogs._BusyButton("确认密码")
    button.resize(120, 40)
    button.show()
    height = button.sizeHint().height()
    button.start_busy(label)
    assert isinstance(button._spinner, widgets.WaitingDotsWidget)
    assert button.sizeHint().width() >= button.fontMetrics().horizontalAdvance(label) + 70
    assert button.minimumSizeHint().width() >= 70
    icon, text = button._content_rects()
    assert button.rect().contains(icon)
    assert not icon.intersects(text)
    geometry = button._spinner.geometry()
    for angle in (0, 60, 120, 180, 240, 300, 360):
        button._spinner.angle = angle
        for index, radius in enumerate(button._spinner.dot_radii()):
            assert 0 <= 5 + index * 10 - radius
            assert 5 + index * 10 + radius <= 30
            assert 0 <= 9 - radius and 9 + radius <= 18
        assert button._spinner.geometry() == geometry
        assert button.sizeHint().height() == height
    button.complete_busy()
    assert button._spinner.isHidden()
    assert not button._check.isHidden()
    button.stop_busy()
    assert button._check.isHidden()
    assert button.sizeHint().height() == height
    button.close()


def test_dots_pulse_in_left_to_right_order():
    _app()
    dots = widgets.WaitingDotsWidget()
    for active, angle in enumerate((60, 180, 300)):
        dots.angle = angle
        radii = dots.dot_radii()
        assert radii[active] == pytest.approx(4.0)
        assert sum(radius == pytest.approx(1.5) for radius in radii) == 2
    dots.angle = 360
    assert dots.dot_radii() == [1.5, 1.5, 1.5]


def test_too_narrow_button_reserves_full_indicator_bounds():
    _app()
    button = dialogs._BusyButton("Verify password")
    button.resize(20, 40)
    button.start_busy("Verifying password…")
    icon, text = button._content_rects()
    assert button.width() >= button.minimumSizeHint().width()
    assert button.rect().contains(icon)
    assert not icon.intersects(text)
    button.stop_busy()


def test_new_vault_action_uses_completed_unlock_handoff(monkeypatch, tmp_path):
    dialog = _unlock_dialog(monkeypatch)
    password = bytearray(b"new master password")
    secret = object()
    vault = object()
    created = []
    records = []
    prepared = []
    accepted = []
    class AddUser:
        restore_name = None
        user_name = "NewUser"
        def __init__(self, *args, **kwargs):
            self.password = password
        def exec(self):
            return dialogs.QDialog.Accepted
    class Recovery:
        def __init__(self, *args, **kwargs):
            self.secret = secret
        def exec(self):
            return dialogs.QDialog.Accepted
    monkeypatch.setattr(dialogs, "AddUserDialog", AddUser)
    monkeypatch.setattr(dialogs, "RecoveryKeyConfirmDialog", Recovery)
    monkeypatch.setattr(dialogs.config, "trashed_accounts", lambda: {})
    monkeypatch.setattr(dialogs.config, "unique_vault_filename", lambda _name: "new.pmv")
    monkeypatch.setattr(dialogs.config, "vault_dir", lambda: tmp_path)
    def create(path, pw, recovery):
        created.append((path, bytes(pw), recovery))
        return vault
    def register(name, filename):
        record = {"name": name, "file": filename}
        records.append(record)
        return record
    monkeypatch.setattr(dialogs, "_create_new_vault", create)
    monkeypatch.setattr(dialogs.config, "register_user", register)
    monkeypatch.setattr(dialog, "_reload_users", lambda select: None)
    monkeypatch.setattr(dialog, "passed", lambda: None)
    def prepare(dlg):
        prepared.append((dlg.vault, dlg.btn._check._progress))
        dlg.finish_handoff()
    dialog._prepare_handoff = prepare
    dialog.accepted.connect(lambda: accepted.append(True))
    dialog._new_user_btn.menu().actions()[0].trigger()
    assert created == [(tmp_path / "new.pmv", b"new master password", secret)]
    assert records == [{"name": "NewUser", "file": "new.pmv"}]
    assert password == bytearray(len(password))
    assert dialog.vault is vault
    assert dialog.isVisible()
    assert dialog._completion_started
    assert dialog.btn._spinner.isHidden()
    assert not dialog.btn._check.isHidden()
    assert prepared == []
    assert accepted == []
    _pump_until(lambda: bool(accepted))
    assert prepared == [(vault, 1.0)]
    assert accepted == [True]
    dialog.finish_handoff()
    assert accepted == [True]
