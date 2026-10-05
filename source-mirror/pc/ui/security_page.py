"""Compact security center with combined filters and virtualized results."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import config, password_health
from core.models import Entry

from . import i18n, widgets
from .smooth_scroll import enable_smooth_scroll
from .editor_workspace import EditorPage, page_shell
from .security_results import SecurityResultDelegate, SecurityResultsModel


class _PasswordHealthWorker(QThread):
    progress = Signal(int, int)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, entries: list[Entry], revision: str, *, force: bool = False, parent=None):
        super().__init__(parent)
        self._entries = entries
        self._revision = revision
        self._force = force

    def run(self) -> None:
        last_progress = [0.0]

        def report_progress(checked, total):
            now = time.monotonic()
            if checked == total or now - last_progress[0] >= 0.05:
                last_progress[0] = now
                self.progress.emit(checked, total)

        try:
            report = password_health.analyze(
                self._entries,
                logical_revision=self._revision,
                force=self._force,
                should_stop=self.isInterruptionRequested,
                on_progress=report_progress,
            )
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        finally:
            self._entries = []
        self.completed.emit(report)


class SecurityCenterPage(EditorPage):
    onlineAuditRequested = Signal()
    passwordViewRequested = Signal(str, object)

    def __init__(self, entries: list[Entry], revision: str, parent=None):
        super().__init__(parent)
        self.setObjectName("SecurityCenterPage")
        self._entries, self._revision = entries, revision
        self._report = password_health.EMPTY_REPORT
        self._workers = []
        self._manual_refresh = self._re_scanning = False
        self._pending_analysis = self._closed = self._delete_pending = False
        self._filter = password_health.HIGH
        shell = page_shell(self, i18n.tr("安全中心"))
        self.page_header = shell.header
        self.page_header.set_subtitle(i18n.tr("先处理高风险密码，再逐步完善账户安全。"))
        refresh = QPushButton(i18n.tr("重新检查"))
        refresh.clicked.connect(self._on_manual_refresh)
        self.page_header.add_action(refresh)
        self._content = shell.content
        self._analysis_status = QLabel(i18n.tr("正在准备本地检查…"))
        self._analysis_status.setObjectName("SettingNote")
        self._analysis_status.setWordWrap(True)
        self._content.addWidget(self._analysis_status)
        self._scan_bar = QProgressBar()
        self._scan_bar.setRange(0, 100)
        self._scan_bar.setTextVisible(False)
        self._scan_bar.setFixedHeight(4)
        self._content.addWidget(self._scan_bar)
        self._card_labels = {"": "全部", password_health.HIGH: "高风险", password_health.IMPROVEMENT: "需改进", password_health.HEALTHY: "未发现问题"}
        self._cards = {}
        group = QButtonGroup(self)
        group.setExclusive(True)
        cards = QHBoxLayout()
        cards.setSpacing(8)
        for key, label in self._card_labels.items():
            button = QPushButton(i18n.tr(label) + "  —")
            button.setObjectName("SecurityFilterCard")
            button.setCheckable(True)
            button.setChecked(key == self._filter)
            button.setMinimumHeight(48)
            button.clicked.connect(lambda checked=False, k=key: self._select_level(k))
            group.addButton(button)
            self._cards[key] = button
            cards.addWidget(button, 1)
        self._content.addLayout(cards)
        filters = QHBoxLayout()
        self._finding_filter = QComboBox()
        self._finding_filter.setAccessibleName(i18n.tr("问题类型"))
        self._finding_filter.addItem(i18n.tr("所有问题类型"), "")
        for finding in password_health.FINDINGS:
            self._finding_filter.addItem(i18n.tr(finding.label), finding.key)
        self._finding_filter.currentIndexChanged.connect(self._apply_filters)
        self._search = QLineEdit()
        self._search.setPlaceholderText(i18n.tr("搜索名称、账户、网址或标签"))
        self._search.setAccessibleName(i18n.tr("搜索安全检查结果"))
        self._search.setClearButtonEnabled(True)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(120)
        self._search_timer.timeout.connect(self._apply_filters)
        self._search.textChanged.connect(lambda: self._search_timer.start())
        filters.addWidget(self._search, 1)
        reset = QPushButton(i18n.tr("重置"))
        reset.clicked.connect(self._reset_filters)
        filters.addWidget(reset)
        self._content.addLayout(filters)
        self._finding_summary = QLabel()
        self._finding_summary.setObjectName("SettingNote")
        self._content.addWidget(self._finding_summary)
        self._results_model = SecurityResultsModel(self)
        self._finding_list = QListView()
        self._list_transition = widgets.ContentTransition(self._finding_list.viewport())
        self._finding_list.setObjectName("SecurityFindingList")
        self._finding_list.setModel(self._results_model)
        self._finding_list.setItemDelegate(SecurityResultDelegate(self._finding_list))
        self._finding_list.setUniformItemSizes(True)
        enable_smooth_scroll(self._finding_list)
        self._finding_list.setFrameShape(QFrame.NoFrame)
        self._finding_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._finding_list.clicked.connect(self._finding_item_clicked)
        self._finding_list.activated.connect(self._finding_item_clicked)
        self._content.addWidget(self._finding_list, 1)
        self._empty = QLabel(i18n.tr("没有符合条件的条目，请调整筛选条件。"))
        self._empty.setAlignment(Qt.AlignCenter)
        self._empty.setWordWrap(True)
        self._content.addWidget(self._empty)
        # ── 检测设置（折叠卡片）──
        self._leak_settings_frame = QFrame()
        self._leak_settings_frame.setObjectName("SettingGroupBox")
        leak_settings_lay = QVBoxLayout(self._leak_settings_frame)
        leak_settings_lay.setContentsMargins(12, 12, 12, 12)
        leak_settings_lay.setSpacing(0)

        self._leak_settings_toggle = QPushButton("检测设置")
        self._leak_settings_toggle.setObjectName("SettingGroupToggle")
        self._leak_settings_toggle.setCheckable(True)
        self._leak_settings_toggle.setChecked(False)
        leak_settings_lay.addWidget(self._leak_settings_toggle)

        self._leak_settings_content = QWidget()
        leak_content_lay = QVBoxLayout(self._leak_settings_content)
        leak_content_lay.setContentsMargins(0, 10, 0, 2)
        leak_content_lay.setSpacing(7)

        self.leak_enabled = QCheckBox("显示密码泄露检测结果")
        self.leak_enabled.setChecked(bool(config.get("leak_check_enabled", True)))
        self.leak_enabled.setToolTip("关闭后不检测、不显示已泄露标签，也不会将泄露条目置顶")
        leak_content_lay.addWidget(self.leak_enabled)

        leak_enabled_note = QLabel("本地规则与联网泄露查询分别执行；未查询不代表从未泄露。")
        leak_enabled_note.setObjectName("SettingNote")
        leak_enabled_note.setWordWrap(True)
        leak_content_lay.addWidget(leak_enabled_note)

        self.leak_online = QCheckBox("联网检测密码泄露")
        self.leak_online.setChecked(bool(config.get("leak_online_check", True)))
        self.leak_online.setToolTip("使用 Pwned Passwords（k-匿名，仅发送哈希前 5 位）")
        leak_content_lay.addWidget(self.leak_online)

        leak_online_note = QLabel("使用密码哈希前 5 位进行查询。")
        leak_online_note.setObjectName("SettingNote")
        leak_online_note.setWordWrap(True)
        leak_content_lay.addWidget(leak_online_note)

        recheck_row = QHBoxLayout()
        recheck_row.addWidget(QLabel("自动检测周期"))
        recheck_row.addStretch()
        self.leak_recheck_days = widgets.ClickToWheelSpinBox()
        self.leak_recheck_days.setRange(0, 30)
        self.leak_recheck_days.setSuffix(" 天")
        try:
            self.leak_recheck_days.setValue(int(config.get("leak_recheck_days", 5)))
        except (TypeError, ValueError):
            self.leak_recheck_days.setValue(5)
        self.leak_recheck_days.setToolTip("已检测条目超过该周期后重新联网检测；设为 0 时关闭自动检测周期")
        recheck_row.addWidget(self.leak_recheck_days)
        leak_content_lay.addLayout(recheck_row)

        self.leak_recheck_days.setEnabled(self.leak_enabled.isChecked() and self.leak_online.isChecked())
        self.leak_online.toggled.connect(self._update_leak_controls_enabled)
        self.leak_enabled.toggled.connect(self._update_leak_controls_enabled)
        self._update_leak_controls_enabled()

        # Auto-save
        self.leak_enabled.toggled.connect(lambda checked: config.set("leak_check_enabled", checked))
        self.leak_online.toggled.connect(lambda checked: config.set("leak_online_check", checked))
        self.leak_recheck_days.valueChanged.connect(lambda v: config.set("leak_recheck_days", v))

        scan_btn_row = QHBoxLayout()
        scan_btn_row.addStretch()
        self._scan_btn = QPushButton("立即检测")
        self._scan_btn.setObjectName("SettingsBtn")
        self._scan_btn.clicked.connect(self._run_full_scan)
        scan_btn_row.addWidget(self._scan_btn)
        scan_btn_row.addStretch()
        leak_content_lay.addLayout(scan_btn_row)

        leak_settings_lay.addWidget(self._leak_settings_content)
        self._leak_settings_content.setVisible(False)
        self._leak_settings_toggle.toggled.connect(self._leak_settings_content.setVisible)
        self._content.addWidget(self._leak_settings_frame)

        self._update_leak_controls_enabled()
        self._apply_filters()
        QTimer.singleShot(0, self._start_analysis)

    def _select_level(self, key):
        self._filter = key
        self._apply_filters()

    def _reset_filters(self):
        self._filter = ""
        self._cards[""].setChecked(True)
        self._finding_filter.setCurrentIndex(0)
        self._search.clear()
        self._apply_filters()

    def _apply_filters(self, *_args):
        if not hasattr(self, "_results_model"):
            return
        self._results_model.filter(self._filter, self._finding_filter.currentData(), self._search.text())
        if self._finding_list.isVisible():
            self._list_transition.begin()
        count = self._results_model.rowCount()
        self._finding_summary.setText(i18n.tr_dynamic(f"显示 {count} / {self._report.total} 个条目"))
        self._empty.setVisible(count == 0)

    def _open_filtered_list(self, key):
        if key in self._cards:
            self._filter = key
            self._cards[key].setChecked(True)
            self._finding_filter.setCurrentIndex(0)
        else:
            self._filter = ""
            self._cards[""].setChecked(True)
            self._finding_filter.setCurrentIndex(max(0, self._finding_filter.findData(key)))
        self._apply_filters()

    def _finding_item_clicked(self, index):
        entry_id = index.data(Qt.UserRole)
        if entry_id:
            self.request_entry(entry_id)

    # ---------- 扫描生命周期 ----------

    def _start_analysis(self, *, force: bool = False) -> None:
        if self._closed or any(worker.isRunning() for worker in self._workers):
            return
        self._pending_analysis = False
        self._scan_bar.show()
        if not self._re_scanning:
            self._scan_bar.setValue(0)
        self._analysis_status.setText(i18n.tr_dynamic(f"正在扫描 {len(password_health.FINDINGS)} 项本地规则…"))
        worker = _PasswordHealthWorker(list(self._entries), self._revision, force=force, parent=self)
        worker.progress.connect(self._analysis_progressed)
        worker.completed.connect(self._analysis_completed)
        worker.failed.connect(self._analysis_failed)
        self._workers.append(worker)
        worker.finished.connect(lambda w=worker: self._worker_finished(w))
        worker.start()

    def _analysis_progressed(self, checked: int, total: int) -> None:
        if self._closed:
            return
        percent = int(min(100, checked / max(total, 1) * 100))
        if self._re_scanning:
            current = self._scan_bar.value()
            remaining = 100 - current
            percent = current + remaining * percent // 100
        self._scan_bar.setValue(percent)
        self._analysis_status.setText(i18n.tr_dynamic(f"正在扫描本地规则：{checked}/{total} 个条目"))

    def _analysis_failed(self, message: str) -> None:
        if self._closed:
            return
        self._re_scanning = False
        self._manual_refresh = False
        self._scan_bar.hide()
        self._analysis_status.setObjectName("SecurityError")
        self._analysis_status.setText(f"本地检测失败：{message or '未知错误'}")
        self._analysis_status.style().unpolish(self._analysis_status)
        self._analysis_status.style().polish(self._analysis_status)

    def _on_manual_refresh(self) -> None:
        self._manual_refresh = True
        self._start_analysis(force=True)

    def _analysis_completed(self, report: password_health.HealthReport) -> None:
        if self._closed:
            return
        notify = self._manual_refresh and self.isVisible()
        self._report = report
        self._analysis_status.setObjectName("SettingNote")

        if self._re_scanning:
            self._re_scanning = False

        if report.total:
            summary = (
                f"已扫描 {report.total} 个含密码条目：高风险 {len(report.high_risk)}，需改进 {len(report.improvement)}，未发现问题 {len(report.healthy)}。"
            )
        else:
            summary = i18n.tr("没有可参与密码安全检测的条目。")

        self._scan_bar.hide()
        self._analysis_status.setText(summary)
        self._analysis_status.style().unpolish(self._analysis_status)
        self._analysis_status.style().polish(self._analysis_status)
        self._manual_refresh = False
        counts = {
            "": report.total,
            password_health.HIGH: len(report.high_risk),
            password_health.IMPROVEMENT: len(report.improvement),
            password_health.HEALTHY: len(report.healthy),
        }
        for key, button in self._cards.items():
            button.setText(f"{i18n.tr(self._card_labels[key])}  {counts[key]}")
        self._results_model.set_report(report)
        self._apply_filters()
        # Background refreshes after delete/edit/sync must not replace the
        # operation's notification with an unrelated security scan summary.
        if notify:
            self.statusMessage.emit(summary)

    def update_entries(self, entries: list[Entry], revision: str) -> None:
        """Refresh local findings after an online audit updates leak evidence."""
        self._entries = entries
        self._revision = revision
        self._pending_analysis = True
        self._start_analysis()

    def _run_full_scan(self) -> None:
        self._manual_refresh = True
        self._scan_bar.setValue(0)
        self._scan_bar.show()
        self._analysis_status.setText("正在准备检测条目…")
        self.onlineAuditRequested.emit()

    def _update_leak_controls_enabled(self) -> None:
        enabled = self.leak_enabled.isChecked()
        self.leak_online.setEnabled(enabled)
        self.leak_recheck_days.setEnabled(enabled and self.leak_online.isChecked())
        scan = getattr(self, "_scan_btn", None)
        if scan is not None:
            scan.setEnabled(enabled and self.leak_online.isChecked())

    def request_entry(self, entry_id: str) -> None:
        self.entryRequested.emit(entry_id)

    # ---------- 关闭清理 ----------

    def can_close(self, reason: str) -> bool:
        return True

    def close_page(self, reason: str) -> None:
        self._closed = True
        self._search_timer.stop()
        self._entries = []
        self._report = password_health.EMPTY_REPORT
        self._results_model.set_report(self._report)
        self._apply_filters()
        for worker in self._workers:
            worker.requestInterruption()
        # Workers keep their own snapshots; retain the page until they finish.
        if self._workers:
            self.setParent(None)

    def deleteLater(self) -> None:
        if self._workers:
            self._delete_pending = True
        else:
            super().deleteLater()

    def _worker_finished(self, worker) -> None:
        if worker in self._workers:
            self._workers.remove(worker)
        worker.deleteLater()
        if not self._workers and self._delete_pending:
            super().deleteLater()
        elif self._pending_analysis and not self._closed:
            self._start_analysis()

    def refresh(self, context) -> None:
        entries = getattr(context, "entries", None)
        if entries is not None:
            self.update_entries(list(entries), "")
