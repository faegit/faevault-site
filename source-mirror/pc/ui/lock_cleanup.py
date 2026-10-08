"""Release a locked session after in-flight work has safely settled."""

import gc

from PySide6.QtCore import QCoreApplication, QEvent, QObject, QThread, QTimer
from PySide6.QtWidgets import QApplication, QDialog
from shiboken6 import isValid

from core import password_health
from core.log import get

_log = get("lock-cleanup")

SESSION_TIMERS = (
    "_maintenance_timer", "_app_timer", "_select_timer", "_search_timer",
    "_otp_ticker", "_leak_recheck_timer", "_external_refresh_timer",
    "_auto_sync_timer", "_local_backup_timer", "_drag_timer",
)


def clear_window_session(window) -> None:
    overlay = getattr(window, "_theme_reveal_overlay", None)
    if overlay is not None:
        overlay.finish()
    window.hide()
    window._native_autofill_pending = None
    window._native_autofill_prepared = None
    window._pending_select = None
    window._detail_entry = None
    window._filter_source_vault = None
    window._filter_source_entries = ()
    window._filter_query_entries = ()
    window._filter_query = None
    window._security_report = password_health.EMPTY_REPORT
    for name in ("_password_stats_cache", "_password_stats_sig", "_pw_stats_id_sets", "_pw_stats_sig", "_last_tag_state"):
        setattr(window, name, None)
    window._active_tag = None
    for name in SESSION_TIMERS:
        timer = getattr(window, name, None)
        if timer is not None:
            timer.stop()
    roots = [window, *QApplication.instance().topLevelWidgets()]
    workers = {worker for root in roots for worker in root.findChildren(QThread)}
    workers.update(QApplication.instance().findChildren(QThread))
    for root in roots:
        for child in root.findChildren(QObject):
            owned = getattr(child, "_workers", ())
            if isinstance(owned, dict):
                owned = tuple(owned.values())
            if isinstance(owned, (tuple, list, set)):
                workers.update(worker for worker in owned if isinstance(worker, QThread))
    for name in ("_pw_stats_worker", "_leak_worker"):
        worker = getattr(window, name, None)
        if worker is not None:
            workers.add(worker)
    workers.update(getattr(window, "_auto_sync_workers", {}).values())
    window._lock_workers = list(workers)
    for worker in workers:
        if isValid(worker) and worker.isRunning():
            worker.requestInterruption()
    window._lock_dialogs = [root for root in roots if isinstance(root, QDialog)]
    window._lock_futures = []
    for root in roots:
        for child in root.findChildren(QObject):
            future = getattr(child, "_thumbnail_future", None)
            if future is not None:
                future.cancel()
                window._lock_futures.append(future)
    window.list.blockSignals(True)
    window.list.clear()
    window.list.blockSignals(False)
    window.search.blockSignals(True)
    window.search.clear()
    window.search.blockSignals(False)
    window._clear_detail()
    window._clear_clipboard_now()
    window._leak_attempted_revisions.clear()
    for button in getattr(window, "_tag_chips", {}).values():
        button.deleteLater()
    window._tag_chips = {}
    window._alpha_index = {}
    window.count_label.clear()
    password_health.clear_cache()


def finish_cleanup(window) -> None:
    if not window._lock_cleanup_pending:
        return
    if any(isValid(worker) and worker.isRunning() for worker in window._lock_workers) or any(
        not future.done() for future in window._lock_futures
    ):
        QTimer.singleShot(100, window, lambda: finish_cleanup(window))
        return
    window.vault.close()
    for dialog in set(window._lock_dialogs):
        if isValid(dialog):
            vault = getattr(dialog, "vault", None)
            if vault is not None and vault is not window.vault:
                vault.close()
                dialog.vault = None
            dialog.deleteLater()
    for worker in window._lock_workers:
        if isValid(worker):
            for name in ("_vault", "_task", "_weak_fn", "payload", "_snapshots"):
                if hasattr(worker, name):
                    setattr(worker, name, None)
    window._lock_workers = []
    window._lock_dialogs = []
    window._lock_futures = []
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    password_health.clear_cache()
    gc.collect()
    window._lock_cleanup_pending = False
    _log.info("锁定会话清理完成：已释放密钥、解密条目和界面缓存")
