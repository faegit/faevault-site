"""Indexed, widget-free rows for the security center."""
from __future__ import annotations

from PySide6.QtCore import QAbstractListModel, QModelIndex, QRect, QSize, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QStyle, QStyledItemDelegate

from core import password_health
from . import i18n, theme


class SecurityResultsModel(QAbstractListModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []
        self._indexed = []

    def set_report(self, report):
        issues = {}
        for finding in password_health.FINDINGS:
            for entry in report.findings.get(finding.key, ()):
                issues.setdefault(entry.id, []).append(finding)
        self._indexed = []
        for level, entries in ((password_health.HIGH, report.high_risk),
                               (password_health.IMPROVEMENT, report.improvement),
                               (password_health.HEALTHY, report.healthy)):
            for entry in entries:
                matches = issues.get(entry.id, [])
                title = entry.title or i18n.tr("未命名条目")
                checked = entry.leak_checked_at and entry.leak_check_revision == entry.updated_at and entry.leak_pwned_count is not None
                online = ("已确认公开泄露" if entry.leak_pwned_count else "联网未发现公开泄露") if checked else "联网未检测或结果已过期"
                reason = " · ".join(i18n.tr(f.label) for f in matches) or i18n.tr("当前本地规则未发现问题")
                reason += " · " + i18n.tr(online)
                advice = i18n.tr(matches[0].recommendation) if matches else i18n.tr("本地检查通过不代表密码从未泄露。")
                search = " ".join((title, entry.username, entry.url, *entry.tags)).casefold()
                self._indexed.append((entry.id, title, reason, advice, level, frozenset(f.key for f in matches), search))

    def filter(self, level, finding, query):
        terms = query.casefold().split()
        self.beginResetModel()
        self.rows = [row for row in self._indexed
                     if (not level or row[4] == level)
                     and (not finding or finding in row[5])
                     and all(term in row[6] for term in terms)]
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.rows):
            return None
        row = self.rows[index.row()]
        if role == Qt.DisplayRole:
            return row[1]
        if role == Qt.UserRole:
            return row[0]
        if role in (Qt.ToolTipRole, Qt.AccessibleTextRole):
            return "\n".join(row[1:4])
        if role == Qt.UserRole + 1:
            return row


class SecurityResultDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        return QSize(240, 90)

    def paint(self, painter, option, index):
        row = index.data(Qt.UserRole + 1)
        if row is None:
            return
        colors = theme.active()
        painter.save()
        selected = bool(option.state & QStyle.State_Selected)
        painter.fillRect(option.rect, QColor(colors["accent_soft"] if selected else colors["surface"]))
        rect = option.rect.adjusted(14, 10, -14, -8)
        level_color = {password_health.HIGH: "#dc4c4c", password_health.IMPROVEMENT: "#c18427", password_health.HEALTHY: "#22a06b"}[row[4]]
        painter.fillRect(QRect(option.rect.left(), option.rect.top() + 12, 3, 64), QColor(level_color))
        for offset, text, bold, color in ((0, row[1], True, colors["text"]),
                                           (25, row[2], False, colors["text"]),
                                           (48, row[3], False, colors["muted"])):
            font = option.font
            font.setBold(bold)
            painter.setFont(font)
            painter.setPen(QColor(color))
            line = painter.fontMetrics().elidedText(text, Qt.ElideRight, rect.width())
            painter.drawText(QRect(rect.left(), rect.top() + offset, rect.width(), 22), Qt.AlignVCenter, line)
        if option.state & QStyle.State_HasFocus:
            painter.setPen(QColor(colors["accent"]))
            painter.drawRect(option.rect.adjusted(1, 1, -2, -2))
        painter.restore()
