"""浅色与深色主题。集中管理配色与全局 QSS。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication

LIGHT = {
    "bg": "#F7F9FC",
    "surface": "#FFFFFF",
    "surface_light": "#FFFFFF",
    "otp_card_font_size": 16,
    "surface_glass": "rgba(255, 255, 255, 0.66)",
    "surface_alt": "#F2F5FA",
    "picker_item": "#E5EAF2",
    "border": "#DCE3EF",
    "scroll_handle": "#A5B1C3",
    "text": "#1F2937",
    "muted": "#667085",
    "accent": "#47669A",
    "accent_hover": "#3C5B8D",
    "accent_soft": "#EEF2F8",
    "accent_text": "#2F6FED",
    "accent_text_hover": "#1D4FB8",
    "primary_button": "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4B6A9D, stop:1 #3F5E8F)",
    "primary_button_hover": "#5674A4",
    "danger": "#E5484D",
    "danger_hover": "#C93B3F",
    "danger_soft": "#FCE9E9",
    "success": "#2FA84F",
    "success_soft": "#E6F6EA",
    "warn": "#E0A100",
    "warn_soft": "#FBF1D9",
}

DARK = {
    "bg": "#101218",
    "surface": "#1E212B",
    "surface_light": "#252833",
    "otp_card_font_size": 16,
    "surface_glass": "rgba(30, 33, 43, 0.62)",
    "surface_alt": "#272B37",
    "picker_item": "#343A48",
    "border": "#333949",
    "scroll_handle": "#69768C",
    "text": "#E6E8EF",
    "muted": "#9197A8",
    # 与浅色同一色相（≈217° 蓝）：深色下提亮以在深底上保持可读，
    # 而不是另起一套紫调。
    "accent": "#6688BE",
    "accent_hover": "#7C9BD0",
    "accent_soft": "#26314A",
    "accent_text": "#6E9CF2",
    "accent_text_hover": "#8DB3F6",
    # 深色主按钮保持纯色（仅浅色用深蓝渐变），与原紫调时同构。
    "primary_button": "#6688BE",
    "primary_button_hover": "#7C9BD0",
    "danger": "#F0676C",
    "danger_hover": "#D8565B",
    "danger_soft": "#3A2226",
    "success": "#46C16A",
    "success_soft": "#1E3326",
    "warn": "#E6B23A",
    "warn_soft": "#332B16",
}

_active = LIGHT


def active() -> dict:
    return _active


def is_system_dark() -> bool:
    """检测操作系统当前是否使用深色主题。"""
    try:
        return QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except Exception:
        return False


def resolve_mode(mode: str, system_dark: bool | None = None) -> str:
    """将保存的主题选项解析为一个可直接渲染的主题。"""
    if mode == "auto":
        dark = is_system_dark() if system_dark is None else system_dark
        return "dark" if dark else "light"
    # 旧版“品牌蓝”已并入浅色，未知值同样回退到浅色。
    return mode if mode in {"light", "dark"} else "light"


def resolve_dark(mode: str) -> bool:
    """兼容仍需布尔深色判断的调用方。"""
    return resolve_mode(mode) == "dark"


def stylesheet(mode: str = "light") -> str:
    global _active
    resolved = resolve_mode(mode)
    c = {"light": LIGHT, "dark": DARK}[resolved]
    _active = c
    chev_down = _asset("chevron-down.svg")
    chev_up = _asset("chevron-up.svg")
    check = _asset("check.svg")
    # Keep the sampled backdrop visible while floating buttons are hovered.
    def glass(color: str) -> str:
        red, green, blue = (int(color[index:index + 2], 16) for index in (1, 3, 5))
        return f"rgba({red}, {green}, {blue}, 0.52)"
    return f"""
    * {{
        font-family: "Segoe UI", "Microsoft YaHei UI", sans-serif;
        font-size: 10.5pt;
        color: {c["text"]};
        outline: none;
    }}
    QWidget#Root {{ background: {c["bg"]}; }}
    QWidget#TopBar {{
        background: transparent;
        border: none;
    }}
    QLabel#TopBarBrand {{
        font-size: 14.25pt;
        font-weight: 700;
        color: {c["accent_text"]};
        line-height: 1.2;
    }}
    QLabel#TopBarBrandSub {{
        font-size: 8.25pt;
        color: {c["muted"]};
    }}
    QLabel#TopBarUser {{
        font-size: 13pt;
        color: {c["muted"]};
    }}

    /* ---------- 自定义标题栏 ---------- */
    QWidget#TitleBar {{
        background: {c["surface"]};
    }}
    QWidget#HeaderDivider {{
        background: {c["border"]};
        min-height: 1px;
        max-height: 1px;
    }}
    QLabel#TitleText {{ font-size: 14.25pt; font-weight: 700; color: {c["accent_text"]}; }}
    QPushButton#TopNavButton {{
        background: transparent;
        border: 1px solid transparent;
        border-radius: 6px;
        padding: 0 10px;
        min-height: 36px;
        max-height: 36px;
        color: {c["muted"]};
        font-weight: 600;
    }}
    QPushButton#TopNavButton:hover {{
        background: {c["surface_alt"]};
        border-color: transparent;
        color: {c["text"]};
    }}
    QPushButton#TopNavButton:pressed {{
        background: {c["surface_alt"]};
        border-color: transparent;
        color: {c["text"]};
    }}
    QPushButton#TopUtilityButton {{
        background: transparent;
        border: 1px solid transparent;
        border-radius: 6px;
        padding: 0;
        min-width: 44px;
        max-width: 44px;
        min-height: 36px;
        max-height: 36px;
    }}
    QPushButton#TopUtilityButton:hover {{
        background: {c["surface_alt"]};
        border-color: transparent;
    }}
    QPushButton#TopUtilityButton:pressed {{
        background: {c["surface_alt"]};
        border-color: transparent;
    }}
    QPushButton#WinBtn, QPushButton#WinClose {{
        background: transparent;
        border: none;
        padding: 0;
        color: {c["muted"]};
    }}

    QWidget#Sidebar {{
        background: {c["surface_light"]};
        border-right: 1px solid {c["border"]};
    }}
    QWidget#SidebarCreateSection {{
        background: transparent;
    }}
    QWidget#SidebarSeparator {{
        border-top: 1px solid {c["border"]};
        margin-left: 6px;
        margin-right: 6px;
    }}
    QSplitter#MainSplitter::handle {{
        background: {c["border"]};
        margin: 0 2px;
    }}
    QSplitter#MainSplitter::handle:hover {{
        background: {c["accent"]};
    }}


    /* ---------- 输入控件 ---------- */
    QLineEdit, QTextEdit, QComboBox, QSpinBox {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 9px 12px;
        selection-background-color: {c["accent_soft"]};
        selection-color: {c["accent_text"]};
    }}
    QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {{
        border: 1px solid {c["accent"]};
    }}
    QLineEdit#Search {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 10px 14px;
    }}
    QLineEdit#Search:hover {{
        border-color: {c["accent"]};
    }}
    QLineEdit#Search:focus {{
        background: {c["surface"]};
        border: 2px solid {c["accent"]};
    }}

    /* ---------- 筛选 ---------- */
    QFrame#FilterPanel {{
        background: transparent;
    }}
    QPushButton#FilterChip {{
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        color: {c["text"]};
        font-size: 9pt;
        padding: 3px 10px;
    }}
    QPushButton#FilterChip:hover {{
        border-color: {c["accent"]};
        color: {c["accent_text"]};
    }}
    QPushButton#FilterChip[active="true"] {{
        background: {c["accent"]};
        border-color: {c["accent"]};
        color: white;
    }}
    QListWidget#TagManagerList {{
        background: transparent;
        border: none;
        padding: 2px;
    }}
    QListWidget#TagManagerList::item {{
        min-height: 30px;
        padding: 4px 10px;
        border-radius: 8px;
    }}
    QListWidget#TagManagerList::item:selected {{
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
    }}
    QPushButton#TypeFilterChip {{
        background: transparent;
        border: none;
        border-radius: 8px;
        color: {c["muted"]};
        font-size: 9.75pt;
        padding: 0 10px;
        text-align: left;
    }}
    QPushButton#TypeFilterChip:hover {{
        background: {c["surface_alt"]};
        color: {c["text"]};
    }}
    QPushButton#TypeFilterChip[active="true"] {{
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
    }}
    QWidget#ReorderChip {{
        background: transparent;
        border: 1px solid transparent;
        border-radius: 8px;
    }}
    QWidget#ReorderChip[pressed="true"] {{
        background: {c["surface_alt"]};
        border-color: {c["border"]};
    }}
    QWidget#ReorderChip[dragging="true"] {{
        background: {c["accent_soft"]};
        border-color: {c["accent"]};
    }}
    QLabel#ReorderHandle {{
        color: {c["muted"]};
        font-size: 15pt;
        font-weight: 700;
    }}
    QWidget#ReorderChip[dragging="true"] QLabel#ReorderHandle,
    QWidget#ReorderChip[dragging="true"] QLabel#ReorderChipLabel {{
        color: {c["accent_text"]};
    }}
    QLabel#ReorderChipLabel {{
        color: {c["muted"]};
        font-size: 9.75pt;
    }}

    /* ---------- 下拉框 ---------- */
    QComboBox {{ color: {c["text"]}; }}
    QComboBox::drop-down {{ border: none; width: 26px; }}
    QComboBox::down-arrow {{ image: url({chev_down}); width: 12px; height: 12px; }}
    QComboBox QAbstractItemView {{
        background-color: {c["surface"]};
        color: {c["text"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 6px;
        outline: none;
        selection-background-color: {c["accent_soft"]};
        selection-color: {c["accent_text"]};
    }}
    QComboBoxPrivateContainer {{
        background-color: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
    }}
    QComboBox QAbstractItemView::item {{
        border-radius: 7px;
        padding: 7px 10px;
        min-height: 20px;
        color: {c["text"]};
        background: transparent;
    }}
    QComboBox QAbstractItemView::item:hover,
    QComboBox QAbstractItemView::item:selected {{
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
    }}

    /* ---------- 弹出菜单 ---------- */
    QMenu {{
        background-color: {c["surface"]};
        color: {c["text"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 6px;
    }}
    QMenu::item {{
        border-radius: 7px;
        padding: 8px 12px;
        padding-right: 24px;
        min-height: 22px;
        background: transparent;
    }}
    QMenu::item:has-submenu {{
        padding-right: 26px;
    }}
    QMenu::item:hover, QMenu::item:selected {{
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
    }}
    QMenu::separator {{
        height: 1px;
        background: {c["border"]};
        margin: 6px 4px;
    }}
    QMenu::right-arrow {{
        width: 14px;
        height: 14px;
    }}

    /* ---------- 数字框 ---------- */
    QSpinBox {{ padding-right: 22px; }}
    QSpinBox::up-button, QSpinBox::down-button {{
        subcontrol-origin: border; width: 22px; border: none; background: transparent;
    }}
    QSpinBox::up-button {{ subcontrol-position: top right; }}
    QSpinBox::down-button {{ subcontrol-position: bottom right; }}
    QSpinBox::up-arrow {{ image: url({chev_up}); width: 11px; height: 11px; }}
    QSpinBox::down-arrow {{ image: url({chev_down}); width: 11px; height: 11px; }}

    /* ---------- 勾选框 ---------- */
    QCheckBox {{ spacing: 8px; }}
    QCheckBox::indicator {{
        width: 19px; height: 19px;
        border: 1.6px solid {c["border"]};
        border-radius: 6px;
        background: {c["surface"]};
    }}
    QCheckBox::indicator:hover {{ border-color: {c["accent"]}; }}
    QCheckBox::indicator:checked {{
        background: {c["accent"]};
        border-color: {c["accent"]};
        image: url({check});
    }}

    /* ---------- 按钮 ---------- */
    QPushButton {{
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 9px 16px;
        font-weight: 600;
    }}
    QPushButton:hover {{ background: {c["accent_soft"]}; border-color: {c["accent"]}; }}
    QPushButton:disabled {{ background: {c["surface_alt"]}; color: {c["muted"]}; border: 1px solid {c["border"]}; }}
    QPushButton:pressed {{ background: {c["accent_soft"]}; }}

    /* 滑块：未启用（如未选择备份目录）时整体置灰 */
    QSlider::groove:horizontal:disabled {{ background: {c["border"]}; height: 6px; border-radius: 3px; }}
    QSlider::sub-page:horizontal:disabled {{ background: {c["border"]}; border-radius: 3px; }}
    QSlider::add-page:horizontal:disabled {{ background: {c["surface_alt"]}; border-radius: 3px; }}
    QSlider::handle:horizontal:disabled {{ background: {c["muted"]}; width: 14px; margin: -5px 0; border-radius: 7px; }}

    QPushButton#Primary,
    QPushButton#SidebarAddMenuButton {{ background: {c["primary_button"]}; color: white; border: none; }}
    QPushButton#Primary:hover,
    QPushButton#SidebarAddMenuButton:hover {{ background: {c["primary_button_hover"]}; }}
    QPushButton#Danger {{ background: {c["danger"]}; color: white; border: none; }}
    QPushButton#Danger:hover {{ background: {c["danger_hover"]}; }}
    QPushButton#FloatingAddButton,
    QPushButton#DetailAction,
    QPushButton#DetailDeleteAction {{
        background: {c["surface_glass"]};
        border: 1px solid {c["border"]};
        border-radius: 12px;
        font-size: 10pt;
        font-weight: 700;
        padding: 0 16px;
    }}
    QPushButton#FloatingAddButton,
    QPushButton#DetailAction {{ color: {c["accent_text"]}; }}
    QPushButton#DetailDeleteAction {{ color: {c["danger"]}; }}
    QPushButton#FloatingAddButton:hover,
    QPushButton#DetailAction:hover {{
        background: {glass(c["accent_soft"])};
        border-color: {c["accent"]};
    }}
    QPushButton#DetailDeleteAction:hover {{
        background: {glass(c["danger_soft"])};
        border-color: {c["danger"]};
    }}
    QPushButton#FloatingPrimaryAction,
    QPushButton#FloatingDangerAction,
    QFrame#FloatingActionGroup {{
        background: {c["surface_glass"]};
        border: 1px solid {c["border"]};
        border-radius: 12px;
    }}
    QPushButton#FloatingPrimaryAction,
    QPushButton#FloatingDangerAction {{
        font-size: 10pt;
        font-weight: 700;
        padding: 0 16px;
    }}
    QPushButton#FloatingPrimaryAction {{ color: {c["accent_text"]}; }}
    QPushButton#FloatingDangerAction {{ color: {c["danger"]}; }}
    QPushButton#FloatingPrimaryAction:hover {{ background: {glass(c["accent_soft"])}; border-color: {c["accent"]}; }}
    QPushButton#FloatingDangerAction:hover {{ background: {glass(c["danger_soft"])}; border-color: {c["danger"]}; }}
    QPushButton#FloatingPrimaryAction:disabled {{ color: {c["muted"]}; }}
    QPushButton#FloatingActionItem,
    QPushButton#FloatingDangerItem {{
        background: transparent;
        border: none;
        border-radius: 9px;
        font-size: 10pt;
        font-weight: 700;
        padding: 0 8px;
    }}
    QPushButton#FloatingActionItem {{ color: {c["accent_text"]}; }}
    QPushButton#FloatingDangerItem {{ color: {c["danger"]}; }}
    QPushButton#FloatingActionItem:hover {{ background: {c["accent_soft"]}; }}
    QPushButton#FloatingDangerItem:hover {{ background: {c["danger_soft"]}; }}
    QPushButton#FloatingActionItem:disabled,
    QPushButton#FloatingDangerItem:disabled {{ color: {c["muted"]}; }}
    QFrame#EditorIdentityCard {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 12px;
    }}
    QLabel#EditorIdentityIcon {{ background: {c["accent_soft"]}; border-radius: 10px; }}
    QLabel#EditorIdentityTitle,
    QLabel#EditorSectionTitle {{ color: {c["text"]}; font-weight: 700; font-size: 10pt; }}
    QLabel#EditorSectionSubtitle {{ color: {c["muted"]}; font-size: 9pt; }}
    QFrame#EditorSectionMarker {{ background: {c["accent"]}; border: none; border-radius: 2px; }}
    /* 带 objectName 的规则优先于 QPushButton:disabled，禁用态必须单独声明，
       否则冷却/等待期间的主按钮看起来仍可点击。 */
    QPushButton#Primary:disabled,
    QPushButton#SidebarAddMenuButton:disabled,
    QPushButton#Danger:disabled {{
        background: {c["surface_alt"]};
        color: {c["muted"]};
        border: 1px solid {c["border"]};
    }}
    QPushButton#SidebarAddMenuButton {{
        padding: 0 28px 0 12px;
    }}
    QPushButton#SidebarAddMenuButton::menu-indicator {{
        image: url({chev_up});
        width: 12px;
        height: 12px;
        subcontrol-origin: padding;
        subcontrol-position: center right;
        right: 10px;
    }}
    QPushButton#Ghost {{
        background: transparent;
        border: none;
        border-radius: 6px;
        padding: 0;
        color: {c["muted"]};
    }}
    QPushButton#Ghost:hover {{
        background: {c["surface_alt"]};
        color: {c["text"]};
    }}
    QPushButton#Ghost:pressed,
    QPushButton#Ghost:checked {{
        background: transparent;
        color: {c["accent_text"]};
    }}
    QPushButton#UnlockNewMenuButton {{
        background: transparent;
        border: none;
        border-radius: 6px;
        padding: 0px 28px 0px 10px;
        color: {c["muted"]};
        font-weight: 600;
    }}
    QPushButton#UnlockNewMenuButton:hover {{
        background: {c["surface_alt"]};
        color: {c["text"]};
    }}
    QPushButton#UnlockNewMenuButton:pressed {{
        background: transparent;
        color: {c["accent_text"]};
    }}
    QPushButton#UnlockNewMenuButton::menu-indicator {{
        image: url({chev_down});
        width: 12px;
        height: 12px;
        subcontrol-origin: padding;
        subcontrol-position: center right;
        right: 10px;
    }}
    QPushButton#Link {{ background: transparent; border: none; color: {c["accent_text"]}; text-decoration: underline; }}
    QPushButton#Link:hover {{ color: {c["accent_text_hover"]}; }}

    /* 设置页按钮：白色背景 */
    QPushButton#SettingsBtn {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 9px 16px;
        font-weight: 600;
    }}
    QPushButton#SettingsBtn:hover {{ background: {c["accent_soft"]}; border-color: {c["accent"]}; }}

    /* 图标按钮：去掉默认内边距，避免图标被裁切 */
    QPushButton#IconBtn {{
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 0;
        font-size: 11.25pt;
        color: {c["muted"]};
    }}
    QPushButton#IconBtn:hover {{ background: {c["accent_soft"]}; border-color: {c["accent"]}; }}
    QPushButton#IconBtn:checked {{
        background: {c["accent_soft"]};
        border-color: {c["accent"]};
        color: {c["accent_text"]};
    }}
    QPushButton#RevealIconBtn {{
        background: transparent;
        border: none;
        border-radius: 6px;
        padding: 0;
        color: {c["muted"]};
    }}
    QPushButton#RevealIconBtn:hover {{
        background: {c["surface_alt"]};
        color: {c["text"]};
    }}
    QPushButton#RevealIconBtn:pressed,
    QPushButton#RevealIconBtn:checked {{
        background: transparent;
        color: {c["accent_text"]};
    }}

    /* ---------- 列表 ---------- */
    QListWidget {{ background: transparent; border: none; outline: none; }}
    QWidget#RecycleListCard {{
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QWidget#RecycleListCard QListWidget {{
        background: transparent;
    }}
    QListWidget::item {{
        background: transparent;
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 0px;
        margin: 4px 2px;
    }}
    QListWidget::item:selected {{
        background: {c["accent_soft"]};
        border: 1px solid {c["accent"]};
        color: {c["text"]};
    }}
    QListWidget::item:hover {{ border: 1px solid {c["accent"]}; }}

    QTreeWidget#TransferList {{
        background: {c["surface_alt"]};
        color: {c["text"]};
        alternate-background-color: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        outline: none;
        padding: 2px;
    }}
    QTreeWidget#TransferList::item {{
        min-height: 34px;
        padding: 3px 6px;
        border-bottom: 1px solid {c["border"]};
    }}
    QTreeWidget#TransferList::item:hover,
    QTreeWidget#TransferList::item:selected {{
        background: {c["accent_soft"]};
        color: {c["text"]};
    }}
    QTreeWidget#TransferList QHeaderView::section {{
        background: {c["surface"]};
        color: {c["muted"]};
        border: none;
        border-bottom: 1px solid {c["border"]};
        border-right: 1px solid {c["border"]};
        padding: 6px 8px;
        font-weight: 600;
    }}
    QProgressBar#TransferProgress {{
        background: {c["surface"]};
        color: {c["text"]};
        border: none;
        border-radius: 4px;
        text-align: center;
        font-size: 8.5pt;
    }}
    QProgressBar#TransferProgress::chunk {{
        background: {c["accent"]};
        border-radius: 4px;
    }}

    QWidget#EntryListCard {{
        background: transparent;
    }}
    QLabel#EntryTitle {{
        color: {c["text"]};
        font-size: 11.25pt;
        font-weight: 700;
        min-height: 20px;
    }}
    QLabel#EntrySub {{
        color: {c["muted"]};
        min-height: 18px;
    }}
    QLabel#EntryBadge_danger, QLabel#EntryBadge_warn {{
        border-radius: 8px;
        padding: 4px 9px;
        font-size: 8.25pt;
        font-weight: 700;
        min-height: 20px;
    }}
    QLabel#EntryBadge_danger {{
        background: {c["danger_soft"]};
        color: {c["danger"]};
    }}
    QLabel#EntryBadge_warn {{
        background: {c["warn_soft"]};
        color: {c["warn"]};
    }}

    QWidget#AlphaNav {{
        background: transparent;
    }}
    QPushButton#AlphaNavBtn {{
        background: transparent;
        border: none;
        border-radius: 6px;
        padding: 0;
        color: {c["muted"]};
        font-size: 7.5pt;
        font-weight: 700;
    }}
    QPushButton#AlphaNavBtn:hover {{
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
    }}
    QPushButton#AlphaNavBtn:disabled {{
        color: {c["border"]};
    }}
    QPushButton#AlphaNavBtn[active="true"] {{
        background: {c["accent"]};
        color: white;
    }}

    QFrame#DetailTitleCard {{
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QLabel#DetailTitleIcon {{
        border: none;
    }}
    QLabel#DetailTypeBadge {{
        border-radius: 6px;
        padding: 4px 8px;
        font-size: 8.5pt;
        font-weight: 700;
    }}
    QLabel#DetailTitle {{
        font-size: 16.5pt; font-weight: 700; color: {c["text"]};
    }}
    /* 详情页「关联自动填充内容」卡片：对齐 Android 的 secondaryContainer 弱化底色 */
    QFrame#LinkedAutofillCard {{
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QFrame#LinkedAutofillCard[linked="true"]:hover {{
        background: {c["accent_soft"]};
    }}
    QLabel#LinkedAutofillTitle {{
        font-size: 10.5pt; font-weight: 600; color: {c["text"]};
    }}
    /* 详情页字段：标签加大加粗、值用 bodyLarge 级别，对齐 Android FieldRow 的
       labelMedium + bodyLarge 组合。原 9pt 标签在 1280×760 窗口下难以辨认。 */
    QLabel#FieldLabel {{ color: {c["muted"]}; font-size: 10.5pt; font-weight: 700; }}
    QLabel#FieldLabel[leaked="true"] {{ color: {c["danger"]}; }}
    QLabel#FieldValue {{ color: {c["text"]}; font-size: 12pt; }}
    /* 编辑页「关联填充内容」条目：对齐 Android 的 secondaryContainer chip */
    QWidget#AutofillLinkChip {{
        background: {c["accent_soft"]};
        border-radius: 8px;
    }}
    QLabel#AutofillLinkChipText {{
        color: {c["text"]};
        font-size: 9.75pt;
    }}
    QPushButton#AutofillLinkRemove {{
        background: transparent;
        border: none;
        border-radius: 8px;
        padding: 0;
    }}
    QPushButton#AutofillLinkRemove:hover {{
        background: {c["border"]};
    }}
    QLabel#EntryExpiryBanner {{
        border-radius: 10px;
        padding: 10px;
    }}
    QLabel#EntryExpiryBanner[state="expired"] {{
        background: {c["danger_soft"]};
        color: {c["danger"]};
    }}
    QLabel#EntryExpiryBanner[state="warn"] {{
        background: {c["warn_soft"]};
        color: {c["warn"]};
    }}
    /* 标题卡内的状态徽章：对齐 Android 的 BadgeChip */
    QLabel#DetailStatusChip {{
        border-radius: 8px;
        padding: 2px 8px;
        font-size: 8.5pt;
        font-weight: 600;
    }}
    QLabel#DetailStatusChip[state="danger"] {{
        background: {c["danger_soft"]};
        color: {c["danger"]};
    }}
    QLabel#DetailStatusChip[state="warn"] {{
        background: {c["warn_soft"]};
        color: {c["warn"]};
    }}
    QScrollArea {{ background: transparent; border: none; }}
    QScrollArea > QWidget {{ background: transparent; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QLabel#Tag {{
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
        border-radius: 6px;
        padding: 5px 10px;
        font-size: 9pt;
        font-weight: 600;
    }}
    QLabel#Empty {{ color: {c["muted"]}; font-size: 11.25pt; }}
    QLabel#ImgPreview {{
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
        color: {c["muted"]};
        font-size: 9pt;
    }}
    QWidget#ImgOverlay {{
        background: rgba(0,0,0,0.42);
        border-radius: 6px;
    }}
    QWidget#ImgViewerBg {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QPushButton#ImgAction {{
        background: transparent;
        border: none;
        border-radius: 8px;
        color: rgba(255,255,255,0.85);
        font-size: 8pt;
        font-weight: 600;
        padding: 0px;
    }}
    QPushButton#ImgAction:hover {{
        background: rgba(255,255,255,0.18);
        color: white;
    }}
    QPushButton#ImgReplace {{
        background: transparent;
        border: none;
        border-radius: 8px;
        color: rgba(255,255,255,0.60);
        font-size: 22pt;
        font-weight: 400;
        padding: 0px;
    }}
    QPushButton#ImgReplace:hover {{
        background: rgba(255,255,255,0.18);
        color: white;
    }}
    QPushButton#ImgClose {{
        background: transparent;
        border: none;
        border-radius: 6px;
        color: white;
        font-size: 11pt;
        font-weight: 400;
        padding: 0px 0px 3px 0px;
    }}
    /* 悬停底色必须半透明：按钮浮在图片上，不透明背景会盖住下方图像内容，
       看起来像叉按钮被背景色覆盖。 */
    QPushButton#ImgClose:hover {{ background: {c["danger_soft"]}; color: white; }}
    QPushButton#ImgClose:pressed {{ background: {c["danger_hover"]}; color: white; }}
    QFrame#ImgBtnBar {{
        background: rgba(0,0,0,0.55);
        border-radius: 8px;
        border: none;
    }}
    QPushButton#ImgAdd {{
        background: {c["surface_alt"]};
        border: 1px dashed {c["border"]};
        border-radius: 8px;
        color: {c["muted"]};
        font-size: 9pt;
    }}
    QPushButton#ImgAdd:hover {{
        border-color: {c["accent"]};
        color: {c["accent_text"]};
    }}
    QLabel#StatTitle {{ color: {c["muted"]}; font-size: 9pt; }}
    QLabel#SecurityRecommendation {{
        color: {c["text"]};
        background: {c["accent_soft"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
        padding: 8px 10px;
    }}
    QLabel#SecurityError {{ color: {c["danger"]}; font-size: 9pt; }}
    QPushButton#RiskEntryRow {{
        background: transparent;
        border: 1px solid transparent;
        border-radius: 8px;
        padding: 0;
        text-align: left;
    }}
    QPushButton#RiskEntryRow:hover, QPushButton#RiskEntryRow:focus {{
        background: {c["surface_alt"]};
        border-color: {c["border"]};
    }}
    QProgressBar#ScanProgressBar {{
        min-height: 4px;
        max-height: 4px;
        background: {c["surface_alt"]};
        border: none;
        border-radius: 2px;
        text-align: center;
        color: transparent;
    }}
    QProgressBar#ScanProgressBar::chunk {{
        background: {c["accent"]};
        border-radius: 2px;
    }}
    QLabel#FieldError {{ color: {c["danger"]}; font-size: 9.5pt; font-weight: 600; }}
    QLabel#LockReason {{
        background: {c["danger_soft"]};
        color: {c["danger"]};
        font-size: 9.5pt;
        font-weight: 600;
        border: 1px solid {c["danger"]};
        border-radius: 8px;
        padding: 8px 10px;
    }}
    /* ---------- 顶部悬浮通知条 ----------
       反色胶囊：浅色主题深底浅字，深色主题浅底深字（对应安卓 inverseSurface）。 */
    QFrame#NoticeBar {{
        background: {c["text"]};
        border: none;
        border-radius: 16px;
    }}
    QLabel#NoticeBarText {{
        background: transparent;
        color: {c["bg"]};
        font-size: 9.5pt;
    }}

    /* ---------- 滚动条 ---------- */
    /* 轨道为内容留出间距，滑块本身保持细线。 */
    QScrollBar:vertical {{
        background: transparent; width: 10px; margin: 2px 0;
    }}
    QScrollBar::handle:vertical {{
        background: {c["scroll_handle"]}; border-radius: 1px;
        margin: 0 1px 0 6px; min-height: 40px;
    }}
    QScrollBar::handle:vertical:hover, QScrollBar::handle:vertical:pressed {{ background: {c["muted"]}; }}
    QScrollBar:horizontal {{
        background: transparent; height: 6px; margin: 0 2px;
    }}
    QScrollBar::handle:horizontal {{
        background: {c["scroll_handle"]}; border-radius: 3px; min-width: 40px;
    }}
    QScrollBar::handle:horizontal:hover, QScrollBar::handle:horizontal:pressed {{ background: {c["muted"]}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

    QFrame#Card {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QFrame#DetailPaneCard {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QFrame#DetailPaneCard > QScrollArea,
    QFrame#DetailPaneCard > QWidget {{
        background: transparent;
        border: none;
    }}
    QTabBar#EditorTabBar {{
        background: {c["bg"]};
        border: none;
        border-top-left-radius: 7px;
        border-top-right-radius: 7px;
    }}
    /* 标题之间及标题栏底部均不绘制分割线。 */
    QTabBar#EditorTabBar::tab {{
        background: transparent;
        color: {c["muted"]};
        border: none;
        padding: 8px 14px;
        font-size: 10pt;
    }}
    QTabBar#EditorTabBar::tab:hover {{
        background: {c["surface_alt"]};
        color: {c["text"]};
    }}
    QTabBar#EditorTabBar::tab:selected {{
        background: {c["surface"]};
        color: {c["accent_text"]};
        border: none;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        font-weight: 700;
    }}
    QTabBar#EditorTabBar::close-button {{
        subcontrol-origin: padding;
        subcontrol-position: right center;
        margin-right: 6px;
        margin-left: 4px;
        padding: 2px;
    }}
    QLabel#OtpCodeCard {{
        color: #00BFA5;
        font-size: {c["otp_card_font_size"]}pt;
        font-weight: 800;
        letter-spacing: 4px;
    }}

    QLabel#OtpDigitDisplay {{
        font-size: 28pt;
        font-weight: 700;
        letter-spacing: 4px;
        color: {c["text"]};
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 6px;
        padding: 12px 16px;
    }}
    QLabel#OtpCountdown {{
        font-size: 12pt;
        font-weight: 700;
        color: {c["muted"]};
    }}
    QFrame#ListCard {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}

    /* ---------- 对话框 / 消息框 ---------- */
    QFrame#Dialog {{
        background: {c["surface_light"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QFrame#SettingsDialogCard {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QLabel#WorkspacePageTitle {{ font-size: 18pt; font-weight: 700; color: {c["text"]}; }}
    QPushButton#SecurityFilterCard {{
        background: {c["surface_alt"]}; color: {c["muted"]};
        border: none; border-radius: 8px; padding: 8px 10px; font-weight: 600;
    }}
    QPushButton#SecurityFilterCard:checked {{
        background: {c["accent_soft"]}; color: {c["accent_text"]};
    }}
    QListView#SecurityFindingList {{ background: {c["surface"]}; border: none; border-radius: 8px; }}
    QLabel#CloudInlineNotice {{ background: {c["surface_alt"]}; color: {c["text"]}; padding: 10px; border-radius: 8px; }}
    QLabel#CloudInlineNotice[state="error"] {{ background: {c["danger_soft"]}; color: {c["danger"]}; }}
    QLabel#CloudInlineNotice[state="warn"] {{ background: {c["warn_soft"]}; color: {c["warn"]}; }}
    QWidget#CloudSyncPage {{ background: transparent; }}
    QScrollArea#CloudContentScroll {{
        background: transparent;
        border: none;
    }}
    QScrollArea#CloudContentScroll > QWidget > QWidget {{ background: transparent; }}
    QWidget#CloudPanel {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QWidget#CloudPanel QLabel#CloudSectionTitle {{ font-size: 15pt; font-weight: 700; color: {c["text"]}; }}
    QWidget#CloudPanel QLabel#CloudResult {{ background: {c["surface_alt"]}; border: 1px solid {c["border"]}; border-radius: 8px; padding: 10px; color: {c["text"]}; }}
    QWidget#CloudPanel QLabel#CloudPath {{ color: {c["muted"]}; }}
    QWidget#CloudPanel QLabel#CloudPhaseStatus {{ color: {c["muted"]}; }}
    QWidget#CloudPanel QLabel#CloudPhaseStatus[state="running"] {{ color: {c["accent_text"]}; font-weight: 600; }}
    QWidget#CloudPanel QLabel#CloudPhaseStatus[state="failed"] {{ color: {c["danger"]}; font-weight: 600; }}
    QFrame#CloudMasterSwitch {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QWidget#CloudPanel QLabel#CloudAdvancedTitle {{ color: {c["muted"]}; font-weight: 600; }}
    QWidget#CloudPanel QLineEdit,
    QWidget#CloudPanel QComboBox {{
        background: {c["surface_alt"]};
        color: {c["text"]};
        border-color: {c["border"]};
    }}
    QWidget#CloudPanel QLineEdit:focus,
    QWidget#CloudPanel QComboBox:focus {{
        background: {c["surface"]};
        border-color: {c["accent"]};
    }}
    QWidget#CloudPanel QProgressBar {{
        min-height: 7px;
        max-height: 7px;
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 4px;
        text-align: center;
        color: transparent;
    }}
    QWidget#CloudPanel QProgressBar::chunk {{
        background: {c["accent"]};
        border-radius: 3px;
    }}
    QWidget#CloudPanel QLabel[state="ok"] {{
        color: {c["success"]};
        font-weight: 600;
    }}
    QWidget#CloudPanel QLabel[state="failed"] {{
        color: {c["danger"]};
        font-weight: 600;
    }}
    QWidget#SettingsPanelTitle {{
        background: transparent;
        border-bottom: none;
    }}
    QPushButton#SettingsClose {{
        background: transparent;
        border: none;
        border-radius: 6px;
        padding: 0;
        color: {c["muted"]};
        font-size: 14pt;
        font-weight: 500;
    }}
    QPushButton#SettingsClose:hover {{ background: {c["danger_soft"]}; color: {c["danger"]}; }}
    QPushButton#SettingsClose:pressed {{ background: {c["danger"]}; color: white; }}
    QLabel#MsgText {{ font-size: 10.5pt; color: {c["text"]}; }}
    QLabel#MsgIcon_info, QLabel#MsgIcon_success,
    QLabel#MsgIcon_warn, QLabel#MsgIcon_error {{
        font-size: 12.75pt; font-weight: 700;
        min-width: 30px; max-width: 30px; min-height: 30px; max-height: 30px;
        border-radius: 15px; qproperty-alignment: AlignCenter;
    }}
    QLabel#MsgIcon_info {{ background: {c["accent_soft"]}; color: {c["accent_text"]}; }}
    QLabel#MsgIcon_success {{ background: {c["success_soft"]}; color: {c["success"]}; }}
    QLabel#MsgIcon_warn {{ background: {c["warn_soft"]}; color: {c["warn"]}; }}
    QLabel#MsgIcon_error {{ background: {c["danger_soft"]}; color: {c["danger"]}; }}

    QFrame#SettingGroupBox {{
        background: {c["surface_alt"]};
        border: 1px solid {c["border"]};
        border-radius: 8px;
    }}
    QLabel#SettingGroup {{
        font-size: 9.5pt;
        font-weight: 700;
        color: {c["accent_text"]};
        padding-bottom: 2px;
    }}
    QPushButton#SettingGroupToggle {{
        background: transparent;
        border: none;
        padding: 2px 0;
        text-align: left;
        font-size: 14px;
        font-weight: 600;
        color: {c["text"]};
    }}
    QPushButton#SettingGroupToggle:hover {{
        color: {c["accent_text"]};
    }}
    QLabel#SettingNote {{
        color: {c["muted"]};
        font-size: 8.5pt;
        line-height: 1.25;
    }}
    QLabel#GearBusyNotice {{
        color: {c["text"]};
        font-size: 12pt;
        font-weight: 600;
        padding: 30px 16px;
    }}
    QLabel#SettingDangerNote {{
        color: {c["danger"]};
        font-size: 8.5pt;        line-height: 1.25;
    }}
    QFrame#SettingSep {{ color: {c["border"]}; }}

    QFrame#ModuleCard {{
        background: {c["surface"]};
        border: 1px solid {c["border"]};
        border-radius: 12px;
    }}
    QFrame#ModuleCard:hover {{
        border-color: {c["accent_soft"]};
    }}
    QFrame#ModuleCardHeader {{
        background: {c["accent_soft"]};
        border: none;
        border-top-left-radius: 12px;
        border-top-right-radius: 12px;
    }}
    QLabel#ModuleCardIcon {{
        background: {c["surface"]};
        border: none;
        border-radius: 10px;
    }}
    QLabel#ModuleSensitivity {{
        color: {c["muted"]};
        font-size: 8.5pt;
    }}
    QFrame#ModuleCard QLineEdit#FieldLabel,
    QFrame#ModuleCard QLabel#FieldLabel {{
        font-size: 11pt;
        font-weight: 700;
        color: {c["text"]};
    }}
    QFrame#ModuleCardHeaderDivider {{
        background: {c["border"]};
        max-height: 1px;
        margin: 4px 0 2px 0;
    }}
    QFrame#ModuleCard QLineEdit#ModuleTitle {{
        font-size: 11pt;
        font-weight: 700;
        color: {c["text"]};
        border: 1px solid transparent;
        border-radius: 6px;
        padding: 2px 6px;
        background: transparent;
    }}
    QFrame#ModuleCard QLineEdit#ModuleTitle:focus {{
        border-color: {c["accent"]};
        background: {c["surface"]};
    }}
    QLabel#ModuleEmpty {{
        color: {c["muted"]};
        border: 1px dashed {c["border"]};
        border-radius: 8px;
    }}
    QPushButton#ModuleAdd {{
        font-size: 10.5pt;
        font-weight: 600;
        min-height: 44px;
        border: none;
        border-radius: 12px;
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
    }}
    QPushButton#ModuleAdd:hover {{ background: {c["border"]}; }}
    QPushButton#ImageAddTile {{
        border: 1px dashed {c["accent"]};
        border-radius: 8px;
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
        font-weight: 600;
    }}
    QPushButton#ImageAddTile:hover {{ background: {c["surface_alt"]}; }}
    QPushButton#PickerItem {{
        text-align: left;
        min-height: 46px;
        background: {c["picker_item"]};
        border: none;
        border-radius: 10px;
        padding: 6px 12px;
    }}
    QPushButton#PickerItem:hover {{
        background: {c["accent_soft"]};
    }}
    QPushButton#PickerItem:pressed {{
        background: {c["accent_soft"]};
        color: {c["accent_text"]};
    }}
    QLabel#ModulePickerGroup {{
        color: {c["accent_text"]};
        font-size: 9pt;
        font-weight: 700;
        padding: 10px 4px 4px 4px;
    }}

    QToolTip {{
        background: {c["text"]}; color: {c["surface"]};
        border: none; border-radius: 6px; padding: 6px 8px;
    }}
    """


_ASSETS = Path(__file__).resolve().parent / "assets"


def _asset(name: str) -> str:
    return (_ASSETS / name).as_posix()
