"""PC 端 Markdown 模块：改名、多行文本编辑、编辑/查看切换与渲染。"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPointF, Qt, QTimer, QUrl
from PySide6.QtGui import QMouseEvent
from PySide6.QtCore import QEvent
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QDateEdit, QHBoxLayout, QScrollArea, QPushButton, QSizePolicy, QSlider, QTextEdit, QVBoxLayout, QWidget

from core import modules
from core.models import Entry, SecretType
from core.markdown_html import _safe_href, render_markdown_html, render_markdown_document, sanitize_html
from ui import i18n, widgets
from ui.module_editor import ModuleCard, ModuleDragHandle, ModuleEditor, ModuleRemoveButton
from ui.dialogs import EntryDialog


def test_multiline_module_is_displayed_as_markdown():
    assert modules.CATALOG[modules.MULTILINE]["title"] == "Markdown"
    assert modules.new_module(modules.MULTILINE)["title"] == "Markdown"
    assert modules.CATALOG[modules.TEXT]["title"] == "文本"
    assert i18n.tr("Markdown") == "Markdown"


def test_render_markdown_html_covers_commonmark_and_gfm_tables():
    html = render_markdown_html(
        "# 标题\n\n**粗体** `code`\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n```python\nx = 1\n```\n"
    )
    assert '<h1 id="标题">标题</h1>' in html
    assert "<strong>粗体</strong>" in html
    assert "<table>" in html
    assert "<pre>" in html and "x = 1" in html


def test_render_markdown_document_embeds_mermaid_and_theme():
    colors = {"text": "#000", "muted": "#666", "accent": "#06c", "border": "#ccc", "surface_alt": "#eee", "bg": "#fff"}
    doc = render_markdown_document(
        "# 标题\n\n```mermaid\ngraph TD\n    A --> B\n```\n",
        colors,
    )
    assert '<pre class="mermaid">' in doc
    assert "graph TD" in doc
    assert 'src="mermaid.min.js"' in doc
    assert "securityLevel" in doc
    assert "Content-Security-Policy" in doc
    assert "initMermaidPanZoom" in doc  # pan/zoom 交互已注入
    assert "mermaid.run" in doc
    assert "#06c" in doc  # accent 主题色已注入 CSS
    # 普通代码块不受影响
    plain = render_markdown_document("```python\nx = 1\n```", colors)
    assert 'class="mermaid"' not in plain
    assert "x = 1" in plain


def test_document_styles_code_tables_and_disables_unsupported_links():
    colors = {"text": "#000", "muted": "#666", "accent": "#06c", "border": "#ccc", "surface_alt": "#eee", "bg": "#fff"}
    doc = render_markdown_document(
        "# 目标\n\n|A|B|\n|-|-|\n|1|2|\n\n```python\nx = 1\n```\n\n"
        "[页内](#目标) [相对](./a.md) [网页](https://example.com)",
        colors,
    )
    assert 'id="目标"' in doc
    assert "md-table-wrap" in doc
    assert "md-code-card" in doc
    assert 'href="#目标"' in doc
    assert 'href="https://example.com"' in doc  # 外部网页链接保留（点击交系统浏览器）
    assert 'href="./a.md"' not in doc  # 相对/本地路径仍禁用
    assert "data-disabled-link" in doc


def test_safe_href_allows_fragments_and_web_links():
    assert _safe_href("#目标") is True
    assert _safe_href("https://example.com") is True
    assert _safe_href("http://example.com/a?b=1") is True
    for value in ("./a.md", "/tmp/a.md", "file:///tmp/a", "mailto:a@b.com", "javascript:alert(1)", "#"):
        assert _safe_href(value) is False


def test_markdown_page_opens_external_links_in_system_browser(monkeypatch):
    QApplication.instance() or QApplication([])
    opened = []
    monkeypatch.setattr(widgets, "_open_external_link", lambda url: opened.append(url.toString()))
    page = widgets.MarkdownPage()
    clicked = QWebEnginePage.NavigationType.NavigationTypeLinkClicked
    assert page.acceptNavigationRequest(QUrl("file:///viewer.html#目标"), clicked, True)
    assert not page.acceptNavigationRequest(QUrl("file:///tmp/a.md"), clicked, True)
    assert not page.acceptNavigationRequest(QUrl("https://example.com/#目标"), clicked, True)
    assert opened == ["https://example.com/#目标"]
    page.deleteLater()


def test_mermaid_toolbar_has_no_fullscreen_action():
    colors = {"text": "#000", "muted": "#666", "accent": "#06c", "border": "#ccc", "surface_alt": "#eee", "bg": "#fff"}
    doc = render_markdown_document("```mermaid\ngraph TD\n    A --> B\n```\n", colors)

    assert "md-fullscreen-card" not in doc
    assert "全屏" not in doc


def test_markdown_document_clamps_negative_svg_sizes_before_they_reach_the_dom():
    """Mermaid 个别图会把负宽高写进 SVG，Chromium 每次都会打印
    ``<rect> attribute width: A negative value is not valid.`` 刷屏控制台。

    页面必须在属性写入前把负值夹到 0（负宽高的渲染结果本来就是 0），这里直接在
    真实 WebEngine 里写一个负宽高，确认控制台不再出现该错误。
    """
    app = QApplication.instance() or QApplication([])
    messages: list[str] = []

    class _ConsolePage(QWebEnginePage):
        def javaScriptConsoleMessage(self, level, message, line_number, source_id):  # noqa: N802
            messages.append(message)

    colors = {"text": "#000", "muted": "#666", "accent": "#06c", "border": "#ccc", "surface_alt": "#eee", "bg": "#fff"}
    doc = render_markdown_document("```mermaid\ngraph TD\n    A --> B\n```\n", colors, enable_mermaid=True)
    probe = (
        "<script>window.addEventListener('DOMContentLoaded', function () {"
        "  var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');"
        "  var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');"
        "  svg.appendChild(rect); document.body.appendChild(svg);"
        "  rect.setAttribute('width', -37.5);"
        "  rect.setAttribute('height', '-24');"
        "  rect.setAttribute('width', '100%');"
        "});</script>"
    )
    view = QWebEngineView()
    view.setPage(_ConsolePage(view))
    view.setHtml(
        doc.replace("</body>", probe + "</body>"),
        QUrl.fromLocalFile(str(widgets._ASSETS / "mermaid.html")),
    )
    view.show()
    deadline = QTimer()
    deadline.setSingleShot(True)
    deadline.timeout.connect(app.quit)
    deadline.start(2_500)
    app.exec()
    view.deleteLater()
    app.processEvents()

    assert [m for m in messages if "negative" in m] == []


def test_markdown_table_alignment_is_preserved():
    html = render_markdown_html("| L | C | R |\n|:--|:-:|--:|\n| a | b | c |")

    assert 'align="left"' in html
    assert 'align="center"' in html
    assert 'align="right"' in html
    # 内联 style 仍被消毒剥离，仅保留受控的 align 属性
    assert "text-align" not in html


def test_markdown_gfm_strikethrough_ins_tasklist_and_autolink():
    html = render_markdown_html(
        "~~删除线~~ 与 ++下划线++\n\n- [x] 完成\n- [ ] 待办\n\n访问 https://example.com/a_b 结束"
    )
    assert "<del>删除线</del>" in html
    assert "<ins>下划线</ins>" in html
    assert '<li class="md-task-done">完成</li>' in html
    assert '<li class="md-task">待办</li>' in html
    assert '<a href="https://example.com/a_b">https://example.com/a_b</a>' in html


def test_markdown_footnotes_render_sup_and_backref():
    html = render_markdown_html("正文[^1]\n\n[^1]: 脚注内容")
    assert '<sup id="fnref:1"><a class="footnote-ref" href="#fn:1">1</a></sup>' in html
    assert '<div class="footnote">' in html
    assert 'class="footnote-backref" href="#fnref:1"' in html
    assert 'id="fn:1"' in html


def test_markdown_details_block_renders_nested_markdown():
    html = render_markdown_html(
        "<details><summary>要点</summary>\n\n- 内购\n- 退款\n\n```python\nx = 1\n```\n\n</details>"
    )
    assert '<details class="md-details"><summary>要点</summary>' in html
    assert "内购" in html and "<li>退款</li>" in html
    assert '<code class="language-python">x = 1' in html  # 围栏代码在折叠正文内正常渲染


def test_markdown_math_paragraphs_render_katex_placeholders():
    html = render_markdown_html("$$E = mc^2$$\n\n仅整段 $x^2$ 才渲染")
    assert html.count("md-math") >= 2
    assert "md-math-display" in html
    assert 'data-tex=' in html
    # 金额等段落内 $ 不应被误判为公式
    plain = render_markdown_html("总计 $100 起，详见 http://a.b")
    assert "md-math" not in plain


def test_markdown_document_includes_katex_only_when_math_present():
    colors = {"text": "#000", "muted": "#666", "accent": "#06c", "border": "#ccc", "surface_alt": "#eee", "bg": "#fff"}
    with_math = render_markdown_document("$$a^2+b^2=c^2$$", colors)
    assert 'src="katex/katex.min.js"' in with_math
    assert 'href="katex/katex.min.css"' in with_math
    without_math = render_markdown_document("# 无公式", colors)
    assert 'src="katex/katex.min.js"' not in without_math
    assert 'href="katex/katex.min.css"' not in without_math


def test_markdown_sanitizer_keeps_inline_formatting_and_blocks_svg_scripts():
    html = render_markdown_html(
        '<mark>高亮</mark> <sub>下</sub> <sup>上</sup> <kbd>K</kbd>\n\n'
        '<svg width="40"><circle r="4"/><script>evil()</script></svg>'
    )
    assert "<mark>高亮</mark>" in html
    assert "<sub>下</sub>" in html and "<sup>上</sup>" in html
    assert "<kbd>K</kbd>" in html
    assert '<svg width="40">' in html and '<circle r="4">' in html
    assert "evil" not in html and "<script" not in html


def test_markdown_page_allows_only_local_fragment_navigation():
    QApplication.instance() or QApplication([])
    page = widgets.MarkdownPage()
    clicked = QWebEnginePage.NavigationType.NavigationTypeLinkClicked
    assert page.acceptNavigationRequest(QUrl("file:///viewer.html#目标"), clicked, True)
    assert not page.acceptNavigationRequest(QUrl("file:///tmp/a.md"), clicked, True)
    page.deleteLater()


def test_markdown_document_sanitizes_injected_html():
    colors = {"text": "#000", "muted": "#666", "accent": "#06c", "border": "#ccc", "surface_alt": "#eee", "bg": "#fff"}
    md = "# 标题\n\n<script>alert('xss')</script>\n\n<img src=x onerror=alert(1)>\n\n<a href=\"javascript:alert(1)\">bad</a>\n\n<iframe src=\"//evil\"></iframe>\n"
    doc = render_markdown_document(md, colors)
    assert "alert" not in doc
    assert "onerror" not in doc
    assert "javascript:" not in doc
    assert "iframe" not in doc
    assert "evil" not in doc
    assert '<h1 id="标题">标题</h1>' in doc


def test_sanitize_html_strips_dangerous_elements():
    out = sanitize_html('<p onclick="x()">hi <b>bold</b> <script>evil()</script></p>')
    assert out == "<p>hi <b>bold</b> </p>"
    assert "<script" not in out and "evil" not in out


def test_markdown_viewer_is_webengine_based():
    assert issubclass(widgets.MarkdownViewer, QWebEngineView)


def test_markdown_render_does_not_block_viewer_creation(monkeypatch):
    from threading import Event

    QApplication.instance() or QApplication([])
    started, release = Event(), Event()

    def slow_render(*_args, **_kwargs):
        started.set()
        release.wait(3)
        return "<p>ready</p>"

    monkeypatch.setattr(widgets.render_jobs, "render_document", slow_render)
    try:
        viewer = widgets.MarkdownViewer("# Long document")
        assert started.wait(2)
        assert viewer._render_future is not None
    finally:
        release.set()
        if "viewer" in locals():
            viewer._render_future.result(timeout=3)
            viewer._finish_markdown_render()
            viewer.deleteLater()


def test_long_document_with_repeated_headings_keeps_unique_anchors():
    html = render_markdown_html(("# 同名标题\n\n段落。\n\n") * 5000)
    assert html.count('<h1 id="同名标题') == 5000
    assert '<h1 id="同名标题">' in html
    assert '<h1 id="同名标题_4999">' in html


def test_markdown_document_cache_is_encrypted_and_reused(tmp_path, monkeypatch):
    import uuid
    from types import SimpleNamespace
    from core import media_files
    from ui import encrypted_document_cache

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    vault = SimpleNamespace(
        pmve_identity=SimpleNamespace(vault_id=uuid.uuid4()),
        root_key_for_device_unlock=lambda: bytes(range(32)),
    )
    media_files.set_vault_context(vault)
    try:
        text, colors = "# 私密内容", {"text": "#123456"}
        assert encrypted_document_cache.read(text, colors) is None
        encrypted_document_cache.write(text, colors, "<p>私密内容</p>")
        path = encrypted_document_cache._parts(text, colors)[0]
        payload = path.read_bytes()
        assert "私密内容".encode() not in payload
        assert encrypted_document_cache.read(text, colors) == "<p>私密内容</p>"
        path.write_bytes(payload[:-1] + bytes([payload[-1] ^ 1]))
        assert encrypted_document_cache.read(text, colors) is None
    finally:
        media_files.remove_vault_context(vault)


def test_text_module_editor_is_multiline():
    QApplication.instance() or QApplication([])
    card = ModuleCard(modules.new_module(modules.TEXT))
    editor = card._editors["value"]
    assert isinstance(editor, QTextEdit)
    card.close()


def test_boolean_module_editor_roundtrips_native_bool():
    QApplication.instance() or QApplication([])
    card = ModuleCard(modules.new_module(modules.BOOLEAN))
    editor = card._editors["value"]
    assert isinstance(editor, QCheckBox)
    assert card.has_content() is True
    editor.setChecked(True)
    assert card.value()["value"] is True
    card.close()


def test_datetime_editor_has_calendar_sliders_and_direct_value():
    QApplication.instance() or QApplication([])
    module = modules.new_module(modules.DATETIME)
    module["value"] = "2026-08-20T21:30"
    card = ModuleCard(module)
    assert card.findChildren(QDateEdit)
    assert len(card.findChildren(QSlider)) == 2
    card._datetime_value.setText("2026-09-01T08:45")
    assert card.value()["config"]["mode"] == "datetime"
    assert card.value()["value"] == "2026-09-01T08:45"
    card.close()


def test_card_type_selector_changes_to_custom_without_losing_saved_fields():
    app = QApplication.instance() or QApplication([])
    module = modules.new_module(modules.CARD_DOCUMENT)
    module["value"].update(bank="Example Bank", future_field="keep")
    card = ModuleCard(module)
    selector = card._editors["card_type"]
    assert isinstance(selector, QComboBox)
    selector.setCurrentIndex(selector.findData(modules.CARD_CUSTOM))
    app.processEvents()
    result = card.value()["value"]
    assert result["card_type"] == modules.CARD_CUSTOM
    assert result["bank"] == "Example Bank"
    assert result["future_field"] == "keep"
    assert "card_name" in card._editors
    card.close()


def test_top_level_card_switches_to_custom_and_preserves_unknown_fields():
    QApplication.instance() or QApplication([])
    entry = Entry(title="卡", secret_type=SecretType.CARD_DOCUMENT, fields={
        "cardholder": "张三", "bank": "Example Bank", "future_field": "keep",
    })
    dialog = EntryDialog(entry)
    page = dialog.stacked.currentWidget()
    page.card_type.setCurrentIndex(page.card_type.findData(modules.CARD_CUSTOM))
    page.card_name.setText("城市会员")
    dialog.accept()
    saved = dialog.entry
    assert saved.fields["card_type"] == modules.CARD_CUSTOM
    assert saved.fields["card_name"] == "城市会员"
    assert saved.fields["bank"] == "Example Bank"
    assert saved.fields["future_field"] == "keep"
    dialog.close()


def test_markdown_module_editor_has_edit_view_toggle_and_preview(monkeypatch):
    QApplication.instance() or QApplication([])
    i18n.set_locale("zh-Hans")
    module = modules.new_module(modules.MULTILINE)
    module["value"] = "# 标题\n\n- 项目 A\n- 项目 B"
    card = ModuleCard(module)

    toggles = card.findChildren(widgets.CapsuleSegmentedControl)
    assert len(toggles) == 1
    toggle = toggles[0]
    # 与页面顶部档位切换条同款胶囊控件，只把高度压到行内档，且左右铺满卡片。
    assert (toggle.count(), toggle.current_key()) == (2, "edit")
    assert (toggle.label_at(0), toggle.label_at(1)) == ("编辑", "查看")
    assert toggle.height() == 30
    assert toggle.sizePolicy().horizontalPolicy() == QSizePolicy.Expanding
    card.show()
    app = QApplication.instance()
    app.processEvents()
    # 铺满所在行的可用宽度，行内不再留 addStretch 造成的左对齐留白。
    row = next(
        lay
        for lay in card.findChildren(QHBoxLayout)
        if any(lay.itemAt(i).widget() is toggle for i in range(lay.count()))
    )
    contents = row.contentsRect()
    assert contents.width() > 0
    assert toggle.geometry().width() == contents.width()
    assert abs(toggle.geometry().left() - contents.left()) <= 1

    editor = card._editors["value"]
    assert isinstance(editor, QTextEdit)
    card.show()
    assert editor.isVisible() and editor.toPlainText() == module["value"]

    assert card.findChildren(widgets.MarkdownViewer) == []

    toggle.set_current_index(1, animate=False)
    card.show()
    assert toggle.current_key() == "view"
    viewers = card.findChildren(widgets.MarkdownViewer)
    assert len(viewers) == 1
    preview = viewers[0]
    assert preview.isVisible()
    assert not editor.isVisible()
    assert isinstance(preview, widgets.MarkdownViewer)

    rendered = []
    monkeypatch.setattr(preview, "set_markdown_text", rendered.append)
    toggle.set_current_index(0, animate=False)
    assert editor.isVisible()
    assert not preview.isVisible()
    toggle.set_current_index(1, animate=False)
    assert card.findChildren(widgets.MarkdownViewer) == [preview]
    assert rendered == []

    editor.setPlainText("# 更新")
    toggle.set_current_index(0, animate=False)
    toggle.set_current_index(1, animate=False)
    assert rendered == ["# 更新"]


def test_markdown_editor_keeps_its_height_when_modules_are_stacked():
    """多个模块同处一个滚动区时，Markdown 编辑框不得被兄弟模块压扁到高度下限以下。"""
    QApplication.instance() or QApplication([])
    from ui.module_editor import _MARKDOWN_EDITOR_MIN_HEIGHT

    cards = [ModuleCard(modules.new_module(modules.MULTILINE)) for _ in range(4)]
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(0, 0, 0, 0)
    for card in cards:
        layout.addWidget(card)
    # 视口远小于四张卡片之和，逼迫布局把富余高度瓜分给兄弟模块
    page.resize(480, 200)
    page.show()
    QApplication.instance().processEvents()

    for card in cards:
        editor = card._editors["value"]
        assert editor.minimumHeight() == _MARKDOWN_EDITOR_MIN_HEIGHT
        assert editor.height() >= _MARKDOWN_EDITOR_MIN_HEIGHT
        # 不与兄弟模块争抢纵向空间
        assert editor.sizePolicy().verticalPolicy() == QSizePolicy.Minimum
    page.close()


def test_module_header_uses_drag_handle_to_reorder():
    QApplication.instance() or QApplication([])
    first = modules.new_module(modules.TEXT)
    first["title"] = "First"
    second = modules.new_module(modules.TEXT)
    second["title"] = "Second"
    editor = ModuleEditor([first, second])
    handles = editor.findChildren(ModuleDragHandle)
    assert len(handles) == 2
    assert editor.findChildren(QPushButton, "ModuleMoveButton") == []
    press = QMouseEvent(QEvent.MouseButtonPress, QPointF(15, 15), QPointF(100, 100),
                        Qt.LeftButton, Qt.LeftButton, Qt.NoModifier)
    release = QMouseEvent(QEvent.MouseButtonRelease, QPointF(15, 15), QPointF(100, 140),
                          Qt.LeftButton, Qt.NoButton, Qt.NoModifier)
    handles[0].mousePressEvent(press)
    handles[0].mouseReleaseEvent(release)
    assert [module["title"] for module in editor.modules()] == ["Second", "First"]
    editor.close()


def test_module_remove_button_is_self_drawn_without_legacy_icon():
    QApplication.instance() or QApplication([])
    module = modules.new_module(modules.IMAGES)
    module["value"] = ["invalid-image-reference"]
    card = ModuleCard(module)
    remove_buttons = card.findChildren(ModuleRemoveButton)
    assert len(remove_buttons) == 2
    assert all(button.icon().isNull() for button in remove_buttons)
    assert {button.accessibleName() for button in remove_buttons} == {"删除模块", "删除图片"}
    card.close()


def test_module_remove_button_keeps_the_cross_visible_while_hovered_or_focused():
    """停靠/聚焦的底色要有，但叉号必须同时还在。

    回归点：旧实现在铺 danger_soft 圆角块之前先 setPen(Qt.NoPen)，之后
    pen = painter.pen() 继承了这支 NoPen——setColor/setWidthF 改不回线条样式，
    两条 drawLine 什么都不画，于是只剩一坨粉色圆角块、叉号消失；点击拿到焦点后
    色块还会一直留着。现在底色照旧，但叉号笔画在两种状态下都必须存在。
    """
    from PySide6.QtGui import QColor, QPixmap

    from ui import theme

    QApplication.instance() or QApplication([])
    button = ModuleRemoveButton("删除模块", size=36)
    # 叉号就是用 danger 这支笔画的，按精确颜色定位笔画像素（不靠明暗阈值：
    # QColor.value() 是 HSV 明度，#E5484D 会算出 220，用阈值会一个都匹配不到）。
    ink = QColor(theme.active()["danger"])

    def paint() -> object:
        pixmap = QPixmap(button.size())
        pixmap.fill()
        button.render(pixmap)
        return pixmap.toImage()

    def ink_pixels(image):
        return {
            (x, y)
            for x in range(image.width())
            for y in range(image.height())
            if image.pixelColor(x, y) == ink
        }

    resting = paint()
    cross = ink_pixels(resting)
    assert len(cross) > 4, f"静止时应画出叉号笔画，实际只有 {len(cross)} 个笔画像素"

    # 停靠：底色出现，但叉号笔画一个都不能少
    button.underMouse = lambda: True  # type: ignore[method-assign]
    hovered = paint()
    assert hovered != resting, "停靠时应出现底色提示"
    assert ink_pixels(hovered) >= cross, "停靠时叉号笔画被底色吃掉了"

    # 聚焦：同上
    button.underMouse = lambda: False  # type: ignore[method-assign]
    button.hasFocus = lambda: True  # type: ignore[method-assign]
    focused = paint()
    assert focused != resting, "聚焦时应出现底色提示"
    assert ink_pixels(focused) >= cross, "聚焦时叉号笔画被底色吃掉了"
    button.close()


def test_image_module_editor_uses_horizontal_image_strip():
    QApplication.instance() or QApplication([])
    module = modules.new_module(modules.IMAGES)
    module["value"] = ["invalid-image-reference"]
    card = ModuleCard(module)

    scrolls = card.findChildren(QScrollArea)

    assert any(scroll.horizontalScrollBarPolicy() == Qt.ScrollBarAsNeeded for scroll in scrolls)
    assert isinstance(card._image_grid, QHBoxLayout)
    card.close()
