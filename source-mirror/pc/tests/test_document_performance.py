"""Full document delivery and cheap detail transitions on the native Qt surface."""
from time import monotonic

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QWidget

from core.markdown_html import render_markdown_document
from ui.widgets import ContentTransition, MarkdownViewer


def test_large_markdown_and_image_keep_gui_event_loop_responsive(tmp_path, monkeypatch):
    from PIL import Image
    import shutil
    from PySide6.QtCore import QTimer
    from core import media_files
    from ui.image_preview import load_image_thumbnail
    from ui import render_jobs

    app = QApplication.instance() or QApplication([])
    source = tmp_path / "large.jpg"
    with Image.new("RGB", (8000, 6000), (60, 120, 180)) as image:
        image.save(source)
    monkeypatch.setattr(media_files, "export_value", lambda _value, dest: shutil.copyfile(source, dest))
    text = "\n\n".join(f"Paragraph {i} " + "**formatted content** " * 10 for i in range(1600))
    text += "\n\n```mermaid\ngraph TD\nA-->B\n```"
    ticks = []
    heartbeat = QTimer()
    heartbeat.setInterval(10)
    heartbeat.timeout.connect(lambda: ticks.append(monotonic()))
    heartbeat.start()
    started = monotonic()
    future = render_jobs.thumbnail_executor.submit(load_image_thumbnail, "large-image")
    document = render_jobs.markdown_executor.submit(MarkdownViewer._prepare_document, text, {})
    view = QWidget()
    view.resize(700, 400)
    view.show()
    deadline = started + 40
    try:
        while monotonic() < deadline:
            QTest.qWait(50)
            if document.done() and future.done():
                break
        assert document.done()
        assert len(document.result()) > 1
        assert not future.result(timeout=1).isNull()
        delays = [b - a for a, b in zip(ticks, ticks[1:])]
        assert len(delays) > 5
        assert max(delays) < 1.0
        print(f"Combined load: {monotonic()-started:.2f}s; longest GUI timer gap: {max(delays)*1000:.0f}ms")
    finally:
        heartbeat.stop()
        view.close()
        view.deleteLater()
        QTest.qWait(100)


def test_plain_document_skips_diagram_runtime():
    html = render_markdown_document("# 标题\n\n正文")
    assert 'src="mermaid.min.js"' not in html
    diagram = render_markdown_document("```mermaid\ngraph TD\nA-->B\n```")
    assert 'src="mermaid.min.js"' in diagram


def test_document_uses_block_level_viewport_rendering():
    html = render_markdown_document("\n\n".join(f"Paragraph {i}" for i in range(1000)))
    assert "content-visibility: auto" in html
    assert "contain-intrinsic-size: auto 120px" in html
    assert html.count("<p>") == 1000


def test_browser_skips_distant_markdown_blocks():
    app = QApplication.instance() or QApplication([])
    view = MarkdownViewer("\n\n".join(f"Paragraph {i}" for i in range(1000)))
    view.resize(700, 400)
    view.show()
    result = []
    deadline = monotonic() + 20
    script = """(() => {
      const distant = document.querySelectorAll('body > p')[900];
      if (!distant) return '';
      return getComputedStyle(distant).contentVisibility + '|' +
             (distant.getBoundingClientRect().top > innerHeight) + '|' +
             distant.textContent;
    })()"""
    while monotonic() < deadline:
        QTest.qWait(100)
        view.page().runJavaScript(script, result.append)
        if any(str(item).startswith('auto|') for item in result):
            break
    try:
        assert 'auto|true|Paragraph 900' in result
    finally:
        view.close()
        view.deleteLater()
        QTest.qWait(100)


def test_full_unicode_document_survives_browser_delivery(monkeypatch):
    app = QApplication.instance() or QApplication([])
    # Deliberately exceed the data URL limit, including its percent encoding.
    text = "完整内容" * 190000 + "结束标记"
    monkeypatch.setattr(MarkdownViewer, "_render_document", staticmethod(
        lambda text, colors: '<html><body><p>' + text + '</p></body></html>'
    ))
    view = MarkdownViewer(text)
    view.resize(700, 400)
    view.show()
    result = []
    deadline = monotonic() + 20
    while monotonic() < deadline:
        QTest.qWait(100)
        view.page().runJavaScript("document.body.innerText.endsWith('结束标记')", result.append)
        if True in result:
            break
    try:
        assert True in result
    finally:
        view.close()
        view.deleteLater()
        QTest.qWait(100)


def test_transition_restarts_and_tracks_viewport():
    app = QApplication.instance() or QApplication([])
    host = QWidget()
    host.resize(500, 300)
    veil = ContentTransition(host)
    host.show()
    for _ in range(8):
        veil.begin()
        QTest.qWait(10)
    host.resize(600, 320)
    QTest.qWait(30)
    assert veil.geometry() == host.rect()
    QTest.qWait(200)
    assert not veil.isVisible()
    assert host.graphicsEffect() is None
    host.close()
    host.deleteLater()


def test_document_bootstrap_keeps_local_diagram_resources():
    app = QApplication.instance() or QApplication([])
    view = MarkdownViewer("```mermaid\ngraph TD\nA-->B\n```")
    view.show()
    result = []
    deadline = monotonic() + 20
    while monotonic() < deadline:
        QTest.qWait(100)

        view.page().runJavaScript("!!document.querySelector('pre.mermaid svg')", result.append)
        if True in result:
            break
    try:
        assert True in result
    finally:
        view.close()
        view.deleteLater()
        QTest.qWait(100)


def test_mermaid_is_rendered_only_near_viewport():
    app = QApplication.instance() or QApplication([])
    diagram = "```mermaid\ngraph TD\nA-->B\n```"
    view = MarkdownViewer(diagram + "\n\n" + "\n\n".join(f"Paragraph {i}" for i in range(200)) + "\n\n" + diagram)
    view.resize(700, 400)
    view.show()
    state = []
    deadline = monotonic() + 25
    try:
        while monotonic() < deadline:
            QTest.qWait(100)
            view.page().runJavaScript("Array.from(document.querySelectorAll('pre.mermaid')).map(p => !!p.querySelector('svg')).join(',')", state.append)
            if "true,false" in state:
                break
        assert "true,false" in state
        view.page().runJavaScript("document.querySelectorAll('pre.mermaid')[1].scrollIntoView()")
        state.clear()
        deadline = monotonic() + 20
        while monotonic() < deadline:
            QTest.qWait(100)
            view.page().runJavaScript("!!document.querySelectorAll('pre.mermaid')[1].querySelector('svg')", state.append)
            if True in state:
                break
        assert True in state
    finally:
        view.close()
        view.deleteLater()
        QTest.qWait(100)
