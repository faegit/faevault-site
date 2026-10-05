"""Markdown → HTML 渲染（CommonMark + GFM + 安卓对齐扩展），供各 UI 复用。

提供两个入口：

- ``render_markdown_html``：渲染为 HTML 片段（旧接口，供 QTextBrowser 等富文本部件）。
- ``render_markdown_document``：渲染为完整 HTML 文档（主题 CSS + Mermaid + KaTeX），
  供 Web 视图（QWebEngineView）整文档渲染。

语法覆盖（与安卓端 commonmark-java + 官方扩展 + 受控 HTML 对齐）：

- CommonMark 基础语法：标题、粗斜体、行内代码、围栏代码、列表、引用、分割线、图片；
- GFM：表格、删除线 ``~~text~~``、任务列表 ``- [x]`` / ``- [ ]``、URL 自动链接；
- 扩展：脚注 ``[^1]``、下划线 ``++text++``；
- 仅整段构成的数学公式 ``$$...$$`` / ``$...$``（本地 KaTeX 渲染，避免误判金额）；
- ``<details><summary>`` 折叠块：summary 提取为标题，内部嵌套继续渲染 Markdown；
- mark/sub/sup/kbd 行内样式与受控 SVG 块（仅静态几何子集，无脚本/外部引用）。

安全约束（保险库内容，渲染面含脚本执行能力）：

- 不启用 ``attr_list`` 等允许注入任意 HTML 属性的扩展；
- 对 python-markdown 透传的原始 HTML 做白名单消毒（剥掉 script / iframe / 事件属性 /
  ``javascript:`` 等危险协议），防止用户 Markdown 注入可执行内容；
- ``href`` 仅允许 ``#`` 页内锚点与 ``http://``/``https://``（点击导航由宿主决定）；
  ``src`` 仅允许 ``data:image/``；
- SVG 仅放行静态元素/属性白名单，不保留 ``href``/``xlink:href``、事件属性与脚本类子元素；
- 完整文档内置 Content-Security-Policy，仅允许本地脚本、样式与字体。
"""

from __future__ import annotations

import base64
import re
import threading
from html import escape
from html.parser import HTMLParser

from markdown import Markdown
from markdown.extensions import Extension
from markdown.extensions.toc import slugify_unicode
from markdown.inlinepatterns import InlineProcessor
from markdown.treeprocessors import Treeprocessor
from markdown.util import AtomicString

_EXTENSIONS = ["fenced_code", "tables", "sane_lists", "toc", "footnotes"]

# ---------------------------------------------------------------------------
# 占位符 / 语法的受控 HTML 预处理（对齐安卓 ControlledMarkdownHtml 思路）
# ---------------------------------------------------------------------------

# 数学公式占位符（含私有区字符，避免与正文混淆）
_MATH_OPEN = "\uE040"
_MATH_CLOSE = "\uE041"
# 代码围栏整体保护占位符（防止 details/数学正则误伤 ``` 内的 <tag> / $ 文本）
_FENCE_OPEN = "\uE030"
_FENCE_CLOSE = "\uE031"

_DETAILS_RE = re.compile(r"<details\s*>(.*?)</details\s*>", re.IGNORECASE | re.DOTALL)
_SUMMARY_RE = re.compile(r"<summary\s*>(.*?)</summary\s*>", re.IGNORECASE | re.DOTALL)


def _protect_fences(source: str) -> tuple[str, tuple[str, ...]]:
    """将 ``` / ~~~ 围栏整体替换为单行占位符，原样保存到 fences。

    与安卓端 protectFences 一致：details 提取 / 数学识别只应作用于围栏外文本，
    否则 ```xml 等块内的 <tag> 会被误删、```$x$``` 会被误判为公式。
    """
    if "```" not in source and "~~~" not in source:
        return source, ()
    lines = source.split("\n")
    out: list[str] = []
    fences: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        stripped = lines[i].lstrip(" \t")
        if not (stripped.startswith("```") or stripped.startswith("~~~")):
            out.append(lines[i])
            i += 1
            continue
        marker = stripped[:3]
        block = [lines[i]]
        i += 1
        while i < n:
            cur = lines[i]
            cs = cur.lstrip(" \t")
            block.append(cur)
            i += 1
            if cs.startswith(marker) and len(cs.strip(marker[0])) == 0:
                break
        fences.append("\n".join(block))
        out.append(f"{_FENCE_OPEN}VAULTFENCE{len(fences) - 1}{_FENCE_CLOSE}")
    return "\n".join(out), tuple(fences)


def _restore_fences(source: str, fences: tuple[str, ...]) -> str:
    if not fences:
        return source
    pattern = re.compile(
        re.escape(_FENCE_OPEN) + r"VAULTFENCE(\d+)" + re.escape(_FENCE_CLOSE)
    )

    def repl(match: re.Match) -> str:
        index = int(match.group(1))
        return fences[index] if index < len(fences) else ""

    return pattern.sub(repl, source)


class _DetailsExtractor:
    """提取 ``<details>...</details>`` 折叠块为 `````vault-details`` 围栏占位符。

    - ``summary`` 单独提取为折叠标题，正文继续作为 Markdown 渲染；
    - 嵌套 details 递归提取，全部存入同一张扁平表，展开时按 key 回填；
    - 与安卓端 ControlledMarkdownHtml 行为对齐。
    """

    def __init__(self) -> None:
        self.blocks: dict[str, tuple[str, str]] = {}

    def extract(self, source: str) -> str:
        def repl(match: re.Match) -> str:
            content = match.group(1)
            summary_m = _SUMMARY_RE.search(content)
            if summary_m:
                summary = summary_m.group(1).strip()
                body = content[: summary_m.start()] + content[summary_m.end():]
            else:
                summary = ""
                body = content
            body = self.extract(body).strip("\n")
            key = f"details-{len(self.blocks)}"
            self.blocks[key] = (summary, body)
            return f"\n\n```vault-details\n{key}\n```\n\n"

        return _DETAILS_RE.sub(repl, source)


def _match_math_paragraph(joined: str) -> tuple[str | None, bool]:
    """仅整段 ``$$...$$`` 或 ``$...$`` 视为公式；返回 (tex, is_display)。

    与安卓端 FormulaParagraph 判定一致，避免把金额等普通 ``$`` 文本误判为公式。
    """
    text = joined.strip()
    if len(text) > 4 and text.startswith("$$") and text.endswith("$$"):
        return text[2:-2].strip(), True
    if len(text) > 2 and text.startswith("$") and not text.startswith("$$") and text.endswith("$"):
        return text[1:-1].strip(), False
    return None, False


def _protect_math(source: str) -> tuple[str, list[tuple[str, bool]]]:
    """保护整段构成的数学公式为单行占位符；返回 (text, [(tex, is_display)])."""
    maths: list[tuple[str, bool]] = []
    lines = source.split("\n")
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        paragraph: list[str] = []
        while i < n and lines[i] != "":
            paragraph.append(lines[i])
            i += 1
        if paragraph:
            joined = "\n".join(paragraph)
            tex, display = _match_math_paragraph(joined)
            if tex is not None:
                index = len(maths)
                maths.append((tex, display))
                out.append(f"{_MATH_OPEN}VAULTMATH{index}{_MATH_CLOSE}")
            else:
                out.extend(paragraph)
        if i < n:
            out.append("")
            i += 1
    return "\n".join(out), maths


# ---------------------------------------------------------------------------
# 自定义 Markdown 扩展（删除线 / 下划线 / 自动链接 / 任务列表）
# ---------------------------------------------------------------------------


class _StrikeProcessor(InlineProcessor):
    """GFM 删除线 ``~~text~~`` → ``<del>``（内容再交给后续行内处理器渲染）。"""

    pattern = r"~~(?P<text>.+?)~~"

    def handleMatch(self, match: re.Match, data: str):
        node = etree_element("del")
        node.text = match.group("text")
        return node, match.start(0), match.end(0)


class _InsProcessor(InlineProcessor):
    """下划线 ``++text++`` → ``<ins>``；内容内不再允许 ``++`` 以防误伤 ``C++``。"""

    pattern = r"\+\+(?P<text>(?:(?!\+\+).)+)\+\+"

    def handleMatch(self, match: re.Match, data: str):
        node = etree_element("ins")
        node.text = match.group("text")
        return node, match.start(0), match.end(0)


class _AutolinkProcessor(InlineProcessor):
    """裸 URL / 邮箱自动链接（与安卓 AutolinkExtension 对齐）。

    文本用 AtomicString 包裹，后续 emphasis 等处理器不会再把 URL 里的 ``_`` 当斜体。
    """

    pattern = r"(?:(?:https?|ftp)://)[^\s<>\"']+|(?<![\w.+-])[\w.+-]+@[\w-]+\.[\w.-]+"

    def handleMatch(self, match: re.Match, data: str):
        literal = match.group(0).rstrip(".,;:!?)}]")
        node = etree_element("a")
        node.set("href", literal)
        node.text = AtomicString(literal)
        return node, match.start(0), match.start(0) + len(literal)


class _TaskListTreeprocessor(Treeprocessor):
    """把 ``- [x] item`` / ``- [ ] item`` 列表项标记为任务项并剥离标记。

    输出 ``<li class="md-task-done">`` / ``<li class="md-task">``，勾选盒由 CSS ::before 绘制。
    """

    _marker = re.compile(r"^\s*\[([ xX])\]\s+")

    def run(self, root):
        for li in root.iter("li"):
            text = "".join(li.itertext())
            match = self._marker.match(text)
            if not match:
                continue
            done = match.group(1).lower() == "x"
            klass = "md-task-done" if done else "md-task"
            existing = (li.attrib.get("class") or "").split()
            if not existing:
                li.attrib["class"] = klass
            elif klass not in existing:
                li.attrib["class"] = " ".join(existing + [klass])
            for element in li.iter():
                if element.text and self._marker.match(element.text):
                    element.text = self._marker.sub("", element.text, count=1)
                    break


class _VaultMarkdownExtension(Extension):
    def extendMarkdown(self, md):  # noqa: N802
        # 优先级：backtick(60) 之后、emphasis(约 30~45) 之前，确保代码跨内容不受影响、
        # 且 del/ins 内部可以再被粗斜体等处理。
        md.inlinePatterns.register(_StrikeProcessor(_StrikeProcessor.pattern), "vault_strike", 55)
        md.inlinePatterns.register(_InsProcessor(_InsProcessor.pattern), "vault_ins", 54)
        md.inlinePatterns.register(_AutolinkProcessor(_AutolinkProcessor.pattern), "vault_autolink", 53)
        md.treeprocessors.register(_TaskListTreeprocessor(md), "vault_tasklist", 30)


# ---------------------------------------------------------------------------
# HTML 消毒（白名单 + 受控 SVG）
# ---------------------------------------------------------------------------

# 白名单标签：仅允许 Markdown 语义所需的安全元素
_ALLOWED_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "br", "hr",
    "ul", "ol", "li",
    "strong", "em", "b", "i", "u", "del", "s", "ins",
    "mark", "sub", "sup", "kbd",
    "blockquote", "pre", "code",
    "a", "table", "thead", "tbody", "tr", "th", "td",
    "img", "span", "div", "section", "details", "summary",
}

# SVG 静态几何白名单（无脚本、无外部引用、无事件）
_SVG_TAGS = {
    "svg", "g", "path", "circle", "rect", "line", "polyline", "polygon",
    "ellipse", "text", "tspan", "textpath", "defs", "lineargradient",
    "radialgradient", "stop", "clippath", "mask", "pattern", "symbol",
    "marker", "use", "title", "desc",
}
_SVG_ATTRS = {
    "class", "id", "viewbox", "preserveaspectratio", "width", "height",
    "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "d", "points",
    "fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin",
    "stroke-dasharray", "stroke-dashoffset", "fill-rule", "clip-rule",
    "clip-path", "opacity", "fill-opacity", "stroke-opacity", "transform",
    "offset", "stop-color", "stop-opacity", "gradientunits", "spreadmethod",
    "pathlength", "text-anchor", "dominant-baseline", "dx", "dy",
    "font-family", "font-size", "font-weight", "font-style", "font-variant",
    "letter-spacing", "word-spacing", "vector-effect", "color", "startoffset",
}

# 允许的全局属性（class 用于 Mermaid 钩子；id / lang 无执行能力）
_ALLOWED_ATTRS = {"class", "id", "lang", "title", "alt"}

# 标签 → 额外允许的属性
_TAG_ALLOWED_ATTRS = {
    "a": {"href", "title"},
    "img": {"src", "alt", "title"},
    "td": {"align", "colspan", "rowspan"},
    "th": {"align", "colspan", "rowspan"},
    "details": {"open"},
}

# href 允许的协议/写法（与安卓 markdownLinkTarget 对齐：页内锚点 + http/https）
_SAFE_HREF = re.compile(r"^(?:#[^#].*|https?://.+)$", re.IGNORECASE)

# python-markdown 表格扩展用内联 style 表达列对齐；消毒时仅识别 text-align 并转成 align 属性
_TABLE_ALIGN_RE = re.compile(r"text-align\s*:\s*(left|center|right)", re.IGNORECASE)


def _table_alignment(style: str) -> str | None:
    match = _TABLE_ALIGN_RE.search(style or "")
    return match.group(1).lower() if match else None

# 内容应整体丢弃的危险标签（其子文本也删除，不只是剥标签）
_DROP_CONTENT_TAGS = {
    "script", "style", "iframe", "object", "embed", "template", "noscript",
    "foreignobject", "math", "form", "input", "button", "textarea", "select", "option",
    "animate", "animatetransform", "animatemotion", "set",
}


def etree_element(tag: str):
    from xml.etree import ElementTree as _etree

    return _etree.Element(tag)


class _Sanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0  # 深度：>0 表示正处于被移除的标签内（子标签移除，文本视情况保留）
        self.drop_content = False  # 正处于内容型危险标签内：其子文本一并丢弃

    def _enter(self):
        self.skip += 1

    def _leave(self):
        if self.skip:
            self.skip -= 1

    def _write_starttag(self, tag, attrs):
        safe_attrs = _SVG_ATTRS if tag in _SVG_TAGS else _ALLOWED_ATTRS
        allowed = set(safe_attrs)
        allowed.update(_TAG_ALLOWED_ATTRS.get(tag, ()))
        kept = []
        disabled_link = False
        for key, value in attrs:
            key = key.lower()
            if key.startswith("on"):
                continue
            if key == "style":
                alignment = _table_alignment(value) if tag in ("td", "th") else None
                if alignment:
                    kept.append(("align", alignment))
                continue
            if key not in allowed:
                continue
            if key == "href":
                if not _safe_href(value):
                    disabled_link = tag == "a"
                    continue
            if key == "src":
                if not _safe_image_url(value):
                    continue
            kept.append((key, value))
        if disabled_link:
            kept = [(key, value) for key, value in kept if key != "class"]
            kept.extend((("class", "md-disabled-link"), ("data-disabled-link", "true")))
        if kept:
            attrs_s = "".join(f' {k}="{_escape_attr(v)}"' for k, v in kept)
        else:
            attrs_s = ""
        self.out.append(f"<{tag}{attrs_s}>")

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.skip:
            self._enter()
            return
        if tag in _DROP_CONTENT_TAGS:
            self.drop_content = True
            self._enter()
            return
        if tag not in _ALLOWED_TAGS and tag not in _SVG_TAGS:
            self._enter()
            return
        self._write_starttag(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if self.skip or tag in _DROP_CONTENT_TAGS:
            return
        if tag not in _ALLOWED_TAGS and tag not in _SVG_TAGS:
            return
        self._write_starttag(tag, attrs)
        self.out.append(f"</{tag}>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip:
            was_drop = tag in _DROP_CONTENT_TAGS
            self._leave()
            if was_drop and self.skip == 0:
                self.drop_content = False
            return
        if tag in _ALLOWED_TAGS or tag in _SVG_TAGS:
            self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.drop_content:
            self.out.append(escape(data, quote=False))

    def handle_entityref(self, name):
        if not self.drop_content:
            self.out.append(f"&{name};")

    def handle_charref(self, name):
        if not self.drop_content:
            self.out.append(f"&#{name};")

    def handle_comment(self, data):
        pass


def sanitize_html(html: str) -> str:
    """白名单消毒 HTML：剥掉脚本、iframe、事件属性与危险协议。

    - 白名单外标签整体移除（子内容保留为文本）；
    - 白名单标签仅保留允许的属性；
    - ``href`` 仅允许 ``#`` 锚点与 http/https；``javascript:``、相对路径等被剥除；
    - ``src`` 仅允许 ``data:image/`` 本地图像；
    - 所有 ``on*`` 事件属性一律移除；
    - SVG 仅保留静态几何子集（无 ``href``/脚本/动画/事件）；
    - ``script``/``style``/``iframe`` 等危险标签连同其子文本整体丢弃。
    """
    sanitizer = _Sanitizer()
    sanitizer.feed(html or "")
    sanitizer.close()
    return "".join(sanitizer.out)


def _safe_href(value: str) -> bool:
    return bool(_SAFE_HREF.match((value or "").strip()))


def _safe_image_url(url: str) -> bool:
    value = (url or "").strip().lower()
    return value.startswith("data:image/")


def _escape_attr(value: str) -> str:
    return escape(value or "", quote=True)


# ---------------------------------------------------------------------------
# 渲染管线
# ---------------------------------------------------------------------------


def _render_fragment(
    text: str,
    *,
    details: dict[str, tuple[str, str]] | None = None,
    extract_details: bool = True,
    enable_math: bool = True,
) -> tuple[str, list[tuple[str, bool]], dict[str, tuple[str, str]]]:
    """渲染为已消毒的 HTML 片段；返回 (body, maths, details)。

    - ``extract_details=True`` 时先提取 details 为围栏占位符；
      内层正文（details body）以 ``details=当前表, extract_details=False`` 复用，避免重复提取。
    - 数学只在存在完整公式段落时保护；fences 先整体保护再恢复，互不干扰。
    """
    source = text or ""
    source, fences = _protect_fences(source)
    if extract_details:
        extractor = _DetailsExtractor()
        source = extractor.extract(source)
        # details 正文是从「围栏已保护」的文本里截取的，需把围栏占位符还原回真实围栏；
        # 否则内层渲染时 ``` 代码块会退化成 sentinel 文本。
        for key, (summary, body) in extractor.blocks.items():
            extractor.blocks[key] = (summary, _restore_fences(body, fences))
        if details is None:
            details = extractor.blocks
        else:
            details = dict(extractor.blocks, **details)
    source, maths = _protect_math(source) if enable_math else (source, [])
    source = _restore_fences(source, fences)

    markdown = _markdown_instance()
    markdown._vault_slug_counts.clear()
    markdown.reset()
    body = sanitize_html(markdown.convert(source))
    body = _expand_math(body, maths)
    body = _expand_details(body, details or {})
    return body, maths, details or {}


def _expand_math(body: str, maths: list[tuple[str, bool]]) -> str:
    if not maths:
        return body
    pattern = re.compile(
        r"<p>" + re.escape(_MATH_OPEN) + r"VAULTMATH(\d+)" + re.escape(_MATH_CLOSE) + r"</p>"
    )

    def repl(match: re.Match) -> str:
        index = int(match.group(1))
        if index >= len(maths):
            return "<p></p>"
        tex, display = maths[index]
        encoded = base64.b64encode(tex.encode("utf-8")).decode("ascii")
        klass = "md-math md-math-display" if display else "md-math"
        return f'<div class="{klass}" data-tex="{encoded}"></div>'

    return pattern.sub(repl, body)


def _expand_details(body: str, blocks: dict[str, tuple[str, str]]) -> str:
    if not blocks:
        return body
    pattern = re.compile(
        r'<pre><code class="language-vault-details">\s*(details-\d+)\s*</code></pre>'
    )

    def repl(match: re.Match) -> str:
        key = match.group(1)
        item = blocks.get(key)
        if not item:
            return match.group(0)
        summary, body_md = item
        if summary:
            summary_html = _render_inline_fragment(summary)
        else:
            summary_html = "详情"
        inner = _render_fragment(body_md, details=blocks, extract_details=False)[0]
        return (
            f'<details class="md-details">'
            f"<summary>{summary_html}</summary>"
            f'<div class="md-details-body">{inner}</div>'
            f"</details>"
        )

    return pattern.sub(repl, body)


def _render_inline_fragment(text: str) -> str:
    html = _render_fragment(text, extract_details=False, enable_math=False)[0]
    if html.startswith("<p>") and html.endswith("</p>"):
        return html[3:-4]
    return html


def render_markdown_html(text: str) -> str:
    """将 Markdown 渲染为富文本 HTML 片段；库缺失或出错时返回空串以回退 Qt 内置渲染。"""
    try:
        return _render_fragment(text or "")[0]
    except Exception:
        return ""


_SVG_SIZE_GUARD_SCRIPT = (
    "function installSvgSizeGuard() {"
    "  var proto = Element.prototype;"
    "  if (proto.setAttribute.__fvSizeGuard) return;"
    # Mermaid 个别图会把负值写进 SVG 的 width/height（文本量测相减得到负宽），
    # Chromium 每次都会打印 "A negative value is not valid."。负宽高的 <rect>
    # 渲染结果本来就是 0，所以在写入前夹到 0：视觉不变，控制台不再被刷屏。
    "  function invalid(value) {"
    "    if (typeof value === 'number') return value < 0 || value !== value;"
    "    return /^-(?:\\d|\\.\\d)/.test(String(value).trim());"
    "  }"
    "  function clamp(name, value) {"
    "    var key = String(name).toLowerCase();"
    "    if (key === 'width' || key === 'height') {"
    "      if (invalid(value)) return '0';"
    "    }"
    "    return value;"
    "  }"
    "  var rawSet = proto.setAttribute;"
    "  var patched = function (name, value) {"
    "    if (this instanceof SVGElement) value = clamp(name, value);"
    "    return rawSet.call(this, name, value);"
    "  };"
    "  patched.__fvSizeGuard = true;"
    "  proto.setAttribute = patched;"
    "  var rawSetNS = proto.setAttributeNS;"
    "  proto.setAttributeNS = function (ns, name, value) {"
    "    if (this instanceof SVGElement) value = clamp(name, value);"
    "    return rawSetNS.call(this, ns, name, value);"
    "  };"
    "}"
)


def render_markdown_document(
    text: str,
    colors: dict | None = None,
    *,
    enable_mermaid: bool = True,
    enable_math: bool = True,
    mermaid_script_src: str = "mermaid.min.js",
    katex_script_src: str = "katex/katex.min.js",
    katex_css_src: str = "katex/katex.min.css",
) -> str:
    """渲染为完整 HTML 文档。

    ``colors`` 为主题色 dict（``text``/``muted``/``accent``/``border``/``surface_alt``/``bg``）。
    ``enable_mermaid`` 时，```mermaid`` 代码块会被转换成 Mermaid 渲染容器，
    页面引入 ``mermaid_script_src``（本地文件相对路径），配合 CSP 仅允许本地脚本。
    ``enable_math`` 时，整段公式由本地 KaTeX（``katex_script_src``/``katex_css_src``）渲染。
    """
    body, maths, _ = _render_fragment(text or "", enable_math=enable_math)
    if enable_mermaid:
        body = _convert_mermaid_blocks(body)

    c = colors or {}
    bg = c.get("bg", "#FFFFFF")
    surface = c.get("surface_alt", "#F0F2F7")
    border = c.get("border", "#E3E6EE")
    text_color = c.get("text", "#1F2430")
    muted = c.get("muted", "#8A90A2")
    accent = c.get("accent", "#6366F1")

    css = f"""
    @keyframes document-enter {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
    body {{ animation: document-enter 140ms ease-out; }}
    @media (prefers-reduced-motion: reduce) {{ body {{ animation: none; }} }}
    body {{ color: {text_color}; font-family: 'Microsoft YaHei UI', system-ui, sans-serif;
          font-size: 10pt; line-height: 1.6; margin: 12px 16px; background: {bg}; }}
    h1 {{ color: {text_color}; font-size: 17pt; font-weight: 700; margin: 4px 0 10px 0; }}
    h2 {{ color: {text_color}; font-size: 13pt; font-weight: 700; margin: 18px 0 6px 0; }}
    h3 {{ color: {accent}; font-size: 11pt; font-weight: 700; margin: 14px 0 4px 0; }}
    p {{ margin: 4px 0 8px 0; }}
    ul, ol {{ margin: 4px 0 10px 20px; }}
    li {{ margin: 3px 0; }}
    blockquote {{ color: {muted}; background-color: {surface};
        border-left: 4px solid {accent}; margin: 4px 0 12px 0; padding: 8px 12px; }}
    strong {{ color: {text_color}; font-weight: 700; }}
    a {{ color: {accent}; }}
    del, s {{ text-decoration: line-through; }}
    ins {{ text-decoration: underline; }}
    mark {{ background-color: {_hex_rgba(accent, 0.18)}; color: inherit; border-radius: 3px; padding: 0 3px; }}
    sub {{ font-size: 0.72em; vertical-align: sub; }}
    sup {{ font-size: 0.72em; vertical-align: super; }}
    kbd {{ font-family: Consolas, 'Courier New', monospace; font-size: 0.88em;
        border: 1px solid {border}; border-radius: 4px; padding: 1px 5px; background-color: {surface}; }}
    li.md-task, li.md-task-done {{ list-style: none; }}
    li.md-task::before, li.md-task-done::before {{ content: '\\2610'; display: inline-block;
        width: 17px; font-weight: 700; color: {muted}; }}
    li.md-task-done::before {{ content: '\\2611'; color: {accent}; }}
    li.md-task-done > * {{ color: {muted}; }}
    .footnote {{ font-size: 9pt; color: {muted}; margin-top: 18px; }}
    .footnote hr {{ display: none; }}
    .footnote .footnote-backref {{ color: {accent}; }}
    .md-details {{ border: 1px solid {border}; border-radius: 12px; margin: 12px 0;
        background-color: {surface}; overflow: hidden; }}
    .md-details > summary {{ cursor: pointer; padding: 9px 12px; font-weight: 700;
        color: {accent}; list-style: none; user-select: none; }}
    .md-details > summary::-webkit-details-marker {{ display: none; }}
    .md-details > summary::before {{ content: '\\25B8'; }}
    .md-details[open] > summary::before {{ content: '\\25BE'; }}
    .md-details-body {{ padding: 2px 12px 12px; }}
    .md-math {{ margin: 10px 0; overflow-x: auto; overflow-y: hidden; }}
    .md-math-display {{ text-align: left; }}
    .md-math .katex-display {{ margin: 0.2em 0; }}
    code {{ font-family: Consolas, 'Courier New', monospace; color: {accent};
        background-color: {surface}; padding: 1px 4px; border-radius: 4px; }}
    pre {{ background-color: {surface}; padding: 10px 12px; border-radius: 8px;
        overflow-x: auto; }}
    pre code {{ color: {text_color}; background-color: transparent; padding: 0; }}
    table {{ border-collapse: collapse; margin: 6px 0 12px 0; }}
    th, td {{ border: 1px solid {border}; padding: 5px 10px; }}
    th {{ background-color: {surface}; font-weight: 700; }}
    th[align="left"], td[align="left"] {{ text-align: left; }}
    th[align="center"], td[align="center"] {{ text-align: center; }}
    th[align="right"], td[align="right"] {{ text-align: right; }}
    hr {{ border: 0; border-top: 1px solid {border}; margin: 12px 0; }}
    img, svg {{ max-width: 100%; }}
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ max-width: 1080px; margin: 0 auto; padding: 18px 22px 30px; }}
    /* Match Android's block-level LazyColumn: keep the full document for search,
       anchors and copy, but defer layout/paint of off-screen top-level blocks. */
    body > :is(h1, h2, h3, h4, h5, h6, p, ul, ol, blockquote, pre, table, div, details, hr, svg) {{
        content-visibility: auto;
        contain-intrinsic-size: auto 120px;
    }}
    h1, h2 {{ padding-bottom: 8px; border-bottom: 1px solid {border}; }}
    .md-disabled-link {{ color: {muted}; text-decoration: underline dotted; cursor: not-allowed; }}
    .md-table-wrap {{ overflow-x: auto; margin: 18px 0; border: 1px solid {border}; border-radius: 12px; }}
    .md-table-wrap table {{ width: 100%; min-width: 460px; margin: 0; border-collapse: separate; border-spacing: 0; }}
    .md-table-wrap th, .md-table-wrap td {{ padding: 10px 13px; border-top: 0; border-left: 0; }}
    .md-table-wrap th:last-child, .md-table-wrap td:last-child {{ border-right: 0; }}
    .md-table-wrap tr:last-child td {{ border-bottom: 0; }}
    .md-code-card {{ margin: 18px 0; overflow: hidden; border: 1px solid {border}; border-radius: 12px; background: {surface}; }}
    .md-code-toolbar {{ min-height: 38px; display: flex; align-items: center; justify-content: space-between; padding: 0 10px 0 13px; border-bottom: 1px solid {border}; color: {muted}; font-size: 9pt; }}
    .md-code-card pre {{ margin: 0; border-radius: 0; background: transparent; }}
    .md-code-copy, .mermaid-toolbar button {{ color: {muted}; background: transparent; border: 1px solid {border}; border-radius: 7px; padding: 4px 9px; cursor: pointer; }}
    .mermaid-card {{ position: relative; margin: 18px 0; overflow: hidden; border: 1px solid {border}; border-radius: 12px; background: {bg}; }}
    .mermaid-toolbar {{ display: flex; justify-content: flex-end; gap: 7px; padding: 6px 9px; border-bottom: 1px solid {border}; background: {surface}; }}
    .mermaid-viewport {{ min-height: 260px; overflow: hidden; padding: 10px; }}
    .mermaid-error {{ margin: 18px 0; padding: 14px; border: 1px solid {border}; border-left: 4px solid #B3261E; border-radius: 10px; background: {surface}; }}
    .mermaid {{ background: transparent; margin: 12px 0; text-align: center; overflow: visible; }}
    """

    mermaid_script = ""
    mermaid_init = ""
    if enable_mermaid and '<pre class="mermaid">' in body:
        mermaid_script = f'<script src="{mermaid_script_src}"></script>'
        mermaid_init = (
            "<script>"
            + _SVG_SIZE_GUARD_SCRIPT
            + "window.addEventListener('DOMContentLoaded', function () {"
            "  installSvgSizeGuard();"
            "  if (window.mermaid) {"
            "    try {"
            "      mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' });"
            "      var queue = [], running = false;"
            "      async function drain() {"
            "        if (running || !queue.length) return;"
            "        running = true; var el = queue.shift();"
            "        try {"
            "          if (!el.isConnected) return;"
            "          await mermaid.run({nodes: [el], suppressErrors: true});"
            "          if (el.querySelector('svg')) initMermaidPanZoom(el);"
            "          el.dataset.renderFinished = '1';"
            "          document.dispatchEvent(new CustomEvent('vault-mermaid-rendered', {detail: el}));"
            "        } catch (e) { el.dataset.renderFinished = '1'; }"
            "        finally { running = false; setTimeout(drain, 16); }"
            "      }"
            "      var observer = new IntersectionObserver(function(entries) {"
            "        entries.forEach(function(entry) {"
            "          if (!entry.isIntersecting) return;"
            "          observer.unobserve(entry.target); queue.push(entry.target);"
            "        });"
            "        setTimeout(drain, 0);"
            "      }, {rootMargin: '300px'});"
            "      document.querySelectorAll('pre.mermaid').forEach(function(el) {observer.observe(el);});"
            "    } catch (e) { console.warn('mermaid init failed', e); }"
            "  }"
            "});"
            "function initMermaidPanZoom(el) {"
            "  if (el.dataset.pz) return;"
            "  el.dataset.pz = '1';"
            "  var svg = el.querySelector('svg');"
            "  if (!svg) return;"
            "  el.style.touchAction = 'none';"
            "  el.style.cursor = 'grab';"
            "  svg.style.transformOrigin = '0 0';"
            "  var scale = 1, tx = 0, ty = 0;"
            "  var active = new Map();"
            "  var prev1 = null, prevPinch = null;"
            "  function apply() {"
            "    svg.style.transform = 'translate(' + tx + 'px,' + ty + 'px) scale(' + scale + ')';"
            "  }"
            "  function pinch() {"
            "    var a = Array.from(active.values());"
            "    if (a.length < 2) return null;"
            "    return { dist: Math.hypot(a[0].x - a[1].x, a[0].y - a[1].y),"
            "             mid: { x: (a[0].x + a[1].x) / 2, y: (a[0].y + a[1].y) / 2 } };"
            "  }"
            "  el.addEventListener('pointerdown', function (e) {"
            "    el.setPointerCapture(e.pointerId);"
            "    active.set(e.pointerId, { x: e.clientX, y: e.clientY });"
            "    if (active.size === 1) prev1 = { x: e.clientX, y: e.clientY };"
            "    prevPinch = null;"
            "  });"
            "  el.addEventListener('pointermove', function (e) {"
            "    if (!active.has(e.pointerId)) return;"
            "    active.set(e.pointerId, { x: e.clientX, y: e.clientY });"
            "    if (active.size === 1) {"
            "      if (prev1) {"
            "        tx += e.clientX - prev1.x;"
            "        ty += e.clientY - prev1.y;"
            "        apply();"
            "      }"
            "      prev1 = { x: e.clientX, y: e.clientY };"
            "    } else if (active.size >= 2) {"
            "      var cur = pinch();"
            "      if (cur && prevPinch) {"
            "        var k = cur.dist / (prevPinch.dist || 1);"
            "        var ns = Math.min(5, Math.max(0.5, scale * k));"
            "        var kk = ns / scale;"
            "        tx = cur.mid.x - (cur.mid.x - tx) * kk + (cur.mid.x - prevPinch.mid.x);"
            "        ty = cur.mid.y - (cur.mid.y - ty) * kk + (cur.mid.y - prevPinch.mid.y);"
            "        scale = ns;"
            "        apply();"
            "      }"
            "      prevPinch = cur;"
            "    }"
            "  });"
            "  function end(e) { active.delete(e.pointerId); prev1 = null; prevPinch = null; }"
            "  el.addEventListener('pointerup', end);"
            "  el.addEventListener('pointercancel', end);"
            "  el.addEventListener('dblclick', function () { scale = 1; tx = 0; ty = 0; apply(); });"
            "  el.addEventListener('wheel', function (e) {"
            "    e.preventDefault();"
            "    var rect = el.getBoundingClientRect();"
            "    var mx = e.clientX - rect.left, my = e.clientY - rect.top;"
            "    var ns = Math.min(5, Math.max(0.5, scale * Math.exp(-e.deltaY * 0.0015)));"
            "    var k = ns / scale;"
            "    tx = mx - (mx - tx) * k;"
            "    ty = my - (my - ty) * k;"
            "    scale = ns;"
            "    apply();"
            "  }, { passive: false });"
            "}"
            "</script>"
        )

    katex_css = ""
    katex_script = ""
    if enable_math and maths:
        katex_css = f'<link rel="stylesheet" href="{katex_css_src}">'
        katex_script = f'<script src="{katex_script_src}"></script>'

    enhancement_script = _document_enhancement_script()
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'self' 'unsafe-inline' file:; script-src 'self' 'unsafe-inline' file:; img-src 'self' data: file:; font-src 'self' data: file:;">
<style>{css}</style>
{katex_css}
</head>
<body>
{body}
{katex_script}
{mermaid_script}
{mermaid_init}
<script>{enhancement_script}</script>
</body>
</html>"""


def _hex_rgba(hex_color: str, alpha: float = 0.18) -> str:
    """把 #RRGGBB 主题色转成 rgba(...)；非法输入回退为透明。"""
    value = (hex_color or "").lstrip("#")
    if len(value) == 3:
        value = "".join(ch * 2 for ch in value)
    if len(value) != 6:
        return "rgba(0,0,0,0)"
    try:
        r, g, b = (int(value[i:i + 2], 16) for i in (0, 2, 4))
    except ValueError:
        return "rgba(0,0,0,0)"
    return f"rgba({r},{g},{b},{alpha:g})"


def _convert_mermaid_blocks(html: str) -> str:
    """把 ```mermaid fenced code 渲染成的 ``<pre><code class="language-mermaid">`` 块
    转换为 ``<pre class="mermaid">`` 容器，供 Mermaid 运行时拾取。"""
    pattern = re.compile(
        r'<pre><code class="language-mermaid">(.*?)</code></pre>',
        re.DOTALL,
    )

    def repl(match: re.Match) -> str:
        content = match.group(1)
        # code 内容已被 markdown 转义，这里再原样放回 pre 内（Mermaid 读取其文本）
        return f'<pre class="mermaid">{content}</pre>'

    return pattern.sub(repl, html)


_markdown_local = threading.local()


def _markdown_instance() -> Markdown:
    instance = getattr(_markdown_local, "instance", None)
    if instance is None:
        slug_counts: dict[str, int] = {}

        def numbered_slug(value: str, separator: str) -> str:
            slug = slugify_unicode(value, separator)
            count = slug_counts.get(slug, 0)
            slug_counts[slug] = count + 1
            return f"{slug}_{count}" if count else slug

        instance = Markdown(
            extensions=[*_EXTENSIONS, _VaultMarkdownExtension()],
            extension_configs={"toc": {"slugify": numbered_slug}},
        )
        instance._vault_slug_counts = slug_counts
        _markdown_local.instance = instance
    return instance


def _document_enhancement_script() -> str:
    """Return local-only DOM enhancements shared by every QtWebEngine document."""
    return r"""
(function () {
  'use strict';
  function wrapTables() {
    document.querySelectorAll('table').forEach(function (table) {
      if (table.parentElement && table.parentElement.classList.contains('md-table-wrap')) return;
      var wrap = document.createElement('div');
      wrap.className = 'md-table-wrap';
      table.parentNode.insertBefore(wrap, table);
      wrap.appendChild(table);
    });
  }
  function wrapCode() {
    document.querySelectorAll('pre').forEach(function (pre) {
      if (pre.classList.contains('mermaid')) return;
      if (pre.parentElement && pre.parentElement.classList.contains('md-code-card')) return;
      var code = pre.querySelector('code');
      var language = '代码';
      if (code) Array.from(code.classList).some(function (name) {
        if (name.indexOf('language-') !== 0) return false;
        language = name.slice(9) || language;
        return true;
      });
      var card = document.createElement('div');
      card.className = 'md-code-card';
      var toolbar = document.createElement('div');
      toolbar.className = 'md-code-toolbar';
      var label = document.createElement('span');
      label.textContent = language;
      var copy = document.createElement('button');
      copy.className = 'md-code-copy';
      copy.textContent = '复制';
      copy.addEventListener('click', function () {
        var value = code ? code.textContent : pre.textContent;
        if (navigator.clipboard) navigator.clipboard.writeText(value || '').catch(function () {});
        copy.textContent = '已复制';
        setTimeout(function () { copy.textContent = '复制'; }, 1200);
      });
      toolbar.appendChild(label);
      toolbar.appendChild(copy);
      pre.parentNode.insertBefore(card, pre);
      card.appendChild(toolbar);
      card.appendChild(pre);
    });
  }
  function initLinks() {
    document.addEventListener('click', function (event) {
      var link = event.target.closest ? event.target.closest('a') : null;
      if (!link) return;
      var href = link.getAttribute('href') || '';
      if (href.charAt(0) === '#' && href.length > 1) {
        event.preventDefault();
        var target = document.getElementById(decodeURIComponent(href.slice(1)));
        if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        return;
      }
      // 外部 http/https 交给宿主（QWebEnginePage）在系统浏览器打开；其余禁用链接阻止默认行为
      if (/^https?:/i.test(href)) return;
      event.preventDefault();
    });
  }
  function renderMath() {
    document.querySelectorAll('.md-math').forEach(function (el) {
      if (el.dataset.rendered) return;
      el.dataset.rendered = '1';
      var tex = '';
      try { tex = atob(el.dataset.tex || ''); } catch (e) { tex = ''; }
      if (!tex) return;
      if (window.katex) {
        try {
          katex.render(tex, el, {
            throwOnError: false,
            trust: false,
            displayMode: el.classList.contains('md-math-display'),
            output: 'htmlAndMathml'
          });
          return;
        } catch (e) { /* fall through to plain text */ }
      }
      el.textContent = tex;
    });
  }
  function upgradeMermaid(root) {
    (root ? [root] : document.querySelectorAll('pre.mermaid')).forEach(function (pre) {
      if (!pre.querySelector('svg')) return;
      if (pre.parentElement && pre.parentElement.classList.contains('mermaid-viewport')) return;
      var card = document.createElement('div');
      card.className = 'mermaid-card';
      var toolbar = document.createElement('div');
      toolbar.className = 'mermaid-toolbar';
      [['适应', function () { pre.dispatchEvent(new MouseEvent('dblclick')); }],
       ['重置', function () { pre.dispatchEvent(new MouseEvent('dblclick')); }]].forEach(function (item) {
        var button = document.createElement('button');
        button.textContent = item[0];
        button.addEventListener('click', item[1]);
        toolbar.appendChild(button);
      });
      var viewport = document.createElement('div');
      viewport.className = 'mermaid-viewport';
      pre.parentNode.insertBefore(card, pre);
      card.appendChild(toolbar);
      card.appendChild(viewport);
      viewport.appendChild(pre);
    });
  }
  function showMermaidErrors(root) {
    (root ? [root] : document.querySelectorAll('pre.mermaid')).forEach(function (pre) {
      if (!pre.dataset.renderFinished) return;
      if (pre.querySelector('svg')) return;
      var box = document.createElement('div');
      box.className = 'mermaid-error';
      var title = document.createElement('strong');
      title.textContent = 'Mermaid 图表无法渲染';
      var source = document.createElement('pre');
      source.textContent = pre.textContent || '';
      box.appendChild(title);
      box.appendChild(source);
      pre.replaceWith(box);
    });
  }
  function start() {
    wrapTables();
    wrapCode();
    initLinks();
    renderMath();
    document.addEventListener('vault-mermaid-rendered', function(event) {
      upgradeMermaid(event.detail);
      showMermaidErrors(event.detail);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
"""
