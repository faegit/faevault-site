# “不止管理密码”内容块设计

## 目标

在主页“功能亮点”与“安全架构”之间增加一个独立内容块，说明 FAEVault 除密码条目外，还能承载图片、附件和 Markdown 内容，并以安卓端已实现的机制解释长篇 Markdown、大段代码和大量文本为何能保持顺畅浏览。

该内容块不新增产品能力，只介绍安卓端源代码中已经存在的功能和处理机制。中英文内容必须语义一致。

## 信息边界

允许介绍：

- 条目中可使用图片、附件和 Markdown 模块。
- 图片和附件使用分块表示、流式读写、分块摘要与整体摘要校验。
- 媒体读取可按块惰性解密，并通过小型 LRU 缓存减少重复解密。
- Markdown 解析在后台线程进行，避免在界面组合阶段阻塞主线程。
- Markdown 按顶层内容块渐进渲染；长代码按固定行数分块；界面使用懒加载列表承载内容。
- Markdown 渲染结果存在受容量约束的缓存。

不得介绍：

- “无限容量”“任意大小附件”或类似承诺。
- 未经源码或测试证明的性能数字。
- 将长篇 Markdown 的顺畅浏览泛化为所有超大文件均不卡顿。
- 网页中不存在于真实产品的编辑、协作或云文档能力。

## 页面位置与结构

新增区块放在主页 `#features` 之后、`#security` 之前。区块采用“编辑器工作台”式双栏结构：

- 左侧为标题、介绍和三项能力标签。
- 右侧为抽象工作台界面，展示目录、Markdown 正文、代码块、图片缩略图和附件条目。
- 工作台用于解释内容类型和处理方式，不伪装成真实产品截图，也不提供虚假的交互入口。
- 下方或左侧增加三条简洁机制说明：后台解析、渐进渲染、按需读取。

桌面端使用左右布局；手机端在 760px 及以下改为上下布局，文字居中，工作台占满可用宽度，不产生横向滚动。

## 建议文案

### 中文

- 眉题：`不止管理密码`
- 标题：`把更多重要内容，放进同一个保险库`
- 正文：`图片、附件与 Markdown 可以和密码条目一起整理。长篇文档、大段代码和大量文本在后台解析，并按内容块逐步呈现，让阅读与滚动保持从容。`
- 能力标签：`图片`、`附件`、`Markdown`
- 机制一：`后台解析` / `Markdown 解析离开界面主线程，减少打开长文档时的阻塞。`
- 机制二：`渐进渲染` / `正文与长代码分块呈现，列表按需加载当前需要显示的内容。`
- 机制三：`按需读取` / `图片和附件以分块方式读写、校验并按需解密，避免一次性展开全部数据。`

### English

- Kicker: `Beyond passwords`
- Title: `Keep more of what matters in one vault`
- Body: `Organize images, attachments, and Markdown alongside your password entries. Long documents, large code blocks, and text-heavy notes are parsed in the background and revealed progressively, keeping reading and scrolling responsive.`
- Capability labels: `Images`, `Attachments`, `Markdown`
- Mechanism one: `Background parsing` / `Markdown parsing runs away from the UI thread to reduce blocking when opening long documents.`
- Mechanism two: `Progressive rendering` / `Documents and long code blocks are rendered in chunks, while lazy lists load only the content currently needed.`
- Mechanism three: `On-demand access` / `Images and attachments are streamed, verified, and decrypted in chunks instead of expanding all data at once.`

## 视觉规则

- 延续主页蓝灰色、白色卡面和轻阴影体系，不引入新的高饱和主题色。
- 区块本身应与现有“功能亮点”卡片网格区分：使用一个完整工作台场景，而不是再做三张并列功能卡。
- 工作台内的 Markdown 内容保持短小，只展示结构，不堆放大量可读正文。
- 图片缩略图使用抽象色块或现有站内安全素材，不使用用户真实内容。
- 附件条目显示通用文件名、类型和状态，不展示容量承诺。
- 所有装饰元素设置为不可交互；文本保持可访问的语义结构。

## 行为与无障碍

- 区块不新增轮播、自动动画或复杂交互。
- 工作台可以使用轻微进入动画，但必须遵循 `prefers-reduced-motion`。
- 标题层级接续主页现有 `h2` 结构。
- 装饰图形使用 `aria-hidden="true"`；可读内容保留正常文本语义。
- 中英文切换后结构保持一致，不依赖固定文本长度定位元素。

## 验收标准

- 中文和英文主页均出现新内容块，位置位于功能亮点与安全架构之间。
- 中英文含义对应，不出现安卓端未实现的功能或无依据性能承诺。
- 320px、390px、760px、1024px 和 1440px 宽度下无截断或横向溢出。
- 手机端为上下布局，正文和工作台均完整可见。
- 桌面端为双栏布局，工作台内容清晰且不与现有产品展示重复。
- 减少动画模式下不依赖动画展示内容。
- Astro 检查、现有测试、内容校验和静态构建全部通过。

## 源码依据

- `PmvAttachmentCodec.kt`：8 MiB 分块、流式封装/读取、分块和整体 SHA-256 校验。
- `PmvMediaContentProvider.kt`：按块惰性解密、随机范围读取和四块 LRU 缓存。
- `MarkdownRenderPipeline.kt`：顶层块权重、渐进块数量、160 行代码分块和受预算约束的文档缓存。
- `MarkdownText.kt`：`Dispatchers.Default` 后台解析、解析中状态、懒加载列表渲染基础。
