# 从 PKI 标准到合规检查代码：规范规则提取、可 lint 性判定与反向传播式代码生成的端到端框架

<!--
合并稿骨架 — 由 Paper2_PKI_Lint_Code_Generation.md（后半段：受限DSL+BIIV）
吸收前作 "LLM-Assisted Normative Rule Extraction and Lintability"（DLEP/CICAS，前半段：提取→IR→lintability）合成。
硬约束：(1) 删除一切人工标注相关内容，由 BIIV 无真值验证取代；(2) 突出学术价值、不写工程实现细节。
统一主线：标准文档 →[KG+确定性GraphRAG]→ 候选规则 →[Layer2 LLM→IR]→ IR →[五条件]→ lintability(𝓡_L)
        →[φ_G 受限DSL]→ DSL树 →[ρ]→ Go代码  ⟲ BIIV(G1/G2/G3)
占位标记：<!--FILL:xxx--> 待填正文；⟦数字待核⟧ 标注需后续核对的数字口径。
-->

## 摘要

公钥基础设施（PKI）以自然语言形式在 RFC 5280、CA/Browser Forum 基线要求（CABF BR）、ETSI EN 319 与 Mozilla 根存储策略等多份标准中规定了证书编码必须满足的大量规范性约束。随着 CA/Browser Forum 自 2025 年起强制要求所有公信 CA 在签发前执行证书 lint 检查，将规范文本系统性地转化为可执行合规逻辑已成为 PKI 治理的关键环节；然而现有静态 lint 工具（zlint、pkilint 等）高度依赖专家手工实现与维护，规范文本与 lint 覆盖之间的关系长期缺乏系统刻画。本研究提出一个**从标准文本到合规检查代码的端到端框架**，统一覆盖"规则提取 → 中间表示（IR）→ 可 lint 性判定 → 代码生成"完整链路。**前半链路**以确定性方式应对 Web PKI 规范中复杂的跨文档引用：构建 PKI 知识图谱并以受限子图遍历（确定性 GraphRAG）组装可溯源上下文，再经双层提取流水线——确定性关键词召回（Layer 1）与受 schema 约束的 LLM 语义解析（Layer 2）——将候选规则转写为结构化 IR（核心四元组 ⟨主体, 义务, 谓词, 约束⟩）；在 IR 之上将可 lint 性形式化为**五条件框架**，使该判定成为对五个离散 IR 字段的确定性布尔函数，从而可追溯、可复现。**后半链路**针对开放式代码生成的幻觉与不可验证问题，**在语言设计层面限制代码空间**：将生成算子 $\phi_G$ 的值域形式化为由有限原子集 $\mathcal{A}$（$|\mathcal{A}|=56$）与类型化词汇表 $\mathcal{V}$ 张成的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，通过词汇封闭性（命题 1）在架构层关闭"编造字段/OID"的幻觉路径，并将 $\phi_G$ 实现为**受限 LLM 树合成**（值域闭合于 $\mathcal{T}_{\mathcal{V}}$，以 IR-字段溯源守卫抑制字段漂移）；针对"生成代码是否忠实于规范"这一判定，进一步引入**证书级语义 oracle**——以逐原子忠实性认证（受控证书 fixture）加结构组合，对仅由已认证原子构成的生成 lint 确定性地*证明* $\mathrm{Code}\equiv\mathrm{IR}$，从而把同义性判据由不可复现的单票 LLM 判别器替换为可复现的执行级证明，并以基于代码摘要的语义等价传递链 $\mathrm{Spec}\equiv\mathrm{IR}\equiv\mathrm{Summary}\equiv\mathrm{Description}$ 与确定性机械翻译算子 $\sigma_{\mathrm{mech}}$ 处理其余子集，将跨模态判定归约为自然语言同义性判定。针对合规代码生成普遍缺乏独立人工真值的根本困难，本研究构建**反向传播式迭代验证框架（Backpropagation-Inspired Iterative Verification, BIIV）**：将"召回完整性"（G1）、"代码-规范同义性"（G2）与"双 oracle 一致性"（G3）形式化为三个可计算残差，给出阶段归因规则与单调修复算子谱，**在无人工标注真值的条件下**提供可收敛、可追溯的质量控制。实证方面，在 39 个 Web PKI 规范源上抽取出 6142 条规范规则，发现仅 18.2% 可还原为静态 lint 检查、现有工具的并集亦仅覆盖其中 48.0%，从两个方向共同揭示了规范与 lint 实践之间的**结构性缺口**（⟦数字待核：全语料口径与下述生成子集口径不同⟧）；在可执行规则子集上，端到端生成取得 100% 的结构解析成功率与 0.886 的综合对齐得分，其中将 $\sigma_{\mathrm{LLM}}$ 替换为 $\sigma_{\mathrm{mech}}$ 这一单步干预贡献了显著的端到端增量（+10.2 个百分点，64.8% → 75.0%）；在此基础上，证书级语义 oracle 进一步把"同义"由单票判别器升级为对生成 lint 的**确定性 $\mathrm{Code}\equiv\mathrm{IR}$ 证明**——该证明纯确定性、不依赖生成或判定所用的 LLM，并以"同义可证子集 + 不可归约边界披露"取代单一同义率阈值；G3 双 oracle 残差亦由 48 单调降至 0。本研究在方法学层面支持"**反向传播式验证链路上的每个算子都应尽可能确定化**"这一一般性设计原则，并以"reducible 子集闭合 + 不可归约边界披露"双指标取代单一收敛阈值，为基于受限词汇的规范-到-代码生成提供可复现的诚实边界声明范式。

**关键词**：公钥基础设施；证书合规检查；规范规则提取；中间表示；可 lint 性分析；受限代码生成；反向传播式验证

## 1. 引言

### 1.1 研究背景与动机

公钥基础设施（Public Key Infrastructure, PKI）是现代互联网信任的基础：证书颁发机构（CA）签发的 X.509 数字证书支撑着身份认证与加密通信。证书是否被正确签发因而直接关系到 Web PKI 的完整性——违反技术性规范要求的证书会削弱浏览器信任、损害安全通信的可靠性。这类失效并非纯理论风险：2024 年 Chrome 与 Mozilla 在一系列未解决的合规事故后相继宣布不再信任 Entrust 作为公信 CA [13], [12]；更早的 2020 年，Let's Encrypt 因一处 CAA 校验缺陷撤销了约三百万张证书 [14]。

这些事故已转化为生态层面的政策变化。CA/Browser Forum 通过 Ballot SC075 要求自 2025 年 3 月 15 日起所有公信 CA 在签发前执行证书 lint 检查 [15]；随后 Ballot SC-081v3 渐进式地将 TLS 证书有效期压缩至 47 天 [16]，显著提高了签发频率与对自动化合规验证的运维需求。当前的证书合规分析主要依赖 zlint [7]、pkilint [8]、certlint [9] 与 x509lint [10] 等静态 lint 工具，它们被广泛集成进证书透明度（CT）监控与 CA 签发流水线。然而，这些工具高度依赖**人工规则工程**：每条检查都需由 PKI 专家随规范修订而单独实现并持续维护。X.509 的编码规范又分散在 RFC 5280 [1]、CABF 基线要求 [2]、ETSI EN 319 412 系列 [3] 与 Mozilla 根存储策略 [4] 等多份文档中，普遍以 RFC 2119 [5] 定义的规范性关键词（MUST、SHALL、SHOULD 等）表达义务级别。随着签发量与规范复杂度持续增长，手工方式愈发难以规模化。

更根本的是，PKI 生态缺乏一个将规范文本系统性转化为可经静态 lint 检查强制执行的合规逻辑的框架。这一缺口随着 lint 在 PKI 治理中日益核心而愈发关键：规范本身并未区分"可由静态检查强制"与"需要证书之外的运行时或外部证据"两类规则。本研究的目标，即是给出一个从 Web PKI 规范源**提取规范规则、判定其可 lint 性、并自动生成对应可执行检查代码**的端到端框架。

### 1.2 研究问题与挑战

将规范文本端到端地转换为可执行、可验证的合规代码，至少面临五方面挑战。

**(挑战一) 跨文档引用与间接约束。** Web PKI 规范源之间存在大量交叉引用与继承关系。例如 CABF BR 第 7 章直接继承 RFC 5280 的字段定义，而 BR §7.1.2.7.12 又在 RFC 5280 §4.2.1.6 之上进一步收紧，要求每张订户证书都包含 subjectAltName 扩展。孤立地分析单一文档不足以还原规则的真实语义。

**(挑战二) LLM 的不可控性与幻觉。** 大语言模型为语义理解提供了有力基础，但其非确定性与幻觉风险与合规分析所要求的可复现性相冲突。提取过程必须保持可审计、可控制，而非依赖端到端黑箱推理。

**(挑战三) 可 lint 性判定本身非平凡。** 规则中出现 RFC 2119 关键词（如 MUST、SHALL）并不意味着它可被翻译为确定性的静态检查；许多带强义务的条款约束的是 CA 行为、链处理或运行时状态，而非证书编码本身。可 lint 性需要被显式刻画。

**(挑战四) 规范与代码之间的语义鸿沟。** 规范以抽象自然语言表达约束，而可执行代码必须落实为具体的字段访问路径、比较操作与控制流逻辑；二者之间的语义鸿沟是开放式代码生成产生漏检与误报的根源。

**(挑战五) 缺乏独立真值。** 大规模合规代码生成场景中并不存在现成的、可信的人工真值来逐条判定"生成代码是否忠实于规范"。验证机制必须能够在**无独立 ground truth** 的条件下提供可计算、可收敛、可追溯的质量信号。

### 1.3 核心思想

针对上述挑战，本研究的方法学由三条相互支撑的设计原则组成，贯穿提取、生成与验证三个阶段。

**第一，提取侧——确定性检索 + LLM 受限角色。** 跨文档上下文的组装不交给 LLM 推断，而由知识图谱上的确定性子图遍历给出可溯源上下文；LLM 的职责被严格限定为"将候选规则解析为受 schema 约束的结构化 IR"，所有规范性判断（可执行性、覆盖、冲突）都推迟到后续确定性阶段。这使提取过程可审计、可复现。

**第二，生成侧——代码空间应在语言层面而非 prompt 层面受限。** 将生成算子 $\phi_G$ 的值域定义为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，使"LLM 编造不存在的字段或 OID"这一类幻觉在架构层即被关闭（命题 1），而非依赖 prompt 约束或 few-shot 引导这类概率性手段。

**第三，验证侧——反向传播链路上的每个算子都应尽可能确定化。** 在语义等价传递链

$$
\mathrm{Spec} \;\to\; \mathrm{IR} \;\to\; t \in \mathcal{T}_{\mathcal{V}} \;\xrightarrow{\sigma}\; \mathrm{Summary} \;\equiv\; \mathrm{Description}
$$

中，关键词召回 $\phi_R$、渲染 $\rho$、后处理 $\Phi_{\mathrm{post}}$、摘要 $\sigma_{\mathrm{mech}}$ 等算子均由确定性函数实现；同义性判定 $\phi_V$ 在**可认证子集**上亦被一道**证书级语义 oracle** 确定化——对仅由逐原子认证过的原子构成的生成 lint，$\mathrm{Code}\equiv\mathrm{IR}$ 由执行证明给出而非 LLM 投票，仅在该 oracle 不适用的子集上才退回 $\phi_C$、$\phi_V$ 等确需语义灵活性的 LLM 端点。该原则的实证依据有二：其一，将 $\sigma$ 由 LLM 替换为确定性机械翻译算子 $\sigma_{\mathrm{mech}}$ 这一单步干预贡献了显著的端到端增量；其二，把生成端的确定性归约整体移除、改由 oracle 在验证端重建 $\mathrm{Code}\equiv\mathrm{IR}$ 的确定性保证，印证了确定性的着力点可从生成迁移到验证（详见 §9）。在缺乏人工真值的前提下，则由反向传播式迭代验证框架（BIIV）将三类质量不变量形式化为可计算残差，提供收敛性与可追溯性。

### 1.4 主要贡献

本研究的贡献可归纳为六点，贯通"提取—判定—生成—验证"全链路。

**(C1) 面向跨文档引用的知识图谱与确定性检索。** 由 Web PKI 规范源构建多边有向知识图谱（章节、定义、证书字段与跨文档继承关系），并设计仅沿显式 source-backed 边做有界遍历的确定性 GraphRAG 检索机制，为规则提取提供可溯源、可复现且不引入 LLM 臆造的上下文（§4.1–4.2）。

**(C2) 双层提取与结构化中间表示。** 提出双层提取流水线：Layer 1 以 RFC 2119 关键词与正则做确定性召回，Layer 2 将 LLM 限定为受 schema 约束的语义解析器，把候选规则转写为结构化 IR（核心四元组 ⟨主体, 义务, 谓词, 约束⟩）。IR 将语义提取与下游任务解耦，支持"一次提取、多处复用"（§4.3–4.4）。

**(C3) 基于 IR 的五条件可 lint 性框架。** 将可 lint 性形式化为对五个离散 IR 字段的确定性布尔函数 $C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$，使判定可复现，且任何误判都可追溯到唯一一个 IR 字段，而非归因于不透明的端到端调用（§5）。

**(C4) 受限代码空间、可逆机械翻译与证书级语义 oracle。** 将 $\phi_G$ 的值域严格形式化为原子集 $\mathcal{A}$（$|\mathcal{A}|=56$）与类型化词汇表 $\mathcal{V}$ 张成的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，给出语法、执行语义、词汇封闭性命题（命题 1）与树规模上界；并给出确定性机械翻译算子 $\sigma_{\mathrm{mech}}:\mathcal{T}_{\mathcal{V}}\to\mathcal{L}_{\mathrm{NL}}$，满足全函数性、决定性与原子等价意义下的可逆性，将反向传播链路上的概率失真压缩至 $\phi_C$、$\phi_V$ 两个端点。在此受限空间之上进一步构建**证书级语义 oracle**——经逐原子忠实性认证（受控证书 fixture）与结构组合，对仅由已认证原子构成的生成 lint 确定性地证明 $\mathrm{Code}\equiv\mathrm{IR}$，把同义性判据由单票 LLM 判别器替换为可复现的执行级证明，并诚实披露其"可认证子集"边界（§6–7）。

**(C5) 反向传播式迭代验证与三目标残差。** 将"召回完整性"（G1）、"代码-规范同义性"（G2）、"双 oracle 一致性"（G3）形式化为三个独立的可计算残差，给出阶段归因规则、修复算子谱与收敛性论证，并以 L4b 双向 FLIP-or-SPURIOUS 机制使 G3 残差单调降至 0。该框架在**无人工标注真值**条件下提供质量控制，结构性地取代了对人工真值的依赖（§8）。

**(C6) 大规模实证与诚实边界声明。** 在 39 个 Web PKI 规范源上揭示规范与 lint 实践之间的双向结构性缺口（仅 18.2% 规则可 lint、现有工具仅覆盖其中 48.0%）；在可执行子集上完成端到端生成（结构解析 100%、综合对齐 0.886），并以"reducible 子集闭合 + 不可归约残差边界披露"双指标取代单一收敛阈值，给出可复现的诚实边界声明范式（§9）。

### 1.5 论文结构

本文余下部分安排如下。第 2 节梳理相关工作并界定本研究的差异化定位；第 3 节给出端到端方法总览；第 4 节描述规范规则提取与中间表示（知识图谱、确定性检索、双层提取、结构化 IR）；第 5 节形式化基于 IR 的五条件可 lint 性判定；第 6 节给出受限 DSL 代码空间与 LLM 引导合成；第 7 节描述三层语义对齐验证与机械翻译算子；第 8 节形式化反向传播式迭代验证框架（BIIV）；第 9 节给出实验设置与实证结果；第 10 节讨论关键发现及对规范作者与工具维护者的启示；第 11 节分析有效性威胁；第 12 节总结全文。

## 2. 相关工作

### 2.1 PKI 标准与静态合规检查

X.509 证书的编码规范由分层的标准与策略框架共同定义。RFC 5280 [1] 给出证书 ASN.1 结构、字段级语义与路径验证算法这一基础层；其上，CABF 基线要求 [2] 对签发公信 TLS 证书的商业 CA 施加操作性与配置性约束；ETSI EN 319 412 系列 [3] 补充了与 eIDAS 框架对齐的欧盟配置档案；Mozilla 根存储策略 [4] 则从浏览器策略层引入额外技术要求。这些规范彼此交叉引用并时有局部覆盖，普遍以 RFC 2119 [5] 关键词表达义务级别（MUST/SHALL 通常映射为 Error，SHOULD/RECOMMENDED 映射为 Warning，MAY/OPTIONAL 一般不宜直接实现为 lint 规则）。

证书合规主要通过静态 lint 工具检查，这些工具只检视单张证书的编码内容、不依赖外部验证状态。zlint [7] 是部署最广的静态 linter，将检查组织为带元数据（引用、生效日期、严重级别）的独立 lint，截至本研究撰写时 zlint v3 已含约 400 条规则；pkilint [8] 以 Python 验证框架的形式表达可复用的嵌套结构校验；certlint [9] 与 x509lint [10] 则是更早的命令行 linter，聚焦语法、编码与档案级异常。尽管目标一致，各工具的覆盖并不均衡，因为每条检查都必须人工地从规范文本推导、映射到特定解析器的字段访问、实现、测试并随规范演进维护。这带来两点重要含义：其一，lint 检查并非规范语句的直接拷贝，而是嵌入了字段路径、谓词、严重级别与作用域条件的工程产物；其二，缺少某条 lint 检查并不意味着对应规范规则不存在，可能只是它尚未被识别为可 lint 或尚未被实现。

### 2.2 规范与规则的自动提取

自动规则提取已在隐私、法律与协议规范等领域被研究，但这些场景与 Web PKI 签发合规存在本质差异。PolicyLint [18] 与 PrivacyFlash Pro [19] 分析隐私文本，Hassani 等 [20] 将 LLM 与知识图谱结合用于法律合规提取；这些方法识别义务或数据实践约束，但并不把规范规则映射到 DER 编码的证书字段，也不判定某条规则能否通过检视单张已签发证书来强制执行。N-Check [21] 将规范规则形式化为 FOL\* 公式，但其目标是良构性分析而非面向 X.509 字段路径的 lint 谓词。

面向技术规范的 LLM 分析系统表明规范可被自动解析，但留下了不同的缺口。PROSPER [22]、ParCleanse [23] 与 SpecGPT [24] 分别提取 RFC 状态机、协议格式与 3GPP 状态机行为；Wu 等 [25] 借助 GraphRAG 式上下文 [26], [27] 将 RFC 文本与内核代码对齐。这些工作聚焦于状态、格式或实现差异，并未将"规范规则的穷尽召回、受 schema 约束的 IR 解析、面向 PKI 签发规则的确定性可 lint 性判定"三者分离处理。

### 2.3 LLM 辅助代码生成与输出约束

大语言模型在代码生成上已取得显著进展，Codex [32]、AlphaCode [33] 与 CodeGeeX [34] 展示了从自然语言生成代码的能力，但主要面向通用编程任务，通常缺乏对领域约束、目标框架接口与可追溯性的显式建模。在协议合规方向，SAGE [35] 提取协议状态机，RFCNLP [36] 构建有限状态自动机以检测协议规范歧义，PROSPER [22] 则提取规范并生成测试用例；这些工作主要面向协议行为的形式化或测试生成，而非面向具体 lint 框架直接产出可执行代码。

输出约束与形式验证类工作与本研究互补。XGrammar [28] 与 CRANE [29] 通过文法约束 LLM 输出，Schall 与 de Melo [30] 则指出受限解码可能损害推理质量；ARMOR [31] 在 Agda 中验证 RFC 5280 路径验证算法。这些方法改进输出形式或算法保证，但并不决定哪些自然语言签发规则应当成为静态 lint 检查。

### 2.4 代码与规范的语义对齐

确保生成代码与规范语义一致是该类任务的核心难点。现有研究大致沿几条路径展开：测试用例验证依赖人工构造测试且难以穷尽边界；符号执行能系统探索路径但易遭遇路径爆炸；差异分析通过比较多个实现发现偏差，但以存在可对照的参考实现为前提；中间表示方法则将规范、IR 与代码组织为三元结构，借助 IR 的语义桥接间接验证一致性。与前三类相比，中间表示路径更适合处理规范文本到代码的语义转换，也为本研究提供了直接启发——本研究进一步以 IR 为桥梁，引入基于代码摘要的同义性归约与确定性机械翻译，使对齐判定既可计算又可追溯。

### 2.5 证书合规性度量

证书签发合规的实证度量与本研究的经验设定最为接近。Kumar 等 [11] 在生态尺度上度量了证书误签发，Zhang 等 [17] 识别了国际化 X.509 证书中与 Unicode 相关的签发与解析不合规。这些研究表明签发失效是可度量且具运维重要性的，但它们通常从已知的 lint 检查或缺陷类别出发，而非从规范文本出发系统性地推导可 lint 规则的全集。

### 2.6 本研究的差异化定位

与上述工作相比，本研究的差异化定位体现在四个方面。**其一**，本研究并不孤立地做提取或生成，而是给出贯通"提取 → IR → 可 lint 性判定 → 代码生成 → 验证"的端到端框架，并以结构化四元组 IR 作为前后两半的统一接缝。**其二**，在提取侧将跨文档上下文交由确定性 GraphRAG 检索、并把 LLM 限定为受 schema 约束的解析器，使提取可审计、可复现，区别于端到端黑箱提取。**其三**，在生成侧将 $\phi_G$ 的值域形式化为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，在语言层关闭字段/OID 编造类幻觉（命题 1），与基于 prompt 约束或 few-shot 引导的方法形成本质区别。**其四**，在验证侧提出反向传播式迭代验证框架，将三类质量不变量形式化为可计算残差，在无人工真值条件下提供收敛性与可追溯性，并由确定性机械翻译算子 $\sigma_{\mathrm{mech}}$ 将概率失真压缩至两个必要的语义端点——这给出一项更一般的设计原则：**反向传播式验证链路上的每个算子都应尽可能确定化**。

## 3. 方法总览

图 1 给出本研究端到端框架的整体结构。系统以 Web PKI 规范文本为输入，以可编译、可追溯的 zlint Go 检查代码为输出，并由反向传播式验证框架在无人工真值条件下闭环修复。整体流程由六个阶段组成，前三个阶段（确定性上下文 + 提取 + 判定）构成"规范 → 可 lint 规则"的前半链路，后三个阶段（合成 + 对齐 + 验证）构成"可 lint 规则 → 可信代码"的后半链路，二者以**结构化中间表示 IR**与**五条件可 lint 性判定**为统一接缝。

1. **知识图谱构建（离线，§4.1）。** 将异构规范源归一化为带稳定标识的层级结构，抽取章节包含、定义、跨文档引用与字段概念等显式关系，形成可溯源的检索基底。
2. **确定性上下文检索（§4.2）。** 以知识图谱为固定输入，对每个目标章节做有界子图遍历，组装术语定义、字段元数据与被引章节作为提取上下文；该过程不使用向量相似度，也不调用 LLM，从而不引入臆造上下文。
3. **双层提取与 IR 构建（§4.3–4.4）。** Layer 1 以 RFC 2119 关键词与正则做确定性召回得到候选规则集合 $\mathcal{R}_{\mathrm{kw}}$；Layer 2 将 LLM 限定为受 schema 约束的语义解析器，把每条候选规则转写为结构化 IR。
4. **五条件可 lint 性判定（§5）。** 由分类算子 $\phi_C$ 依据五个离散 IR 字段的确定性布尔函数 $C(r)=C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$，将每条规则映射至可执行（可 lint）集合 $\mathcal{R}_L$。$\mathcal{R}_L$ 即下游代码生成的定义域。
5. **受限 DSL 合成（§6）。** 生成算子 $\phi_G$ 在形式化的原子 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$ 内合成 DSL 树 $t$，再经确定性渲染算子 $\rho$ 与可溯源字段后处理 $\Phi_{\mathrm{post}}$ 物化为 Go 代码。
6. **三层对齐验证（§7）。** 通过描述溯源性、基于 $\sigma_{\mathrm{mech}}$ 机械翻译摘要与 `Description` 的同义性判定、以及结构与编译检查，综合输出对齐得分 $S_{\mathrm{align}}$；对由已认证原子构成的可认证子集，另由证书级语义 oracle 确定性证明 $\mathrm{Code}\equiv\mathrm{IR}$，无需 LLM 判官。

当样本级对齐不达阈值时，系统进入 §7 的样本级局部修复；当需要在大规模、无独立真值的场景下定位并修复系统性误差来源时，则进入第 8 节的反向传播式管道级验证与修复框架（BIIV），将"召回完整性、代码-规范同义性、双 oracle 一致性"三类不变量作为可计算残差，沿管道反向归因并触发阶段性修复。

## 4. 规范规则提取与中间表示

本节描述前半链路：如何在确定性可控的前提下，从分散且交叉引用密集的 Web PKI 规范源中提取规范规则，并将其转写为结构化中间表示 IR。

### 4.1 PKI 知识图谱构建

知识图谱构建器是离线组件，将异构的 Web PKI 规范源转换为供后续检索使用的基底。它把文档归一化为层级结构，为规范、章节、标题与文本单元赋予稳定标识；随后抽取章节引用、RFC 引用与策略交叉链接等**显式引用**，并在目标可被无歧义解析时将其链接到对应节点；同时记录证书字段概念及其别名（如 subjectAltName、dNSName、basicConstraints.cA 与策略 OID），以便在后续提取中把自然语言提及映射到规范的证书路径。

PKI 规范构成一个高度互联的跨文档网络——例如 RFC 5280 引用多份 RFC，CABF BR 又直接依赖 RFC 5280 的字段定义。本研究将该知识建模为多边有向图，含八类节点（Specification、Section、Definition、CertificateField、Rule、Operation、Value、Concept）与四种 source-backed 关系（CONTAINS、DEFINES、REFERENCES、APPLIES TO）。该构建器刻意保持保守：只存储由文档结构或文本证据直接支持的关系，而把冲突、覆盖、可 lint 性等**规范性判断**留给后续确定性阶段。诸如 CONFLICTS WITH、OVERRIDES 等规范性判断关系由规则引擎独立产生，**不进入检索图**。由此得到的图是一个可溯源的上下文索引，而非裁决 oracle：它帮助提取器定位定义、继承约束与被引规则，但并不决定某条要求是否可 lint。各关系类型及其检索可入性详见附录。

### 4.2 确定性上下文检索

为应对跨文档引用，本研究以确定性方式组织上下文，而非依赖 LLM 推断关系。检索模块将知识图谱（§4.1）视为固定输入，通过有界子图查询获取上下文：给定一个目标 Section 节点，沿 source-backed 的 CONTAINS、DEFINES、REFERENCES、APPLIES TO 关系在其 $k$-跳邻域内做 BFS 扩展，再按关系类型优先级装配出术语定义、字段元数据与被引章节。整个检索过程既不使用向量相似度也不调用 LLM 推理，因而不产生任何独立判断。

检索阶段额外遵守四条约束（GR-1 至 GR-4）：不允许引入任何被推断出的规范规则；只有原始规范节点可进入检索；任何推断性关系不得进入检索；所有上下文必须可追溯至规范源。这些约束保证了"提供给 LLM 的上下文"本身是可审计、可复现的，从根本上抑制了"模型据臆造上下文作答"的风险。

### 4.3 双层提取流水线

为在保留 LLM 语义理解能力的同时维持提取过程的可审计性，本研究采用双层结构。

**Layer 1：确定性召回。** Web PKI 规范普遍以 RFC 2119 关键词表达规范性要求，可按义务强度分层（强制类 MUST/SHALL/REQUIRED、禁止类 MUST NOT/SHALL NOT、推荐类 SHOULD/SHOULD NOT/RECOMMENDED、可选类 MAY/OPTIONAL）。RFC 8174 [6] 进一步规定这些关键词仅在大写时具规范效力，从而支持确定性的关键词匹配；ETSI EN 319 不遵循该约定，其候选则通过小写匹配召回。为最大化召回，Layer 1 以三遍方式运行：第一遍直接匹配 RFC 2119 关键词；第二遍识别嵌套结构，使从属规则继承父级义务等级；第三遍捕获不遵循标准 RFC 2119 形式的规范性陈述。Layer 1 的输出是候选规范规则集合 $\mathcal{R}_{\mathrm{kw}}$。

**Layer 2：受控语义解析。** Layer 2 使用 LLM，但将其限定为受约束的语言理解角色：模型并不直接生成 lint 规则或合规判断，而是把规范文本转写为 JSON 序列化的中间表示 IR，所有规范性推理都推迟到后续确定性阶段。该设计将 LLM 的职责收敛为 schema 受限的语义解释。为提升分类字段的稳定性，IR 生成采用**分阶段**策略：模型先判定规则类别，再填充其余字段——相较一次性生成全部字段，这显著降低了误差。Layer 2 同时受一组确定性约束的约束：输出必须严格符合预定义 IR schema，否则被拒并重提；在可确定性判定的情形下由规则引擎覆盖 LLM 分类（如"in step"→`algorithm_ref`、"is defined as"→`definition`）；每条 IR 都附带索引到源文本的引用片段，并由文本对齐校验器核验其文本字段确实源自该片段，未能对齐者作为幻觉被丢弃；当 IR 涉及证书 subject DN 之下的属性时，其路径必须落在由 RFC 5280 ASN.1 定义构建的规范路径树上，由确定性字段解析器注入并校验。这些约束分别在 IR 的文本层与 schema 层抑制了"编造原文"与"编造不存在字段层级"两类幻觉。

### 4.4 结构化中间表示

IR 是连接前后两半链路的核心数据结构。其核心为四元组

$$
\mathrm{IR} = \langle \text{subject},\ \text{obligation},\ \text{predicate},\ \text{constraint} \rangle,
$$

其中 subject 为由字段解析器解析得到的证书字段路径（如 `extensions.subjectAltName.dNSName`），obligation 为 RFC 2119 义务关键词，predicate 为断言类型（如 `must_be_present`、`conform_to`、`equal`），constraint 为约束值或模式。四元组之外，IR 还携带若干关键扩展字段，用于支撑可 lint 性判定与下游生成与审计，其中最重要的是 `rule_category`（规则语义类别）、`assertion_subject`（断言主体：证书 / CA / 依赖方 / 外部生态）、`enforcement_phase`（约束所依赖的阶段：编码 / 运行时 / 外部验证），以及 `source_section`、`source_span`、`evidence_text`、`context_nodes` 等溯源字段。

以 IR 为桥梁带来三点相较"从原文端到端直接生成 lint 检查"的优势：其一，引用、约束与义务信息被分离存储，提升可追溯性与冲突处理能力；其二，IR 作为 §5 五条件可 lint 性判定的确定性输入，使判定可复现而非依赖模型；其三，一旦规则被判为可 lint，由结构化 IR（字段路径、断言类型、约束值均已显式化）生成代码更稳定、更可解释。IR 由此支持"一次提取、多处复用"——同一提取结果可同时服务于可 lint 性分析与代码生成等多个下游任务。

## 5. 可 lint 性判定

在生成代码之前，需判定每条规范规则的**可 lint 性**，即它是否允许一个不依赖外部上下文或运行时行为、且仅凭**单一制品**（一张证书或一份 CRL）即可裁决的静态检查。本研究不让 LLM 直接做此判断，而是从其已产出的 IR 上**确定性地计算**可 lint 性。三点观察支撑这一设计：其一，实践中决定一条规则可 lint 性的恰是五类信息——义务的道义强度、被约束的主体、约束生效的阶段、规则的类型，以及裁决该约束所需的**数据范围**（单一制品 vs 跨制品/外部状态）；其二，这五者中的每一个都可编码为取值于一个小而封闭集合的单一 IR 字段，于是可 lint 性判定退化为五个离散字段的布尔函数；其三，分离这五个条件，使任何错误标签都可追溯到恰好一个 IR 字段，而非归因于不透明的端到端调用。

形式上，可 lint 性是以下五个条件的合取，每个条件都是恰好一个 IR 字段的布尔函数：

$$
\mathrm{lintable}(r) \;\Longrightarrow\; C_1(r) \wedge C_2(r) \wedge C_3(r) \wedge C_4(r) \wedge \neg C_5(r),
$$

其中

- **$C_1$（道义强度）**：$C_1(r) \equiv \mathrm{is\_normative}(r.\text{obligation})$，即 $r.\text{obligation} \notin \{\text{MAY}, \text{OPTIONAL}\}$；
- **$C_2$（主体边界）**：$C_2(r) \equiv (r.\text{assertion\_subject} \in \{\text{Certificate}, \text{CA}, \text{CRL}\})$，纳入三类"其义务落实在单一签发制品字节中"的主体——直接对证书的义务、由 CA 履行但其效果可在签发出的证书/CRL 上静态观测的义务（如"CA MUST 将此扩展标记为 critical"），以及对 CRL 这一独立制品自身的义务（如 IssuingDistributionPoint、CRLNumber、thisUpdate 等）；而将以**依赖方（relying party）或周边生态**为主体、无法在单一签发制品上裁决的义务排除在外；
- **$C_3$（运行时边界）**：$C_3(r) \equiv (r.\text{enforcement\_phase} = \text{Encoding})$，将"可在已签发字节中观测的义务"与"在链处理、名称比较、撤销处理或 CAA 获取等阶段才触发的义务"分开；
- **$C_4$（数据边界 / 单一制品）**：$C_4(r) \equiv (r.\text{check\_scope} \in \{\text{single\_certificate}, \text{single\_crl}\})$，要求该约束可仅凭**一份制品**（一张证书或一份 CRL）孤立裁决，从而排除需要比对证书链中其他证书（跨制品，如"子证书的 SKI 须等于签发者的 AKI"）、查询外部状态（CAA DNS 记录、OCSP 响应、CT 日志）或撤销历史才能判定的义务；
- **$C_5$（过程边界，取反）**：$C_5(r) \equiv (r.\text{rule\_category} \in N)$，其中 $N = \{\text{definition}, \text{capability}, \text{algorithm\_ref}, \text{display}, \dots\}$ 为承载术语定义、CA 能力声明、对外部算法规范的委派、UI 呈现等**不对证书编码施加静态检查**的类别集合；可 lint 要求 $r.\text{rule\_category} \notin N$，即 $\neg C_5$。$C_5$ 与 $C_4$ **正交**：$C_5$ 回答"这是哪一**类型**的义务"（定义？能力声明？编码约束？），$C_4$ 回答"裁决它需要**哪些数据**"（仅此一份制品，还是更多）——一条规则可以是编码约束（不在 $N$ 中，即 $\neg C_5$）却仍需访问签发者证书做密钥比对（不通过 $C_4$）。

记 $\phi_C : r \mapsto \mathbb{1}[C_1 \wedge C_2 \wedge C_3 \wedge C_4 \wedge \neg C_5]$，则可 lint 规则集合 $\mathcal{R}_L = \{r : \phi_C(r) = 1\}$ 即后续代码生成阶段 $\phi_G$ 的定义域。obligation 字段同时固定了 lint 的严重级别（MUST 类 $\mapsto$ Error，SHOULD 类 $\mapsto$ Warning），因此严重级别不是第二个分类器，而是对 obligation 的直接读取。四个非道义条件 $C_2$、$C_3$、$C_4$、$\neg C_5$ 刻画了四条正交边界——主体边界、运行时边界、数据边界（单一制品）与过程边界。值得注意的是，$C_4$ 把原先只在审计阶段事后判定的 $\mathrm{StaticallyObservable}$ 谓词（§8.9，其 $\mathrm{verif}_{\mathrm{scope}}=\mathrm{observable}$ 分量）提升为提取阶段即确定的一等 IR 字段 $\mathrm{check\_scope}$；$C_2$（主体）与 $C_4$（范围）合取后即与 $\mathrm{StaticallyObservable}$ 在提取时重合，从而把一类此前依赖人工审计的边界判断前移为可复现的确定性计算。由于每个 $C_i$ 都是单一 IR 字段的确定性函数，$\mathrm{lintable}(r)$ 是从 IR 计算得到而非由 LLM 预测的：相同的规则 IR 在每次运行上都给出逐位一致的标签，且任何误判都可追溯到 Layer 2 某一个具体的字段赋值。这一可追溯性正是第 8 节反向传播式验证得以沿管道反向归因的前提。

## 6. 受限 DSL 代码空间与 LLM 引导合成

本节描述后半链路的核心：如何在**语言设计层面**限制代码生成算子 $\phi_G$ 的值域，使生成结果既不产生编造字段/OID 的幻觉，又使"代码语义等价于规范语义"成为可计算的判定问题。

### 6.1 受限代码空间的动机

直接将 $\phi_G$ 实现为"$r \mapsto$ 自由形式 Go 代码"会面临两类风险：**(i) 幻觉风险**——LLM 可能输出引用证书结构中不存在字段、调用不存在标准库函数或编造 OID 常量的代码，且这类错误在编译层难以全部捕获；**(ii) 验证不可计算性**——开放代码空间下，证明"代码语义等价于规范语义"需要程序分析或动态符号执行，远超工程可行性。本研究的核心方法学回应是**在语言设计层面限制 $\phi_G$ 的值域**：将 Go 代码空间替换为一个有限闭合的 DSL 树空间 $\mathcal{T}$，并由确定性渲染函数 $\rho:\mathcal{T}\to\mathrm{Go}$ 完成代码物化。LLM 仅需输出一棵合法的 DSL 树，所有"字段名是否合法 / OID 是否存在 / 比较算子是否类型匹配"等正确性属性，均由 DSL 的类型系统在生成时即被静态保证。

### 6.2 原子 DSL：语法与原子集

定义代码 DSL 的抽象语法为：

$$
\mathcal{T} \;::=\; a(\bar{v}) \;\mid\; \neg\, \mathcal{T} \;\mid\; \mathcal{T} \wedge \mathcal{T} \;\mid\; \mathcal{T} \vee \mathcal{T}
\tag{1}
$$

其中 $a \in \mathcal{A}$ 为原子谓词，$\bar{v}$ 为该原子的参数列表。$\mathcal{A}$ 是一个**有限闭合**的原子集合：本文版本下 $|\mathcal{A}| = 56$，每个原子对应一类语义上不可再分的证书属性判定（如"扩展存在"、"字段等于常量"、"列表中每元素匹配某正则"等）；$\{\neg, \wedge, \vee\}$ 为命题逻辑组合子，完整 $\mathcal{A}$ 的枚举见附录 D。一条 lint 规则的代码体被建模为有序对 $(p, q) \in \mathcal{T}_\perp \times \mathcal{T}$，其中 $p \in \mathcal{T}_\perp = \mathcal{T} \cup \{\perp\}$ 为可选前提条件，$q \in \mathcal{T}$ 为主断言，其执行语义为：

$$
\lVert (p, q) \rVert(c) \;=\; \begin{cases}
\mathrm{NA}, & p \neq \perp \;\land\; \lVert p \rVert(c) = \mathrm{false} \\
\mathrm{Pass}, & (p = \perp \;\lor\; \lVert p \rVert(c) = \mathrm{true}) \;\land\; \lVert q \rVert(c) = \mathrm{true} \\
\mathrm{Severity}(r), & \text{otherwise}
\end{cases}
\tag{2}
$$

其中 $c$ 为待检查证书，$\mathrm{Severity}(r) \in \{\text{Error}, \text{Warn}, \text{Notice}\}$ 由规则义务级别确定性映射给出（MUST/MUST NOT $\mapsto$ Error；SHOULD/SHOULD NOT $\mapsto$ Warn；MAY $\mapsto$ Notice）。

### 6.3 类型化词汇表与参数封闭性

设 $\mathcal{V}$ 为系统所携带的**类型化词汇表**，是若干有限集合的不相交并：

$$
\mathcal{V} \;=\; \mathcal{F}_{\mathrm{cert}} \;\sqcup\; \mathcal{F}_{\mathrm{dn}} \;\sqcup\; \mathcal{O} \;\sqcup\; \mathcal{B}_{\mathrm{KU}} \;\sqcup\; \mathcal{B}_{\mathrm{EKU}} \;\sqcup\; \mathcal{E}_{\mathrm{ASN1}} \;\sqcup\; \mathcal{R}_{\mathrm{regex}}
\tag{3}
$$

各分量分别是证书字段名、DN 字段、OID 常量、KeyUsage 位、ExtKeyUsage 位、ASN.1 编码类型与命名正则集合，均在系统启动时被冻结。每个原子 $a \in \mathcal{A}$ 有签名 $\mathrm{sig}(a) = (\tau_1, \dots, \tau_{n_a})$，其中 $\tau_i$ 是 $\mathcal{V}$ 的某一分量或基础类型 $\{\mathbb{Z}, \mathbb{B}, \mathrm{String}\}$；原子调用 $a(v_1, \dots, v_{n_a})$ 合法当且仅当每个 $v_i$ 隶属于 $\tau_i$ 所规定的集合。记 $\mathcal{T}_{\mathcal{V}}$ 为所有参数均落在 $\mathcal{V}$ 内的合法 DSL 树集合。本研究将 $\phi_G$ 的值域严格限定为 $\mathcal{T}_{\mathcal{V}}$，这提供如下封闭性命题。

**命题 1（词汇封闭性）**。*对任意 LLM 输出 $t$，若 $t \in \mathcal{T}_{\mathcal{V}}$，则 $t$ 中不出现 $\mathcal{V}$ 之外的字段名、OID 或正则；若 $t \notin \mathcal{T}_{\mathcal{V}}$，则解析阶段必然报错并触发修复，不会进入 $\rho$ 渲染。*

该命题在架构层面消除了 LLM 编造证书字段或 OID 这一类幻觉。

### 6.4 渲染与可逆机械翻译

定义两个全函数：

$$
\rho : \mathcal{T}_{\mathcal{V}} \to \mathrm{Go}, \qquad \sigma_{\mathrm{mech}} : \mathcal{T}_{\mathcal{V}} \to \mathcal{L}_{\mathrm{NL}}
\tag{4}
$$

其中 $\rho$ 将 DSL 树渲染为类型正确的 Go 表达式，$\sigma_{\mathrm{mech}}$ 将 DSL 树机械翻译为 PKI 英文摘要（详见 §8.13）。两个函数共享三项性质：**类型安全**（$\rho$ 输出 100% 通过 Go 编译器解析与类型检查）；**决定性**（对相同输入 $t$，$\rho(t)$ 与 $\sigma_{\mathrm{mech}}(t)$ 输出唯一）；**可逆性（在原子等价意义下）**（给定 $\sigma_{\mathrm{mech}}(t)$ 可机械还原 $t$，即 $\sigma_{\mathrm{mech}}$ 在反向验证链路上不引入信息瓶颈，详见 §8.13 命题 2）。

### 6.5 代码空间复杂度估计

记 $\mathcal{T}_{\mathcal{V}}^{(n)}$ 为大小不超过 $n$ 的合法 DSL 树集合，设原子平均参数空间大小为 $\bar k$，则有粗粒度上界：

$$
\bigl|\mathcal{T}_{\mathcal{V}}^{(n)}\bigr| \;\leq\; \sum_{i=1}^{n} (|\mathcal{A}| \bar k + 3)^{i}
\tag{5}
$$

其中 $3$ 对应组合子 $\{\neg, \wedge, \vee\}$ 的基数。在本文实验数据上 $|\mathcal{A}|=56$、$\bar k \approx 8$、典型 $n \leq 8$，对应 $|\mathcal{T}_{\mathcal{V}}^{(8)}|$ 仍是有限可枚举量级——与开放 Go 程序空间的"语法上无穷"形成鲜明对比。这一有限性正是 $\sigma_{\mathrm{mech}}$ 可被设计为可逆机械函数（§8.13）与生成修复可被设计为可终止过程（§8.7）的基础前提。

### 6.6 从 IR 谓词到原子的语义映射

为支持上游 IR 与 DSL 的衔接，本研究维护一个**多对多语义映射** $\mu : \mathrm{Pred}_{\mathrm{IR}} \rightrightarrows 2^{\mathcal{A}}$，其中 $\mathrm{Pred}_{\mathrm{IR}}$ 为 IR 中可能出现的谓词类型集合（如 `must_be_present`、`encode_as`、`in_range` 等）。$\mu$ 在本框架中作为**给受限 LLM 合成提供候选原子集合的提示性约束**：对每条规则 IR 中出现的谓词，$\mu$ 给出语义上可承载它的原子子集，连同词汇表 $\mathcal{V}$ 与原子签名表一并进入 §6.7 的合成提示，把模型的选择空间从全集 $\mathcal{A}$ 收窄到与该谓词相关的候选，而非由 $\mu$ 直接装配输出。$\mu$ 不进入 $\rho$ 的渲染逻辑——最终的原子选择与组合结构由 LLM 给出，并经 §6.7 的封闭性强制与 §7.1 的证书级语义 oracle 校验。$\mu$ 的多对多性质保证"一个 IR 谓词可由不同原子组合实现"，即代码空间在语义上仍具有合理的表达冗余度。

### 6.7 受限 LLM 树合成与 IR-字段溯源守卫

**全 LLM 树合成。** 给定可执行规则 $r \in \mathcal{R}_L$（$\mathcal{R}_L$ 由 §5 的五条件判定给出），代码生成算子 $\phi_G$ 实现为一次**受限 LLM 树合成**：模型在得到规则上下文、结构化 IR、由 §6.6 映射 $\mu$ 收窄的候选原子集合，以及词汇表 $\mathcal{V}$ 与原子集 $\mathcal{A}$ 的可读枚举与签名表（实际系统提示与四区段拼接见附录 I）之后，仅返回一棵 DSL 树的序列化或一个显式弃权标记：

$$
\phi_G : r \;\longmapsto\; t \in \mathcal{T}_{\mathcal{V}} \cup \{\perp_{\mathrm{NT}}\}, \qquad t \;=\; \eta\bigl(M.\mathrm{generate}(\mathrm{prompt}(r,\,\mathcal{V},\,\mathcal{A},\,\mu))\bigr)
\tag{6}
$$

其中 $\perp_{\mathrm{NT}}$ 是显式的"无模板"标记，由 LLM 自主返回——当且仅当模型判断当前 $(\mathcal{A}, \mathcal{V})$ 不足以表达 $r$ 的语义时返回，此时该规则进入修复路径而非渲染，使 $\phi_G$ 不必产生"形式合法但语义错位"的输出。所有"会被检查"的部分都被约束落在 $\mathcal{T}_{\mathcal{V}}$ 之内（命题 1）。在执行体上 $\phi_G$ 是受约束的 LLM 调用，对**所有**可执行规则走同一条通路——不再有按规则区分的确定性主路或模板分类。

**从级联到全 LLM 合成的沿革。** 早期版本曾以一条确定性 IR→DSL 归约作为生成主路、LLM 仅作兜底（"级联"）。该归约只能覆盖可被无歧义查表的子集，且其声称的"$\mathrm{Code}\equiv\mathrm{IR}$ 由构造保证"仅在 IR→树这一跳成立、并不直接担保 $\mathrm{Code}\equiv\mathrm{Spec}$。本研究随后将该归约整体移除、改由 LLM 统一合成全部 DSL 树，并把原先"由构造保证"的忠实性改由 §7.1 的**证书级语义 oracle** 事后*证明*。其效果是把链路上的确定性从**生成端**移到**验证端**：生成保持单一、受限的 LLM 通路，而 $\mathrm{Code}\equiv\mathrm{IR}$ 的确定性保证在可认证子集上由可执行的 oracle 重新建立（§7.1、§9.10）——这与"反向传播链路上每个算子都应尽可能确定化"原则一致，只是确定化的着力点从 $\phi_G$ 自身转移到对 $\phi_G$ 产物的验证。

**IR-字段溯源守卫。** 确定性归约移除后，生成端唯一的结构性 soundness 机制是 IR-字段溯源守卫 $\mathrm{IRGuard}$：它复用字段解析器把 LLM 树中出现的每个证书字段 / 扩展 OID 规范化为其 DSL 身份（扩展按数值 OID 归一，使 `subjectaltname` 与 `SubjectAlternateNameOID` 比较相等，二者同属 OID `2.5.29.17`），并核验它们都被本规则的 IR 所涵盖。引用了 IR 之外字段的树被标记为**字段漂移**，连同"哪个字段越界"的诊断回传 LLM 触发重写（至多 $K$ 轮）。该守卫刻意保守——因 IR 解析本身会漏抽子字段（IR 写 `extensions.subjectaltname`、LLM 正确地用其子字段 `IPAddresses`，二者实为同一扩展），硬性拒绝将误伤约两成的好树——故它定位漂移并驱动修复，而非充当不可逆否决。它承接了原级联中"防塌缩门"的忠实性把关职责，但作用点从"确定性树是否塌缩为过粗的存在性原子"前移到"LLM 树是否引用了 IR 之外的字段"。真正的语义忠实性（$\mathrm{Code}\equiv\mathrm{IR}$）则不由生成端担保，而留待 §7.1 的证书级语义 oracle 在可认证子集上*证明*。

**解析与封闭性强制。** LLM 输出经解析算子 $\eta : \mathrm{string} \to \mathcal{T}_{\mathcal{V}} \cup \{\perp_{\mathrm{NT}}, \mathrm{Err}\}$ 处理：合法序列化映射为 $t \in \mathcal{T}_{\mathcal{V}}$，弃权映射为 $\perp_{\mathrm{NT}}$，解析失败或包含 $\mathcal{V}$ 之外参数则映射为 $\mathrm{Err}$。当 $\eta(s) = \mathrm{Err}$ 时，将"具体到哪一原子签名不匹配、哪一 OID 未注册"的错误信息注入下一轮提示，触发受反馈引导的重新生成。这一过程把 LLM 的"幻觉表面积"严格压缩在原子参数选择与组合结构两个维度，而不允许新增未注册谓词或未注册字段。

**可溯源字段的确定性绑定。** 记 $\Phi_{\mathrm{post}} : \mathcal{T}_{\mathcal{V}} \times r \to \mathrm{Go}$ 为后处理-渲染复合算子，在 $\rho$ 渲染出检查体之后，将 `Description`、`Citation`、`Name` 三个**可溯源字段**强制绑定为规范原文与规则元数据的字面值：

$$
\Phi_{\mathrm{post}}(t, r) \;=\; \rho(t) \;\oplus\; \mathrm{Bind}\bigl(\text{Description} \mapsto \mathrm{rule\_text}(r),\; \text{Citation} \mapsto \mathrm{section}(r),\; \text{Name} \mapsto \mathrm{lint\_id}(r)\bigr)
$$

该确定性绑定在架构层面保证 $\mathrm{Description} \equiv \mathrm{Specification}$ 这一前提（§7.1 等价链中的最右支），而无需依赖 LLM 自我约束。

## 7. 三层语义对齐验证与机械翻译算子

验证管道包含三个层次，从低成本到高成本递进，形成多重保障；当样本级验证不达阈值时，进一步触发样本级与管道级修复。

### 7.1 三层语义对齐验证

**层次 A：描述溯源性验证。** 该层检查生成代码的 `Description` 字段是否可追溯到源文档，采用由严到宽的三种匹配（逐字符精确、连续子串、句子级语义等价）。由于只关注描述与来源的关系而不解释代码逻辑，验证成本最低，适合作第一道快速过滤器。

**层次 B：基于代码摘要的语义对齐验证。** 这是本研究的核心方法学贡献。传统方法直接判定"代码是否实现规范"，需同时理解代码执行语义与规范约束语义；本研究将该跨模态判定归约为自然语言同义性判定。流程为：从生成代码中提取 `Description`；由摘要算子 $\sigma$ 生成代码摘要，以一句自然语言概括"该代码检查了什么约束"；再判定代码摘要与 `Description` 是否语义等价并输出置信度 $c_{\mathrm{syn}}$。其优势在于 LLM 只需比较两条自然语言陈述而无需推演完整 Go 执行语义，摘要对人类可读，且同义性失败时可由"代码实际表达"与"规范要求"之差为修复提供精确诊断信号。该方法的理论基础是语义等价的传递性：
$$
\mathrm{Code} \equiv \mathrm{Summary} \;\land\; \mathrm{Summary} \equiv \mathrm{Description} \;\land\; \mathrm{Description} \equiv \mathrm{Specification} \;\Rightarrow\; \mathrm{Code} \equiv \mathrm{Specification}
$$

其中 $\mathrm{Code} \equiv \mathrm{Summary}$ 由摘要算子 $\sigma$ 的忠实性提供，$\mathrm{Summary} \equiv \mathrm{Description}$ 由同义性置信度 $c_{\mathrm{syn}}$ 验证，$\mathrm{Description} \equiv \mathrm{Specification}$ 由 §6.7 的确定性后处理（从规范原文注入 `Description`）保证。三项前提依赖不同机制，使整条等价链的失效点可分段归因。需要强调：层次 B 是面向**一般情形**（含外部既有 lint、以及本系统中不可认证的子集）的同义性判定路径；对本系统自身生成、可被下述**证书级语义 oracle** 认证的子集，$\mathrm{Code} \equiv \mathrm{IR}$ 由 oracle 经执行直接*证明*，无需经由 $\sigma$ 摘要这一跳，亦无需 LLM 判官。

**层次 C：编译与结构验证。** 该层执行结构性检查：验证代码可被语法解析、必要的检查函数与元数据字段（描述、引用等）完整存在、所用依赖均被正确导入、且规则注册已完成。与前两层相比，该层偏向可执行性验证，确保生成结果不仅语义可解释，且在目标框架内具备基本结构合法性。

**综合对齐得分。** 四个维度加权平均给出：

$$
S_{\mathrm{align}} = 0.20 \cdot \mathbb{1}[\mathrm{compile}] + 0.10 \cdot \mathbb{1}[\mathrm{struct}] + 0.20 \cdot s_{\mathrm{desc}} + 0.50 \cdot c_{\mathrm{syn}}
$$

其中 $s_{\mathrm{desc}} \in [0,1]$ 为描述溯源性得分，$c_{\mathrm{syn}} \in [0,1]$ 为同义性置信度。同义性置信度占 50% 权重，构成综合判定的主要依据。当 $S_{\mathrm{align}} < \theta$（默认 $\theta = 0.7$）时，系统触发 §8 的反向传播式修复机制。

**证书级语义 oracle（$\mathrm{Code}\equiv\mathrm{IR}$ 的确定性证明）。** 层次 B 的同义性判定由 LLM 判官 $\phi_V$ 给出，是单票、非确定、且会对"前提被丢弃的过严 lint"误盖橡皮章的。对**由本系统自身生成、因而持有 DSL 树 $t$** 的 lint，本研究以一道确定性的**证书级语义 oracle** 取代该判官，分两部分：**(i) 逐原子忠实性认证。** 对每个原子 $a \in \mathcal{A}$，用一个由 JSON 规格驱动的 Go 证书工厂（stdlib `crypto/x509`，其 OID 取值复用 zlint `util.*` 常量以杜绝与 lint 渲染端漂移）合成一对受控 fixture——一张使 $a$ 的谓词为真（期望 $\mathrm{Pass}$）、一张为假（期望 $\mathrm{Error}$，按执行体契约 `if {expr} { Pass } else { Error }`）；再由一个 Go driver 经 zcrypto 解析该 fixture、运行 `CheckApplies`+`Execute`、读回 `LintResult.Status`，当且仅当每张 fixture 都得到期望状态时，$a$ 被**认证**。fixture 按原子类参数化于 $\mathcal{V}$，绝不绑定某一 `rule_id`。**(ii) 结构组合的同义保证。** 一棵仅由已认证原子构成、且渲染后通过 `go build` 的 DSL 树 $t$，其渲染代码 $\rho(t)$ 对 $t$ 的语义**逐原子忠实**，故由结构归纳得 $\mathrm{Code}\equiv t$；又因在可确定性归约的子集上 $t$ 是该规则 IR 的忠实实现（由 IR→树这一跳保证），得 $\mathrm{Code}\equiv\mathrm{IR}$——**无需任何判官**。满足该条件的规则记为**同义可证（synonymy-guaranteed）**，其 $S_{\mathrm{align}}$ 中的 $c_{\mathrm{syn}}$ 项被该证明直接短路为通过。对不在可认证子集内的规则（树含未认证原子、或不可确定性归约），仍回退到层次 B 的 LLM 判官——但此时其判定被显式标注为"未证"，与"已证"分账报告（§9.10）。该 oracle 是**确定性**的：同义可证集合不依赖于生成或判定所用的 LLM 模型，故更换生成器 / 判官模型不改变这一证明子集。需与 §8 中 G3 的"双 oracle"区分：后者指可执行性分类 $\phi_C$ 与外部工具覆盖 $\mathrm{cov}_{\mathcal{T}}$ 两个判定源之间的一致性，而此处的**证书级语义 oracle** 是以真实证书执行结果为真值、证 $\mathrm{Code}\equiv\mathrm{IR}$ 的另一对象，二者不应混淆。

**oracle 的边界与过严哨兵（诚实声明）。** 该 oracle 有三条确定性边界：**(a) fixture 可构造性**——只有能用证书工厂造出"满足 / 违反"区分对的原子才可认证；需要跨证书上下文（子证书 SKI = 签发者 AKI）、密码学事实（模数素性、PSS 参数）或字节级编码（stdlib 发射经 zcrypto 解析的往返会丢原始 ASN.1 tag）的原子无法认证，其规则因而落在"未证"集——这也正是 §9.9 不可归约残差在验证侧的对应面。**(b) 经验性而非定理**——"认证"是在受控 fixture 边界上的有限测试，并非对所有证书的形式证明，其强度取决于 fixture 对真 / 假边界的覆盖。**(c) 共享 OID 表**——fixture 与 lint 渲染端共用同一 `util.*` OID 表（刻意防漂移），故它能捕获发射器逻辑错误、却捕获不到 OID 身份层的错误。此外 oracle 附带一道**过严哨兵**：把同义可证的 lint 在一批真实证书语料上运行，若在大比例有效证书上误报 $\mathrm{Error}$，则疑为"前提被丢弃"的过严 lint——这是 $\mathrm{IR}\neq\mathrm{Spec}$ 的**上游**信号，而非 $\mathrm{Code}\neq\mathrm{IR}$。该哨兵当前因真实语料过窄（约百张同质 CT 监控证书，多为无 AIA / 无策略的叶证书）而仅作**报告、不计入**判据，待更具多样性的语料后方可升为硬门。

**确定性实体级忠实性筛查（必要条件）。** 证书级 oracle 给出 $\mathrm{Code}\equiv\mathrm{IR}$ 的*充分*证明、但只覆盖可认证子集；对其余仍由 LLM 判官判定的 lint，本研究再引入一道**无 LLM 的实体级忠实性筛查** $\mathrm{Faithful}_{\mathrm{nec}}$，作为一个与 oracle、判官皆独立的可机械计算*必要*条件。其依据是一个 sound 的**必要条件**：一条操作于 PKI 实体集 $E(t)$（DSL 树 $t$ 的谓词中出现的 OID 常量与证书字段）的 lint，忠实于规则 $r$ 的前提是——$t$ 所检查的每个主要实体都在 $r$ 的文本中被提及：

$$
\mathrm{Faithful}_{\mathrm{nec}}(t, r) \;\Longleftrightarrow\; \forall\, e \in E_{\mathrm{prim}}(t):\ \mathrm{alias}(e) \cap \mathrm{tokens}\bigl(\mathrm{text}(r)\bigr) \neq \varnothing,
$$

其中 $\mathrm{alias}(\cdot)$ 是一座由"自动词干化（去 OID 后缀、拆驼峰、去 Oid/Id/Ad 方法前缀、去连字符）+ 一张冻结的标准扩展词表别名"构成的桥。筛查给出三种判读：$\mathtt{ENTITY\_OK}$（每个实体都在文本中点名）、$\mathtt{ENTITY\_MISMATCH}$（lint 检查了文本从未提及的实体——可疑）、$\mathtt{NO\_ENTITY}$（谓词不引用任何 OID/字段实体，如纯结构检查，判定不适用）。该筛查**不是**完全语义等价证明（后者不可判定），而是一个可机械计算的必要条件，专门捕获"分段/指代把错误主语交给代码生成"的失效模式——例如一条关于 authorityCertIssuer / authorityCertSerialNumber（二者均为 AKI 字段）的规则，其 IR 主语被误抽为 AIA 扩展、归约出 $\mathrm{ExtPresent}(\mathrm{AIA})$：筛查会标记"AIA 在文本中从未出现"。由于它确定性且与判官独立，可与非确定性的层次 B 相互交叉验证——二者分歧之处，要么定位到指代盲区（实体在节标题而非句中），要么定位到真正的主语错抽。其已知盲区（诚实声明）有二：指代（"this extension"）与别名表的词表缺口（如具体曲线/签名算法名），两者都表现为**保守地多报** $\mathtt{ENTITY\_MISMATCH}$ 而非漏报，与 IR-字段溯源守卫同向偏保守。

### 7.2 样本级局部修复算子

记 $\rho_G^{\mathrm{loc}}$ 为作用于单条规则的局部修复算子，含两类子操作：

$$
\rho_G^{\mathrm{loc}}(t, c) \;=\; \begin{cases}
\Phi_{\mathrm{post}}(t, r), & \text{Description / Citation 偏差} \\
\phi_G\bigl(r,\; \mathrm{feedback}(\eta(s), \mathcal{V}, \mathcal{A})\bigr), & \eta(s) = \mathrm{Err} \;\text{或}\; \mathrm{compile}(\rho(t)) = 0
\end{cases}
\tag{7}
$$

第一支为**幂等闭式修复**：对可溯源字段调用 §6.7 的 $\Phi_{\mathrm{post}}$ 一次即终止，复杂度 $O(1)$；第二支为**类型反馈式重生成**：将解析错误（哪一原子签名不满足）或编译错误以结构化形式注入提示，触发 LLM 重新合成 DSL 树。$\rho_G^{\mathrm{loc}}$ 的迭代上界为 $K_{\mathrm{loc}}$（默认 3）。在该上界内仍未达到 $S_{\mathrm{align}} \geq \theta$ 的样本进入 §8 的管道级修复——此时错误源已不在样本本身的字段或语法层，而需沿管道 $\Pi = \phi_V \circ \phi_G \circ \phi_C \circ \phi_R$ 反向归因。两层修复的分工对应**算子-管道两级**：$\rho_G^{\mathrm{loc}}$ 不改变 $\mathcal{V}$、$\mathcal{A}$ 与 $\phi_C$ 的输出，§8 的 $\rho_R / \rho_C / \rho_G / \rho_V$ 才允许触及这些更上游的对象。

### 7.3 端到端生成算法

算法 1 给出在原子 DSL 受限代码空间下的端到端合成-验证流程。整个流程不依赖任何模板分类，而是以 $(\mathcal{V}, \mathcal{A})$ 这一对全局结构作为唯一的代码空间约束。

```
算法 1：DSL 受限合成与验证
输入：可执行规则 r ∈ R_L，词汇表 V，原子集 A，LLM 模型 M，对齐阈值 θ
输出：可编译 Go 代码 Φ_post(t, r) 或失败标志

 1: prompt ← BuildPrompt(r, V, A)
 2: for k = 1 to K_loc do
 3:     s ← M.generate(prompt)                        // LLM 输出 JSON
 4:     case η(s):
 5:         ⊥_NT  : return FAIL("no_template", reason)
 6:         Err   : prompt ← prompt ⊕ feedback(η(s))   // 类型错误反馈
 7:                 continue
 8:         t ∈ T_V :
 9:             code ← Φ_post(t, r)
10:             if not compile(code) then
11:                 prompt ← prompt ⊕ feedback(compile_error(code))
12:                 continue
13:             S_align ← Verify(code, r)              // §7.1 综合对齐得分
14:             if S_align ≥ θ then return code
15:             prompt ← prompt ⊕ feedback(S_align, σ_mech(t))
16: return FAIL("local_repair_exhausted", t)           // 进入 §8 管道级修复
```

算法 1 在 $K_{\mathrm{loc}}$ 内终止，每条规则的主要开销为 LLM 调用。在 $\eta$ 与 $\Phi_{\mathrm{post}}$ 的封闭性保证下，进入第 14 行返回分支的代码同时满足：(i) $t \in \mathcal{T}_{\mathcal{V}}$（词汇封闭）；(ii) $\rho(t)$ 通过 Go 编译；(iii) $\sigma_{\mathrm{mech}}(t)$ 与 $\mathrm{spec}(r)$ 经 $\phi_V$ 判定同义置信度满足 $S_{\mathrm{align}} \geq \theta$（在 $\theta = 0.7$ 时蕴含 $c_{\mathrm{syn}} \geq 0.4$）。这三项构成对返回代码"语义可追溯 + 结构可执行 + 类型受约束"的下界保证。

### 7.4 端到端示例

以 RFC 5280 §4.2.1.9 关于 dNSName 编码的规则为例。规范原文："Conforming implementations MUST convert internationalized domain names to the ASCII Compatible Encoding (ACE) format ... before storage in the dNSName field." 经受控提取得到 IR：

```json
{
  "rule_id": "RFC5280:4.2.1.9-R03",
  "subject": "SubjectAltName.dNSName",
  "obligation": "MUST",
  "predicate": "encode_as",
  "constraint": {"format": "ACE", "ref": "RFC 3490 §4"},
  "precondition": null
}
```

LLM 在得到原子集 $\mathcal{A}$ 与词汇表 $\mathcal{V}$ 后，输出 DSL 树（主断言为"DNSNames 列表中每一项匹配 ACE-或-ASCII 标签正则"）。经 $\eta$ 解析为合法 $t \in \mathcal{T}_{\mathcal{V}}$ 后，$\rho$ 渲染为检查体，$\Phi_{\mathrm{post}}$ 注入 `Description / Citation / Source / Name` 等可溯源字段。$\sigma_{\mathrm{mech}}(t)$ 输出机械摘要 _"every entry in DNSNames matches the ACE-or-ASCII label regex"_，$\phi_V$ 比对该摘要与原文 `Description` 得 $c_{\mathrm{syn}} = 0.92$，综合对齐得分 $S_{\mathrm{align}} = 0.20 + 0.10 + 0.20 + 0.5 \times 0.92 = 0.96 > 0.7$，验证通过。注意整个流程中 LLM 输出的所有命名均落在 $\mathcal{V} \cup \mathcal{A}$ 之内——若 LLM 编造一个不存在的字段（如 `cert.IDN_Names`），$\eta$ 会拒绝并触发反馈式重生成，该幻觉路径在架构层即被关闭。

## 8. 反向传播式迭代验证框架（BIIV）

### 8.1 动机与问题陈述

第 6–7 节给出的方法在单次前向生成下已能产出结构完整的 zlint 代码，但在缺少独立人工真值的大规模场景中，系统仍面临三类不可回避的质量风险：**其一**，上游 IR 提取可能漏召回规范性条款，使下游生成从根本上无从验证；**其二**，可执行性分类本身可能出错，若被误判为 `non_lintable`，其后所有检查均失去对象；**其三**，即便分类正确，代码语义仍可能在字段访问路径、边界条件或触发逻辑层面偏离原文。这三类风险分别归因于召回、分类与生成三个阶段。

传统自动合规代码生成多采用"单向前向 + 启发式重试"模式，其反馈信号要么是单一标量（如编译是否通过）、要么是粗糙的布尔指示，难以定位具体出错阶段。为此，本研究借鉴神经网络反向传播的基本思想，构造一个**沿管道反向定位误差来源并触发阶段性修复**的迭代验证机制（BIIV）。该机制并不学习参数，而是将若干可直接计算的不变量作为端到端损失信号，**在无独立真值条件下提供可收敛、可追溯的质量控制**。这一点至关重要：它使整条管道的质量保证不再依赖于对每条规则的人工标注，而是由结构性不变量（规则集合守恒）与客观外部证据（工具实现存在性）共同支撑——质量验证因此由可计算残差承担，而非由独立的人工真值集合承担。

### 8.2 形式化定义

定义受控规范-代码生成管道 $\Pi$ 为四阶段复合函数：

$$
\Pi = \phi_V \circ \phi_G \circ \phi_C \circ \phi_R
$$

其中 $\phi_R$ 为 RFC 2119 关键词驱动的规则召回模块（对 ETSI 标准族则采用等价关键词集合 $\mathcal{K}_{\mathrm{ETSI}}$ 作为召回算子 $\phi_R^{\mathrm{ETSI}}$）、$\phi_C$ 为五条件可执行性分类模块（§5）、$\phi_G$ 为受限于 DSL 代码空间 $\mathcal{T}_{\mathcal{V}}$（§6）的 LLM 合成模块、$\phi_V$ 为三层语义对齐验证模块（§7）。给定标准文档 $\mathcal{D}$，令 $\mathcal{R}_{\mathrm{kw}}(\mathcal{D})$ 为 $\phi_R$ 召回的候选规则集合；对每条 $r \in \mathcal{R}_{\mathrm{kw}}$，$\phi_C$ 将其映射至互斥三元分类空间 $\{\mathrm{noise}, \mathrm{lintable}, \mathrm{nonLintable}\}$，记由此得到的三个子集为 $\mathcal{R}_N$（噪声）、$\mathcal{R}_L$（可执行）、$\mathcal{R}_U$（不可执行但具规范性义务）。

### 8.3 召回完整性不变量

**定理 1（召回完整性不变量）**。*若 $\phi_R$ 对非 ETSI 标准族仅由 RFC 2119 关键词触发，且 $\phi_C$ 为 $\mathcal{R}_{\mathrm{kw}}$ 上的互斥穷尽划分，则以下守恒关系成立：*

$$
|\mathcal{R}_{\mathrm{kw}}(\mathcal{D})| = |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U| \tag{8}
$$

直观含义是：一旦关键词召回完成，规则总量在下游任何分类步骤中都不应增加或减少。式 (8) 因此构成一个**结构性闭合条件**：若在任意阶段观测到等式不成立，则必可断定某下游模块引入了规则级别的增删误差。**该性质无需任何人工真值即可计算**，因此可在缺乏 ground truth 的大规模场景下作为第一级质量信号。对于 ETSI 标准族，不变量相应替换为 $|\mathcal{R}_{\mathrm{kw}}^{\mathrm{ETSI}}(\mathcal{D})| = |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U|$，其余推理不变。

### 8.4 代码正确性标签

设 $r \in \mathcal{R}_L$，$c = \phi_G(r)$。由于 $c$ 的 `Description` 已由确定性后处理与规范原文 $\mathrm{spec}(r)$ 对齐（§6.7），代码正确性标签 $\lambda_{\mathrm{code}}(r) \in [0,1]$ 由以下乘积度量：

$$
\lambda_{\mathrm{code}}(r) = \mathbb{1}[\mathrm{compile}(c)] \cdot s_{\mathrm{struct}}(c) \cdot c_{\mathrm{syn}}(\sigma(c),\; \mathrm{spec}(r)) \tag{9}
$$

基于 §7.1 的语义等价传递链，若 $\sigma(c) \equiv \mathrm{spec}(r)$ 且 `Description` $\equiv \mathrm{spec}(r)$，则可在不实际解析 Go 代码语义的前提下推得 $c \equiv \mathrm{spec}(r)$。对由证书级语义 oracle 认证为同义可证的 $r$，式 (9) 中的 $c_{\mathrm{syn}}$ 项以 oracle 的二值 $\mathrm{Code}\equiv\mathrm{IR}$ 证明取代（取 $1$），$\lambda_{\mathrm{code}}$ 退化为 $\mathbb{1}[\mathrm{compile}(c)]\cdot s_{\mathrm{struct}}(c)$ 与该证明的合取，不再经由非确定的 $c_{\mathrm{syn}}$。

### 8.5 损失函数

将上述标签组合为端到端损失：

$$
\mathcal{L}_{\mathrm{recall}}(\mathcal{D}) = 1 - \frac{\min(|\mathcal{R}_{\mathrm{kw}}|, |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U|)}{\max(|\mathcal{R}_{\mathrm{kw}}|, |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U|)} \tag{10}
$$

$$
\mathcal{L}_{\mathrm{code}}(\mathcal{D}) = 1 - \frac{1}{|\mathcal{R}_L|} \sum_{r \in \mathcal{R}_L} \lambda_{\mathrm{code}}(r) \tag{11}
$$

$$
\mathcal{L}_{\mathrm{total}}(\mathcal{D}) = w_R \cdot \mathcal{L}_{\mathrm{recall}} + w_C \cdot \mathcal{L}_{\mathrm{code}}, \quad w_R + w_C = 1 \tag{12}
$$

默认 $w_R = w_C = 0.5$。定理 1 描述的是 $\phi_C$ 作为互斥穷尽划分时的**理想恒等**，而 $\mathcal{L}_{\mathrm{recall}}$ 是对该不变量在**实际运行**中被违反程度的经验度量——现实中 $\phi_C$ 由 LLM 辅助实现，可能因漏判或幻觉破坏等式。对称归一化形式可同时惩罚两个误差方向：$|\mathcal{R}_{\mathrm{kw}}|$ 大于划分之和意味着分类模块丢弃了部分召回规则，反之意味着产生了额外的规则级条目。

### 8.6 反向定位规则

先引入两个辅助量。**编译失败率** $p_{\mathrm{fail}}^{(t)} = \frac{1}{|\mathcal{R}_L|} \sum_{r \in \mathcal{R}_L} \mathbb{1}[\neg\mathrm{compile}(\phi_G(r))]$；**平均结构得分** $\bar{s}_{\mathrm{struct}}^{(t)} = \frac{1}{|\mathcal{R}_L|} \sum_{r \in \mathcal{R}_L} s_{\mathrm{struct}}(\phi_G(r))$。据此，第 $t$ 轮的阶段归因规则为：

$$
\mathrm{Stage}^{(t)} = \begin{cases}
\phi_R, & \mathcal{L}_{\mathrm{recall}}^{(t)} > \tau_R \\
\phi_C, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} > \tau_C \\
\phi_G, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} < 1 \\
\phi_V, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} = 1
\end{cases}
\tag{13}
$$

四条分支两两互斥，构成对观测状态空间的完备划分（默认 $\tau_R = \tau_C = 0.10$）：**首先**检查结构性不变量是否违反——若违反，任何下游修复均无意义，必须回到 $\phi_R$；**其次**若结构不变量满足但编译失败率超 $\tau_C$，错误多来自 $\phi_C$ 误分类；**第三**，若编译普遍通过但语义对齐低且平均结构得分 $<1$，错误位于 $\phi_G$ 本身；**最后**，若结构完整且编译通过但同义率偏低，可能源于 $\phi_V$ 的判定偏差。

### 8.7 阶段修复算子

针对每一被归因阶段，设计一组阶段内修复算子 $\rho_R, \rho_C, \rho_G, \rho_V$，并在 IR 内容错误路径上补充自反思修复算子 $\rho_{\mathrm{IR}}$：

- **$\rho_R$（召回修复）**：对缺口区间重跑关键词正则，补充被误分词项（如 "MUST NOT" 因分词被拆为 "MUST"+"NOT"），或将候选规则的最小窗口从句级扩展至子句级。$\rho_R$ 仅处理 G1 数量缺口，不修 IR 内容。
- **$\rho_C$（分类修复）**：引入多工具交叉证据——若规则在 zlint、pkilint、certlint、x509lint 至少一个中存在对应实现，则必然可执行；若被判为 `non_lintable`，即视为假阴性回传 $\phi_C$ 重判（见 §8.9）。
- **$\rho_G$（生成修复）**：先尝试确定性修复（如 `Description`/`Citation` 字面替换）；若失败，将失败码片段与 IR 约束差异、或解析阶段的原子签名/封闭性错误作为反馈注入提示，触发 LLM 在 $\mathcal{T}_{\mathcal{V}}$ 内重新合成；若持续返回 $\perp_{\mathrm{NT}}$，则该规则进入 §8.11 的离线词汇扩展通道 $\rho_A$。
- **$\rho_V$（验证修复）**：扩大同义判定的语义邻域（如允许否定/肯定互换、一对多分解），或在摘要阶段引入推理链提示以缩小抽象层差。
- **$\rho_{\mathrm{IR}}$（IR 内容自反思修复）**：当 $\phi_G$ 在 $K_{\mathrm{loc}}$ 轮内持续返回 $\perp_{\mathrm{NT}}$、或 G2 同义性持续低于阈值时，将下游所有失败信号（当前 IR、编译结果、摘要、判官理由、历史尝试）构成完整反向失败轨迹回传 LLM，令其诊断并决定：**(a)** 更正 IR 的 subject/predicate/constraint/precondition，或 **(b)** 声明 `NO_FIX`——确认当前词汇 $(\mathcal{A}, \mathcal{V})$ 确实不足以表达该规则。LLM 返回的修正须经 g4-sanity 事后闸门（§8.7.1）校验方可进入后续流程；未通过者被拒，该规则归入**不可归约残差** $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$——即 IR 正确而表达力已至边界的规则集合，其经验识别与五类分群披露见 §9。

$\rho_{\mathrm{IR}}$ 与其余算子的本质区别在于：其余算子修复目标在 $\phi_C$、$\phi_G$、$\phi_V$ 阶段内，而 $\rho_{\mathrm{IR}}$ 修复的是 NL$\to$IR 提取阶段（管道最上游的 LLM 端）。这也是 BIIV 链路在 $\rho_{\mathrm{IR}}$ 加入后第一次真正覆盖从规范文本到代码的**完整五阶段**。

#### 8.7.1 g4-sanity：IR 修复后的事后闸门

$\rho_{\mathrm{IR}}$ 将修复权交给 LLM，因此需要一个轻量的**事后合法性闸门**防止引入新幻觉。g4-sanity 对返回的新 IR 执行三项无需 ground truth 的检查：**(1) Subject 可解析性**——新 IR 的 `subject` 须能被确定性字段解析器解析为合法的 $\mathcal{V}$ 内字段路径；**(2) 约束值溯源性**——`constraint.value`（若存在）须作为子串出现于规则原文中（允许 OID 符号名前缀剥离与十六进制归一化）；**(3) 谓词极性一致性**——`predicate` 极性须与原文 RFC 2119 关键词极性相符（MUST NOT/SHALL NOT→`must_not_*`；MUST/SHALL→`must_*`；MAY→`may_*`）。任一项失败即视为修复引入幻觉，拒绝新 IR。g4-sanity 是事后闸门而非事前分类器——不预判错误类型，仅在修复后验证合法性。

### 8.8 迭代算法与终止条件

算法 2 给出完整流程。

```
算法 2：反向传播式迭代验证（BIIV）
输入：标准文档 D，阈值 θ，最大迭代数 K，权重 (w_R, w_C)
输出：最终代码集 C* 与收敛标志 converged

1:  (R_kw, R_N, R_L, R_U) ← Π(D)
2:  C ← {φ_G(r) : r ∈ R_L}
3:  t ← 0
4:  repeat
5:      L_recall ← 式 (10);  L_code ← 式 (11);  L_total ← w_R·L_recall + w_C·L_code
6:      if L_total < θ then break
7:      stage ← StageAttribution(L_recall, L_code, p_fail, s̄_struct)   // 式 (13)
8:      apply ρ_{stage} to the corresponding module
9:      更新 (R_kw, R_N, R_L, R_U) 与 C
10:     t ← t + 1
11: until t ≥ K or stage = ⊥
12: return (C, L_total < θ)
```

**终止条件**：$\mathcal{L}_{\mathrm{total}} < \theta$（默认 $\theta = 0.05$）或达到最大迭代数 $K = 10$；若连续两轮归因阶段相同且损失未下降，终止并标记为局部不收敛。**收敛性**：由于每一阶段修复算子均为单调操作（要么严格减少该阶段误差项，要么保持不变），且 $\mathcal{L}_{\mathrm{total}}$ 每轮非递增，故序列 $\{\mathcal{L}_{\mathrm{total}}^{(t)}\}$ 必然收敛；该收敛点不保证全局最优，实证中亦观察到部分样本收敛于次优解（见 §9）。

### 8.9 难点一：可执行性判定的外部验证

反向传播式迭代无法对 $\phi_C$ 的**绝对正确性**给出梯度信号——召回完整性不变量仅约束总量守恒，而不约束三元划分的正确性。为缓解这一缺口，本研究提出基于**外部证据融合**的间接验证策略。设 $\mathcal{T} = \{\mathrm{zlint}, \mathrm{pkilint}, \mathrm{certlint}, \mathrm{x509lint}\}$，$\mathrm{Impl}_{\mathcal{T}}(r) = 1$ 当且仅当 $r$ 已在 $\mathcal{T}$ 任一工具中被实现为静态检查，则：

$$
\mathrm{Impl}_{\mathcal{T}}(r) = 1 \Rightarrow r \in \mathrm{Lintable} \tag{14}
$$

因此若系统判定 $r \in \mathcal{R}_U$ 但 $\mathrm{Impl}_{\mathcal{T}}(r) = 1$，则必为假阴性。该策略的重要性质是**可执行性语言无关**——规则是否可程序化表达与实现语言（Go/Python/Ruby/C）无关，故五条件框架在所有工具上同时适用。由此 $\rho_C$ 可利用 $\mathcal{T}$ 任一工具的规则库作为"真阳性种子集"，**在不依赖人工标注的条件下**获得对 $\phi_C$ 召回率的下界估计。需要强调式 (14) 仅提供单向推论，**不能**反向用于证伪：工具未实现某规则并不意味着该规则不可执行，因为工具实现范围受工程资源限制。因此本策略只验证召回率而非精确率，其局限将在 §11 进一步讨论。

### 8.10 难点二：分类准确性的二路交叉验证

对无法通过外部工具覆盖的规则，本研究采用二路交叉验证。**(i) 下游一致性**：若规则被判为 `lintable` 但在 $K$ 次独立生成尝试中均无法产出可编译代码，则提高其被误分类的后验概率并触发 $\rho_C$ 重判。**(ii) 多次抽样一致性**：对随机抽样规则重复分类 $n$ 次，计算一致性率 $\gamma = \frac{1}{n}\max_y \sum_{i=1}^{n}\mathbb{1}[\phi_C^{(i)}(r)=y]$；$\gamma < 1$ 的样本被认为分类不稳定，需复核。

**(iii) 下游一致性触发 $\rho_C$ 重判的形式化。** 设 $K$ 为对单条 $r \in \mathcal{R}_L$ 的独立 codegen 尝试数（取 $K = 5$），定义降级算子

$$
\rho_C^{\downarrow}(r) =
\begin{cases}
r \in \mathcal{R}_U, & \text{若 } \sum_{k=1}^{K} \mathbb{1}[\phi_G^{(k)}(r) = \perp_{\mathrm{NT}}] = K \text{ 且 audit 确认 } r \notin \mathrm{StaticallyObservable} \\
r \in \mathcal{R}_L, & \text{否则}
\end{cases}
\tag{15}
$$

两个触发条件须同时成立：纯粹的下游连续失败仅提示假阳性嫌疑（可能源自 codegen 端瓶颈或 atom 缺失），需 audit 端独立确认规则的实际 scope/subject 可观察性后才执行迁移，以防 codegen 端暂时性失败把真 lintable 规则误降级。

**(iv) IR schema 的 verifiability 字段拆分。** 当 LLM-$\phi_C$ 的判错来自 description 字段的结构压平（section heading 与表格主体被合并为单行），$n$ 次独立抽样会复现同一偏差（**稳定假阳性**），使 $\gamma = 1$ 而不触发 (ii) 的复核。为通用化地堵此漏洞，将 `verifiability` 字段拆为两个独立标注：

$$
\mathrm{verifiability}(r) = \big(\mathrm{verif}_{\mathrm{subject}}(r),\; \mathrm{verif}_{\mathrm{scope}}(r)\big) \in \{\mathrm{observable},\mathrm{unobservable}\}^2
\tag{16}
$$

其中 $\mathrm{verif}_{\mathrm{subject}}$ 标注约束本体是否在证书静态文本中可观察，$\mathrm{verif}_{\mathrm{scope}}$ 标注 precondition 是否可观察。Lintable 谓词由二者合取给出：

$$
\mathrm{StaticallyObservable}(r) \iff \mathrm{verif}_{\mathrm{subject}}(r) = \mathrm{observable} \;\wedge\; \mathrm{verif}_{\mathrm{scope}}(r) = \mathrm{observable}
\tag{17}
$$

拆分前的单字段 schema 允许"约束本体可观察 + scope 不可观察"被笼统判为 observable；拆分后须独立判定两项，单点失败即触发重审。该改动是**通用 schema 改造**，对所有规则同等适用，不为任一条规则定制。

### 8.11 难点三：原子词汇表的离线扩展

当某条规则 $r$ 的语义无法用当前 $(\mathcal{A}, \mathcal{V})$ 表达时，LLM 给出 $\phi_G(r) = \perp_{\mathrm{NT}}$。定义 $\rho_A : (\mathcal{A}, \mathcal{V}) \to (\mathcal{A}', \mathcal{V}')$ 为离线词汇扩展算子，其在保持下式约束下扩张代码空间：

$$
\mathcal{A} \subseteq \mathcal{A}', \quad \mathcal{V} \subseteq \mathcal{V}', \quad \mathcal{T}_{\mathcal{V}} \subseteq \mathcal{T}_{\mathcal{V}'}
\tag{18}
$$

即 $\rho_A$ **仅向上单调扩张**——已可表达的规则在新版本中仍可表达，已生成代码仍合法，该单调性保证扩展不破坏先前实验的可比性。其流程为：聚合经 $K_{\mathrm{loc}}$ 轮局部修复后仍返回 $\perp_{\mathrm{NT}}$ 的规则集合 $\mathcal{R}_{\perp}$，以 IR 谓词或 `subject` 为键聚类，对每个同质簇设计新原子（给出签名、$\rho$ 中 Go 模板与 $\sigma_{\mathrm{mech}}$ 中短语），再在新代码空间上重试。需强调 $\rho_A$ 是**离线人工设计**操作，不进入运行时迭代——因为扩展原子集涉及对 PKI 语义的判断，目前不属于 LLM 自动化的合理边界。$\rho_A$ 因此属于框架的**设计-时演化路径**，对 §8.8 的运行时收敛性非递增前提不构成影响。

### 8.12 与直接神经反向传播的区别

本研究中"反向传播"系类比性使用。与标准神经网络反向传播相比，BIIV 的关键差异为：**(i)** 不存在可微参数空间——阶段修复为离散规则重写而非梯度下降；**(ii)** 损失信号为结构性不变量与同义性置信度，而非端到端训练损失；**(iii)** 反向过程为阶段归因而非链式求导。两者在"以可计算信号沿管道反向定位误差并进行有方向修复"这一思想层面高度相似，此为采用该术语的主要依据。

### 8.13 机械翻译算子 $\sigma_{\mathrm{mech}}$：代码摘要的确定化替代

§7.1 将摘要算子 $\sigma$ 实现为 LLM 调用。当上游代码生成由原子 DSL 树驱动时，$\sigma$ 的输入并非任意 Go 源码，而是一类**可结构化拆解**的代码体，此时由 LLM 实现 $\sigma$ 会引入一类可被消除的系统性失真。

**条件分支上的系统性 NA-反转失真。** 考察形如下式的检查体：

```
if !(P) { return NA }   // 规则不适用
if Q    { return Pass }  // 适用且满足
return  Severity         // 适用但违反
```

该形式表达"当 $P$ 成立（规则适用）时 $Q$ 必须成立；$P$ 不成立时返回 NA"的条件语义，对应规范原文"WHEN $P$, THEN $Q$"的蕴含结构。然而经验观测发现，由 LLM 实现的 $\sigma$ 倾向于将 $P$ 直接复述为"WHEN"分句内容，丢失"$\neg P \Rightarrow \mathrm{NA}$"的极性反转；即便在提示中显式给出对照示例并要求取反，重复试验仍稳定复现该失真——它因此不属于 prompt 工程可消除的范畴，而是 $\sigma$ 由概率模型实现时的固有偏差。

**$\sigma_{\mathrm{mech}}$ 的定义。** 当代码生成端持有结构化 DSL 树 $t$ 时，可绕过 Go 源码直接对 $t$ 实施结构归纳翻译 $\sigma_{\mathrm{mech}} : \mathcal{T} \to \mathcal{L}_{\mathrm{NL}}$。它由两组规则给出：(i) 对每个原子 $a \in \mathcal{A}$ 预先指派固定 PKI 语义短语 $\mu(a)$，记入闭合词典 $\mathcal{M} : \mathcal{A} \to \mathcal{L}_{\mathrm{NL}}$；(ii) 对组合子按 $\mu(\neg t) = $ "NOT ($\mu(t)$)"、$\mu(t_1 \wedge t_2) = $ "($\mu(t_1)$) AND ($\mu(t_2)$)"、$\mu(t_1 \vee t_2) = $ "($\mu(t_1)$) OR ($\mu(t_2)$)" 递归。对含条件前提的二元组，当 $\mathrm{pre} = \neg(\mathrm{pre.inner})$ 时显式生成 "WHEN NOT ($\mu(\mathrm{pre.inner})$), THEN $\mu(\mathrm{pred})$"。

**关键性质。** $\sigma_{\mathrm{mech}}$ 具三项性质：**全函数性与确定性**（在合法 DSL 树空间上为全函数且不引入概率项，相同输入恒产生相同输出）；**极性正确性**（条件前提为否定时显式生成 "WHEN NOT" 形式，消除 LLM-$\sigma$ 的 NA-反转失真）；**可逆性**（命题 2）。

**命题 2（$\sigma_{\mathrm{mech}}$ 可逆性）**。*给定 $\sigma_{\mathrm{mech}}(t)$ 的输出，原始 DSL 树 $t$ 在原子层等价意义下可机械恢复（同义原子被映射到同一短语时不可区分，其余结构保留）。该性质保证 $\sigma_{\mathrm{mech}}$ 在反向传播链路中不构成信息瓶颈。*

**对反向传播链路的意义。** 引入 $\sigma_{\mathrm{mech}}$ 后，语义传递链 $\mathrm{Spec} \to \mathrm{IR} \to t \xrightarrow{\sigma_{\mathrm{mech}}} \mathrm{Summary} \equiv \mathrm{Description}$ 中，LLM 仅在 $\phi_C$、$\phi_V$ 两端出现，其余环节均为确定性算子。由此链路上的概率失真被压缩至**原子词典 $\mathcal{M}$ 的选择**这一离线设计问题，而不再随每条规则的判定独立采样。需强调 $\sigma_{\mathrm{mech}}$ 仅适用于**由本系统自身代码生成器产出的 lint**（其前提是持有 DSL 树）；对纯人工编写或来自外部仓库的既有 lint，仍需 LLM-$\sigma$ 提取语义。

### 8.14 不变量残差 L4b 修复

§8.9 引入了"实现存在性 $\Rightarrow$ 可执行性"的单向推论。本节将其扩展为一个**双向 falsifiable 残差**，并给出基于二元判官的修复机制。给定外部工具集 $\mathcal{T}$ 及覆盖判定 $\mathrm{cov}_{\mathcal{T}} : r \mapsto \{\text{full}, \text{partial}, \text{none}\}$，定义违反集合 $\mathcal{V} = \{ r : \mathrm{cov}_{\mathcal{T}}(r) \in \{\text{full}, \text{partial}\} \land \phi_C(r) \neq \mathrm{lintable} \}$，记 $N_{\mathrm{viol}} = |\mathcal{V}|$。若 $\phi_C$ 与 $\mathrm{cov}_{\mathcal{T}}$ 同时正确则 $N_{\mathrm{viol}} = 0$，因此 $N_{\mathrm{viol}}$ 构成一个不依赖人工真值的可计算残差。

**FLIP-or-SPURIOUS 二元判官。** 对每条 $r \in \mathcal{V}$ 调用仲裁判官 $\phi_J : r \to \{\mathrm{FLIP}, \mathrm{SPURIOUS}\}$，输入为规则原文与覆盖证据：**FLIP** 表示 $\phi_C(r)$ 错判，应翻转为 lintable；**SPURIOUS** 表示 $\mathrm{cov}_{\mathcal{T}}(r)$ 为假阳，应降级为 none。任一支被采纳后对应标签被修正，$r$ 离开 $\mathcal{V}$。

**命题 3（残差单调性）**。*若 $\phi_J$ 在每条违反上均给出 FLIP 或 SPURIOUS 之一并被采纳，则 L4b 一轮过程后 $N_{\mathrm{viol}}$ 严格下降至 0。* 证明梗概：FLIP 使 $\phi_C(r) = \mathrm{lintable}$（违反式右侧成立），SPURIOUS 使 $\mathrm{cov}_{\mathcal{T}}(r) = \mathrm{none}$（违反式左侧不再触发），两类修复均移除该 $r$ 而不引入新违反，$\mathcal{V}$ 严格收缩至空集。

L4b 在 §8.7 的修复算子分类下属于 $\rho_V$ 的一种特化：它不调整代码本身或生成模块，而是修正双 oracle 输出之间的不一致；触发条件为 $N_{\mathrm{viol}} > 0$，终止条件为 $N_{\mathrm{viol}} = 0$。该扩展使式 (14) 的 falsifiable 残差具备真正的"零点"，从而可作为收敛判据。

### 8.15 三目标分解：面向规范工程师的诠释性视角

为便于工程落地，本节将前述形式化不变量重述为三个目标，每一目标对应一个可计算残差；框架的收敛态由三残差同时为零刻画。

**目标 G1（召回完整性）。** 所有召回的候选规则必被互斥划分为噪声、可执行、不可执行三类，可执行类又细分为"已被外部工具覆盖"与"未覆盖"两子类：

$$
|\mathcal{R}_{\mathrm{kw}}| = |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U|, \qquad |\mathcal{R}_L| = |\mathcal{R}_L^{\mathrm{cov}}| + |\mathcal{R}_L^{\mathrm{uncov}}|
$$

第一式即式 (8)，G1 的残差为 $\mathcal{L}_{\mathrm{recall}}$（式 10）。

**目标 G2（未覆盖可执行规则的代码-规范同义）。** 对 $r \in \mathcal{R}_L^{\mathrm{uncov}}$，生成代码经 $\sigma_{\mathrm{mech}}$ 或 $\sigma_{\mathrm{LLM}}$ 提取摘要后须与规范原文同义：$\forall r \in \mathcal{R}_L^{\mathrm{uncov}}, \; c_{\mathrm{syn}}(\sigma(\phi_G(r)), \mathrm{spec}(r)) \geq \tau_{\mathrm{syn}}$。G2 的残差为 $\mathcal{L}_{\mathrm{code}}$（式 11）。由于自动生成的主要价值在于补足生态之外的空白，未覆盖子集是 G2 最重要的观测域。

**目标 G3（被覆盖规则的反向可执行性证明）。** 对 $r \in \mathcal{R}_L^{\mathrm{cov}}$，外部工具存在静态实现这一事实被作为 $\phi_C$ 判其可执行的反向证据，以双向 falsifiable 形式给出：

$$
\forall r : \quad \mathrm{cov}_{\mathcal{T}}(r) \in \{\text{full}, \text{partial}\} \;\Longrightarrow\; \phi_C(r) = \mathrm{lintable}
\tag{19}
$$

$$
N_{\mathrm{viol}}(\mathcal{D}) = \bigl| \{\, r \in \mathcal{D} \mid \mathrm{cov}_{\mathcal{T}}(r) \in \{\text{full}, \text{partial}\} \;\wedge\; \phi_C(r) \neq \mathrm{lintable} \,\} \bigr|
\tag{20}
$$

G3 的硬等式收敛条件为 $N_{\mathrm{viol}} = 0$。其残差结构（集合基数）与 G1（守恒等式）、G2（连续平均损失）在数学形式上不同构，这也是该残差通过 §8.14 单独定义的根本原因。三目标残差在反向传播链路中职责互补：

| 目标 | 残差 | 主要修复算子 | 修复对象 |
|---|---|---|---|
| G1 | $\mathcal{L}_{\mathrm{recall}}$（式 10） | $\rho_R$ | 召回窗口 / 关键词集合 |
| G2 | $\mathcal{L}_{\mathrm{code}}$（式 11） | $\rho_G$（含 $\sigma$ 确定化）；$\rho_{\mathrm{IR}}$ | DSL 树重合成 / $\sigma_{\mathrm{mech}}$ 替换 / IR 修正 |
| G3 | $N_{\mathrm{viol}}$（式 20） | $\rho_V$（L4b 二元判官） | $\phi_C$ 假阴性 / $\mathrm{cov}$ 假阳性 |

G1 关注规则集合的封闭性，G2 关注生成代码的语义忠实性，G3 关注双 oracle 之间的一致性；三者构成对端到端管道质量的覆盖性度量。当 $\mathcal{L}_{\mathrm{recall}} = \mathcal{L}_{\mathrm{code}} = N_{\mathrm{viol}} = 0$ 时，BIIV 进入闭合态——此即 §9 报告的"残差全部归零"的工程含义。

## 9. 实验与实证评估

本节的实证评估覆盖端到端框架的前后两半，并按"无独立人工真值"的原则组织：所有质量信号均来自系统估计、结构性不变量、跨运行一致性或外部工具客观证据，而非对单条规则的人工标注。

### 9.1 实验设置

实证分为两个互补的范围。**范围 A（全语料的可 lint 性与覆盖分析）** 用于刻画规范与 lint 实践之间的结构性缺口：在 39 个 Web PKI 规范源（RFC 5280、CABF BR/EV/S-MIME/CS、ETSI、Mozilla、Apple 根程序策略）上运行前半链路，得到 6142 条规范规则，提取与判定使用 QWen3-8B 与 GPT-5.4（每个完整实验只用单一模型，不在同一设定内混用）。**范围 B（代码生成与 BIIV 收敛）** 用于评估后半链路：代码生成器为 Claude Opus 4.6，语义对齐判官为 GPT-5.4，NL→IR 抽取器为 GLM-Z1-9B-0414，并以 MiniMax-M2.1 的小批量生成作为交叉验证存档；目标框架为 zlint v3。两类参照基线为 **`LLM-Direct`**（不约束于 DSL 代码空间，直接生成完整 Go 代码，衡量受限代码空间的边际贡献）与 **`LLM-σ`**（保持 DSL 路径但将 $\sigma_{\mathrm{mech}}$ 替换回 LLM 实现的 $\sigma_{\mathrm{LLM}}$，衡量 $\sigma$ 确定化的影响）。

> ⟦数字待核：范围 A 的全语料口径（6142 条 / 1117 条可 lint）与范围 B 的代码生成评测口径（召回 1326 条、可执行子集 706 条、未覆盖子集 88→87 条）来自不同实验设定与抽样，二者的精确交叉对齐留待后续单独一轮核对；本节按两个 scope 分别报告，不强行统一分母。⟧

### 9.2 可 lint 性分析

表 1 给出全语料的可 lint 性分布（系统估计）。在 6142 条规范规则中，仅 1117 条（18.2%）可还原为静态证书 lint 检查。

**表 1：全 Web PKI 语料的可 lint 性统计（按规范源）**

| 规范源 | 总数 | 可 lint | 不可 lint | 可 lint 率 |
|---|---:|---:|---:|---:|
| RFC | 1,975 | 349 | 1,626 | 17.7% |
| CABF | 2,543 | 595 | 1,948 | 23.4% |
| ETSI | 1,309 | 117 | 1,192 | 8.9% |
| Mozilla | 283 | 53 | 230 | 18.7% |
| Apple | 32 | 3 | 29 | 9.4% |
| **合计** | **6,142** | **1,117** | **5,025** | **18.2%** |

CABF（23.4%）与 Mozilla（18.7%）处于高端，RFC（17.7%）居中，ETSI（8.9%）与 Apple（9.4%）最低：编码约束密集的规范源更契合单证书静态检查的范围，而以委派式或过程式语句为主的规范源可 lint 率更低。对 1117 条可 lint 规则按约束形态进一步分群（表 2），其中存在性约束（31.1%）、值相等约束（24.1%）与条件约束（16.2%）三类合计占七成以上。该分布应被理解为描述性而非精确分布——分群标签由 LLM 依其对规则语义的理解给出，边界样本（如混合存在与取值约束、或前件本身是编码约束的条件规则）会继承模型偏差。

**表 2：可 lint 规则的约束形态分群（全语料，1,117 条）**

| 类别 | 描述 | 数量 | 占比 |
|---|---|---:|---:|
| L1 | 存在性约束 | 347 | 31.1% |
| L2 | 值相等约束 | 269 | 24.1% |
| L3 | 枚举约束 | 41 | 3.7% |
| L4 | 编码格式约束 | 121 | 10.8% |
| L5 | 包含约束 | 119 | 10.7% |
| L6 | 数值范围约束 | 37 | 3.3% |
| L7 | 条件约束 | 181 | 16.2% |
| 其他 | 新类型（如可除性） | 2 | 0.2% |
| **合计** | | **1,117** | **100%** |

### 9.3 lint 与规范的双向覆盖缺口

本节度量既有 lint 工具与规范规则之间的对齐程度。

**代码摘要的反向蒸馏。** 许多工具的 lint 元数据 `description` 字段经过工程简化（如 zlint `w_ct_sct_policy_count_unsatisfied` 仅写作 *"Check if certificate has enough embedded SCTs to meet Apple CT Policy"*），既不揭示实际检查的字段、阈值与判定方向，也不直接引用规范条款，直接用于嵌入对齐会大量丢失语义。为此覆盖分析对每条 lint 检查 $\ell$ 引入**代码–`code_summary` 反向蒸馏**：将其源码（zlint Go / pkilint Python / certlint Ruby / x509lint C）、伴随的 Pass/Error 测试样本与元数据组装为受约束 prompt 输入蒸馏模型 $M_{\mathrm{distill}}$（temperature = 0），令其反向输出一条 RFC 2119 风格的规范化语义句 $\ell.\text{code\_summary}$ 作为对齐载体。三个要点：(a) 读取 `Execute()` 分支实际判定的字段与阈值，绕开 `description` 的工程化损失；(b) 以 Pass/Error 测试消歧判定方向（哪些取值被允许/禁止）与适用范围；(c) 输出限定为单句 RFC 2119 词汇，使其在嵌入空间与规范条款的规范化文本天然对齐。

**五阶段对齐管道。** 设 lint 检查集 $L=\{\ell_1,\dots,\ell_n\}$（每条已附 $\ell.\text{code\_summary}$）、规范后端池 $B=\{b_1,\dots,b_m\}$（每条含 source、section、text 与 lintable 标志）。对齐由三个确定性步骤与两次受控 LLM 调用按五阶段串联（算法 3）：Stage 0 代码摘要反向蒸馏（每条 lint 一次 $M_{\mathrm{distill}}$，离线缓存复用）、Stage 1 嵌入预计算（embedding 模型生成 1,024 维向量并缓存）、Stage 2 Top-$K$ 候选召回（余弦相似度，$K=30$）、Stage 3 受控判定（对每条候选给出 full/partial/none 三档）、Stage 4 偏序聚合（按 full ≻ partial ≻ none 取最高档，工具级覆盖率为 verdict ≠ none 占比）。LLM 仅出现在 Stage 0 与 Stage 3，且均为局部语义识别——前者回答"该 lint 实际在检查什么"，后者回答"候选集中哪些规范条款与之等价或更严"——其余聚合全部为确定性算子。

```
算法 3：Lint–Spec 对齐（覆盖分析）
输入：lint 检查集 L（每条附源码 src、伴随测试 tests、元数据 meta={description,citation,severity}），
      规范后端池 B（每条附 text），蒸馏模型 M_distill，嵌入模型 M_emb，
      受控判官 M_judge（输出 full/partial/none），候选窗口 K
输出：V = {(ℓ, verdict(ℓ), picks(ℓ)) : ℓ ∈ L}，verdict(ℓ) ∈ {full, partial, none}

 1: V ← ∅
 2: for each ℓ ∈ L do                                   // Stage 0：代码摘要反向蒸馏
 3:     ℓ.code_summary ← M_distill(ℓ.src, ℓ.tests, ℓ.meta)   // 读源码+测试样本 → RFC 2119 单句
 4: for each ℓ ∈ L do                                   // Stage 1：嵌入预计算
 5:     e(ℓ) ← M_emb(ℓ.description ⊕ ℓ.code_summary)
 6: for each b ∈ B do
 7:     e(b) ← M_emb(b.text)
 8: for each ℓ ∈ L do
 9:     C(ℓ) ← Top-K_{b ∈ B} cos(e(ℓ), e(b))            // Stage 2：确定性候选召回
10:     picks(ℓ) ← M_judge(ℓ, C(ℓ))                     // Stage 3：受控 LLM 判定
11:     verdict(ℓ) ← max{ v : (b, v) ∈ picks(ℓ) }       // Stage 4：偏序 full ≻ partial ≻ none；picks=∅ 取 none
12:     V ← V ∪ {(ℓ, verdict(ℓ), picks(ℓ))}
13: return V
```

表 3 给出四款工具的覆盖结果。两个方向共同揭示了**结构性缺口**：从工具侧看，四款工具并集仅匹配到 48.0% 由系统判为可 lint 的规范规则，意味着约 581 条可 lint 规范规则在所分析语料下没有对应的 lint 实现；从规范侧看，45.0% 的已实现 lint 检查（约 525 条手工检查）在所分析语料中找不到清晰的规范基。该缺口并非单一原因，而是 lint 生态中四类结构性因素（异步演进、多源非规范依据、规范文本不完备、粒度不对称）共同作用的结果，其完整定义见附录。

**表 3：四款工具的 lint↔规范覆盖（3 轮均值）**

| 工具 | 检查数 | 命中检查占比 | 匹配可 lint 规则占比 |
|---|---:|---:|---:|
| ZLint | 413 | 62.5% | 32.8% |
| pkilint | 354 | 51.8% | 21.1% |
| certlint | 250 | 49.1% | 14.0% |
| x509lint | 150 | 52.2% | 12.3% |
| **并集** | **1,167** | **55.0%** | **48.0%** |

### 9.4 提取的可复现性与确定性

在删除人工标注真值后，提取质量改由**无真值的可复现性与确定性信号**刻画。其一，多轮提取确定性：将每个评测单元独立提取五次，确定性组件贡献不均——obligation 经正则匹配达 100%，subject 95.7%，constraint 93.3%，predicate 92.0%（predicate 为主要方差来源），等权聚合得 96.4% 综合一致性；按源看 CABF 最高（99.1%），ETSI 最低（91.1%，其委派与引用从句的语义复杂度最高）。其二，IR→DSL 的确定性可达比例：将 IR→DSL 映射收敛为查表式 dispatcher（仅依赖 IR 字段值、无 LLM 调用），其扩展版在未覆盖子集上对 53/88 = 60.2% 的样本实现"NL→IR→DSL 全链路确定性合成"。其三，NL→IR 抽取的同义稳定性：在未覆盖子集上对同一规则做 $N=10$ 次独立抽取（共 880 次调用），五元组 IR 的同义率均值为 0.906，其中 67.0% 的规则达到完美同义（10 次逐字段一致），仅 1 条样本同义率低于 0.50，提示抽取失稳是局部而非系统性问题。三项信号共同表明：在 $\sigma_{\mathrm{mech}}$ 已将 Code→Summary 中间跳确定化的基础上，IR→DSL 中间跳亦可在过半子集上确定化，整条链路的概率失真被压缩至 NL→IR 与同义判定两个端点；而其中"可确定性归约"的那部分（即此处统计的 IR→DSL 可达子集）正是 §7.1 证书级语义 oracle 能把同义判定也确定化、给出 $\mathrm{Code}\equiv\mathrm{IR}$ 证明的子集，故该比例同时构成 oracle 同义可证产量（§9.10）的上游预算。

### 9.5 可执行性分类的外部证据验证

#### 9.5.1 提取与可 lint 性判定的基线对比

在 276 条验证规则（组织为 10 个评估单元）上，将双层提取流水线与三种基线方法对照——Regex-Only（仅 Layer 1）、Zero-Shot LLM 与 Few-Shot LLM（3 示例，二者均不经检索直接调用 LLM）——三者使用与本方法相同的 LLM，每方法重复三次取段落级宏平均。如表 4 所示，双层提取流水线在 Avg F1 = 0.766、Recall = 0.836、Core-Acc = 0.717、Lint-Acc = 0.752 四项指标上均领先；其中可 lint 性判定准确率（Lint-Acc）较最佳基线（Few-Shot LLM 的 0.631）提升 12.1 个百分点，提升主要来自架构层面的提取约束（确定性 Layer 1 召回、结构化 Layer 2 字段提取与五条件可 lint 性框架），而非简单增加示例或检索上下文。

**表 4：双层提取流水线与基线方法对比（276 条验证规则，10 评估单元，每方法重复三次取段落级宏平均）**

| **方法** | **Avg F1** | **Recall** | **Core-Acc** | **Lint-Acc** |
|---|---|---|---|---|
| **双层提取流水线 (Full)** | **0.766** | **0.836** | **0.717** | **0.752** |
| Zero-Shot LLM | 0.743 | 0.751 | 0.627 | 0.567 |
| Few-Shot LLM | 0.751 | 0.732 | 0.644 | 0.631 |
| Regex-Only | 0.603 | 0.695 | 0.359 | 0.461 |

#### 9.5.2 四工具召回率下界

以 zlint、pkilint、certlint、x509lint 四款跨语言工具的规则库为真阳性种子集，估计 $\phi_C$ 召回率下界。四款工具规则规模分别约为 410（zlint，排除 community 后 381）、388（pkilint）、300（certlint）、174（x509lint）。经去重融合得到约 485 条扩展种子集，据此估得 $\phi_C$ 召回率下界为 **72%–78%**（阈值 0.75 下中位约 75%）。

#### 9.5.3 第三方金标外部验证

引入 zlint 维护者公开的 BR 映射表 [37], [38] 作为完全独立的第三方人工金标。对 BR v1.4.8 与 v2.0.2 两个版本，分别在对应版本的官方 CA/Browser Forum BR.md 源上重跑双层提取流水线，并将其输出与同版本映射表对齐，以排除版本漂移带来的混淆。如表 5 所示，两版召回率接近（83.8% vs 83.2%），但 Cohen's κ 差异显著：BR 2.0.2 达到 96.6% Lint-Acc，但其正类极小（208 条匹配对中仅 12 条为正，占 5.8%），朴素 all-negative 基线已达 94.2%，故 κ=0.615 才是类别不平衡下更有意义的判别力指标，其正类指标（P=0.86、R=0.50、n=12）置信区间相应较宽；BR 1.4.8 类别更均衡（正类约 63%），κ=0.802、正类 F1=0.92 且零假阳性，更紧地刻画了系统与外部金标的实际一致性。

**表 5：BR 1.4.8 / BR 2.0.2 第三方金标外部验证（同版本对照）**

| 版本 | 召回率 | Lint-Acc | Cohen's κ | 正类 F1 |
|---|---:|---:|---:|---:|
| **BR 1.4.8**（n=111） | 83.8% | 90.3% | **0.802** | 0.92 |
| **BR 2.0.2**（n=250） | 83.2% | 96.6% | 0.615 | 0.63 |

注：n 为映射表行数（denominator）。召回率为 DLEP 匹配到的 sheet 行占比，Lint-Acc 为匹配行上逐对可 lint 性判定准确率（口径同 §4.1，限定于外部映射表）。BR 1.4.8 剔除 11 行其 lintable 标签源自非 RFC 2119 文本者。

### 9.6 代码生成成功率与稳定性

在范围 B 上，对 723 条抽样规则执行端到端 DSL 树合成，其中 17 条在前置过滤阶段由 $\phi_C$ 判为非可执行而排除，其余 706 条进入受限合成管道。表 6 给出整体结果：706 条全部被解析为合法 DSL 树并渲染为结构完整代码，**lintable 子集成功率 100%（706/706）**，端到端成功率 97.65%（706/723）。这一结果与命题 1 的词汇封闭性预测相符——未观测到任何 $\eta$ 解析失败的样本。（受实验环境限制，此处"成功"以 $\eta$ 解析为合法 $t \in \mathcal{T}_{\mathcal{V}}$ 并经 $\rho$ 渲染为结构完整源文件为准，未独立执行 `go build`。）

**表 6：大规模 DSL 树合成结果（Claude Opus 4.6）**

| 指标 | 数值 |
|---|---|
| 输入规则总数 | 723 |
| 前置过滤排除（non-lintable） | 17 |
| 进入合成管道（lintable） | 706 |
| 响应解析与结构验证通过 | 706 |
| **lintable 子集成功率** | **100% (706/706)** |
| **端到端成功率（含前置过滤）** | **97.65% (706/723)** |

按标准族分解，RFC 5280 子集成功率最低（91.45%），因其规则文本最长且交叉引用最密；以小谢关键词召回的 126 条 ETSI 规则达到 98.41% 成功率，与 RFC 2119 关键词召回的主流标准族（97.30–100%）无显著差异，为"ETSI 等价召回算子"提供了间接证据。在多次独立生成的稳定性上（50 条规则 × 3 次），表面文本一致性很低（3.1%），但语义一致性达 90.6%、结构解析一致性达 100%——即生成代码的语法表面不稳定而检查意图通常稳定，故工程部署应以结构与语义一致性而非文本一致性为质量标准。

**API 层不可靠性与双重口径可用率。** 上述 50 条规则 × 3 次（共 150 次运行）的稳定性实验中，有 23 次（15.3%）因 LLM 服务返回 HTTP 502/503 而未产出有效响应，涉及 18 条规则至少存在一次 API 错误。本研究据此以两种口径报告可用率：**乐观口径**剔除受影响的 18 条、仅在 32 条干净规则上评估（对应上文一致性数字）；**悲观口径**将 API 错误一律计为失败、不作剔除，则三轮均成功率降至 32/50 = **64.0%**，代表端到端部署环境下可观察到的真实可用率下界——其首要瓶颈是 API 层不可靠性而非模型能力本身；据此建议部署中启用重试与多提供商冗余以收敛两口径差距。

### 9.7 语义对齐质量

对 706 条进入对齐验证的样本，平均综合对齐得分 $S_{\mathrm{align}} = 0.886$，结构解析通过率 100%，描述溯源率 96.2%，被判为代码摘要与 `Description` 语义同义者 265 条（同义率 37.5%）。需要强调，同义率并不直接等价于真实语义正确率：许多样本未被判同义，并非代码逻辑错误，而是代码摘要与规范原文处于不同抽象层级（如规范写"serial number MUST be a positive integer"而摘要写"检查 serialNumber 是否大于 0"），或存在方向变换与规范化表达差异（否定句式 vs 正向条件）。确有少部分样本反映真实实现偏差，集中于边界条件、字段访问路径或条件触发逻辑。本研究因此将同义性结果视为**语义诊断信号**而非简单的二元正确性标签——其价值在于定位"代码实际检查的约束"与"规范要求的约束"之间的差距。

### 9.8 BIIV 端到端收敛

本节在未覆盖可执行子集（$\mathcal{R}_L^{\mathrm{uncov}}$，初始 88 条）上给出 BIIV 三目标残差的端到端收敛证据，聚焦两个问题：$\sigma$ 确定化对 G2 残差的贡献，以及 L4b 对 G3 残差的归零。

**$\sigma_{\mathrm{mech}}$ 单步替换是最大的方法学拐点。** 表 7 给出 G2 残差（EXPRESSES 比例）在迭代干预序列下的演进。在不修改代码生成、不增改原子词典、不调整判官模型的条件下，仅将 $\sigma_{\mathrm{LLM}}$ 替换为 $\sigma_{\mathrm{mech}}$ 一步即获得 **+7** 个 EXPRESSES 样本（64.8% → 75.0%，+10.2pp），而对生成端或判官端的迭代式 prompt 调优仅累计推动 +2 个。被解锁的 7 条样本全部具有非空条件前提，其中 6 条前提形如 $\neg(\mathrm{inner})$——正是 §8.13 所刻画的、$\sigma_{\mathrm{LLM}}$ 会发生 NA-反转失真而 $\sigma_{\mathrm{mech}}$ 通过结构归纳消除的形态。这一量级对比支持 §8.13 的核心论断：$\sigma$ 不是中性翻译层，而是反向传播链路上一个独立且不可由 prompt 调优消除的失真源。

**表 7：G2 残差在迭代干预序列下的演进（$|\mathcal{R}_L^{\mathrm{uncov}}| = 88$）**

| 轮次 | 主要干预 | EXPRESSES | 累计提升 |
|---|---|---:|---:|
| 基线 | 树架构 codegen + LLM judge | 57/88 = 64.8% | — |
| | 桶级 judge 重判 | 58/88 = 65.9% | +1.1pp |
| | 新原子 + $\neg$-precondition 模板 | 59/88 = 67.0% | +2.2pp |
| **拐点** | **$\sigma_{\mathrm{LLM}} \to \sigma_{\mathrm{mech}}$ 全量重判** | **66/88 = 75.0%** | **+10.2pp** |
| | 离线 $\rho_A$ 新增通用原子 | 67/88 = 76.1% | +11.3pp |
| | judge 稳定性补跑 | 70/88 = 79.5% | +14.7pp |

**L4b 将 G3 残差单调归零。** 对全部候选规则计算违反集合 $\mathcal{V}$，L4b 修复前 $N_{\mathrm{viol}} = 48$；逐条调用 FLIP-or-SPURIOUS 二元判官后全部结清——8 条经 FLIP（$\phi_C$ 由 noise/non-lintable 翻为 lintable）、40 条经 SPURIOUS（覆盖判定由 full/partial 降为 none），最终 $N_{\mathrm{viol}} = 0$。该修正仅依赖外部 lint 工具实现存在性这一可机械计算的证据，**不引入人工真值**即完成对 $\phi_C$ 假阴性的定向纠错。综合两项干预，表 8 给出三目标残差在三个观测时刻的同步状态。

**表 8：三目标残差在 L4b + $\sigma_{\mathrm{mech}}$ 干预前后的状态**

| 目标 | 残差 | 干预前 | $\sigma_{\mathrm{mech}}$ 后 | 数据冻结时 |
|---|---|---:|---:|---:|
| G1 召回完整性 | $\mathcal{L}_{\mathrm{recall}}$ | 0 | 0 | 0 |
| G2 未覆盖可执行规则同义 | EXPRESSES / 88 | 64.8% | **75.0%** | **79.5%** |
| G3 双 oracle 一致性 | $N_{\mathrm{viol}}$ | 48 | **0** | **0** |

此外，一组朴素反馈基线实验（对 52 条低对齐规则追溯应用阶段归因）表明：当归因信号缺失时，反馈循环在低对齐规则上的期望改善趋近于零（49 条仅可重生成的样本得分完全不变）；而 69% 的低对齐样本缺乏显式错误类型标签——正是 BIIV 阶段归因规则（式 13）所针对的归因不确定区，即便单条规则错误类型未知，仍可依据上游损失分量给出阶段级判定并触发非 $\phi_G$ 的修复动作。

### 9.9 不可归约残差与 audit-honest 终态

BIIV 的终止条件不是简单的"$\mathcal{L}_{\mathrm{code}} \to 0$"。在保持"不通过单规则 wrapper 原子或逐字节 hex-literal 容器原子强行扩展词汇表"的纪律下，存在一个非空子集 $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$，对其而言任何符合纪律（满足概念通用性与运行时非 vacuous 双轴）的原子组合都无法达成代码-规范等价。本研究因此以**"可归约子集闭合 + 不可归约边界披露"双指标**取代单一阈值，并经独立审计给出诚实终态。

一次独立审计（针对一种"atomic-fallback"判官启发式——当 DSL 树仅含单一容器原子且名称与规则关键词字面匹配时直接判 EXPRESSES）发现三条样本（一条单规则 wrapper、两条 hex-literal 容器）的 EXPRESSES 为假阳性升级，与 broad-judge 的一致拒绝矛盾；据双轴判据，该启发式被永久禁用、三条标签回滚，audit-honest 基线降为 75/88。在此基础上对剩余非 EXPRESSES 样本按修复算子范畴分三路径处理：**Path A**（剔除上述假阳性）；**Path B**（仅允许通用判官/生成 prompt 改写的通用通路修复，净贡献 +1，并在 R4566 上触发一次 $\rho_C^{\downarrow}$ 重判）；**Path C**（经审计判定属 $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$ 的 11 条，作为方法学边界诚实声明）。其中 R4566 经 §8.10 (iii) 的 $\rho_C^{\downarrow}$ 识别为上游 $\phi_C$ 假阳性——其 scope precondition（"证书是否为 TLS 交叉认证子 CA"）需查外部目录服务、不满足 $\mathrm{StaticallyObservable}$，故按式 (15) 由 $\mathcal{R}_L^{\mathrm{uncov}}$ 迁至 $\mathcal{R}_U$，使分母由 88 修正为 87。最终终态如表 9。

**表 9：G2 子集的 audit-honest 终态**

| 指标 | 中期冻结 | atomic-fallback 虚高 | **audit-honest 终态** |
|---|---:|---:|---:|
| $\mid\mathcal{R}_L^{\mathrm{uncov}}\mid$（分母） | 88 | 88 | **87**（R4566 迁出 $\mathcal{R}_U$） |
| EXPRESSES | 70/88 = 79.5% | 78/88 = 88.6% | **76/87 = 87.4%** |
| DOES_NOT_EXPRESS | 10/88 | 2/88 | 0/87 |
| honest_no_template（即 $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$） | 8/88 | 8/88 | **11/87** |
| $\mathcal{L}_{\mathrm{code}}^{\mathrm{red}}$（可归约子集） | 不可分解 | 含失真 | **0**（76/76） |
| $\rho^{\mathrm{irred}}_{\mathrm{code}}$ | 未识别 | 未对齐双轴 | **11/87 = 12.6%** |

audit-honest 终态满足修正后的终止条件：可归约子集上 $\mathcal{L}_{\mathrm{code}}^{\mathrm{red}} = 0$，全部 87 条样本进入稳定状态集 $\{\mathrm{EXPRESSES},\ \mathrm{honest\_no\_template}\}$。对 11 条不可归约残差，本研究按 5 类成因做完整披露（表 10），每条附审计理由，第三方可挑战任一条"实属可归约"——前提是给出满足双轴并通过同一判官端到端等价判定的原子组合。本研究不主张其在所有方法学下不可归约，仅声明在本文双轴可容许子集下不可归约。

**表 10：不可归约残差的 5 类分群披露（$|\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}| = 11$）**

| # | 类别 | 数量 | 不可归约的双轴理由 |
|---|---|---:|---|
| 1 | PKI 外部 primitive | 2 | 涉及 PKI 范畴外基础 primitive（Unicode NFC 规范化、IDN→ACE 转换），合规原子须封装整个算法，违概念通用性 |
| 2 | 逐字节 hex 字面 | 4 | 要求字段按特定 16 进制字节序列逐字节相等，合规原子等价于把 hex 字面编码为常量，违通用性（字面复述） |
| 3 | 语料内单形态 | 3 | 规则在语料内仅以单一形态出现，无第二条结构同构规则可复用同一原子，原子与规则 1:1 绑定即 wrapper |
| 4 | 子约束再封装 | 1 | 含复合子句，分解需引入仅服务此一条规则的子原子，违重用要求 |
| 5 | 多子句缺通用原子 | 1 | 含并列子句，其中一子句的合规判定缺一个通用原子，引入即专项 wrapper |

类别 1 来源于 PKI 外部世界对证书静态文本的不可表达性，原则上不可迁出；类别 2–5 来源于语料内的通用性测试，第三方若在新增语料中找到结构同构样本即可将其迁出至可归约子集。这一诚实边界声明取代了单一比例数字，构成本框架"以受限原子词汇换可验证性"之代价的完整刻画。

### 9.10 五条件重抽、全 LLM 代码生成与证书级 oracle 验证（RFC 5280 + CABF BR 范围）

§9.2–§9.9 的数字来自范围 A/B 的早期抽样设定（与 §9.1 的 ⟦数字待核⟧ 一致，本研究不强行跨设定统一分母）。本节单列一个**独立范围**——在引入第五条件 $C_4$（$\mathrm{check\_scope}$，§5）后，对 RFC 5280（standard_id = 1）与 CABF BR（standard_id = 19）全量**重抽 IR 并重算**的结果，用以验证五条件框架下守恒方程的闭合性，以及全 LLM 代码生成（§6.7）经证书级语义 oracle（§7.1）验证后的**同义可证**产量。该范围与上文范围 A/B 不共享分母，仅在内部自洽。

**守恒方程在五条件下闭合，$C_4$ 的必要性。** 引入 $C_4$ 之前的旧判定（实质仅以义务强度过滤、其余条件失效）误判出 875 条"可 lint"；五条件收紧后回落至一个显著更小的可 lint 集——被剔除者恰为跨制品 / 外部状态 / 撤销历史类规则，印证了数据边界条件的必要性。在该可 lint 集上，按 §9.3 的对齐管道与 zlint 源码比对，覆盖被划分为"已被 zlint 覆盖"与"未覆盖"两个互斥部分，二者之和严格等于可 lint 总数（守恒不变量，§8.3 定理 1）。经可 lint 性复核（reverse-check 误判修正 + CRL 域消歧，方法同 §9.9）与口径校正后，进入**全 LLM 代码生成**的未覆盖目标稳定在 **363 条**；下文 oracle 验证结果均在该 363 条目标集上计算。

**全 LLM 代码生成与 oracle 同义可证产量。** 对 363 条未覆盖目标运行 §6.7 的全 LLM 树合成，再以 §7.1 的证书级语义 oracle 重新接管同义判据（取代旧的单票 LLM 判别器）。其中能被确定性归约并渲染的有 136 条，再经"全部原子已认证 + 离线 `go build` 通过"两关，得 **135 条同义可证（$\mathrm{Code}\equiv\mathrm{IR}$，零判官）**；落选的极少——1 条含未认证原子、17 条因原子-语义错配被渲染器*正确*拒绝（如把 `FieldEncodedAs` 套到 URI / 时间字段、`FieldCount` 套到 KeyUsage），其余约 210 条不可确定性归约、仅有 LLM 产物而无证明。作为对照，旧的单票 LLM 判别器在同一 363 条上"接受"172 条——但其中仅 135 条与 oracle 的证明一致，另 **37 条纯靠判别器、oracle 未证**（风险所在），印证了单票判据的不可靠（表 11）。该 135 条同义可证集合是**纯确定性**的，不依赖生成 / 判定所用的 LLM 模型。

**表 11：证书级 oracle 与单票判别器在 363 条未覆盖目标上的对照（RFC 5280 + CABF BR 范围）**

| 接受判据 | 接受数 | 其中 oracle 可证（$\mathrm{Code}\equiv\mathrm{IR}$） | 仅该判据、无证明 |
|---|---:|---:|---:|
| **证书级语义 oracle**（确定性证明） | **135** | 135 | — |
| 单票 LLM 判别器（EXPRESSES） | 172 | 135 | **37（风险）** |

oracle 一支的漏斗为：363 目标 → 确定性归约 + 渲染 136 → 全认证原子 + 编译通过 **135**（落选 1 条含未认证原子、17 条原子错配被渲染器拒绝、约 210 条不可归约仅余 LLM 产物）。

**三档诚实覆盖。** 据此本研究以三档刻画覆盖，而非单一产量数：① **被 zlint 直接覆盖**（第三方既有实现）；② **由 oracle 确定性证明 $\mathrm{Code}\equiv\mathrm{IR}$** 的新生成 lint（zlint 未覆盖者 135 条）；③ **LLM 生成但 oracle 未证**（含上述 37 条判别器-only 与约 210 条不可归约产物，如实披露为未验证）。若把判据扩展到**全部可 lint 规则**（含已被 zlint 覆盖者与 CRL 域），oracle 同义可证约为 ⟦258 / 556 ≈ 46%；该全口径数依赖一项进行中的后端抽取修复（结构化约束字段的重抽），数字待核⟧。

**确定性忠实性筛查交叉验证。** 对生成产出运行 §7.1 的实体级筛查 $\mathrm{Faithful}_{\mathrm{nec}}$（与 oracle、判官皆独立的第三重确定性必要条件），其判读分为 $\mathtt{ENTITY\_OK}$ / $\mathtt{NO\_ENTITY}$（纯结构检查，判定不适用）/ $\mathtt{ENTITY\_MISMATCH}$ 三类 ⟦三类具体计数随当前重抽口径待核⟧。值得注意的是，oracle 同义可证子集上的 $\mathtt{ENTITY\_MISMATCH}$ 极少——其代表案例 R24081 经审计确认根因是**上游 IR 主语错抽**（authorityCertIssuer / authorityCertSerialNumber 属 AKI 字段，却被抽成 AIA 扩展）而非代码生成错误：oracle 仍可证 $\mathrm{Code}\equiv\mathrm{IR}$（代码忠实于那条**错** IR），但 $\mathrm{IR}\neq\mathrm{Spec}$——恰为 §7.1 所述"oracle 只担保 $\mathrm{Code}\equiv\mathrm{IR}$、$\mathrm{IR}\neq\mathrm{Spec}$ 须由过严哨兵或上游修复处理"这一边界的实证。其余标红多落在 LLM 判官路径，按确定性子分类为指代盲区与筛查词表缺口两类，与 §7.1 声明的两类盲区一致。后续按筛查定位的根因做了**上游修复**：为字段 schema 的 AuthorityKeyIdentifier 补齐 keyIdentifier / authorityCertIssuer / authorityCertSerialNumber 三个子字段（此前缺失，导致 ASN.1 模块附录中无 §4.2.1.1 锚点的规则误归到 authorityInfoAccess）；R24081 重抽后主语正确归到 AKI，且因其"共现"语义无对应原子而诚实转为残差——印证了"筛查 → 定位 → 上游修复"的闭环。

### 9.11 2026-06 全量重核：citation 覆盖、手裁同义率与守恒未闭合的诚实快照

§9.10 的 363 / 556 / 135 来自 2026-06-09 一轮抽样；本节给出 2026-06-11/12 在更干净的守恒数据（仅 RFC 5280 与 CABF BR 全库重抽，standard_id ∈ {1,19}）上重算、并经**逐条手工裁定**校准后的当前快照。该快照是后续"全量 370 重抽"之前的诚实基线，明确暴露守恒方程底层尚未闭合，取代 §9.10 的早期口径。

**守恒漏斗（当前；顶两层闭合）。** 召回 2091 = 噪声 510 + 真规则 1581；真规则 1581 = 可 lint 370 + 不可 lint 1211（两式严格相等，§8.3 定理 1）。可 lint 370 = CABF 251 + RFC 5280 119。

**覆盖：zlint 的 Source+Citation 才是 ground-truth，语义匹配严重低估。** 此前以 DSL 树 `relate` 语义匹配得覆盖 91 / 109，但 zlint 每条 lint 自带 `Source`（RFC5280 / CABF…）与 `Citation`（所实现条款）——这是覆盖的第一手证据。以"规则 section 被同源 zlint lint 引用"为判据，**citation 覆盖达 177**（CABF 91 + RFC 86），远高于语义匹配的 109（表 12）。二者差额 117 条经逐条归因：**63 条我方无可比树**（191 codegen 缺口或退化 IR；而 zlint 常常是覆盖的，如 §4.1.2.5 → `e_utc_time_not_in_zulu`）；**50 条同节但多为该节内别的需求**（section 共享 ≠ 需求覆盖；少数是同需求而我方树错，如 §4.2.1.4 "策略 OID 不得重复" ↔ zlint `e_ext_cert_policy_duplicate`，被我方 uniqueness→count 误抽拖累而未匹配）；**4 条 zlint 有 lint 但其 DSL 未抽**（413 条 zlint lint 中 86 条无 `dsl_atom`，多为 `CONFORMS_TO_REF` 算法类不可归约）。**重要纠正：此前"未覆盖项中约 83 条系 zlint 根本没有该检查"的结论不成立**——那实为"没有匹配上的 DSL 树"，而非"zlint 无此 lint"；真覆盖被 `relate` 低估，漏因为 zlint 侧 DSL 未抽全 + 我方树错/无树 + 比对器编码鸿沟。

**表 12：zlint citation 覆盖 vs 语义匹配覆盖（370 条可 lint）**

| 口径 | CABF | RFC 5280 | 合计 |
|---|---:|---:|---:|
| citation 覆盖（section 被同源 zlint 引用） | 91 | 86 | **177** |
| `relate` 语义覆盖 | 72 | 37 | **109** |
| 差额（citation 覆盖但语义未匹配） | — | — | **117** |

**"能写成代码"分层。** 该能力随严格度分层（表 13）：最严（确定性归约 + 渲染 + 原子全认证 + 离线编译）179 条；中（能渲染成 Go 树）213 条；宽（`ir_to_dsl` 产出 well-formed 树）219 条。其中**未被 zlint citation 覆盖**者分别为 88 / 104 / 110——即系统"净新增"领地随口径在 88–110 之间，而非单一数字。

**表 13：codegen 分层及其未覆盖子集**

| "能写成代码"的定义 | 总数 | ∧ 未被 zlint 覆盖 |
|---|---:|---:|
| 最严：确定性 + certify + 编译 | 179 | 88 |
| 中：能渲染成 Go 树 | 213 | 104 |
| 宽：`ir_to_dsl` well-formed | 219 | 110 |

**手裁同义率 = 50%（认证 88）/ 42%（全 104），且判官不可信需校准。** 对"能渲染 ∧ 未覆盖"的 104 条，以 tree→自然语言 + 同义判官初判仅 34%（30/88）；但该判官有两层污染：① `tree_to_natural` 缺 `FieldCount` 模板，使 23 条吐错误串被判否（已修补模板）；② 判官对表格残片 / 指代 / 版本编码存在假阴性（如 "cA MUST be set TRUE" ↔ `IsCA()` 实为同义却判否）。经**逐条手工裁定**（纯 tree-vs-text，无 LLM；工件 `synonymy_groundtruth_88.jsonl`）校准后：认证 88 子集真同义 **44（50%）**；扩到全 104 真同义仍 44（**42%**——新增的 16 条 render-but-uncertified 全部不同义，印证认证门与同义性正相关，认证门正确滤除了不 sound 者）。同义性是**二元判定**（表达 / 没表达，无第三档）；判官三档中的 partial 一律归"没表达"。

**约 60 条真缺陷全部源于上游抽取，无 reducer 捷径。** 43（认证 88 内）+ 16（uncertified）+ 少量 LLM ≈ 60 条真·不同义，按根因聚类（表 14）。逐条核实表明：reducer 忠实地把**错 IR** 映成**错树**（reducer 本身 sound——本轮已对其加硬化门，使其对退化原子如空 `And`、`FieldEncodedAs` 套 GeneralName 选择、OID 当数值字段返回 honest None），病根全部在抽取端；故唯一出路是**改抽取 + 全量重抽**，而非在 reducer 上打补丁（与 §9.10 之 R24081 同源：oracle 仍可证 Code≡IR，但 IR≠Spec）。

**表 14：约 60 条真·不同义缺陷的根因聚类（全在上游抽取）**

| 簇 | 典型 | 铁证 |
|---|---|---|
| wrong-subject（主语错抽） | "有效期编码 UTCTime" | IR `subject` 竟为 `subject` DN；"序列号"抽成 `issuer.serialNumber` |
| subfield→整扩展 | `authorityCertSerialNumber MUST NOT` | 子字段被查成"整个 AKI 不存在"（R24081 同类） |
| uniqueness→count | "OID 不得重复" | 被压成 `FieldCount ≤ 1`，与 zlint `e_ext_cert_policy_duplicate` 失配 |
| over-claim 丢限定 | "非*相对* URI" / "*空*序列" | → "无 URI" / "不存在" |
| specific-vs-total | "exactly one *Reserved* policy" | ≠ 策略总数 = 1 |
| token 当值 | CRL DP 结构词 | `'LDAP'`/`'cRLIssuer'` 进 `allowed_values` |

**方法学结论：同义性应作为发射门，而非事后指标。** 系统价值在于忠实翻译——一条不同义的 lint 即一条**错件**。故正确目标不是"把同义率提高一点"，而是**只发射经双重验证（`Code≡IR` 由 §7.1 证书级 oracle，`IR≡Spec` 由同义门）的 lint，其余拒发为诚实残差**；如此发射集 **100% 同义 by construction**（当前约 44 条），收敛 = 迭代修上游抽取把残差转同义、发射集随之增长而始终维持 100%。本快照明确：守恒底三层（覆盖 / codegen / 同义）尚未闭合，**闭合引擎为下一步按上述缺陷簇改进抽取后对 RFC 5280 + CABF BR 全量 370 条一次性重抽**，再重算覆盖与同义至数稳。

## 10. 讨论

### 10.1 关键发现

**受限代码空间对生成稳定性的贡献。** 将 $\phi_G$ 的值域限定于 $\mathcal{T}_{\mathcal{V}}$ 在三个层面约束生成：结构层面，所有合法 $t$ 经 $\rho$ 渲染后类型正确，706 条样本的结构解析成功率达 100%，未观测到字段名/OID 编造；幻觉抑制层面，命题 1 给出输出封闭性，任何越界引用在解析阶段即被拒绝并触发反馈式重生成，幻觉路径在架构层关闭；验证可计算层面，代码空间的可枚举性是 $\sigma_{\mathrm{mech}}$ 可被设计为信息无损可逆函数的前提。配合 $\Phi_{\mathrm{post}}$ 对 `Description`/`Citation`/`Name` 的确定性绑定，生成代码与源文档之间的双向可追溯成为架构属性而非概率属性。

**$\sigma$ 的实现选择决定反向传播链路的稳健性（核心方法学发现）。** 在保持代码生成、原子词典、判官模型与阈值均不变的条件下，仅将 $\sigma$ 由 LLM 替换为基于 DSL 树的确定性 $\sigma_{\mathrm{mech}}$，即使 G2 残差单步下降 10.2 个百分点——这一增量远超四轮 prompt 调优的累计效果（+2 个样本）。该结果挑战了"$\sigma$ 只是中性翻译层"的直觉：$\sigma$ 一旦由概率模型实现，其失真即在条件分支的极性识别上系统性累积，且无法通过增加示例消除，因为 LLM 倾向于复述"代码看起来在做什么"而非"代码在哪种条件下触发严重度"。确定化是该层唯一的根本性修复。由此提炼出一项不局限于 PKI 的一般性设计原则：**反向传播式验证链路上的每个算子都应尽可能由确定性函数实现，LLM 仅在确实需要语义灵活性的端点（此处为 $\phi_C$ 与 $\phi_V$）处出现**——当一个中间算子的输入与输出空间均为闭合集合时，确定性实现严格优于概率实现，因为它把链路上的方差压缩至可估计、可单调下降的两个端点。本研究进一步把同一原则推到 $\phi_V$ 自身：对可认证子集，证书级语义 oracle 以执行级 $\mathrm{Code}\equiv\mathrm{IR}$ 证明取代 LLM 投票，使原本"两个 LLM 端点"之一在该子集上也被确定化——这与生成端确定性归约的移除是同一迁移的两面：确定性的着力点从生成端移到验证端，而非消失。

**语义对齐率应理解为正确率的下界。** 初始前向生成的同义率 37.5% 不应被过度解读为语义错误率：大量"不同义"样本源于抽象层次差（宣告式规范 vs 实现式摘要）、表达方向差（否定义务 vs 正向条件）与分解粒度差，仅少数反映真实实现偏差。因此同义性结果更宜作为**语义诊断信号**——其价值在于定位"代码实际检查"与"规范要求"之间的差距，并为 BIIV 提供阶段级可操作输入。

**结构性缺口是一项独立的经验贡献。** 双向覆盖分析（§9.3）表明，规范与 lint 实践之间存在显著的结构性缺口：约 581 条可 lint 规范规则缺乏对应实现，而约 525 条已实现检查缺乏清晰规范基。这一发现独立于代码生成方法本身，刻画了"为何自动化规范-到-代码生成是必要的"——它正是本框架后半链路的现实动机。

### 10.2 跨 PKI 的适用性

本框架的核心机制并不特定于 PKI。前半链路的 Layer 1 当前面向 RFC 2119 关键词，但该关键词集可通过正则配置替换为其他标准生态的道义关键词（如 ISO 的 shall/should/may 三元，或其他语言监管文本中的强/弱/许可型表述）。因此方法适用于满足三个条件的规范源：**(1)** 文档使用可识别的形式化道义关键词表达强制或推荐规则；**(2)** 约束目标是结构化、可机器解析的产物（如证书、协议消息或配置文件）；**(3)** 文档具备支持知识图谱构建与作用域继承建模的层级化章节-规则结构。这一适用性边界使本框架的方法学价值超出 PKI 单一领域。

### 10.3 对规范作者与工具维护者的建议

基于提取过程中遇到的障碍，本研究给出两组面向实践的建议，亦构成对 PKI 生态的方法学外溢。

**面向规范作者的三条起草原则。** **(i) 单句单义务**：一句至多承载一个 MUST/SHALL，多重义务应拆分为独立编号的语句而非以从句聚合；**(ii) 以 ASN.1 路径精确引用字段**：书写 `tbsCertificate.extensions.subjectAltName.dNSName` 而非"SAN 扩展"或"它"，避免代词与跨段指代；**(iii) 规范化跨文档引用**：跨文档引用应遵循"[动词] [文档] §[章节]（必要时附步骤或参数）"的固定模式，避免"如 [RFC X] 所述"这类模糊形式，使每个引用都能直接映射为知识图谱上的一条类型化边。

**面向 lint 工具维护者的建议。** 建议将 lint 元数据的 `description` 字段直接写为**代码摘要**——即一句 RFC 2119 风格、复述实际检查逻辑并显式给出字段路径、断言类型、允许/禁止取值与裁定严重级别的句子，并附对所依据规范规则的显式引用。本研究观察到大量 lint 检查的描述既非对原规范的引用、也非对实现逻辑的忠实摘要，致使覆盖分析必须先执行一次代码摘要步骤才能在嵌入空间对齐规范文本，徒增工程开销并在 partial/none 边界引入裁决噪声。

### 10.4 与现有 lint 规则的关系

所生成规则与现有 lint 规则呈现三类关系，分别对应反向传播链路上不同种类的残差来源：**重建类**（与现有规则语义等价，构成 G3 双向不变量的覆盖一致性证据）、**补足类**（当前未覆盖但被判为可执行，构成 G2 端到端验证域与自动生成的直接价值来源）、**冲突类**（与现有规则存在语义冲突或实现差异，需经 $\rho_V$ 的 SPURIOUS 路径或人工裁决处理）。三类划分并非以覆盖率为定量目标，而是作为残差来源标识。

### 10.5 局限性

本方法存在若干局限：**语义对齐验证**末端的 $\phi_V$ 同义性判定仍由 LLM 实现，其失真不可被结构化方法直接消除，更稳健的路径应将自然语言同义判定与形式化验证或测试用例结合；**原子词典完备性**方面，当前 $|\mathcal{A}|=56$ 已覆盖主流约束模式，但对 ASN.1 原始字节级编码、宿主框架未暴露的解析层字段、严重度多分支输出等仍存表达缺口，需经离线 $\rho_A$ 单调扩展逐步消除；**跨文档引用**与**动态约束**（如"有效期不得超过 N 天"）的支持仍有限，前者需更强的跨文档知识表示，后者需面向时间/外部状态的原子类。这些局限界定了结论的适用边界——本框架更适合处理可在单文档上下文中闭合的静态约束规则子空间。

## 11. 有效性威胁

### 11.1 内部有效性

**LLM 判断的可靠性。** 语义对齐验证依赖 LLM 对代码摘要与 `Description` 同义性的判断，该判断本身并非人工真值，存在误判风险。为缓解，实验使用置信度阈值过滤低置信样本，并将结果主要解释为诊断信号而非最终裁决；后续可引入抽样校准以系统评估模型判定与独立判定之间的一致性。

**IR 提取的误差传播。** 代码生成的直接输入是上游提取的 IR，而 IR 提取并非无误：一旦在规则边界、字段路径或约束表达上发生偏差，错误便会向 $\phi_C$、$\phi_G$、$\phi_V$ 传播，并最终表现为看似属于生成模块的问题。本研究**不以人工标注真值来界定该上游质量**，而以无真值信号刻画其稳健性边界——NL→IR 抽取在 $N=10$ 下的五元组同义率均值为 0.906（67% 完美同义），多轮提取的综合确定性为 96.4%（§9.4）。在此之上，§8.7 引入的 $\rho_{\mathrm{IR}}$ 自反思修复算子（含 g4-sanity 事后闸门）为 IR 内容错误提供运行时修复路径：它将下游失败信号回流给 LLM 令其诊断 IR 字段错误或声明 `NO_FIX`，闸门则对修复后的 IR 执行三项无需真值的合法性检验以防新幻觉。

在不可归约残差候选集上运行的 $\rho_{\mathrm{IR}}$ 消融实验给出 0/12 的"救回"率，且本身具方法学价值：6 条 `NO_FIX` 表示 LLM 独立确认"DSL 词汇不足、非 IR 错误"——与审计分群理由高度一致，构成对不可归约残差归类的 **LLM 独立见证**；3 条被 g4-sanity 拦截则验证了闸门的有效性（LLM 反思修复时确会产生幻觉，如把合法 EKU 名瞎改为 OID 字符串）。因此 $\rho_{\mathrm{IR}}$ 不以提高救回率为目标，而是提供 IR 错误的**运行时可证伪窗口**：若有效修复存在则应被挑出，0/12 即对边界归类给出独立证据。

**Prompt 敏感性。** LLM 输出对提示词细节敏感，可能影响代码实现与同义判定。为缓解，实验采用固定 prompt 模板并记录模型版本与主要参数以提升可复现性。

### 11.2 外部有效性

**标准族代表性。** 实证覆盖 RFC 5280、CABF BR、ETSI 与 Mozilla 等主要公共场景，但不代表所有证书规范体系（如国密 GM/T、JIS 或行业特定标准未纳入），方法在此类体系上的表现有待验证。**框架特定性。** 生成代码面向 zlint 框架，其渲染样板、命名约定与元数据绑定带有框架特定性，跨框架迁移不应视为即插即用。**规则规模。** 虽已在数百条规则上完成大规模验证，但相对完整规范条款仍属子集，跨文档依赖更强或结构化程度更低的规则尚未充分纳入评估。

### 11.3 构念有效性

**编译率与正确性的差异。** 编译/结构通过仅衡量代码能否被框架接受，而非是否忠实实现规范语义；本研究以语义对齐验证补充，但该验证自身亦有局限，故二者不能直接等同。**对齐得分的有效性。** 综合对齐得分的权重（0.20/0.10/0.20/0.50）基于工程经验而非严格理论推导，不同配置可能改变阈值附近样本的判定。**覆盖率的定义。** 覆盖判定依赖 LLM 辅助匹配而非严格语义等价证明，故所报告的覆盖率应作为规则空间重叠程度的近似估计而非生态真值。**覆盖率不被自我污染（防火墙）。** 由于本框架既度量 zlint 既有覆盖、又为未覆盖规则生成 zlint 代码，必须防止生成产物回流污染覆盖语料、造成"自己覆盖自己"的循环虚高。为此生成的 lint 在命名空间上与 zlint 原生代码**显式区隔**（统一前缀 `cicasgen_*`，并在文件头标注"本文件为自动生成、非 zlint 原生"的横幅），且被物理隔离在 zlint 源码树之外；zlint 语料抽取器与覆盖匹配器两端均拒绝任何带生成前缀的 lint。由此守恒方程中的"已覆盖"项严格只计第三方（zlint）实现，生成代码只能落在"未覆盖"项的产出侧、绝不反向计入覆盖——保证"可 lint = 已覆盖 + 未覆盖"这一恒等式不被自指破坏。

**证书级 oracle 的边界。** §7.1 的证书级语义 oracle 给出 $\mathrm{Code}\equiv\mathrm{IR}$ 的确定性证明，但其有效性受三条边界约束，不应被读作对所有证书的形式正确性保证：**(i) 可认证子集**——只有能用证书工厂造出"满足 / 违反"区分对的原子才可认证，需跨证书上下文、密码学事实（如模数素性）或字节级编码的原子无法认证，其规则因而落在"未证"集；故 oracle 的覆盖是有界的（本范围约 ⟦135 / 363；全可 lint 约 46%，待重抽核定⟧），其余规则仍依赖 LLM 判官且被显式标注为未证。**(ii) 经验性而非定理**——原子认证是受控 fixture 边界上的有限测试而非对全体证书的形式证明，其强度取决于 fixture 对真 / 假边界的覆盖。**(iii) 共享 OID 表与往返损失**——fixture 与 lint 渲染端共用同一 `util.*` OID 表（防漂移但盲于 OID 身份层错误），且 stdlib 发射经 zcrypto 解析的往返会丢失原始 ASN.1 tag。此外，过严哨兵当前因真实证书语料过窄（约百张同质 CT 监控证书）而仅作报告、不计入判据。这些边界与 §9.9 的不可归约残差互为表里，共同界定"可被确定性证明忠实"的子空间，其外的产出由本框架诚实归入未证类而非冒充已证。

### 11.4 结论有效性

本文结论的适用范围严格受限于所采用的输入表示（结构化 IR）、受限代码空间（$\mathcal{T}_{\mathcal{V}}$）与验证流程（三层语义对齐 + BIIV），不应被外推为"所有 PKI 规范均可被完全自动化实现"；跨文档引用、动态约束与复杂条件规则现阶段仍需离线 $\rho_A$ 扩展或更强的上游建模。本研究在四个标准族上验证了有效性，但这不等同于对所有标准族、所有语言与监管语境具备稳定泛化能力，后者有待在更广泛、更多样的数据集上检验。

## 12. 结论

### 12.1 研究总结

本研究面向 PKI"规范-到-合规检查代码"的端到端自动化，给出一个贯通"规则提取 → 中间表示 → 可 lint 性判定 → 代码生成 → 验证"的统一框架。前半链路以确定性方式应对跨文档引用——构建 PKI 知识图谱并以确定性 GraphRAG 检索组装可溯源上下文，经双层提取（确定性召回 + 受 schema 约束的 LLM 语义解析）将规则转写为结构化 IR，并在 IR 之上将可 lint 性形式化为五个离散字段的确定性布尔函数。后半链路则在语言设计层面限制代码空间：将 $\phi_G$ 的值域形式化为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，由词汇封闭性命题在架构层关闭字段/OID 编造类幻觉，并以确定性机械翻译算子 $\sigma_{\mathrm{mech}}$ 将代码-规范同义判定的概率失真压缩至两个必要端点；进而以**证书级语义 oracle** 对生成 lint 经执行确定性证明 $\mathrm{Code}\equiv\mathrm{IR}$，在可认证子集上把同义判据由不可复现的单票判别器升级为可复现的执行级证明，并诚实披露其覆盖边界。两半链路以 IR 与五条件为统一接缝，并由反向传播式迭代验证框架（BIIV）将"召回完整性、代码-规范同义性、双 oracle 一致性"三个不变量作为可计算残差，在**无人工标注真值**的条件下提供沿管道反向定位与定向修复的收敛性保证。

### 12.2 主要结论

实证支持三点经验结论与一项方法学论断。**其一**，Web PKI 规范源与现有静态 lint 工具之间存在显著的**双向对齐缺口**：四款工具并集仅匹配 48.0% 的可 lint 规范规则（约 581 条缺乏实现），而约 45.0% 的已实现检查（约 525 条）在所分析语料中缺乏清晰规范基。**其二**，可靠的规则提取依赖**受约束的提取**而非端到端直接提示——将 LLM 限定为受 schema 约束的解析器、并以确定性检索与确定性可 lint 性判定包裹之，是提取可审计、可复现的关键。**其三**，Web PKI 规范规则中仅有一小部分（6142 条中约 18.2%）可被还原为静态证书 lint 检查，这一比例本身即是对"哪些规范可被静态强制"这一长期模糊问题的量化回答。在方法学层面，本研究给出并以实证支持一项一般性原则——**反向传播式验证链路上的每个算子都应尽可能确定化**——并以"可归约子集闭合 + 不可归约边界披露"双指标取代单一收敛阈值，为基于受限词汇的规范-到-代码生成提供了可复现的诚实边界声明范式。

### 12.3 未来工作

后续工作沿以下方向展开：将自然语言同义判定与符号执行、模型检查等形式化方法结合以建立交叉证据，缓解 $\phi_V$ 端点的判定失真；以单调可加流程持续扩展原子词典 $\mathcal{A}$，逐步消除 ASN.1 字节级编码、宿主框架未暴露字段等表达缺口；构建支持引用解析与依赖追踪的跨文档知识表示，并探索将引用解析纳入 $\mathcal{A}$ 的扩展规则；设计面向动态约束（时间、外部状态）的原子类与参数化规则表达；以及探索框架无关的 DSL 中间表示，即给定多套 $(\mathcal{A}, \rho)$ 对而保持同一 $\mathcal{T}$，使同一棵 DSL 树可被渲染至多语言宿主框架。

### 12.4 更广泛的影响

"在语言设计层面限制代码空间 + 沿管道反向传播残差"这一方法学路径，对任何具有"结构化中间表示 + LLM 端点判定"形态的合规验证链路均具可迁移性。潜在应用包括将网络协议规范（TCP/IP、HTTP、TLS）转换为合规检查代码、将隐私法规（GDPR、CCPA）或安全标准（ISO 27001、NIST）转换为配置与数据处理合规检查，以及医疗（HIPAA）、金融（PCI-DSS）等行业的领域特定合规检查。这些领域同样面临规范文本与可执行代码之间的语义鸿沟，其差异主要体现在领域 DSL（即 $\mathcal{A}, \mathcal{V}$ 的具体内容）的设计上，而代码空间封闭性、$\sigma_{\mathrm{mech}}$ 确定化与反向传播式残差归因机制可在方法学层面整体迁移。

## 参考文献

[1] D. Cooper, S. Santesson, S. Farrell, S. Boeyen, R. Housley, and W. Polk, "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile," RFC 5280, May 2008.

[2] CA/Browser Forum, "Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates," v2.x, 2023.

[3] ETSI, "Electronic Signatures and Infrastructures (ESI); Certificate Profiles; Part 4: Certificate profile for web site certificates," ETSI EN 319 412-4, 2020.

[4] Mozilla, "Mozilla Root Store Policy," 2023.

[5] S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels," RFC 2119, March 1997.

[6] B. Leiba, "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words," RFC 8174, May 2017.

[7] ZMap Project, "ZLint: X.509 Certificate Linter." [Online]. Available: https://github.com/zmap/zlint

[8] C. Bonnell, "pkilint: A framework for verifying PKI structures," DigiCert, 2023. [Online]. Available: https://github.com/digicert/pkilint

[9] P. Bowen, "certlint: X.509 certificate linter," 2016. [Online]. Available: https://github.com/amazon-archives/certlint

[10] K. Roeckx, "x509lint: A linter for X.509 certificates," 2016. [Online]. Available: https://github.com/kroeckx/x509lint

[11] D. Kumar, Z. Wang, M. Hyder, J. Dickinson, G. Beck, D. Adrian, J. Mason, Z. Durumeric, J. A. Halderman, and M. Bailey, "Tracking Certificate Misissuance in the Wild," in Proc. IEEE Symposium on Security and Privacy (S&P), 2018, pp. 785–798.

[12] Mozilla, "CA/Entrust Issues," MozillaWiki, 2024.

[13] Chrome Root Program, "Sustaining Digital Certificate Security — Entrust Certificate Distrust," Google Security Blog, 2024.

[14] Let's Encrypt, "2020.02.29 CAA Rechecking Bug," Let's Encrypt Community Forum, 2020.

[15] CA/Browser Forum, "Ballot SC075: Pre-sign Linting," 2024.

[16] CA/Browser Forum, "Ballot SC-081v3: Introduce Schedule of Reducing Validity and Data Reuse Periods," 2025.

[17] M. Zhang, J. Guo, Y. Zhang, S. Zhang, B. Liu, H. Zhao, X. Li, and H. Duan, "Analyzing Compliance and Complications of Integrating Internationalized X.509 Certificates," in Proc. ACM Internet Measurement Conference (IMC), 2025, pp. 851–870.

[18] B. Andow, S. Y. Mahmud, W. Wang, J. Whitaker, W. Enck, B. Reaves, K. Singh, and T. Xie, "PolicyLint: Investigating Internal Privacy Policy Contradictions on Google Play," in Proc. USENIX Security Symposium, 2019, pp. 585–602.

[19] S. Zimmeck, R. Goldstein, and D. Baraka, "PrivacyFlash Pro: Automating Privacy Policy Generation for Mobile Apps," in Proc. NDSS, 2021.

[20] S. Hassani, M. Sabetzadeh, D. Amyot, and J. Liao, "Rethinking Legal Compliance Automation: Opportunities with Large Language Models," in Proc. IEEE Int. Requirements Engineering Conf. (RE), 2024, pp. 432–440.

[21] N. Feng, L. Marsso, S. Getir Yaman, Y. Baatartogtokh, R. Ayad, V. O. De Mello, B. Townsend, I. Standen, I. Stefanakos, C. Imrie et al., "Analyzing and Debugging Normative Requirements via Satisfiability Checking," in Proc. IEEE/ACM Int. Conf. on Software Engineering (ICSE), 2024, pp. 1–12.

[22] P. Sharma and V. Yegneswaran, "PROSPER: Extracting Protocol Specifications Using Large Language Models," in Proc. ACM Workshop on Hot Topics in Networks (HotNets), 2023, pp. 41–47.

[23] M. Zheng, D. Xie, Q. Shi, C. Wang, and X. Zhang, "Validating Network Protocol Parsers with Traceable RFC Document Interpretation," Proc. ACM on Software Engineering, vol. 2, no. ISSTA, pp. 1772–1794, 2025.

[24] M. Zhang, R. Feng, H. Tang, Y. Zhao, J. Yang, H. Qiu, and Q. Liu, "Automated Extraction of Protocol State Machines from 3GPP Specifications with Domain-Informed Prompts and LLM Ensembles," arXiv:2510.14348, 2025.

[25] Y. Wu, X. Feng, Y. Yang, and K. Xu, "Uncovering Gaps Between RFC Updates and TCP/IP Implementations: LLM-Facilitated Differential Checks on Intermediate Representations," arXiv:2510.24408, 2025.

[26] D. Edge, H. Trinh, N. Cheng, J. Bradley, A. Chao, A. Mody, S. Truitt, D. Metropolitansky, R. O. Ness, and J. Larson, "From Local to Global: A Graph RAG Approach to Query-Focused Summarization," arXiv:2404.16130, 2024.

[27] B. Peng, Y. Zhu, Y. Liu, X. Bo, H. Shi, C. Hong, Y. Zhang, and S. Tang, "Graph Retrieval-Augmented Generation: A Survey," ACM Trans. Inf. Syst., vol. 44, no. 2, pp. 1–52, 2025.

[28] Y. Dong, C. F. Ruan, Y. Cai, Z. Xu, Y. Zhao, R. Lai, and T. Chen, "XGrammar: Flexible and Efficient Structured Generation Engine for Large Language Models," Proc. Machine Learning and Systems (MLSys), vol. 7, 2025.

[29] D. Banerjee, T. Suresh, S. Ugare, S. Misailovic, and G. Singh, "CRANE: Reasoning with Constrained LLM Generation," arXiv:2502.09061, 2025.

[30] M. Schall and G. de Melo, "The Hidden Cost of Structure: How Constrained Decoding Affects Language Model Performance," in Proc. RANLP, 2025, pp. 1074–1084.

[31] J. Debnath, C. Jenkins, Y. Sun, S. Y. Chau, and O. Chowdhury, "ARMOR: A Formally Verified Implementation of X.509 Certificate Chain Validation," in Proc. IEEE Symposium on Security and Privacy (S&P), 2024, pp. 1462–1480.

[32] M. Chen, J. Tworek, H. Jun, Q. Yuan, H. P. de Oliveira Pinto et al., "Evaluating Large Language Models Trained on Code," arXiv:2107.03374, 2021.

[33] Y. Li, D. Choi, J. Chung, N. Kushman, J. Schrittwieser et al., "Competition-Level Code Generation with AlphaCode," Science, vol. 378, no. 6624, pp. 1092–1097, 2022.

[34] Q. Zheng, X. Xia, X. Zou, Y. Dong, S. Wang et al., "CodeGeeX: A Pre-Trained Model for Code Generation with Multilingual Evaluations on HumanEval-X," in Proc. ACM SIGKDD (KDD), 2023, pp. 5673–5684.

[35] J. Yen, P. Sharma, R. Skowyra, S. Biswas, H. Okhravi, and J. Landry, "Semi-Automated Protocol Disambiguation and Code Generation," in Proc. ACM SIGCOMM, 2021, pp. 272–288.

[36] M. L. Pacheco, M. Goldwasser, and S. Bagchi, "Automated Attack Synthesis by Extracting Finite State Machines from Protocol Specification Documents," in Proc. IEEE Symposium on Security and Privacy (S&P), 2022, pp. 1950–1968.

[37] ZMap Project, "ZLint Scope Mapping — CA/Browser Forum Baseline Requirements v1." [Online]. Available: https://github.com/zmap/zlint/blob/master/util/scoping/CA-Browser%20Forum%20Baseline%20Requirements%20v1%20-%20Sheet1.csv

[38] ZMap Project, "ZLint Scope Mapping — CA/Browser Forum Baseline Requirements v2.0.2." [Online]. Available: https://github.com/zmap/zlint/blob/master/util/scoping/CA-Browser%20Forum%20Baseline%20Requirements%20v2.0.2%20-%20Sheet1.csv

## 附录

### 附录 A：结构化 IR 的关键字段

系统内部使用一个机器可读的 IR 对象（JSON 序列化）。除 §4.4 核心四元组外，其关键字段如下；其余字段支持溯源、归一化、匹配与下游产物生成。可 lint 性判定（§5）只直接使用 obligation、assertion_subject、enforcement_phase、check_scope、rule_category 五个字段。

| 字段 | 角色 | 含义 |
|---|---|---|
| subject | 核心 | 受约束的证书字段或路径 |
| obligation | 核心 | RFC 2119 道义级别（MUST/SHOULD/…） |
| predicate | 核心 | 约束关系（存在、相等、包含、范围） |
| constraint | 核心 | 约束值、模式或条件 |
| rule_category | 关键扩展 | 规则语义类别（encoding_constraint、definition、algorithm_ref 等） |
| assertion_subject | 关键扩展 | 断言主体（证书 / CA / 依赖方 / 外部生态） |
| enforcement_phase | 关键扩展 | 约束所依赖的阶段（编码 / 运行时 / 外部验证） |
| source_section | 关键扩展 | 规范源与章节标识 |
| source_span | 关键扩展 | 源文本中的字符 / 句子跨度 |
| evidence_text | 关键扩展 | 支撑该 IR 记录的原文片段 |
| context_nodes | 关键扩展 | 来自 GraphRAG 检索的定义、字段元数据或被引上下文节点 |

### 附录 B：知识图谱关系类型与检索可入性

GraphRAG 检索（§4.2）围绕一组核心关系构建上下文，并显式区分"可进入检索的关系"与"仅用于后处理的关系"。检索阶段遵守四条约束（GR-1 至 GR-4）：不允许推断出的规范规则进入检索；只有原始规范节点可进入检索；任何推断性关系不得进入检索；所有上下文必须可追溯至规范源。

| 类型 | 关系 | 角色 | 进入检索 |
|---|---|---|---|
| 核心 | CONTAINS | 规范、章节与规则之间的包含层级 | 是 |
| 核心 | DEFINES | 术语/字段/定义段落到其被定义对象的连接 | 是 |
| 核心 | REFERENCES | 对其他规范/章节/算法的显式引用 | 是 |
| 核心 | APPLIES TO | 规则到其所约束抽象概念的连接 | 是 |
| 辅助 | AFFECTS | 规则到其影响的具体证书字段（字段解析器使用） | 否 |
| 辅助 | DERIVED FROM | 派生规则到其源章节的溯源链接 | 否 |
| 推断 | OVERRIDES | 更具体规则覆盖一般规则（规则引擎产生） | 否 |
| 推断 | CONFLICTS WITH | 规则之间的潜在冲突（规则引擎产生） | 否 |

### 附录 C：Layer 2 受控提取的六项约束

为把 LLM 限定为受 schema 约束的语义解析器，Layer 2 施加六项约束。**[L2-1] 强制分类**：每条规则须落入封闭的规则类别集合（encoding_constraint、definition、algorithm_ref、clarification、comparison、capability、display 等），仅 encoding_constraint、clarification、comparison 进入下游可 lint 性判定。**[L2-2] 输出 schema 校验**：LLM 输出须严格符合预定义 IR schema，不符者被拒并重提。**[L2-3] 规则引擎覆盖**：在可确定性判定的情形下规则引擎覆盖 LLM 分类（如"in step"→algorithm_ref、"is defined as"→definition）。**[L2-4] 源验证**：每条 IR 附带索引到源文本的引用片段，文本对齐校验器核验其文本字段确源自该片段，未对齐者作为幻觉丢弃（文本层）。**[L2-5] subject 路径约束**：涉及 subject DN 之下属性时，路径须落在由 RFC 5280 ASN.1 定义构建的规范路径树上（schema 层，与 L2-4 互补）。**[L2-6] 分阶段 IR 提取**：当单次调用须填充 15 个以上字段时分类准确率仅 65–72%，故采用两阶段策略——先以分类提示输出四个分类字段，再以其作为软约束填充其余字段。

### 附录 D：受限代码空间 $\mathcal{T}_{\mathcal{V}}$ 的构造细节

**词汇表 $\mathcal{V}$ 的七个分量。** $\mathcal{V}$ 是若干在系统启动时冻结的有限集合的不相交并（式 3）：

| 分量 | 大小（近似） | 内容 |
|---|---:|---|
| $\mathcal{F}_{\mathrm{cert}}$（证书字段） | ~40 | `c.Version`、`c.SerialNumber`、`c.NotBefore`、`c.DNSNames`、`c.IPAddresses`、`c.RawSubjectPublicKeyInfo`、`c.PermittedDNSNames`、… |
| $\mathcal{F}_{\mathrm{dn}}$（DN 字段） | ~15 | `Subject.CommonName`、`Subject.Country`、`Subject.OrganizationalUnit`、…（Issuer 同样适用） |
| $\mathcal{O}$（OID 常量） | ~30 | `SubjectAlternateNameOID`、`BasicConstOID`、`KeyUsageOID`、…（对应 zlint `util.*OID`） |
| $\mathcal{B}_{\mathrm{KU}}$（KeyUsage 位） | 9 | `DigitalSignature`、`KeyEncipherment`、`KeyCertSign`、`CRLSign`、… |
| $\mathcal{B}_{\mathrm{EKU}}$（ExtKeyUsage 位） | ~10 | `ServerAuth`、`ClientAuth`、`CodeSigning`、`EmailProtection`、`OCSPSigning`、… |
| $\mathcal{E}_{\mathrm{ASN1}}$（ASN.1 编码类型） | 5 | `UTF8String`、`PrintableString`、`IA5String`、`BMPString`、`VisibleString` |
| $\mathcal{R}_{\mathrm{regex}}$（命名正则） | ~20 | `Re_LDH_Hostname`、`Re_Rfc3986Uri`、`Re_HttpOrLdapStrict`、…（每项为已审核的字面 RE2 模式） |

所有分量均为冻结有限集合；LLM 在 prompt 区段 C（附录 I）获得各分量全量枚举，故其输出中出现 $\mathcal{V}$ 之外的标识符即触发 $\eta$ 解析错误（命题 1）。

**代表性原子（节选）。** 原子集 $\mathcal{A}$（$|\mathcal{A}|=56$）按语义簇组织，每个原子有类型化签名 $\mathrm{sig}(a)$（§6.3）。下表按簇节选关键原子（完整 56 项随代码与数据一并公开）：

| 簇 | 原子 | 签名 | 语义 |
|---|---|---|---|
| I 扩展存在性 | `ExtPresent` | $(\mathcal{O})$ | 扩展 OID 存在 |
| I | `ExtCritical` | $(\mathcal{O})$ | 扩展存在且 Critical 位置位 |
| I | `ExtRawValueEqualsHex` | $(\mathcal{O}, \mathrm{Hex})$ | extnValue 原始字节等于十六进制字面量 |
| II 宏属性 | `IsCA` / `IsServerCert` | $()$ | BasicConstraints.cA=true / EKU 含 ServerAuth |
| II | `KeyUsageHas` | $(\mathcal{B}_{\mathrm{KU}})$ | KeyUsage 位图含指定位 |
| II | `ExtKeyUsageHas` | $(\mathcal{B}_{\mathrm{EKU}})$ | EKU 列表含指定项 |
| III 字段值/形态 | `FieldEq` | $(\mathcal{F}, \mathrm{lit})$ | 字段等于字面量 |
| III | `FieldMatchesRegex` | $(\mathcal{F}, \mathcal{R}_{\mathrm{regex}})$ | 字段匹配命名正则 |
| III | `FieldLenInRange` | $(\mathcal{F}, \mathbb{Z}, \mathbb{Z})$ | 字段长度 ∈ [lo, hi] |
| III | `FieldEncodedAs` | $(\mathcal{F}, \mathcal{E}_{\mathrm{ASN1}})$ | 字段 ASN.1 编码类型为指定类型 |
| III | `OidEq` | $(\mathcal{F}, \mathcal{O})$ | OID 字段等于命名 OID |
| IV 列表/字节级 | `ListAllMatch` / `ListAnyMatch` | $(\mathcal{F}, \mathcal{T})$ | 列表全部 / 至少一项满足子树 |
| IV | `WildcardFilter` | $(\mathcal{F}, \mathrm{String}, \mathcal{T})$ | 匹配前缀的子项满足子树 |
| IV | `OidListContains` | $(\mathcal{F}, \mathcal{O})$ | OID 列表包含命名 OID |
| IV | `BytesContainsOidDer` | $(\mathcal{F}, \mathcal{O})$ | 字节切片包含 OID 的 DER 编码 |
| V NameConstraints | `SubtreeIPListAnyHasOctetCountAndNotAllZero` | $(\mathcal{F}, \mathbb{Z})$ | NC IP 子树存在指定字节数且非全零项 |
| VI 特殊结构 | `DomainComponentOrdered` | $()$ | Subject 中 domainComponent 按 RFC 4519 反向排列 |

组合子 $\{\neg, \wedge, \vee\}$ 三个，语义遵循经典命题逻辑。

**共享 Go 渲染样板。** 所有 DSL 树经 $\rho$ 渲染后嵌入下列固定外壳，规则间差异完全集中在 `{{EXECUTE_BODY}}` 与 `{{IMPORTS}}`；`{{PACKAGE}}`/`{{SOURCE}}`/`{{EFFECTIVE_DATE}}`/`{{DESCRIPTION}}`/`{{CITATION}}`/`{{LINT_NAME}}` 由 $\Phi_{\mathrm{post}}$（§6.7）确定性绑定：

```go
package {{PACKAGE}}
import (
{{IMPORTS}}
)
type {{STRUCT_NAME}} struct{}
func init() {
    lint.RegisterCertificateLint(&lint.CertificateLint{
        LintMetadata: lint.LintMetadata{
            Name:          "{{LINT_NAME}}",
            Description:   "{{DESCRIPTION}}",
            Citation:      "{{CITATION}}",
            Source:        lint.{{SOURCE}},
            EffectiveDate: util.{{EFFECTIVE_DATE}},
        },
        Lint: New{{STRUCT_NAME}},
    })
}
func New{{STRUCT_NAME}}() lint.LintInterface { return &{{STRUCT_NAME}}{} }
func (l *{{STRUCT_NAME}}) CheckApplies(c *x509.Certificate) bool { return true }
func (l *{{STRUCT_NAME}}) Execute(c *x509.Certificate) *lint.LintResult {
    {{EXECUTE_BODY}}
}
```

**后处理元数据映射。** $\Phi_{\mathrm{post}}$ 按下表将可溯源字段确定性注入；义务级别到严重度的映射为 MUST/MUST NOT/SHALL/SHALL NOT/REQUIRED $\mapsto$ `lint.Error`（lint 名前缀 `e_`）、SHOULD 类 $\mapsto$ `lint.Warn`（`w_`）、MAY/OPTIONAL $\mapsto$ `lint.Notice`（`n_`）：

| `source_id` | `PACKAGE` | `SOURCE` 常量 | `EFFECTIVE_DATE` 常量 |
|---|---|---|---|
| RFC5280 | `rfc` | `RFC5280` | `RFC5280Date` |
| CABF-TLS-BR | `cabf_br` | `CABFBaselineRequirements` | `CABEffectiveDate` |
| CABF-SMIME-BR | `cabf_smime_br` | `CABFSMIMEBaselineRequirements` | `CABF_SMIME_BRs_1_0_0_Date` |
| CABF-CS | `cabf_cs_br` | `CABFCSBaselineRequirements` | `CABF_CS_BRs_1_2_Date` |
| CABF-EV | `cabf_ev` | `CABFEVGuidelines` | `CABEffectiveDate` |
| ETSI-412-4 | `etsi` | `EtsiEsi` | `EtsiEsiEffectiveDate` |
| Mozilla-MRSP | `mozilla` | `MozillaRootStorePolicy` | `MozillaPolicy27Date` |
| Apple | `apple` | `AppleRootStorePolicy` | `AppleReducedLifetimeDate` |

### 附录 E：机械翻译算子 $\sigma_{\mathrm{mech}}$ 的短语字典（节选）

$\sigma_{\mathrm{mech}}$（§8.13）由原子-短语字典 $\mu : \mathcal{A} \to \mathcal{L}_{\mathrm{NL}}$ 与三组合子归约规则构成。代表性条目：

| 原子 | $\mu(a)$ 短语模板 |
|---|---|
| `ExtPresent(O)` | "the {O} extension is present" |
| `ExtCritical(O)` | "the {O} extension is present and marked critical" |
| `FieldEq(F, v)` | "{F} equals {v}" |
| `FieldEncodedAs(F, T)` | "{F} is encoded as ASN.1 {T}" |
| `KeyUsageHas(B)` | "the KeyUsage bit {B} is asserted" |
| `ListAllMatch(F, T)` | "every entry of {F} satisfies ({σ_mech(T)})" |
| `SubtreeIPListAnyHasOctetCountAndNotAllZero(F, n)` | "the NameConstraints IP subtree {F} contains a non-zero entry of {n} octets" |

组合子归约：$\mu(\neg t) =$ "NOT ($\mu(t)$)"；$\mu(t_1 \wedge t_2) =$ "($\mu(t_1)$) AND ($\mu(t_2)$)"；$\vee$ 同理。对条件二元组 $(p,q)$：当 $p = \neg(p')$ 时输出 "WHEN NOT ($\mu(p')$), THEN $\mu(q)$"（消除双重否定的 NEG-PRE 模板），否则输出 "WHEN ($\mu(p)$), THEN $\mu(q)$"，$p=\perp$ 时输出 $\mu(q)$ 单句。

### 附录 F：lint 覆盖缺口的四类结构性成因

§9.3 报告的双向覆盖缺口并非单一原因，而是 lint 生态中四类结构性因素共同作用的结果。**(C1) 异步演进**：CABF Ballots 与 RFC 勘误的修订速度快于维护者的吸收能力，新增与废止的规范规则都表现为未匹配。**(C2) 多源非规范依据**：相当一部分 lint 检查根植于 issue tracker 决策、根程序实践或 CA 运维经验，构成所分析语料之外、不可达的次级权威。**(C3) 规范文本不完备**：规范源中的自然语言歧义（如"appropriate""reasonable"）由工具维护者解释而非在文本中写明，故不计为覆盖命中。**(C4) 粒度不对称**：规范规则与 lint 检查原子之间存在多对多映射，使覆盖完整性难以人工核验。

### 附录 G：典型 lint↔规范对照案例

本附录以 zlint 为例，从 §9.3 对齐结果（算法 3）中按 full / partial / none 三类各采样一个代表性案例，展示覆盖分析管道在不同情形下的判定与受控判官给出的理由。

| lint rule_id | code_summary | 匹配规范规则 | 判定 | 判定原因 |
|---|---|---|---|---|
| `e_ca_common_name_missing` | The CA certificate subject MUST include a commonName attribute. | CABF-Server §7.1.2.10.2：`commonName` \| MUST | **full** | 两者都要求 CA 证书 subject 中存在 commonName，字段与义务级别一致。 |
| `e_ca_key_usage_not_critical` | The root CA and intermediate CA certificate keyUsage extension MUST be marked critical. | CABF-SMIME §7.1.2.3：`keyUsage`（SHALL be present）This extension SHOULD be marked critical | **partial** | lint 对 keyUsage criticality 施加了比规范 SHOULD 更严的 MUST 约束。 |
| `e_cab_dv_subject_invalid_values` | The subscriber certificate subject DN MUST NOT contain attribute types other than countryName and commonName. | —（未召回） | **none** | 在严格语义等价判据下，候选后端池中未召回匹配规则，尽管该 lint 引用了 CABF-BR §7.1.2.7.2。 |

### 附录 H：典型失败案例分析

本附录基于 §9.8 反馈循环实验（52 条低对齐规则）与 §9.6 大规模代码生成中观察到的真实失败样本，给出失败类型分布与典型案例。

**错误类型分布。** 对 52 条反馈循环输入样本自动错误分型：

| 错误类型 | 出现次数 | 可确定性修复 |
|---|---:|---|
| description_mismatch | 3 | 是（`Description` 原文替换） |
| hallucinated_checks | 3 | 否（需重新生成） |
| missing_check_applies | 2 | 否（需重新生成） |
| missing_execute | 2 | 否（需重新生成） |
| wrong_field | 2 | 否（需重新生成） |
| wrong_obligation | 2 | 否（需重新生成） |
| citation_mismatch | 1 | 是（章节号正则替换） |
| wrong_logic | 1 | 否（需重新生成） |

其中可确定性修复者共 4 条（description_mismatch × 3、citation_mismatch × 1）；其余均需重新生成，但在单轮重试条件下平均得分由 0.849 略降至 0.837（改善 1、恶化 2、不变 49，收敛率 94.2%）。该分布直接支撑正文"朴素反馈循环在缺乏阶段归因时无法稳定改善质量"的判断，也是引入 §8 反向传播式阶段归因的动机。

**案例 1：Description 不匹配（可确定性修复）。** 来源 RFC 5280 §4.3.4；初始对齐 0.67、反馈后 0.40；症状为 LLM 自由复述规范原文导致 `Description` 与 IR `rule_text` 不一致；修复以正则 `Description:\s*"[^"]*"` 整块替换为原文。若替换后仍低，说明其他字段（如 `wrong_field`）亦偏差，须触发 §8 阶段归因。

**案例 2：Hallucinated Checks（需重新生成）。** 来源 ETSI EN 319 412-4 §4.4；初始 0.59、反馈后 0.15；症状为代码引入规范未要求的额外检查（如对 CommonName 的长度断言），使代码摘要严重偏离 `Description`；该类错误常源于 few-shot 示例偏置，修复需在 prompt 中显式禁止引入 IR 之外的约束并回注差异触发重生成。

**案例 3：Citation 错误（可确定性修复）。** 来源跨文档引用 `unknown §1.3.2.1.2`；症状为 `Citation` 指向章节与 IR `provenance.section` 不一致；以 IR `section` 为权威源重新生成 `"{SOURCE_ID}: {SECTION}"` 并替换。

**代码块解析失败（格式偏差）。** §9.6 大规模生成中，8 条因"响应未找到 ```go 代码块"失败——源于模型把 Go 代码嵌入无围栏自由文本，而非理解能力不足。加入无围栏回退解析（自 `package ` 起、至最后一个右花括号止切片）后恢复 6 条，其余 2 条确属返回被截断，进入下一轮重试。

### 附录 I：DSL 合成 Prompt 模板

本附录给出 §6.7 所述受约束 LLM 调用 $\phi_G$ 的实际系统提示与四区段拼接结构。

**系统提示。**

```
You are a structured DSL synthesizer for X.509 certificate lint rules.
You DO NOT write Go code. You output ONLY a JSON tree describing a
predicate over the certificate, drawn strictly from the closed atom
catalogue and typed vocabulary provided in the user message.

HARD CONSTRAINTS (violation = automatic rejection by the parser η):
1. Every atom name MUST appear in the supplied catalogue A.
2. Every leaf argument MUST be a literal of the declared type, or a
   name that appears in the supplied vocabulary V (CERT_FIELDS,
   DN_FIELDS, OID_CONSTS, KEY_USAGE_BITS, EKU_BITS, ASN1_TYPES,
   NAMED_REGEXES, DATE_FIELDS). Inventing identifiers is forbidden.
3. The output MUST be one of:
     {"predicate": <Tree>, "precondition": <Tree>|null,
      "severity": "lint.Error"|"lint.Warn"|"lint.Notice",
      "label": <string>}
   OR
     {"no_template": true, "reason": <string>}
   Any other shape will fail parsing.
4. Description / Citation / Name fields are NOT generated by you;
   they are bound deterministically by the post-processor Φ_post.
```

**四区段拼接。** 每次调用的完整 prompt 由四区段依次拼接：**区段 A（Rule Context）**——源 ID、章节号、规则 ID、逐字 `rule_text`（即将作为 `Description` 注入的字面量）与 `source` 元数据；**区段 B（Structured IR）**——扁平展开的 IR 四元/五元组（`subject`、`obligation`、`predicate`、`constraint`、`precondition`）；**区段 C（DSL Schema）**——附录 D 所述 $\mathcal{V}$ 与 $\mathcal{A}$ 的全量枚举（按分量分组的字段名清单与按语义簇分组的原子签名表，附每原子一行 PKI 语义注释）；**区段 D（Output Protocol）**——上述两种合法 JSON 形态的精确 schema，含字段类型、必选/可选标记与一条 minimal positive 示例。
