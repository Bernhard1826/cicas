# 从 PKI 标准到合规检查代码：规则提取、可 lint 性判定与可验证代码生成的端到端框架

## 摘要

公钥基础设施（PKI）的证书编码规则分散在 RFC 5280、CA/Browser Forum 基线要求（CABF BR）、ETSI EN 319 与 Mozilla 根存储策略等多份自然语言标准中。自 2025 年起 CA/Browser Forum 要求所有公信 CA 在签发前对证书执行 lint 检查，将规范文本系统转化为可执行的合规代码因而成为 PKI 治理的关键环节。然而现有 lint 工具（如 zlint、pkilint）的每条检查均由专家逐条手写并随规范修订维护，"哪些规范条款能被静态检查、现有工具又覆盖到何种程度"长期缺乏系统答案。

本文的出发点是一个常被忽略的事实：**并非每条带 MUST 的规范都能写成 lint**——许多强义务约束的是 CA 线下行为、证书链或运行时状态，而非单张证书的字节。我们因此把**可 lint 性**（一条规则能否仅凭一张证书的字节被静态裁决）形式化为五个离散 IR 字段上的确定性布尔合取，使判定可复现、误判可追溯到唯一字段；并在其上构建一个从标准文本到合规检查代码的端到端框架，串联规则提取、中间表示（IR）、可 lint 性判定、代码生成与验证。

总设计原则是：仅在确需语言理解之处使用大语言模型（LLM），其余环节实现为可复现的确定性函数。跨文档上下文由规范知识图谱上的确定性子图检索给出；LLM 只承担受 schema 约束的 IR 解析（四元组 ⟨主体, 义务, 谓词, 约束⟩）。代码生成不输出自由 Go 代码，而把生成算子的值域限制为有限原子模板集（77 个原子模板）与类型化词汇表张成的受限 DSL 树空间，在架构层排除"编造字段/OID"类幻觉（命题 1）。针对"代码是否忠实于规范"这一最难判定，本文不依赖 LLM 投票，而构建**证书级语义 oracle**：为每个原子模板生成"满足/违反"两类受控证书、由真实执行读回状态，从而对仅由已认证原子模板构成的生成 lint 给出与模型无关、可复现的"代码≡IR"执行级验证（受控 fixture 上的验证而非对全体证书的定理，详见 §6.6）。缺乏人工真值时，再由**阶段归因式迭代验证（Stage-Attribution Iterative Verification, SAIV）**把召回完整性、覆盖度、代码-规范同义性与双判定源一致性形式化为可计算残差，配以阶段归因与"有下降才接受"的修复策略，在无真值下提供可追溯、可有限终止的质量控制。

在 RFC 5280 与 CABF BR 上的实证如下。关键词召回 2077 条候选，守恒划分得 1555 条真规则、其中 373 条可 lint；zlint 既有实现完整覆盖 141 条、部分覆盖 29 条，余 224 条为代码生成的直接目标。在 224 条未完整覆盖的目标中，217 条目标集经确定性路实测 Form A 编译通过 90 条（41.5%），再经 code_summary≡规范（去噪 5 票多数同义判官）得 71 条 EXPRESSES（30.4%）；LLM 路对 146 条残差分别经 best-of-N（10次采样，14 syn）和 LLM-compile（28条编译，7 syn）两种路径尝试，去重后 net new 17 条同义；合计 **88/217 = 40.6%**（det 71 + LLM 17），经 oracle ∧ 去噪双门口径下全部同义。

**一项贯穿全文的发现是：端到端瓶颈在 Spec→IR 抽取、而非 IR→Code 生成。** 确定性路 over 217 条目标实测原始同义率约 30.4%（71/217），与历史天花板一致；不同义几乎全部可追溯到上游抽取（主语错抽、把子字段当成整个扩展），更换更强抽取器并未抬高该率，说明天花板由抽取任务难度而非模型规模所界。LLM 路在最难子集（146条残差）上进一步 rescue 17 条，综合同义率提升至 40.6%。其中"代码≡IR"为自动验证、而同义判官直接比对的是"code_summary≡规范"（code_summary 即机械摘要 $\sigma_{\mathrm{mech}}(t)$、忠实于原文）、当前仍依赖去噪多数判官；二者复合方得端到端"代码≡规范"（"IR≡规范"是其在该子集上的推论），故仅对发射集成立——如何把这一最后同义端点进一步确定化，是本框架定位出的首要开放问题。

方法学上，本文提炼出一条不限于 PKI 的设计原则：验证链路上每个算子都应尽可能确定化，证书级 oracle 把原属 LLM 的"忠实性判定"也确定化，即其在验证端的体现。相应地，本文以"可归约子集闭合 + 不可归约边界诚实披露"双指标取代单一收敛阈值。

**关键词**：公钥基础设施；证书合规检查；规范规则提取；中间表示；可 lint 性分析；受限代码生成；证书级语义 oracle；阶段归因式迭代验证

## 1. 引言

### 1.1 研究背景与动机

公钥基础设施（Public Key Infrastructure, PKI）是现代互联网信任的基础：证书颁发机构（CA）签发的 X.509 数字证书支撑着身份认证与加密通信。证书是否被正确签发因而直接关系到 Web PKI 的完整性——违反技术性规范要求的证书会削弱浏览器信任、损害安全通信的可靠性。这类失效并非纯理论风险：2024 年 Chrome 与 Mozilla 在一系列未解决的合规事故后相继宣布不再信任 Entrust 作为公信 CA [13], [12]；更早的 2020 年，Let's Encrypt 因一处 CAA 校验缺陷撤销了约三百万张证书 [14]。

这些事故已转化为政策变化：据 CA/Browser Forum Ballot SC075，公信 CA 自 2025 年 3 月 15 日起需在签发前执行 lint 检查 [15]；Ballot SC-081v3 则规划将 TLS 证书有效期分阶段压缩、最终降至 47 天 [16]。二者共同抬高了签发频率与自动化合规需求。当前合规分析依赖 zlint [7]、pkilint [8]、certlint [9]、x509lint [10] 等静态工具，但它们高度依赖**人工规则工程**——每条检查须由专家随规范修订单独实现并维护；而 X.509 编码规范分散在 RFC 5280 [1]、CABF 基线要求 [2]、ETSI EN 319 412 系列 [3]、Mozilla 根存储策略 [4] 等多份文档、普遍以 RFC 2119 [5] 关键词表达义务级别，手工方式愈发难以规模化。

更根本的是，PKI 生态缺乏一个将规范文本系统性转化为可经静态 lint 检查强制执行的合规逻辑的框架。这一缺口随着 lint 在 PKI 治理中日益核心而愈发关键：规范本身并未区分"可由静态检查强制"与"需要证书之外的运行时或外部证据"两类规则。本研究的目标，即是给出一个从 Web PKI 规范源**提取规范规则、判定其可 lint 性、并自动生成对应可执行检查代码**的端到端框架。

理解这一缺口的关键是一个朴素却常被忽略的区分。同样含 MUST，"证书 MUST 包含 keyUsage 扩展"可仅凭一张证书的字节静态裁决，而"CA MUST 在签发前核验申请人身份"约束的是线下行为、任何静态检查都无从判定。我们称前者具备**可 lint 性**——能否被一个不依赖运行时或外部上下文、仅凭单张证书字节即可裁决的静态检查所表达；它是把规范转化为代码的前置闸门，本文将其形式化为 IR 上的确定性布尔判定（§5）。在此之上，本框架在 RFC 5280 与 CABF BR 上从 2077 条候选判出 **373 条可 lint 规则**，并定位出一项贯穿全文的发现——**端到端瓶颈在 Spec→IR 抽取、而非 IR→Code 生成**（§8）。

### 1.2 研究问题与挑战

将规范文本端到端地转换为可执行、可验证的合规代码，至少面临五方面挑战。

**(挑战一) 跨文档引用与间接约束。** Web PKI 规范源大量交叉引用与继承——如 CABF BR §7.1.2.7.12 在 RFC 5280 §4.2.1.6 之上进一步收紧、要求订户证书含 subjectAltName 扩展——孤立分析单一文档不足以还原规则真实语义。

**(挑战二) LLM 的不可控性与幻觉。** LLM 的非确定性与幻觉与合规分析所需的可复现性相冲突，提取须可审计、可控，而非端到端黑箱推理。

**(挑战三) 可 lint 性判定本身非平凡。** 出现 MUST/SHALL 并不意味着可被翻译为确定性静态检查——许多强义务约束的是 CA 行为、链处理或运行时状态而非证书编码，可 lint 性须被显式刻画。

**(挑战四) 规范与代码之间的语义鸿沟。** 规范以抽象自然语言表达约束、可执行代码须落实为具体字段路径与控制流，二者的鸿沟是开放式代码生成漏检与误报的根源。

**(挑战五) 缺乏独立真值。** 大规模生成缺乏现成可信的人工真值来逐条判定"代码是否忠实于规范"，验证须在**无独立真值**下提供可计算、可复算、可追溯的质量信号。

### 1.3 核心思想

把规范文本转化为可信代码，难点不在让 LLM 生成一段代码，而在让整条流水线可复现、可审计、可验证。本文的方法学由三条相互支撑的设计原则构成，可概括为：仅在确需 LLM 之处使用 LLM，其余环节尽量实现为确定性函数。

**第一，提取侧——确定性检索 + LLM 受限角色。** 跨文档上下文由知识图谱上的确定性子图遍历给出（可溯源），LLM 仅"将候选规则解析为受 schema 约束的结构化 IR"，所有规范性判断（可执行性、覆盖、冲突）推迟到后续确定性阶段，使提取可审计、可复现。

**第二，生成侧——代码空间应在语言层面而非 prompt 层面受限。** 与其用 prompt 反复约束 LLM 不要编造字段，不如使其无从编造：把代码生成算子的值域定义为一个有限闭合的 DSL 树空间，使编造字段/OID 的幻觉在架构层即被排除（命题 1），不依赖 prompt 约束或 few-shot 引导这类概率性手段。

**第三，验证侧——验证链路上的每个算子都应尽可能确定化。** 在语义等价传递链

$$
\mathrm{Spec} \;\to\; \mathrm{IR} \;\to\; t \in \mathcal{T}_{\mathcal{V}} \;\xrightarrow{\sigma}\; \mathrm{Summary} \;\equiv\; \mathrm{Description}
$$

中，关键词召回、可 lint 性判定、渲染、后处理、机械翻译均由确定性函数实现。尤为关键的是，连"生成代码是否忠实于 IR"这一判定本身也被确定化：可认证子集上由证书级语义 oracle 以真实证书执行给出"代码≡IR"的执行级验证，只有 oracle 不适用的忠实性判断和最终"code_summary≡规范"（机械摘要 $\sigma_{\mathrm{mech}}(t)$ 与原文）同义性把关仍需语义灵活的判官（详见 §6.6）。这印证一个更一般的观察——确定性的着力点可由生成端迁移到验证端。缺乏人工真值时，再由 SAIV 将多类质量不变量形式化为可计算残差，提供可追溯的迭代控制信号。

### 1.4 主要贡献

**(C1) 基于 IR 的五条件可 lint 性框架。** 将可 lint 性形式化为五个离散 IR 字段上的确定性布尔合取（道义强度、被约束主体、运行时阶段、单证书数据范围、规则类型），使判定可复现，任何误判可追溯到唯一 IR 字段而非不透明的端到端调用（§5）。

**(C2) 受限代码空间、可逆机械翻译与证书级语义 oracle。** 将代码生成算子的值域形式化为 77 个原子模板与类型化词汇表张成的受限 DSL 树空间（给出语法、执行语义与词汇封闭性命题 1），并定义确定性机械翻译算子（全函数、确定、原子模板等价意义下可逆）。其上构建证书级语义 oracle：经逐原子模板认证与结构组合，对仅由已认证原子模板构成的生成 lint 给出"代码≡IR"执行级验证，以与模型无关的可复现判据取代单票 LLM 判别器，并诚实披露可认证子集边界（§6）。

**(C3) 阶段归因式迭代验证（SAIV）与多目标残差。** 将召回完整性、lint 覆盖度（相对 zlint 既有实现的覆盖广度）、代码-规范同义性与双判定源一致性形式化为可计算残差，给出阶段归因规则、修复算子谱、有限终止条件与单调性前提；首要算子为 IR 内容自反思修复、经确定性闸门自动闭环，并以二元仲裁判官对双判定源一致性残差给出可复算的单调清零路径。该框架在无人工标注真值条件下提供质量控制（§7）。

## 2. 相关工作

### 2.1 PKI 标准与静态合规检查

X.509 证书的编码规范由分层的标准与策略框架共同定义。RFC 5280 [1] 给出证书 ASN.1 结构、字段级语义与路径验证算法这一基础层；其上，CABF 基线要求 [2] 对签发公信 TLS 证书的商业 CA 施加操作性与配置性约束；ETSI EN 319 412 系列 [3] 补充了与 eIDAS 框架对齐的欧盟配置档案；Mozilla 根存储策略 [4] 则从浏览器策略层引入额外技术要求。这些规范彼此交叉引用并时有局部覆盖，普遍以 RFC 2119 [5] 关键词表达义务级别（MUST/SHALL 通常映射为 Error，SHOULD/RECOMMENDED 映射为 Warning，MAY/OPTIONAL 一般不宜直接实现为 lint 规则）。

证书合规主要由静态 lint 工具检查（只检视单张证书、不依赖外部验证状态）：zlint [7] 部署最广，将检查组织为带元数据（引用、生效日期、严重级别）的独立 lint（v3 约 400 条）；pkilint [8] 是 Python 嵌套结构校验框架；certlint [9] 与 x509lint [10] 为更早的命令行 linter。每条检查都须人工从规范推导、映射到解析器字段、实现并随规范维护，故各工具覆盖不均衡。两点含义：其一，lint 是嵌入字段路径/谓词/严重级别/作用域的工程产物，而非规范语句的直接拷贝；其二，缺某条 lint 不等于对应规范规则不存在，可能只是尚未被识别为可 lint 或尚未实现。

### 2.2 规范提取与 LLM 辅助代码生成

自动规则提取已见于隐私、法律与协议规范，但与 Web PKI 签发合规本质不同。PolicyLint [18]、PrivacyFlash Pro [19] 分析隐私文本，Hassani 等 [20] 以 LLM 加知识图谱做法律合规提取，但都不映射到 DER 证书字段、也不判某规则能否凭单张证书强制执行；N-Check [21] 把规范形式化为 FOL\* 公式，目标是良构性分析而非 lint 谓词。面向技术规范的 LLM 系统中，PROSPER [22]、ParCleanse [23]、SpecGPT [24] 分别提取 RFC 状态机、协议格式与 3GPP 行为，Wu 等 [25] 以 GraphRAG 式上下文 [26], [27] 对齐 RFC 与内核代码——它们聚焦状态/格式/实现差异，未把"穷尽召回、schema 受限 IR 解析、确定性可 lint 性判定"三者分离处理。

LLM 代码生成进展显著（Codex [32]、AlphaCode [33]、CodeGeeX [34]），但主要面向通用编程，缺乏对领域约束、目标框架接口与可追溯性的显式建模；协议合规方向 SAGE [35]、RFCNLP [36]、PROSPER [22] 提取状态机或生成测试用例，而非面向具体 lint 框架产出可执行代码。输出约束与形式验证类工作与本研究互补：XGrammar [28]、CRANE [29] 以文法约束 LLM 输出，Schall 与 de Melo [30] 指出受限解码可能损害推理，ARMOR [31] 在 Agda 中验证 RFC 5280 路径验证算法——它们改进输出形式或算法保证，但不决定哪些自然语言签发规则应成为静态 lint。

### 2.3 语义对齐与证书合规度量

确保生成代码与规范语义一致是该类任务的核心难点：测试用例难穷尽边界、符号执行易路径爆炸、差异分析需可对照的参考实现，而中间表示方法借 IR 语义桥接间接验证一致性，最适合规范文本到代码的转换。本研究即以 IR 为桥梁，进一步引入基于 code_summary（机械摘要）的同义性归约与确定性机械翻译，使对齐判定既可计算又可追溯。经验设定上，Kumar 等 [11] 在生态尺度度量证书误签发、Zhang 等 [17] 识别国际化 X.509 证书的 Unicode 相关不合规，表明签发失效可度量且具运维重要性；但它们通常从已知 lint 或缺陷类别出发，而非从规范文本系统性推导可 lint 规则全集。

### 2.4 本研究的差异化定位

本研究的差异化定位有四。其一，给出贯通"提取 → IR → 可 lint 性判定 → 代码生成 → 验证"的端到端框架，以结构化四元组 IR 为前后两半的统一接缝，而非孤立地做提取或生成。其二，提取侧把 LLM 限定为受 schema 约束的解析器，并以确定性可溯源检索（沿规范结构的显式边遍历，而非向量相似度或 LLM 推断）组装跨文档上下文——差异在于"受约束 + 可溯源"，本文不主张图检索相对普通 RAG 的量化优越性（难做干净消融，见 §9.3）。其三，生成侧将代码生成算子的值域形式化为有限闭合的受限 DSL 树空间，在语言层排除字段/OID 编造类幻觉（命题 1）。其四，验证侧提出阶段归因式迭代验证，将多类质量不变量形式化为可计算残差，在无人工真值下提供可追溯的阶段归因与停止准则——由此给出一项更一般的设计原则：验证链路上每个算子都应尽可能确定化。

## 3. 方法总览

图 1 给出整体结构：系统以 Web PKI 规范文本为输入，输出可编译、可追溯的 zlint Go 检查代码，并由阶段归因式迭代验证（SAIV）在无人工真值下闭环修复。六阶段分两半——前半（确定性上下文、提取、判定）构成"规范 → 可 lint 规则"，后半（合成、对齐、验证）构成"可 lint 规则 → 可信代码"，以结构化中间表示 IR 与五条件可 lint 性判定为统一接缝。

```mermaid
flowchart LR
  S[Web PKI 规范文本] --> KG[知识图谱构建 §4.1]
  KG --> R[确定性子图检索 §4.2]
  R --> L1["Layer 1 关键词召回 φ_R"]
  L1 --> L2["Layer 2 受控解析 → IR"]
  L2 --> C["五条件可 lint 性判定 φ_C §5"]
  C -->|"可 lint 集 R_L"| G["受限 DSL 树合成 φ_G §6"]
  G --> RHO["渲染 ρ + 后处理 Φ_post"]
  RHO --> V["三层对齐验证 φ_V + 证书级 oracle §6"]
  V -->|残差| SAIV["阶段归因式迭代验证 SAIV §7"]
  SAIV -. "ρ_R 修复上游 IR" .-> L2
```

**图 1：** 从 PKI 规范文本到可信 zlint 检查代码的端到端框架。前半链路（§4–5）产出可 lint 规则，后半链路（§6）合成并验证代码；SAIV（§7）以可计算残差沿管道反向归因，由首要算子 $\rho_R$ 修复上游 IR 后闭环。

1. **知识图谱构建（离线，§4.1）。** 将异构规范源归一化为带稳定标识的层级结构，抽取包含、定义、跨文档引用与字段概念等显式关系，形成可溯源检索基底。
2. **确定性上下文检索（§4.2）。** 对每个目标章节做有界子图遍历，组装术语定义、字段元数据与被引章节；不用向量相似度、不调 LLM，不引入臆造上下文。
3. **双层提取与 IR（§4.3–4.4）。** Layer 1 以 RFC 2119 关键词确定性召回候选集 $\mathcal{R}_{\mathrm{kw}}$；Layer 2 把 LLM 限为 schema 受限解析器，转写每条候选为结构化 IR。
4. **五条件可 lint 性判定（§5）。** $\phi_C$ 按五个离散 IR 字段的布尔函数 $C=C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$ 得可 lint 集 $\mathcal{R}_L$（下游代码生成的定义域）。
5. **受限 DSL 合成（§6）。** $\phi_G$ 在 $\mathcal{T}_{\mathcal{V}}$ 内合成 DSL 树 $t$，经确定性渲染 $\rho$ 与可溯源后处理 $\Phi_{\mathrm{post}}$ 物化为 Go。
6. **三层对齐验证（§6）。** 描述溯源 + 基于 $\sigma_{\mathrm{mech}}$ 摘要的同义性 + 结构/编译，综合为 $S_{\mathrm{align}}$；可认证子集另由证书级 oracle 经真实证书执行验证 $\mathrm{Code}\equiv\mathrm{IR}$，无需 LLM 判官。样本级不达阈值进入 §6 局部修复，系统性误差则进入 §7 的 SAIV 沿管道反向归因修复。

全文以 §6.8 的一条 RFC 5280 dNSName 编码规则为贯穿示例、逐阶段走完上述六步。为便于通读，下表汇总全文使用的主要算子与集合记号。

| 记号 | 含义 |
|---|---|
| $\Pi=\phi_V\circ\phi_G\circ\psi_C\circ\phi_R$ | 受控规范-代码生成管道（§7.2） |
| $\phi_R$ | 关键词召回算子（Layer 1，§4.3） |
| $\phi_C$ | 五条件二值可 lint 性判定算子（§5） |
| $\psi_C$ | 候选规则三元划分算子：noise / lintable / nonLintable（§7.2） |
| $\phi_G$ | 受限 DSL 树合成算子（§6.5） |
| $\phi_V$ | 三层对齐验证算子（§6.6） |
| $\mathcal{T}_{\mathcal{V}},\ \mathcal{A},\ \mathcal{V}$ | 受限 DSL 树空间 / 原子模板集（$\lvert\mathcal{A}\rvert=77$）/ 类型化词汇表（§6） |
| $\rho,\ \Phi_{\mathrm{post}}$ | 确定性渲染算子 / 可溯源字段后处理（§6.5） |
| $\sigma_{\mathrm{mech}}$ | 确定性机械翻译算子（DSL 树 → 英文摘要；定义见 §6.4，构造见附录 E） |
| $\eta,\ \mu$ | 输出解析算子 / IR 谓词到原子模板的语义映射（§6.5–6.6） |
| $\rho_R$ | 首要修复算子：IR 内容自反思修复（§7.5） |
| $\rho_C,\ \rho_G,\ \rho_V,\ \rho_A$ | 分类 / 生成 / 验证 / 离线扩原子模板 修复算子（§7.5） |

## 4. 规范规则提取与中间表示

本节描述前半链路：如何在确定性可控的前提下，从分散且交叉引用密集的 Web PKI 规范源中提取规范规则，并转写为结构化中间表示 IR。核心困难在于跨文档引用——孤立地阅读任一段落都不足以还原一条规则的完整语义。本文的应对是分工：以确定性的图遍历组装上下文，以受约束的 LLM 解析语义，从而既不丢失上下文、又不让模型自由发挥。

### 4.1 PKI 知识图谱构建

知识图谱构建器（离线）把异构 Web PKI 规范源归一化为层级结构、为规范/章节/文本单元赋稳定标识，抽取章节引用、RFC 引用与策略交叉链接等**显式引用**并链到对应节点，同时记录证书字段概念及别名（subjectAltName、dNSName、basicConstraints.cA、策略 OID 等），以便把自然语言提及映射到规范证书路径。

本研究将该跨文档网络建模为多边有向图：八类节点（Specification、Section、Definition、CertificateField、Rule、Operation、Value、Concept）与四种 source-backed 关系（CONTAINS、DEFINES、REFERENCES、APPLIES TO）。构建器刻意保守——只存文档结构或文本证据直接支持的关系，冲突/覆盖/可 lint 性等**规范性判断**留给后续确定性阶段（CONFLICTS WITH、OVERRIDES 由规则引擎产生、**不进入检索图**）。故该图是可溯源的上下文索引、而非裁决 oracle（关系类型与检索可入性见附录 B）。

### 4.2 确定性上下文检索

检索以确定性方式组织上下文，而非依赖 LLM 推断关系：给定目标 Section，沿 source-backed 的 CONTAINS、DEFINES、REFERENCES、APPLIES TO 在 $k$-跳邻域内 BFS 扩展，按关系类型优先级装配术语定义、字段元数据与被引章节。不用向量相似度、不调 LLM 推理，故不产生独立判断。

检索阶段额外遵守四条约束（GR-1 至 GR-4）：不引入推断规则、只原始规范节点可入检索、推断性关系不入检索、所有上下文须可追溯至规范源——保证"喂给 LLM 的上下文"可审计、可复现，从根本上抑制"据臆造上下文作答"。

### 4.3 双层提取流水线

为在保留 LLM 语义理解能力的同时维持提取过程的可审计性，本研究采用双层结构。

**Layer 1：确定性召回。** Web PKI 规范普遍以 RFC 2119 关键词表达义务强度；RFC 8174 [6] 规定这些关键词仅在大写时具规范效力，从而支持确定性匹配（ETSI EN 319 不遵循该约定，按小写召回）。Layer 1 以三遍运行——直接关键词匹配、嵌套结构的义务继承、非标准 RFC 2119 形式的规范陈述捕获——输出候选规范规则集合 $\mathcal{R}_{\mathrm{kw}}$。

**Layer 2：受控语义解析。** LLM 被限为受约束的语言理解角色：不直接生成 lint 或合规判断，而是把规范文本转写为 JSON 序列化 IR，规范性推理全推迟到确定性阶段。IR 生成采用**分阶段**策略（先判规则类别、再填其余字段，显著降低误差），并受一组确定性约束（schema 校验、规则引擎覆盖确定可判类、源文本对齐校验、ASN.1 路径树约束）在文本层与 schema 层分别抑制"编造原文"与"编造字段层级"两类幻觉（六项约束完整列举见附录 C）。

### 4.4 结构化中间表示

IR 是连接前后两半链路的核心数据结构。其核心为四元组

$$
\mathrm{IR} = \langle \text{subject},\ \text{obligation},\ \text{predicate},\ \text{constraint} \rangle,
$$

其中 subject 为由字段解析器解析得到的证书字段路径（如 `extensions.subjectAltName.dNSName`），obligation 为 RFC 2119 义务关键词，predicate 为断言类型（如 `must_be_present`、`conform_to`、`equal`），constraint 为约束值或模式。四元组之外，IR 还携带若干关键扩展字段，用于支撑可 lint 性判定与下游生成与审计，其中最重要的是 `rule_category`（规则语义类别）、`assertion_subject`（断言主体：证书 / CA / 依赖方 / 外部生态）、`enforcement_phase`（约束所依赖的阶段：编码 / 运行时 / 外部验证），以及 `source_section`、`source_span`、`evidence_text`、`context_nodes` 等溯源字段（关键字段的完整列举见附录 A）。

以 IR 为桥梁相较"从原文端到端直接生成"有三点优势：引用/约束/义务分离存储，提升可追溯性与冲突处理；IR 作为 §5 五条件判定的确定性输入，使判定可复现而非依赖模型；由显式化的 IR（字段路径、断言类型、约束值）生成代码更稳定、可解释。IR 由此支持"一次提取、多处复用"，同时服务可 lint 性分析与代码生成。

## 5. 可 lint 性判定

并非每条带 MUST 的规范都能写成 lint 检查。承 §1.1 的对照——"证书 MUST 包含 keyUsage 扩展"可仅凭一张证书裁决，但"CA 必须核验申请人身份"约束的是 CA 线下行为，还有的要比对证书链上的其他证书、查 DNS 记录或撤销历史——后三类都无法仅凭一张证书的字节静态裁决。因此在生成代码之前，必须先回答一个前置问题，即每条规范规则的**可 lint 性**：它能否被一个不依赖外部上下文或运行时行为、仅凭**一张证书**的字节即可裁决的静态检查所表达？（CRL 等其他制品自身的合规检查不在本文范围内。）

本文不让 LLM 直接判定，而把它分解为五个独立布尔条件、各只读一个 IR 字段、全满足才判可 lint，从而在 IR 上确定性计算可 lint 性。三点观察：其一，决定可 lint 性的恰是五类信息——义务道义强度、被约束主体、约束生效阶段、规则类型、裁决所需数据范围（单一证书 vs 跨证书/其他制品/外部状态）；其二，五者各可编码为取值于小而封闭集合的单一 IR 字段，故判定退化为五个离散字段的布尔函数；其三，分离使任何错误标签可追溯到恰好一个 IR 字段、而非不透明的端到端调用。

形式上，本文的**操作性可 lint 标签**定义为以下五个条件的合取，每个条件都是恰好一个 IR 字段的布尔函数：

$$
\mathrm{lintable}(r) \;\overset{\mathrm{def}}{\Longleftrightarrow}\; C_1(r) \wedge C_2(r) \wedge C_3(r) \wedge C_4(r) \wedge \neg C_5(r),
$$

其中

- **$C_1$（道义强度）**：$C_1(r) \equiv \mathrm{is\_normative}(r.\text{obligation})$，即 $r.\text{obligation} \notin \{\text{MAY}, \text{OPTIONAL}\}$；
- **$C_2$（主体边界）**：$C_2(r) \equiv (r.\text{assertion\_subject} \in \{\text{Certificate}, \text{CA}\})$，纳入两类"其义务落实在签发出的证书字节中"的主体——直接对证书的义务，以及由 CA 履行但其效果可在签发出的证书上静态观测的义务（如"CA MUST 将此扩展标记为 critical"）；而将以**依赖方（relying party）或周边生态**为主体、或落实在证书之外的其他制品（如 CRL 文档自身）上的义务排除在外；
- **$C_3$（运行时边界）**：$C_3(r) \equiv (r.\text{enforcement\_phase} = \text{Encoding})$，将"可在已签发字节中观测的义务"与"在链处理、名称比较、撤销处理或 CAA 获取等阶段才触发的义务"分开；
- **$C_4$（数据边界 / 单一证书）**：$C_4(r) \equiv (r.\text{check\_scope} = \text{single\_certificate})$，要求该约束可仅凭**一张证书**孤立裁决，从而排除需要比对证书链中其他证书（跨制品，如"子证书的 SKI 须等于签发者的 AKI"、或预证书须与最终证书逐字节一致）、查询外部状态（CAA DNS 记录、OCSP 响应、CT 日志）、撤销历史，或裁决另一份独立制品（如 CRL 文档）才能判定的义务；
- **$C_5$（过程边界，取反）**：$C_5(r) \equiv (r.\text{rule\_category} \in N)$，其中 $N = \{\text{definition}, \text{capability}, \text{algorithm\_ref}, \text{display}, \dots\}$ 为承载术语定义、CA 能力声明、对外部算法规范的委派、UI 呈现等**不对证书编码施加静态检查**的类别集合；可 lint 要求 $r.\text{rule\_category} \notin N$，即 $\neg C_5$。$C_5$ 与 $C_4$ **正交**：$C_5$ 回答"这是哪一**类型**的义务"（定义？能力声明？编码约束？），$C_4$ 回答"裁决它需要**哪些数据**"（仅此一张证书，还是更多）——一条规则可以是编码约束（不在 $N$ 中，即 $\neg C_5$）却仍需访问签发者证书做密钥比对、或与配对的（预）证书逐字节比对（不通过 $C_4$）；这一正交性是 $C_4$ 不可被 $C_2$/$C_3$/$\neg C_5$ 替代的根据。

记 $\phi_C : r \mapsto \mathbb{1}[C_1 \wedge C_2 \wedge C_3 \wedge C_4 \wedge \neg C_5]$，则 $\mathcal{R}_L = \{r : \phi_C(r) = 1\}$ 即 $\phi_G$ 的定义域。obligation 同时固定严重级别（MUST 类 $\mapsto$ Error，SHOULD 类 $\mapsto$ Warning），故严重级别是对 obligation 的直接读取、而非第二个分类器。四个非道义条件刻画主体、运行时、数据（单一证书）与过程四条正交边界——其中 $C_2 \wedge C_4$ 把一类此前依赖人工审计的"静态可观测"边界（$\mathrm{StaticallyObservable}$）前移为提取阶段即确定的 IR 字段 $\mathrm{check\_scope}$。由于每个 $C_i$ 都是单一 IR 字段的确定性函数，$\mathrm{lintable}(r)$ 从 IR 计算而非 LLM 预测：同一 IR 每次给出逐位一致的标签，任何误判可追溯到 Layer 2 某个具体字段赋值——这正是第 7 节阶段归因式验证沿管道反向归因的前提。

## 6. 受限代码生成与验证

第 5 节已把每条规范规则判为可 lint 或不可 lint。给定一条可 lint 规则 $r\in\mathcal{R}_L$，生成算子 $\phi_G$ 要产出既能编译、又忠实于规范语义的检查代码。若把 $\phi_G$ 实现为"规则 $\mapsto$ 自由 Go 代码"，会撞上两堵墙。其一是幻觉：LLM 可能编造不存在的字段、OID 或库调用，而这类错误未必在编译期暴露。其二是验证不可计算：在开放代码空间上证明"代码语义等价于规范语义"需要程序分析或符号执行，工程上不可行。本文的回应不在提示词层面劝阻模型，而在**语言设计层面**收紧 $\phi_G$ 的值域——把开放的 Go 代码空间换成一个有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，让 LLM 只能输出该空间内的一棵树，再由确定性算子把树物化为 Go。于是防幻觉从"靠提示约束的概率手段"变为"被语言排除的架构属性"，"代码 $\equiv$ 规范"也从不可计算的程序分析，降为可在 $\mathcal{T}_{\mathcal{V}}$ 上判定的结构问题（§6.6）。

### 6.1 受限代码空间的动机

两堵墙都说明"事后检查"为何不够。**幻觉**的危险不是类型不符（Go 编译器会拒绝），而是能通过编译的静默偏差：把字段名写成另一个恰好存在却语义无关的字段（如 zcrypto 中并不存在的 `cert.IDN_Names`），或把 OID 写错一位。**验证不可计算**：编译通过只保证语法和类型合法，不保证"所检查的正是规范要求的约束"，而后者在开放代码空间一般需程序分析或符号执行才能确证。受限 DSL 同时关闭两者：LLM 只输出合法 DSL 树，字段/OID 合法性与算子类型匹配由 DSL 类型系统在生成时静态保证（§6.3 命题 1），防幻觉由此从概率手段变为架构属性。

### 6.2 原子模板 DSL：语法与原子模板集

原子模板 DSL 的设计思路是：在足以表达单证书静态检查的前提下把语言压到最小，以保证树空间有限、可静态分析。PKI 的单证书合规检查大多是若干**原子模板证书属性判定**的命题逻辑组合——"某扩展是否存在"、"某字段是否等于某常量"、"某列表的每个元素是否匹配某模式"等原子模板，用"与 / 或 / 非"组合即可刻画大多数静态约束。代码 DSL 的抽象语法为：

$$
\mathcal{T} \;::=\; a(\bar{v}) \;\mid\; \neg\, \mathcal{T} \;\mid\; \mathcal{T} \wedge \mathcal{T} \;\mid\; \mathcal{T} \vee \mathcal{T}
\tag{1}
$$

其中 $a \in \mathcal{A}$ 为原子模板谓词，$\bar{v}$ 为其参数列表。$\mathcal{A}$ 是一个**有限闭合**的原子模板集合：本文版本下 $|\mathcal{A}| = 77$，每个原子模板对应一类不可再分的证书属性判定（如"扩展存在"、"字段等于常量"、"列表每元素匹配某正则"等）；$\{\neg, \wedge, \vee\}$ 为命题逻辑组合子，完整枚举见附录 D。一条 lint 规则的代码体建模为有序对 $(p, q) \in \mathcal{T}_\perp \times \mathcal{T}$，其中 $p \in \mathcal{T}_\perp = \mathcal{T} \cup \{\perp\}$ 为可选前提，$q \in \mathcal{T}$ 为主断言，执行语义为：

$$
\lVert (p, q) \rVert(c) \;=\; \begin{cases}
\mathrm{NA}, & p \neq \perp \;\land\; \lVert p \rVert(c) = \mathrm{false} \\
\mathrm{Pass}, & (p = \perp \;\lor\; \lVert p \rVert(c) = \mathrm{true}) \;\land\; \lVert q \rVert(c) = \mathrm{true} \\
\mathrm{Severity}(r), & \text{otherwise}
\end{cases}
\tag{2}
$$

直观地：前提 $p$ 是**规则适用性闸门**——当它存在且在 $c$ 上为假时返回 $\mathrm{NA}$（不适用）；前提缺失或成立且 $q$ 成立时返回 $\mathrm{Pass}$；前提成立而 $q$ 不成立则为违反，按义务返回 $\mathrm{Severity}(r)$。因 §5 的 $C_1$ 已排除 MAY/OPTIONAL，进入生成的义务必属 MUST 族或 SHOULD 族，即 $\mathrm{Severity}(r) \in \{\text{Error}, \text{Warn}\}$。显式区分 $\mathrm{NA}$ 与 $\mathrm{Pass}$ 并非冗余：PKI 大量要求是**条件式**（"WHEN $P$, THEN $Q$"），把适用前提建模为 $p$ 可避免"前提不满足却误判违反"，并使前提与断言在后续验证中分别归因。

### 6.3 类型化词汇表与参数封闭性

§6.2 限定了树的*结构*，却没约束原子模板的*参数*——参数若可任填，LLM 仍能写出引用虚构字段或 OID 的"结构合法"之树。§6.3 用一张**类型化词汇表** $\mathcal{V}$ 封住这道缺口：$\mathcal{V}$ 是若干在系统启动时冻结的有限集合的不相交并，每个原子模板参数只能取自其中某个集合：

$$
\mathcal{V} \;=\; \mathcal{F}_{\mathrm{cert}} \;\sqcup\; \mathcal{F}_{\mathrm{dn}} \;\sqcup\; \mathcal{O} \;\sqcup\; \mathcal{B}_{\mathrm{KU}} \;\sqcup\; \mathcal{B}_{\mathrm{EKU}} \;\sqcup\; \mathcal{E}_{\mathrm{ASN1}} \;\sqcup\; \mathcal{R}_{\mathrm{regex}}
\tag{3}
$$

各分量分别是证书字段名、DN 字段、OID 常量、KeyUsage 位、ExtKeyUsage 位、ASN.1 编码类型与命名正则集合，均在系统启动时冻结（大小与代表内容见附录 D）。每个原子模板 $a$ 有签名 $\mathrm{sig}(a) = (\tau_1, \dots, \tau_{n_a})$，$\tau_i$ 是 $\mathcal{V}$ 的某一分量或基础类型 $\{\mathbb{Z}, \mathbb{B}, \mathrm{String}\}$；调用 $a(v_1, \dots, v_{n_a})$ 合法当且仅当每个 $v_i$ 属于 $\tau_i$ 规定的集合。记 $\mathcal{T}_{\mathcal{V}}$ 为所有参数都落在 $\mathcal{V}$ 内的合法 DSL 树集合。本研究把 $\phi_G$ 的值域严格限定为 $\mathcal{T}_{\mathcal{V}}$，由此得到封闭性命题。

**命题 1（词汇封闭性）**。*对任意 LLM 输出 $t$，若 $t \in \mathcal{T}_{\mathcal{V}}$，则 $t$ 不出现 $\mathcal{V}$ 之外的字段名、OID 或正则；若 $t \notin \mathcal{T}_{\mathcal{V}}$，解析阶段必然报错并触发修复，不会进入 $\rho$ 渲染。*

该命题在架构层消除"LLM 编造字段/OID"这一整类幻觉，不依赖运行期检测或人工审查：参数越界的原子模板调用不属于 $\mathcal{T}_{\mathcal{V}}$，在解析算子 $\eta$（§6.5）处即判 $\mathrm{Err}$、带诊断回传触发重写，根本不进入 $\rho$ 渲染——即把 §6.1 第一堵墙从"事后捕获"前移为"事前结构排除"。代价是 $\phi_G$ 的表达力被限在 $\mathcal{V}$、$\mathcal{A}$ 张成的范围内，这一边界正是 §6.5 的 $\mu$ 要用尽、§9.3 覆盖残差要度量的对象。

### 6.4 渲染与可逆机械翻译

合法 DSL 树 $t$ 要**物化**成两种制品：可在 zlint 运行的 Go 检查代码（系统产出），与一句供人/LLM 与原文比对的自然语言摘要（验证依据）。承担二者的算子都是 DSL 树空间上的**确定性全函数，而非 LLM 调用**，故不引入概率失真：

$$
\rho : \mathcal{T}_{\mathcal{V}} \to \mathrm{Go}, \qquad \sigma_{\mathrm{mech}} : \mathcal{T}_{\mathcal{V}} \to \mathcal{L}_{\mathrm{NL}}
\tag{4}
$$

其中 $\rho$ 把 DSL 树渲染为类型一致的 Go 表达式（系统的可执行产出，固定的 Go 宿主外壳见附录 D），$\sigma_{\mathrm{mech}}$ 把同一棵树机械翻译为一句 PKI 英文摘要（验证所用的自然语言陈述，构造与短语字典见附录 E）。用确定性 $\sigma_{\mathrm{mech}}$ 而非 LLM 摘要，是为消除一类**可消除的系统性失真**：对"若 $\neg P$ 则 NA、若 $P\wedge Q$ 则 Pass"这类条件检查体，LLM 摘要倾向把前提 $P$ 复述成"WHEN"分句、丢掉"$\neg P\Rightarrow\mathrm{NA}$"的极性反转，且给出取反示例后仍稳定复现，属概率模型固有偏差；$\sigma_{\mathrm{mech}}$ 对树做结构归纳翻译、在前提为否定时显式生成 "WHEN NOT … THEN …"，由此获得极性正确性，并把概率失真压缩到词典 $\mathcal{M}$ 的离线选择。两个函数共享三项性质，每项都对应验证链上的一个具体作用：

- **类型安全**：$\rho$ 不生成越界字段/OID/参数类型，把命题 1 的封闭性从 DSL 树保持到 Go 层（完整文件可编译性由 §6.6/算法 1 最终确认）。
- **决定性**：$\rho(t)$、$\sigma_{\mathrm{mech}}(t)$ 对相同 $t$ 输出唯一——这使 §6.6 oracle 可把 $\rho(t)$ 当作 $t$ 的固定函数，执行行为不随运行或模型而变。
- **可逆性（原子模板等价意义下）**：由 $\sigma_{\mathrm{mech}}(t)$ 可机械还原 $t$（同义原子模板映射同一短语时不可区分），故 $\sigma_{\mathrm{mech}}$ 不构成信息瓶颈（命题 2，附录 E）。

两个算子由此**分工**：$\rho$ 通向执行/oracle 验证（代码被真实证书运行、由结果裁断），$\sigma_{\mathrm{mech}}$ 通向同义性验证（摘要与 `Description` 比对是否语义等价）。同一棵树经两条独立确定性通路受检，是 §6.6 多重保障的结构基础。

### 6.5 IR 谓词到原子模板的映射与受限 LLM 树合成

**从 IR 谓词到原子模板的映射 $\mu$。** 上游 IR 与下游 DSL 用两套词汇：IR 以**抽取阶段的谓词**描述要求（如 `must_be_present`、`encode_as`、`in_range`），DSL 以**原子模板**表达检查，二者并非一一对应。为衔接两者，本研究维护一个多对多映射

$$
\mu : \mathrm{Pred}_{\mathrm{IR}} \rightrightarrows 2^{\mathcal{A}},
$$

对 IR 中每个谓词，$\mu$ 给出语义上能承载它的候选原子模板子集。例如 `must_be_present` 可由 $\{\mathrm{ExtPresent}, \mathrm{FieldNonEmpty}\}$ 承载，`in_range` 可由 $\{\mathrm{IntInRange}, \mathrm{PathLenConstraintHas}, \dots\}$ 承载——取哪个取决于被约束字段的类型。该候选子集连同词汇表 $\mathcal{V}$ 与原子模板签名表进入合成提示，把 LLM 的选择空间从全集 $\mathcal{A}$（$\lvert\mathcal{A}\rvert=77$）收窄到与当前规则相关的少数候选，既降低误选、又缩短提示。

$\mu$ 仅是**提示性约束**：不直接装配输出、不进入 $\rho$ 渲染，最终选用与组合仍由 LLM 给出，再经封闭性强制与 §6.6 oracle 校验。用"提示"而非"确定性谓词 $\to$ 原子模板翻译"，是因后者在跨原子模板组合或上下文相关字段类型上太脆弱；语义健全性由下游封闭性强制与 oracle 兜底，不由 $\mu$ 承担。多对多是双向的：一个谓词可由不同原子模板实现（冗余即修复备选），一个原子模板也可服务多个谓词。

下文给出 $\phi_G$ 的实现，以及"全 LLM 合成"下保证生成端结构可检查的三道机制：**IR-字段溯源守卫**约束树只引用本规则 IR 涵盖的字段（防主语漂移）；**解析与封闭性强制**把输出钉在 $\mathcal{T}_{\mathcal{V}}$ 内（防字段/OID 编造）；**可溯源字段确定性绑定**用原文字面值填 `Description`/`Citation`/`Name`（保证 $\mathrm{Description}\equiv\mathrm{Specification}$）。三者都**不**判定"代码是否忠实于规范"（那留给 §6.6 的 oracle），只把产出约束在结构可验证、可追溯的空间内。

**全 LLM 树合成。** 给定可执行规则 $r \in \mathcal{R}_L$（由 §5 五条件判定给出），代码生成算子 $\phi_G$ 实现为一次**受限 LLM 树合成**：模型拿到规则上下文、结构化 IR、由 $\mu$ 收窄的候选原子模板集，以及 $\mathcal{V}$、$\mathcal{A}$ 的可读枚举与签名表（实际提示的四区段拼接见附录 H），只返回一棵 DSL 树的序列化，或一个显式弃权标记：

$$
\phi_G : r \;\longmapsto\; t \in \mathcal{T}_{\mathcal{V}} \cup \{\perp_{\mathrm{NT}}\}, \qquad t \;=\; \eta\bigl(M.\mathrm{generate}(\mathrm{prompt}(r,\,\mathcal{V},\,\mathcal{A},\,\mu))\bigr)
\tag{5}
$$

其中 $\perp_{\mathrm{NT}}$ 是显式的"无模板"标记，由 LLM 自主返回——当且仅当模型判断当前 $(\mathcal{A}, \mathcal{V})$ 不足以表达 $r$ 时返回，该规则随即进入修复路径而非渲染，使 $\phi_G$ 不必产出"形式合法但语义错位"的代码。所有会被检查的部分都落在 $\mathcal{T}_{\mathcal{V}}$ 内（命题 1）。

**IR-字段溯源守卫。** 生成端的结构可检查性由守卫 $\mathrm{IRGuard}$ 提供：复用字段解析器把树中每个证书字段/扩展 OID 规范化为 DSL 身份（扩展按数值 OID 归一），核验它们都被本规则 IR 涵盖；引用 IR 之外字段的树被标记**字段漂移**、带诊断回传重写（至多 $K$ 轮）。守卫刻意保守——IR 解析本身会漏抽子字段（IR 只记整个扩展，而 LLM 正确引用其子字段），硬拒会误伤约两成好树——故它定位漂移、驱动修复，而非不可逆否决；真正的 $\mathrm{Code}\equiv\mathrm{IR}$ 留待 §6.6 的证书级 oracle。

**解析与封闭性强制。** 解析算子 $\eta : \mathrm{string} \to \mathcal{T}_{\mathcal{V}} \cup \{\perp_{\mathrm{NT}}, \mathrm{Err}\}$ 把合法序列化映射为 $t$、弃权映射为 $\perp_{\mathrm{NT}}$、解析失败或参数越界映射为 $\mathrm{Err}$；遇 $\mathrm{Err}$ 时把"哪个原子模板签名不匹配、哪个 OID 未注册"注入下一轮提示触发重生成。这把 LLM 的幻觉表面积压缩到原子模板参数选择与组合结构两个维度，不容新增未注册的谓词或字段。

**可溯源字段的确定性绑定。** 记 $\Phi_{\mathrm{post}} : \mathcal{T}_{\mathcal{V}} \times r \to \mathrm{Go}$ 为后处理-渲染复合算子：$\rho$ 渲染出检查体后，把 `Description`、`Citation`、`Name` 三个**可溯源字段**强制绑定为规范原文与规则元数据的字面值：

$$
\Phi_{\mathrm{post}}(t, r) \;=\; \rho(t) \;\oplus\; \mathrm{Bind}\bigl(\text{Description} \mapsto \mathrm{rule\_text}(r),\; \text{Citation} \mapsto \mathrm{section}(r),\; \text{Name} \mapsto \mathrm{lint\_id}(r)\bigr)
$$

该绑定在架构层保证 $\mathrm{Description} \equiv \mathrm{Specification}$（§6.6 等价链的最右支），无需 LLM 自我约束；义务级别到严重度的完整映射、各规范源的 `PACKAGE`/`SOURCE`/`EFFECTIVE_DATE` 元数据绑定表见附录 D。

§6.1–6.5 已产出词汇封闭、可渲染为 Go 的树 $t$ 与其代码 $\rho(t)$；但"代码 $\equiv$ 规范"一般不可判定，而朴素地让 LLM 直接裁断又要跨模态推演 Go 执行语义与规范语义、无法复核。§6.6–6.8 把这一判定拆成由低到高的级联验证，并对其中最关键的一环（同义性）施以确定化：§6.6 给出三层对齐与证书级 oracle，§6.7 给出端到端算法（含样本级修复），§6.8 走一个完整实例。

### 6.6 三层语义对齐验证

三层验证按成本递增排列，由粗到精过滤：**层次 A**（描述溯源）最廉价，只看 `Description` 能否回溯到原文；**层次 B**（同义性）是核心，把"代码是否实现规范"这一跨模态判定，归约为"两句自然语言是否同义"；**层次 C**（编译与结构）确认产物在目标框架内可执行。三层加权汇总为对齐得分 $S_{\mathrm{align}}$，驱动 §6.7 起的修复闭环。但层次 B 依赖一次 LLM 判官，是单票且非确定的，故本小节随后引入一道**证书级语义 oracle**：对系统自己生成、因而持有 DSL 树的可认证子集，用真实证书的执行结果取代判官，把同义性判定也确定化；再用一道无 LLM 的**实体级忠实性筛查**作为独立的交叉校验。

**层次 A：描述溯源。** 检查 `Description` 能否追溯到源文档（逐字符精确 / 连续子串 / 句子级语义等价，由严到宽三档）。只比对描述与来源、不解释代码逻辑，成本最低，作第一道快速过滤。

**层次 B：基于 code_summary（代码行为摘要）的语义对齐。** 把"代码是否实现规范"归约为自然语言同义性：取 `Description`，由摘要算子 $\sigma$（系统持有 DSL 树时其确定化实现即 $\sigma_{\mathrm{mech}}$，见 §6.4 与附录 E）生成一句"该代码检查什么约束"的摘要，再判它与 `Description` 是否语义等价、输出置信度 $c_{\mathrm{syn}}$。好处：LLM 只需比两句自然语言，无需推演完整 Go 执行语义；摘要可读；失败时由"代码实际表达"与"规范要求"之差给出精确诊断。理论基础是语义等价的传递性：
$$
\mathrm{Code} \equiv \mathrm{Summary} \;\land\; \mathrm{Summary} \equiv \mathrm{Description} \;\land\; \mathrm{Description} \equiv \mathrm{Specification} \;\Rightarrow\; \mathrm{Code} \equiv \mathrm{Specification}
$$

三项前提机制不同：$\mathrm{Code} \equiv \mathrm{Summary}$ 由 $\sigma$ 的忠实性保证，$\mathrm{Summary} \equiv \mathrm{Description}$ 由 $c_{\mathrm{syn}}$ 判定，$\mathrm{Description} \equiv \mathrm{Specification}$ 由 §6.5 的确定性后处理保证，故整条链的失效点可分段归因。层次 B 面向**一般情形**（外部既有 lint、本系统不可认证子集）；对可被下述**证书级 oracle** 认证的自生成子集，$\mathrm{Code} \equiv \mathrm{IR}$ 由执行直接*验证*，无需 $\sigma$ 摘要这一跳、也无需 LLM 判官。

**层次 C：编译与结构。** 验证代码可语法解析、函数与元数据字段（描述、引用等）齐全、依赖正确导入、规则注册完成，确保产物在目标框架内结构合法、可执行。

**综合对齐得分。** 五个维度加权平均给出：
$$
S_{\mathrm{align}} = 0.15 \cdot \mathbb{1}[\mathrm{compile}] + 0.10 \cdot \mathbb{1}[\mathrm{struct}] + 0.15 \cdot s_{\mathrm{desc}} + 0.50 \cdot c_{\mathrm{syn}} + 0.10 \cdot s_{\mathrm{revIR}}
$$

其中 $c_{\mathrm{syn}}$（同义置信度）占 50%、为主要依据，$s_{\mathrm{desc}}$ 为描述溯源性，$s_{\mathrm{revIR}}$ 为逆向 IR 往返一致性（把生成代码反抽成 IR、再与原 IR 逐字段比对）。$S_{\mathrm{align}} < \theta$（默认 0.7）触发 §7 修复闭环；但 §8.4 中"$\mathrm{Code}\equiv\mathrm{IR}$ 可证"子集的接受不取决于该标量，而由证书级 oracle 以二值独立给出。

**证书级语义 oracle（$\mathrm{Code}\equiv\mathrm{IR}$ 的执行级验证）。** 这是本框架的核心装置。层次 B 的 LLM 判官 $\phi_V$ 单票、非确定，且会对"前提被丢弃的过严 lint"误判通过；关键一步是把这个判定也确定化：与其再问 LLM，不如为待检原子模板各造两张证书——一张使其谓词成立（应 $\mathrm{Pass}$）、一张使其不成立（应返回 $\mathrm{Severity}(r)$）——让代码真执行、比对结果。对持有 DSL 树 $t$ 的自生成 lint，分两步：(i) **逐原子模板认证**——给每个原子模板 $a$ 合成一对受控 fixture（谓词真/假），执行读回状态，两张都符合期望才认证（fixture 按原子模板类参数化于 $\mathcal{V}$、不绑定具体规则）；(ii) **结构组合**——仅由已认证原子模板构成且编译通过的树 $t$，其 $\rho(t)$ 逐原子模板忠实，由结构归纳得 $\mathrm{Code}\equiv t$；又因 $t$ 是 IR 的忠实归约，故 $\mathrm{Code}\equiv\mathrm{IR}$，无需判官。须界定证据地位：单原子模板忠实性是受控 fixture 上的经验认证、整树由结构归纳建立，故为执行级验证而非定理，以 fixture 能真正区分满足/违反为前提，外延受可认证子集所限。满足者记为**$\mathrm{Code}\equiv\mathrm{IR}$ 可证**，其 $c_{\mathrm{syn}}$ 项在代码-IR 忠实性维度短路为通过；不在可认证子集者回退层次 B 判官、标"未证"并与"已验证"分账（§8.4）。该 oracle 是确定性的：$\mathrm{Code}\equiv\mathrm{IR}$ 可证集合不随模型而变。它须与 §7 的 G3（双判定源一致性）区分——后者指 $\psi_C$ 与外部工具覆盖之间的一致，与此处验证 $\mathrm{Code}\equiv\mathrm{IR}$ 是两回事。

**oracle 的边界与过严检测（诚实声明）。** 该 oracle 覆盖有界：只有能用证书工厂造出"满足/违反"区分对的原子模板才可认证，而需跨证书上下文、密码学事实（如模数素性）或字节级编码的原子模板无法认证（边界见 §9.3）。oracle 另附一道过严检测：把 $\mathrm{Code}\equiv\mathrm{IR}$ 可证的 lint 在真实证书语料上运行，若在大比例有效证书上误报 $\mathrm{Error}$，即疑为前提被丢弃的过严 lint——这是 $\mathrm{IR}\neq\mathrm{Spec}$ 的上游信号，而非 $\mathrm{Code}\neq\mathrm{IR}$；该检测当前因语料过窄仅作报告、不计入判据。

**确定性实体级忠实性筛查（必要条件）。** oracle 给出 $\mathrm{Code}\equiv\mathrm{IR}$ 的充分验证，但只覆盖可认证子集；对其余仍由 LLM 判官判定的 lint，再引入一道无 LLM 的实体级筛查 $\mathrm{Faithful}_{\mathrm{nec}}$，作为与 oracle、判官皆独立的机械必要条件。依据是：一条操作于 PKI 实体集 $E(t)$（树 $t$ 谓词中出现的 OID 常量与证书字段）的 lint，要忠实于规则 $r$，前提是——$t$ 检查的每个主要实体都在 $r$ 的文本中被提及：

$$
\mathrm{Faithful}_{\mathrm{nec}}(t, r) \;\Longleftrightarrow\; \forall\, e \in E_{\mathrm{prim}}(t):\ \mathrm{alias}(e) \cap \mathrm{tokens}\bigl(\mathrm{text}(r)\bigr) \neq \varnothing,
$$

其中 $\mathrm{alias}(\cdot)$ 是词干化加一张冻结的标准扩展别名表构成的桥。三种判读：$\mathtt{ENTITY\_OK}$（实体都被点名）、$\mathtt{ENTITY\_MISMATCH}$（检查了文本未提及的实体，可疑）、$\mathtt{NO\_ENTITY}$（不引用实体，不适用）。它是机械可算的必要条件（非完全等价证明），专捕"分段/指代把错误主语交给生成"这一失效；与层次 B 交叉时，分歧处定位到指代盲区或真正的主语错抽。其盲区（"this extension"类指代、别名缺口）只会保守地多报 $\mathtt{ENTITY\_MISMATCH}$，与 IRGuard 同向偏保守。

### 6.7 端到端生成算法与样本级局部修复

$S_{\mathrm{align}} < \theta$ 时修复分两级。本小节是**较轻**的样本级局部修复：假定误差仍在该规则的字段或语法层，就地重修、不动全局 $\mathcal{V}$/$\mathcal{A}$/$\phi_C$（更重的管道级留 §7，仅在样本级耗尽后介入）。局部修复算子 $\rho_G^{\mathrm{loc}}$ 含两类子操作：

$$
\rho_G^{\mathrm{loc}}(t, c) \;=\; \begin{cases}
\Phi_{\mathrm{post}}(t, r), & \text{Description / Citation 偏差} \\
\phi_G\bigl(r,\; \mathrm{feedback}(\eta(s), \mathcal{V}, \mathcal{A})\bigr), & \eta(s) = \mathrm{Err} \;\text{或}\; \mathrm{compile}(\rho(t)) = 0
\end{cases}
\tag{6}
$$

第一支是**幂等闭式修复**：对可溯源字段调一次 $\Phi_{\mathrm{post}}$ 即止（$O(1)$）。第二支是**类型反馈式重生成**：把解析错误（哪个原子模板签名不满足）或编译错误结构化注入提示、触发重合成。$K_{\mathrm{loc}}$（默认 3）轮内仍未达 $S_{\mathrm{align}}\geq\theta$ 者进入 §7 管道级修复，沿 $\Pi = \phi_V \circ \phi_G \circ \psi_C \circ \phi_R$ 反向归因。$\rho_G^{\mathrm{loc}}$ 不动 $\mathcal{V}$/$\mathcal{A}$/$\phi_C$，只有 §7 的 $\rho_R/\rho_C/\rho_G/\rho_V$ 才触及更上游对象。

算法 1 给出原子模板 DSL 受限代码空间下的端到端合成-验证流程，把上述样本级修复嵌入循环。整个流程不依赖任何模板分类，只以 $(\mathcal{V}, \mathcal{A})$ 这一对全局结构作为代码空间约束。

```
算法 1：DSL 受限合成与验证
输入：可执行规则 r ∈ R_L，词汇表 V，原子模板集 A，LLM 模型 M，对齐阈值 θ
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
13:             S_align ← Verify(code, r)              // §6.6 综合对齐得分
14:             if S_align ≥ θ then return code
15:             prompt ← prompt ⊕ feedback(S_align, σ_mech(t))
16: return FAIL("local_repair_exhausted", t)           // 进入 §7 管道级修复
```

算法 1 在 $K_{\mathrm{loc}}$ 轮内终止；它区别于"启发式重试"的关键，是每次重试都携带结构化诊断（类型错误、编译错误，或 $\sigma_{\mathrm{mech}}(t)$ 与对齐得分反馈），而非空白重采样。在 $\eta$ 与 $\Phi_{\mathrm{post}}$ 的封闭性下，返回分支的代码同时满足：词汇封闭（$t \in \mathcal{T}_{\mathcal{V}}$）、通过 Go 编译、$S_{\mathrm{align}} \geq \theta$（$\theta=0.7$ 蕴含 $c_{\mathrm{syn}}\geq 0.4$）——即"语义可追溯 + 结构可执行 + 类型受约束"。

### 6.8 端到端示例

为把第 6 节的算子串成一条可追踪的链，本节用一个贯穿示例走完整个流程。§1.1 的 keyUsage 例子用来厘清可 lint 性概念，这里取一条更能体现受限合成的规则——RFC 5280 §4.2.1.9 关于 dNSName 编码。原文："Conforming implementations MUST convert internationalized domain names to the ASCII Compatible Encoding (ACE) format ... before storage in the dNSName field." 经受控提取得到 IR：

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

LLM 输出 DSL 树（主断言"DNSNames 每项匹配 ACE-或-ASCII 标签正则"），经 $\eta$ 解析为合法 $t \in \mathcal{T}_{\mathcal{V}}$，由 $\rho$ 渲染、$\Phi_{\mathrm{post}}$ 注入 `Description / Citation / Source / Name`。$\sigma_{\mathrm{mech}}(t)$ 输出机械摘要 _"every entry in DNSNames matches the ACE-or-ASCII label regex"_，$\phi_V$ 比对得 $c_{\mathrm{syn}} = 0.92$、$S_{\mathrm{align}} = 0.96 > 0.7$，通过。全程命名都落在 $\mathcal{V} \cup \mathcal{A}$ 内——若编造 `cert.IDN_Names`，$\eta$ 即拒绝并触发重生成，该幻觉路径在架构层被关闭。该规则走完 $r \to \mathrm{IR} \xrightarrow{\mu,\,\mathcal{V},\,\mathcal{A}} t \xrightarrow{\rho,\,\Phi_{\mathrm{post}}} \mathrm{Go} \xrightarrow{\sigma_{\mathrm{mech}}} \text{摘要} \xrightarrow{\phi_V} S_{\mathrm{align}}$，无一处依赖模板分类或词汇表外命名，即第 6 节"受限合成 + 多重验证"的落地。

## 7. 阶段归因式迭代验证框架（SAIV）

第 6 节的方法在单次前向生成下已能产出结构完整的 zlint 代码，但在大规模、无人工真值的场景下仍有质量风险，且风险高度集中在最上游的 NL$\to$IR 提取：IR 内容抽错（主语/谓词极性/约束/前提）会使下游分类、生成、验证全作用在错误对象上（§8.5–§8.6 表明底三层缺陷几乎全源于此），而召回数量由结构不变量 G1（§7.3）独立闭合。故首要着力点是 IR 内容，其修复算子 $\rho_R$ 排在修复序列最前。相比"单向前向 + 启发式重试"（反馈只是单一标量、难定位出错阶段），SAIV 沿管道反向定位误差阶段再定向修复——它不学参数，而把若干可直接计算的不变量当作损失信号；这些信号由结构性不变量与客观外部证据（工具实现存在性）支撑，使质量验证由可计算残差而非人工真值承担。

### 7.1 形式化定义

定义受控规范-代码生成管道 $\Pi$ 为从候选召回到可 lint 代码验证的复合函数：

$$
\Pi = \phi_V \circ \phi_G \circ \psi_C \circ \phi_R
$$

其中 $\phi_R$ 是 RFC 2119 关键词驱动的规则召回模块，$\phi_C$ 是 §5 的五条件二值可 lint 性判定模块，$\phi_G$ 是受限于 DSL 代码空间 $\mathcal{T}_{\mathcal{V}}$（§6）的 LLM 合成模块，$\phi_V$ 是三层语义对齐验证模块（§6）。给定标准文档 $\mathcal{D}$，令 $\mathcal{R}_{\mathrm{kw}}(\mathcal{D})$ 为 $\phi_R$ 召回的候选规则集；实现中先由候选过滤器判一条候选是否为规范规则，再对规范规则调用 $\phi_C$。把组合后的三元划分算子记为

$$
\psi_C(r)=
\begin{cases}
\mathrm{noise}, & r \text{ 不是规范规则},\\
\mathrm{lintable}, & r \text{ 是规范规则且 } \phi_C(r)=1,\\
\mathrm{nonLintable}, & r \text{ 是规范规则且 } \phi_C(r)=0.
\end{cases}
$$

$\psi_C$ 给出三个互斥子集 $\mathcal{R}_N$（噪声）、$\mathcal{R}_L$（可执行）、$\mathcal{R}_U$（不可执行但具规范义务），只有可执行子集 $\mathcal{R}_L$ 进入 $\phi_G$ 合成代码。

### 7.2 召回完整性不变量

**定理 1（召回完整性不变量）**。*若 $\phi_R$ 对非 ETSI 标准族仅由 RFC 2119 关键词触发，且 $\psi_C$ 为 $\mathcal{R}_{\mathrm{kw}}$ 上的互斥穷尽划分，则以下守恒关系成立：*
$$
|\mathcal{R}_{\mathrm{kw}}(\mathcal{D})| = |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U| \tag{7}
$$

直观含义是：关键词召回一旦完成，规则总量在下游任何分类步骤里都不应增多或减少。式 (7) 因此是一个**结构性闭合条件**：任意阶段观测到等式不成立，即可断定某下游模块引入了规则级别的增删误差。**该性质无需任何人工真值即可计算**，故在缺乏独立真值的大规模场景下可作第一级质量信号。

### 7.3 代码正确性标签与损失函数

设 $r \in \mathcal{R}_L$，$c = \phi_G(r)$。由于 $c$ 的 `Description` 已由确定性后处理与规范原文 $\mathrm{spec}(r)$ 对齐（§6.5），代码正确性标签 $\lambda_{\mathrm{code}}(r) \in [0,1]$ 由以下乘积度量：

$$
\lambda_{\mathrm{code}}(r) = \mathbb{1}[\mathrm{compile}(c)] \cdot s_{\mathrm{struct}}(c) \cdot c_{\mathrm{syn}}(\sigma(c),\; \mathrm{spec}(r)) \tag{8}
$$

由 §6.6 的语义等价传递链，$\sigma(c) \equiv \mathrm{spec}(r)$ 且 `Description` $\equiv \mathrm{spec}(r)$ 即可推出 $c \equiv \mathrm{spec}(r)$。对证书级 oracle 认证者，式 (8) 的 $c_{\mathrm{syn}}$ 项用二值 $\mathrm{Code}\equiv\mathrm{IR}$ 验证取代（取 $1$），$\lambda_{\mathrm{code}}$ 不再经由非确定的 $c_{\mathrm{syn}}$。

在此标签之上，SAIV 把四类质量信号形式化为可计算残差（精确式见附录 I）。**召回守恒残差** $\mathcal{L}_{\mathrm{recall}}$（式 9）以对称归一化度量定理 1 的理想恒等被违反的程度，同时惩罚丢规则与增条目两个方向。**代码忠实残差** $\mathcal{L}_{\mathrm{code}}$（式 10）是可 lint 集上正确性标签的平均缺口。二者加权组合为**总损失** $\mathcal{L}_{\mathrm{total}} = w_R\mathcal{L}_{\mathrm{recall}} + w_C\mathcal{L}_{\mathrm{code}}$（式 11，默认 $w_R = w_C = 0.5$）。

第四类是**覆盖残差** $\mathcal{L}_{\mathrm{cov}}$（式 11b）。前三项刻画"召回是否守恒"与"可 lint 规则是否被忠实写成代码"，覆盖残差刻画另一个问题：在**非硬编码**前提下，端到端生成能复现多少现有工具已实现的规则。它以 zlint 同源 lint 为参照系——项目内置 v3 源码按 `Source` 字段实测 RFC 5280 **122** 条、CABF BR **170** 条、合计 **292** 条（含 CRL lint 13 条：RFC 7、CABF 6，经 `RegisterRevocationListLint` 识别）——度量"本系统已通过 $\mathrm{Code}\equiv\mathrm{IR}$ oracle 与 code_summary≡规范（$\sigma_{\mathrm{mech}}(t)$ 与原文）同义双门、且命中某条同源 zlint lint 的 citation 条款"的规则数相对该 292 的缺口。$\mathcal{L}_{\mathrm{cov}}\to 0$ 意味着不硬编码任一 lint 而覆盖广度逼近 zlint（"非硬编码"由 §9.3 的 `cicasgen_*` 防火墙保证）。它与 G2 正交：G2 管"已写的对不对"、$\mathcal{L}_{\mathrm{cov}}$ 管"该写的还有多少没写"，由 $\rho_R$ 与离线扩原子模板 $\rho_A$ 驱动下降，当前远未闭合（§8.1/§8.3）。

### 7.4 阶段归因与修复算子

**阶段归因。** 令编译失败率 $p_{\mathrm{fail}}^{(t)} = \frac{1}{|\mathcal{R}_L|} \sum_{r \in \mathcal{R}_L} \mathbb{1}[\neg\mathrm{compile}(\phi_G(r))]$、平均结构得分 $\bar{s}_{\mathrm{struct}}^{(t)}$，第 $t$ 轮按一组互斥完备的四分支择一定位出错阶段（精确条件见附录 I 式 12，默认阈值 $\tau_R=\tau_C=0.10$）：召回守恒残差超阈归 $\phi_R/\psi_C$；否则编译失败率超阈归 $\phi_C$ 误分类；否则编译通过但对齐低、结构得分 $<1$ 归 $\phi_G$；否则结构完整、编译通过而同义率低归 $\phi_V$。G1 闭合后（$\mathcal{L}_{\mathrm{recall}}\approx 0$，§8.2），$\phi_R$ 分支的误差不再是召回数量、而是 IR 内容（错主语/极性/约束/前提），故其修复算子重定向为下文的 $\rho_R$。无人工真值的触发信号是两个确定性比例：可归约 lint 中被 §6.6 判 $\mathtt{ENTITY\_MISMATCH}$（非指代）者、与持续 $\perp_{\mathrm{NT}}$ 者；偏高即触发 $\rho_R$。

**修复算子。** $\rho_R$（IR 内容自反思修复）是首要算子、也是唯一改动 IR 本身的算子：上游 NL$\to$IR 一旦出错（主语错抽、极性反转、约束散文化、前提丢失），下游分类、生成、验证都失去正确对象（§8.5–§8.6）。其余 $\rho_C/\rho_G/\rho_V$ 并列、无优先级，由归因决定本轮触发哪个，均在 IR 给定下工作。

- **$\rho_R$（IR 内容自反思修复，首要算子）**：当 $\phi_G$ 在 $K_{\mathrm{loc}}$ 轮内持续返回 $\perp_{\mathrm{NT}}$（IR 不可归约）、或 G2 同义性持续低于阈值时，把下游完整失败轨迹——当前 IR、不可归约类别、$\sigma_{\mathrm{mech}}$ 摘要、判官裁定与理由、同义置信度、本会话已试过的历史 IR——构成一条**反向失败信号**回传 LLM，令其自我诊断并决定：**(a)** 更正 IR 的 subject / predicate / constraint / precondition（连同取自原文、支持该修正的证据子串一并输出），或 **(b)** 声明 `NO_FIX`——确认 IR 已正确而当前词汇 $(\mathcal{A}, \mathcal{V})$ 确不足以表达该规则。它不是盲目重试（同提示 → 同错），也不是静态规则修补，而是一次能看到完整下游证据的反思调用，修复管道最上游的 NL$\to$IR 阶段。
- **$\rho_C$（分类修复）**：引入多工具交叉证据——规则若在 zlint、pkilint、certlint、x509lint 中至少一个存在对应实现，则必然可执行；若被判为 `non_lintable`，即视为假阴性回传 $\phi_C$ 重判。
- **$\rho_G$（生成修复）**：先试确定性修复（如 `Description`/`Citation` 字面替换）；失败则把失败码片段与 IR 约束差异、或解析阶段的原子模板签名/封闭性错误作为反馈注入提示、触发 LLM 在 $\mathcal{T}_{\mathcal{V}}$ 内重新合成；若持续返回 $\perp_{\mathrm{NT}}$，则进入离线词汇扩展通道 $\rho_A$（按同质簇设计新原子模板、只向上单调扩张词汇表、不破坏既有代码可比性）。
- **$\rho_V$（验证修复）**：扩大同义判定的语义邻域（如允许否定/肯定互换、一对多分解），或修正双判定源输出之间的不一致（§7.7 的 L4b 二元判官）。

### 7.5 迭代算法与终止条件

算法 2 给出完整流程。

```
算法 2：阶段归因式迭代验证（SAIV），ρ_R 为首要算子、g4 自动闸门负责回路内验收
输入：标准文档 D，阈值 θ，最大迭代数 K
输出：最终代码集 C* 与终止状态 status

 1:  R_kw ← φ_R(D);  (R_N, R_L, R_U) ← ψ_C(R_kw)
 2:  C ← {φ_G(r) : r ∈ R_L}
 3:  t ← 0
 4:  repeat
 5:      计算残差 L_recall(9), L_cov(11b), L_code(10), N_viol(§7.7)
 6:      if 全部残差 < θ then break                       // 多目标同时闭合
 7:      stage ← StageAttribution(...)                    // 式(12)；G1 已闭合 ⇒ 首查 IR 内容
 8:      if stage = φ_R then                              // 首要算子 ρ_R：IR 内容自反思修复
 9:          for each r 失败于 IR 内容（⊥_NT，或 Faithful_nec=ENTITY_MISMATCH 且非指代）do
10:              rep ← ρ_R(失败轨迹(r))                    // 自反思，返 REPAIR(ir') 或 NO_FIX
11:              if rep = NO_FIX  or  g4_sanity(rep.ir', text(r)) ≠ ∅ then
12:                  r → R^irred_code                     // 自动闸门否决 ⇒ 诚实留残差
13:              else if 重测(rep.ir') 通过（归约∧认证∧编译∧忠实）then
14:                  IR(r) ← rep.ir'                      // 接受修复
15:      else apply ρ_{stage}∈{ρ_C, ρ_G, ρ_V}             // 并列，按归因分支触发
16:      更新 (R_kw, R_N, R_L, R_U) 与 C
17:      t ← t + 1
18: until t ≥ K 或 本轮无任何残差下降（loop-until-dry）
19: return (C, status ∈ {closed, dry, budget_exhausted})
```

第 8–14 行即 $\rho_R$ 回路：第 11 行的 g4-sanity 是确定性闸门，负责回路内的机械验收；既未被否决又通过下游重测者才接受，其余诚实落入 $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$。这不替代 §8.5 对最终发射集的去噪多数同义判定。

**终止条件**：$\mathcal{L}_{\mathrm{total}}<\theta$（默认 0.05）、达最大迭代 $K=10$、或本轮无残差下降。若每个被采纳的阶段修复算子都单调（减少该阶段误差或不变），则 $\mathcal{L}_{\mathrm{total}}$ 每轮非递增；实际系统用"无下降即停止"策略，故保证有限轮终止，但不保证全局最优（见 §8）。

### 7.6 多目标残差总览与双判定源一致性

**双判定源一致性（G3 / L4b）。** §7.4 的 $\rho_C$ 用"实现存在性 $\Rightarrow$ 可执行性"的单向推论；这里把它扩为双向 falsifiable 残差。给定外部工具覆盖 $\mathrm{cov}_{\mathcal{T}} : r \mapsto \{\text{full}, \text{partial}, \text{none}\}$，违反集 $\mathcal{V} = \{ r : \mathrm{cov}_{\mathcal{T}}(r) \in \{\text{full}, \text{partial}\} \land \psi_C(r) \neq \mathrm{lintable} \}$、$N_{\mathrm{viol}} = |\mathcal{V}|$；$\psi_C$ 与 $\mathrm{cov}_{\mathcal{T}}$ 同时正确则 $N_{\mathrm{viol}} = 0$，故它不依赖人工真值。对每条违反调用二元仲裁判官 $\phi_J$：**FLIP**（$\psi_C/\phi_C$ 错判、翻转为 lintable）或 **SPURIOUS**（$\mathrm{cov}_{\mathcal{T}}$ 假阳、降级为 none），任一支被采纳后 $r$ 即离开 $\mathcal{V}$。命题 3（残差单调性，完整陈述与证明见附录 I）表明：若 $\phi_J$ 对每条违反都给出 FLIP 或 SPURIOUS 之一并被采纳，则一轮后 $N_{\mathrm{viol}}$ 严格降至 0。L4b 是 $\rho_V$ 的特化——只修双判定源的不一致、不改代码或生成模块，使该残差具备真正的"零点"、可作收敛判据。

**四目标总览。** 前述不变量可重述为四个目标，收敛态由各残差同时为零刻画（四者形式不同构：守恒等式 / 覆盖比 / 平均损失 / 集合基数）；Gcov 与 G2 是当前开放目标，$\rho_R$ 是驱动二者闭合的首要算子。

| 目标 | 残差 | 主要修复算子 | 修复对象 |
|---|---|---|---|
| G1 召回完整性 | $\mathcal{L}_{\mathrm{recall}}$（式 9） | —（结构不变量，已闭合） | 召回窗口 / 关键词集合（如需） |
| Gcov 覆盖度 | $\mathcal{L}_{\mathrm{cov}}$（式 11b） | **$\rho_R$（首要）**；$\rho_A$ | IR 内容修正（→ 更多规则可归约可生成）/ 离线扩原子模板 |
| G2 同义性 | $\mathcal{L}_{\mathrm{code}}$（式 10） | **$\rho_R$（首要）**；$\rho_G$ | IR 内容修正 / DSL 树重合成 / $\sigma_{\mathrm{mech}}$ 替换 |
| G3 双判定源一致 | $N_{\mathrm{viol}}$（本节） | $\rho_V$（L4b 二元判官） | $\phi_C$ 假阴性 / $\mathrm{cov}$ 假阳性 |

$\mathcal{L}_{\mathrm{recall}} = \mathcal{L}_{\mathrm{cov}} = \mathcal{L}_{\mathrm{code}} = N_{\mathrm{viol}} = 0$ 时 SAIV 闭合。§8 的诚实快照表明 G1 已闭合、底三层（Gcov / G2）未闭合——这正体现框架以可计算残差暴露未闭合处，而非以单一指标掩盖。$\rho_R$ 的纪律是拿不准时诚实判 NO_FIX 而非臆造，与 §8.5–§8.6"残差几乎全在上游抽取"的发现一致。

## 8. 实验与实证评估

本节按"无独立人工真值"的原则组织实证：所有质量信号都来自结构性不变量、确定性复算、外部工具的客观证据，或去噪多数 LLM 判官，而非对单条规则的人工标注真值。评测范围取**当前最干净的一轮全库重抽**——RFC 5280 与 CABF BR（standard_id ∈ {1, 19}）——并诚实地分层报告：守恒方程的顶两层已闭合，而覆盖、代码生成、同义性这底三层尚未闭合。本节即给出这一**诚实快照**，既展示框架已做到什么，也明确暴露未闭合处及其根因。

### 8.1 实验设置与结果快照

评测在 RFC 5280（standard_id = 1）与 CABF BR（standard_id = 19）两个标准源的全库重抽结果上进行。NL→IR 抽取器为 GLM-Z1-9B-0414（一个 9B 量级的小模型）；一次替换为更强抽取器的对照运行未抬高 §8.5 的原始同义率，提示该率主要受抽取任务难度与 IR 表达丰度限制、而非单纯受模型规模限制。代码生成为 §6.5 的受限 LLM 树合成，目标框架为 zlint v3，同义性判官仅在证书级 oracle 不适用的子集上启用并取去噪 5 票多数。所有覆盖与同义性数字均经**去噪多数判官**或确定性复算校准（判定工件随代码公开）；本快照是当前全量重抽后的诚实基线，**不掩盖**底三层尚未闭合这一事实。

**评测并非系统自评。** SAIV 迭代回路不需人工真值（g4-sanity 闸门取代人工确认）；本节评测有效性建立在三道判据上：(i) zlint 自带 `Source` + `Citation` 元数据（第三方声明每条 lint 实现哪一条款，§8.3 覆盖判据）；(ii) 以真实证书执行为真值的证书级 oracle（判定来自 zcrypto 解析与 zlint 读回 `Status`，与生成 LLM 无关，§8.4）；(iii) tree-vs-text 去噪 5 票多数同义判官（§8.5）。前两道为外部客观证据；第三道仍是 LLM 判官，但只比对确定性渲染 $\sigma_{\mathrm{mech}}(t)$ 与原文、不读系统 IR/Go，故三者皆非"以系统输出验证系统输出"。未做的两件事——与现代 LLM 直接生成 Go 的基线对比、各组件受控消融——见 §9.3。

**结果快照与三项方法学硬化。** 本节结果取自最新一轮全库重抽 + 方法学硬化后的一致快照，可在干净数据上确定性复算。三项硬化：(i) **去噪同义判官**——单票约 11% 噪声，改取 5 票多数、单票不再作发射依据；(ii) **lintability 高精度负向门**——在抽取源头把过程/跨证书/runtime/真实世界语义内容类判为非可 lint，于源头拦下（522→373）；(iii) **best-of-N 采样**——LLM 路对每条残差采样 N 个候选树、经证书级 oracle + 去噪判官择优，把 LLM 组合自由转为覆盖而不降低发射集同义性。

**表 1：端到端结果当前快照（standard_id ∈ {1, 19}，RFC 5280 + CABF BR）**

| 指标 | 数 | 口径/说明 |
|---|---:|---|
| 召回规则总量 | 2077 | RFC 5280 637 + CABF BR 1440 |
| **可 lint（单证书可观测）** | **373** | 经硬化分类器：负向门排除过程/跨证书/runtime/语义类（1555→373），CRL 文档规则不在本口径 |
| zlint 覆盖（full，已有同源 lint） | **141** | 该规则已被某条同源 zlint lint 实现 |
| zlint 覆盖（partial） | **29** | 部分实现 |
| 未覆盖可 lint（codegen 定义域） | **224** | 需本系统生成自有 lint |
| **uncovered_lintable_v2（codegen 定义域中未覆盖子集）** | **217** | 从 uncovered_lintable_v2.jsonl（排除 cross-cert 跨证书规则后全部闭合） |
| Form A 编译通过（217 目标中 reducible 子集） | **90** | 占 reducible 子集 144 条的 62.5% |
| Form B（树不可构造，no_atom + 抽取欠表达） | **127** | 73 no_atom（缺原子模板）+ 54 DNE（可构造但抽取欠表达） |
| **det路同义表达（去噪 5 票多数判官）** | **88/217 = 40.6%** | det 71 + LLM best-of-N net new 17；瓶颈：抽取欠表达 73 条 + 原子模板缺口 73 条 + resolver 可救 9 条 |
| LLM路 best-of-N net new synonymous（非det_E） | **17** | best-of-N候选10个 + LLM-compile-28条经去噪5票后得7syn，取非det重复后净增17 |
| 原始同义率（最难题干子集） | **≈30%** | 与历史天花板一致；不同义几乎全可追溯到上游抽取欠表达，非生成端问题 |

**读法。** 表3数字均测量自同一干净目标集（217条 uncovered_lintable_v2）。det路（纯确定性归约）得 Form A 编译90条，其中71条经去噪5票同义判官判 EXPRESSES；LLM路对146条残差（去除det_E后的剩余目标）分别经 best-of-N（10次采样，scaffold+去噪判官）和 LLM-compile（28条编译+去噪5票）两种路径尝试，共得 net new 17条synonymous（去重后）。两路合计 **88/217 = 40.6%**，其中 det 71 + LLM 17。det路原始同义率约30.4%（71/217）≈30%，与项目历史天花板一致，反映瓶颈在上游抽取欠表达；LLM路在残差上贡献+17（10.3% rescue）。

#### 8.1a 不可生成 DSL 树的逐条归因

一个表面矛盾值得正面回答：若一条规则被判为可 lint（原则上仅凭单证书字节即可静态裁决），为何确定性路仍生成不出 DSL 树？关键在于"可 lint 性"是规则的**内在属性**（§5 五条件判定），而"当前能否生成树"取决于其**上游 IR 质量**与**原子模板集覆盖**——二者正交。对 codegen 定义域中确定性路返回 `no_template`（树不可构造）的全部 74 条规则，我们按失败发生的确切环节逐条归因，结果见表 1a。归因可确定性复算（按 `deterministic_tree` 的三段——主语解析 / 谓词派发 / 桥接解析——定位首个失败点，再按约束语义裁定）。

**表 1a：确定性路不可生成 DSL 树（no_template）的归因（74 条）**

| 类 | 子类 | 数 | 根因 | 是否可 lint | 提升路径 |
|---|---|---:|---|---|---|
| **A 抽取欠表达** | A1 约束值丢失 | 24 | IR 的 `constraint.value` 为空或被抽成表格碎片（`'Y'`/`'-'`/null），原子模板与字段齐备但无值可填 | 是 | 改抽取 + 重抽（**禁**在数据上打补丁） |
| | A2 主语错抽/未解析 | 11 | `subject` 被抽错或未解析（如 "subjectAltName MUST be critical" 抽成 subject=issuer） | 是 | 改抽取 + 重抽 |
| **B 误标可 lint** | B 跨证书/线下/外部知识 | 8 | 约束的是签发体系、线下流程或需外部语义（如 unexpired/un-revoked、"Internal Name"、O 字段人读语义顺序），非单证书字节可裁决 | **否（假阳）** | 在抽取源头降级为非可 lint，移出定义域 |
| **C 当前能力边界** | C1 格式/语法（可补通用原子模板） | 11 | FQDN/LDH 语法、enum 取值等，可加**通用**原子模板表达 | 是 | 扩通用原子模板 ρ_A |
| | C2 子字段基数 | 4 | "exactly one AttributeTypeAndValue"、AIA 同 accessMethod 计数等，需子字段计数原子模板 | 是 | 扩通用原子模板 ρ_A |
| | C3 跨字段 + 条件 | 8 | "subject 编码 MUST 同 issuer"、"subject 为空则 MUST 含 SAN"，需带前提的跨字段原子模板 | 是 | 部分可扩原子模板，部分为真残差 |
| | C4 编码语义（重言/byte-level） | 8 | 近乎重言的编码声明、需 byte-level oracle，确定性可救空间小 | 是（多为真残差） | 专用 byte-level oracle 或披露为 R^irred |

**读法。** 三大类边界清晰：**A 类（35 条 = A1+A2）是上游抽取问题**——规则真可 lint，树生不出怪 IR 不忠实于原文、不怪代码生成器，按铁律只能改抽取重抽；**B 类（8 条）是可 lint 性分类器的假阳性**——本不该进 codegen 定义域，应在抽取源头降级，这是表面矛盾的唯一真实来源且可消解；**C 类（31 条）才是代码生成的真实天花板**，其中 C1+C2（15 条）可由**通用**原子模板扩展回收，C3+C4（16 条）多为跨字段条件或需专用 oracle 的真残差。由此，"可 lint 却生不出树"并非定义矛盾：A 归抽取、B 归误标（需降级）、C 归当前能力边界，三者皆非可 lint 性定义的反例。这也解释了同义率为何不是 100%——能编译 ≠ 含义等价，Form A 中判 DNE 者几乎全部可追溯到 A 类同源的抽取欠表达。

#### 8.1b 不同义（Form A 判 DNE）的逐条归因与逐项消解

能生成 DSL 树（Form A）只保证树良构、字段/原子模板合法、类型正确，**不保证树的含义等于规范含义**。同义判官比对"代码渲染语义 $\sigma_{\mathrm{mech}}(t)$ vs 规范原文"，挂掉者即 DNE。我们对初始全部 70 条 DNE 逐条归因（表 1b），并据此**逐项消解**：其中两类是可立即回收的工程问题，已在本轮修复。

**表 1b：不同义（DNE）归因与处置（初始 70 条）**

| 类 | 数 | 根因 | 性质 | 处置 |
|---|---:|---|---|---|
| **D5 判官噪声** | 8 | 代码实际正确，单轮判官误判 DNE；去噪 5 票重判翻回 EXPRESSES | 非真不同义 | **已回收**（重判，+8） |
| **D3 cardinality 错挂** | 1+5 | reducer 把"扩展内部元素计数"错挂为 `FieldCount("Extensions")`（数的是证书有几个扩展，二义皆错，不健全） | codegen 侧 bug | **修 reducer**：映射内部内容列表（如 CRLDP→CRLDistributionPoints），否则诚实返回 None；已回收 1（CRLDP），余 5 为内容列表无干净映射、降级为诚实残差 |
| **D2 前提条件丢失/多加** | 9 | 抽取丢掉前提（"if subject 为空则…"变无条件），或 reducer 多加了 `When` 守卫 | 上游抽取/守卫 | 改抽取重抽 + 守卫审计 |
| **D4 义务级错抽** | 9 | SHOULD / NOT RECOMMENDED 被抽成 MUST，代码按强义务生成 | 上游抽取 | 改抽取（obligation 字段重抽） |
| **D6 主语/字段错抽** | 7 | subject 或目标字段抽错 | 上游抽取 | 改抽取重抽 |
| **D1 约束值丢失** | 1 | 值未抽到、降级为存在性 | 上游抽取 | 改抽取重抽 |
| **D7 真跨字段/语义近似** | 10 | 跨字段条件、语义近似但判官严格区分；多为真残差 | 能力边界/真残差 | 扩跨字段原子模板或披露为 R^irred |

**读法与处置结论。** 70 条 DNE 中，**可立即回收的工程问题占 9 条**（D5 判官噪声 8 + D3 CRLDP 修复 1），本轮已全部回收，使 Form A 同义率从 51.0%（73/143）升至 **58.2%（82/141）**（分母略降因 D3 修复把 2 棵不健全的 `FieldCount("Extensions")` 树诚实降级为 None，移出 Form A）。**剩余 61 条里，D1+D2+D4+D6 共 26 条是上游抽取问题**（义务级错抽、前提丢失、主语错抽、值丢失）——与 §8.1a 的 A 类同源，按铁律只能改抽取重抽、不能在数据上打补丁；**D3 残 5 + D7 共 15 条**为真跨字段/内容歧义残差，需扩跨字段原子模板或专用 oracle。这与全文主结论一致：**同义率的天花板由 Spec→IR 抽取质量决定，而非代码生成环节**——故下一步主攻方向是定向重抽那 26 条抽取问题，而非继续加原子模板。



第一层质量信号是 G1 守恒（§7.3 定理 1）：关键词召回的规则总量，在下游任何分类步骤中都不应增减。当前快照下守恒严格成立：

$$
\underbrace{2077}_{\text{召回}} \;=\; \underbrace{522}_{\text{噪声}} + \underbrace{1555}_{\text{真规则}}, \qquad \underbrace{1555}_{\text{真规则}} \;=\; \underbrace{373}_{\text{可 lint}} + \underbrace{1182}_{\text{不可 lint}}.
$$

两式逐项相等，即 G1 残差 $\mathcal{L}_{\mathrm{recall}} = 0$、守恒顶两层闭合（数据见 §8.1，可确定性复算）。可 lint 的 373 条按标准源分为 CABF 260 条与 RFC 5280 113 条；这 373 条即下游代码生成 $\phi_G$ 的定义域。

### 8.2 lint 覆盖分析

要回答"现有工具覆盖了多少可 lint 规则"，关键在于用对判据。本文以"该可 lint 规则是否被某条同源 zlint lint 真正实现"为判据：对每条规则检索候选 zlint lint，再逐字段（subject / obligation / predicate / constraint）比对，给出 full（完整实现）/ partial（部分实现）/ none（无实现）三档裁定——这比仅看"规则所在 section 是否被某条 zlint 引用"更严格（后者会把同节内的不同需求误计为覆盖）。

算法 3 给出该判定流程。它沿用"先把 lint 源码摘要为反向 IR、再做语义对齐"的思路，但相对早期版本（嵌入向量 top-K 检索 + 单层判官）有三处与当前实现一致的修订：**(i) 候选检索按 source/section 确定，不用嵌入**——RFC lint 的 citation 章节号稳定，故 RFC 规则按章节前缀匹配收窄候选；CABF BR 章节号随版本漂移、不可按节匹配，故 CABF 规则按 source 取**全部** CABF lint 为候选。**(ii) 新增确定性"错字段"一致性闸门**——按 source 取全体 CABF 候选会抬高"full"假阳（判官的 align/differ 自标不可靠，曾把 keyUsage 规则判作覆盖于 SAN lint），故由规则与所匹配 lint 的**主语族**做确定性比对：两者都解析到具体且不同的字段族时，把 full/partial 降级为 none（只降不升），这正是放心使用全体候选的前提。**(iii) 覆盖以 full 计**——partial/none 一并作为代码生成定义域。LLM 仅在阶段 0（离线摘要）与阶段 2（字段级判官，temperature$=0$、提示含方向反转/字段错位/约束类型混淆三类正反例）介入，候选检索、一致性闸门与聚合均确定性。

```
算法 3：lint 覆盖判定（逐规则，LLM 仅摘要与判官两处，聚合确定性）
输入：可 lint 规则集 R_L（每条带 IR）；zlint lint 集 Z；判官 M_judge
输出：每条 r 的 verdict(r) ∈ {full, partial, none}

 1: 阶段 0（离线，每条 lint 一次、可缓存）：
 2:   for each ℓ ∈ Z:  ℓ.ir ← M_summ(ℓ.源码, ℓ.Pass/Error 测试, ℓ.元数据)   // 反向 IR + 一句 RFC2119 摘要
 3: for each r ∈ R_L do
 4:   // 阶段 1：按 source/section 收窄候选（无嵌入）
 5:   if source(r) = RFC then  C ← { ℓ ∈ Z_RFC : 章节前缀匹配(r.section, ℓ.citation 章节) }   // RFC 章节稳定
 6:   else /* CABF */          C ← Z_CABF                                                   // 章节随版本漂移 → 按 source 取全部 CABF lint
 7:   // 阶段 2：字段级判官（候选多则分批、取跨批最优 full>partial>none）
 8:   (v, ℓ*) ← M_judge(IR(r), C)        // 逐字段比对 subject/obligation/predicate/constraint/precondition
 9:   // 阶段 3：确定性"错字段"一致性闸门（只降不升）
10:   if v ∈ {full, partial} and family(r.subject) ≠ family(ℓ*.subject) 且二者均具体 then v ← none
11:   verdict(r) ← v
12: 聚合（确定性）：覆盖 ← |{r : verdict(r)=full}|;  codegen 定义域 ← {r : verdict(r) ∈ {partial, none}}
```

373 条可 lint 规则中，**完整覆盖 141 条、部分覆盖 29 条、未覆盖 203 条**（表 2）；以"非完整覆盖即需本系统自行生成"计，代码生成的定义域为 partial + none = **224 条**。

**表 2：zlint 同源 lint 数，及其对 373 条可 lint 规则的覆盖（按标准源）**

| 项 | CABF | RFC 5280 | 合计 |
|---|---:|---:|---:|
| *zlint 同源 lint 总数（参照）* | *170* | *122* | *292* |
| *　— 其中证书 lint（单证书口径）* | *164* | *115* | *279* |
| *　— 其中 CRL lint（单证书口径外）* | *6* | *7* | *13* |
| full（完整覆盖） | 87 | 54 | **141** |
| partial（部分覆盖） | 25 | 4 | **29** |
| none（未覆盖） | 148 | 55 | **203** |
| 需生成（partial + none，codegen 定义域） | 173 | 59 | **224** |

前三行（斜体）为 zlint 侧按其 `Source` 元数据字段从项目内置 v3 源码直接计得的 lint 数（单位：lint，13 条 CRL lint 经 `RegisterRevocationListLint` 识别、列出但不属本文单证书口径）；其余各行为我方可 lint 规则的覆盖档（单位：规则）。二者并列以示匹配规模：zlint 的 122 条 RFC 5280 与 170 条 CABF BR lint（剔 CRL 后为单证书 115 + 164 = 279 条）完整实现了我方 54 + 87 = 141 条可 lint 规则。full/partial/none 计的是"我方某条规则是否被某条同源 zlint lint 实现"，与 zlint lint 总数不构成简单比值（一条 lint 可命中多条规则、反之亦然）。结构性成因见附录 F，典型对照案例见附录 G。

### 8.3 代码生成分层与同义发射（主要结果）

"一条可 lint 规则能否被写成同义 lint"分口径报告（表 3）：codegen 定义域 = 224 条未完整覆盖目标，其中 217 条已全部闭合（cross-cert 规则排除），剩余 7 条待处理；217 条目标中确定性路 Form A 编译通过 90 条（41.5%），其中 71 条经去噪 5 票同义判官 EXPRESSES（det 30.4%）；LLM 路对 146 条残差经 best-of-N（net new 14 syn）和 LLM-compile（net new 7 syn）两条路径，去重后净增 17 条同义；合计 **88/217 = 40.6%**（det 71 + LLM 17），经 oracle ∧ 去噪双门口径下全部同义。LLM路 rescue 率 17/146 ≈ 10.3%。

**表 3：代码生成分层（当前定版快照，§8.1）**

| 口径 | 数 |
|---|---:|
| codegen 定义域（未完整覆盖可 lint） | **224** |
| 目标集（排除 cross-cert 后闭合） | **217** |
| Form A 编译通过 | **90**（41.5%）|
| det 路同义 EXPRESSES（去噪 5 票） | **71**（30.4%）|
| LLM 路 net new synonymous（去重后） | **17**（10.3% rescue over 146残差）|
| **同义发射合计（oracle ∧ 去噪双门）** | **88/217 = 40.6%** |

当前 snapshot 同义发射共计 **88 条**（det 71 + LLM best-of-N net new 17），占 217 条目标集的 40.6%，经 oracle ∧ 去噪5票双门口径下全部同义。det路原始率 30.4% 与历史天花板一致，反映瓶颈在抽取而非生成；LLM路在146条残差上贡献+17（10.3% rescue）。

### 8.4 同义性作为发射判据（去噪多数判官）

oracle 验证的是 $\mathrm{Code}\equiv\mathrm{IR}$（代码忠实于 IR），但系统的最终价值在于 $\mathrm{Code}\equiv\mathrm{Spec}$（代码忠实于原文）。须澄清同义判官直接比对的对象：它不读 IR 的结构化字段，而是判 **code_summary（即机械摘要 $\sigma_{\mathrm{mech}}(t)$）与原文（抽取时逐字存下的 rule_text）是否同义**——故它**直接测得的只是 code_summary≡规范**；再借"$\sigma_{\mathrm{mech}}(t)$ 忠实渲染代码行为"（其确定性构造，§6.4/附录 E）方升为 $\mathrm{Code}\equiv\mathrm{Spec}$，再与 oracle 的 $\mathrm{Code}\equiv\mathrm{IR}$ 复合、于可认证子集由传递性得 $\mathrm{IR}\equiv\mathrm{Spec}$。三者层层外推：判官只直接担保最内层的 code_summary≡规范，$\mathrm{Code}\equiv\mathrm{Spec}$ 与 $\mathrm{IR}\equiv\mathrm{Spec}$ 均为其下游推论。该同义判定与 §8.3 用作覆盖判据的 zlint 既有实现、§8.4 以真实证书执行为真值的 oracle 一起，构成本评测三道判定信号（前两者为外部客观证据，本道为去噪多数 LLM 判官、只比对 $\sigma_{\mathrm{mech}}(t)$ 与原文）。为抑制判官单票噪声（同一输入两跑约 11% 翻转），该同义判定改取**去噪 5 票多数**。**当前快照**：217 条目标集，det 路 Form A 编译 90 条，经去噪 5 票判官得 **71 条 EXPRESSES（30.4%）**；LLM 路对 146 条残差分别经 best-of-N（10次采样，159条尝试，14 syn）和 LLM-compile（28条编译，7 syn）两种路径尝试，去重后 **net new 17 条 syn**；合计 **88/217 = 40.6%**（det 71 + LLM 17）。LLM路在最难子集（146条残差）上同义 rescue 率为 17/146 ≈ **10.3%**。

须正确解读这个 30.4% 的 det 路原始率，以免误读为系统大部分代码错误。其一，**选择偏差**：该子集（217条目标，zlint未覆盖且可编译）富集连 zlint 都未实现的困难规则，非 373 条可 lint 的平均水平。其二，**瓶颈在抽取**：它反映 $\mathrm{Spec}\to\mathrm{IR}$ 而非 $\mathrm{IR}\to\mathrm{Code}$ 质量；更强抽取、子字段内容原子模板或更丰富 IR 均是尚未穷尽的杠杆（§9.3）。

这一步也暴露了 LLM 同义判官的单票不可靠：同一输入两跑约 11% 翻转（18/166），且初判常含假阴性——既有渲染端模板缺口导致的错误摘要，也有判官对表格残片、指代、版本编码的系统性误判（如 "cA MUST be set TRUE" ↔ `IsCA()` 实为同义却被判否）。这正是本快照改取去噪 5 票多数、并由确定性 oracle 与去噪判官双向校准的原因（§6.6）。此处同义性按二元判定处理（表达 / 未表达，无中间档），判官三档中的 partial 一律归入"未表达"。

**方法学结论：同义性应作为发射判据，而非事后指标。** 一条不同义的 lint 即错误产物，故目标不是把同义率调高，而是只发射经 $\mathrm{Code}\equiv\mathrm{IR}$（oracle）∧ code_summary≡规范（去噪多数同义判定）双验证者。须澄清判定的操作对象：判官不读 IR 的 JSON、也不读 Go 源码（否则会把"读不懂 zcrypto 习惯写法"误计为不同义），而是判确定性渲染 $\sigma_{\mathrm{mech}}(t)$ 是否 EXPRESSES 原文；这道判定直接给出的只是 code_summary≡规范；经"$\sigma_{\mathrm{mech}}(t)$ 忠实渲染代码行为"升为 $\mathrm{Code}\equiv\mathrm{Spec}$，再与 oracle 已验的 $\mathrm{Code}\equiv\mathrm{IR}$ 复合方为 $\mathrm{IR}\equiv\mathrm{Spec}$ 的操作性证据。判官比对的是代码的实际行为，IR 欠表达时 $\sigma_{\mathrm{mech}}(t)$ 说得比原文少、判官据此正确判不同义，瓶颈因而被定位到上游 IR 丰度。当前 snapshot 发射集共计 **88 条（det 71 + LLM 17）/217 = 40.6%**，在该双门口径下全部同义；迭代目标随之改为在不降低同义性门槛的前提下扩大可发射集合。

**确定性忠实性筛查的交叉验证。** 第三重独立检查是 §6.6 的实体级筛查 $\mathrm{Faithful}_{\mathrm{nec}}$。代表案例 R24081：主语错抽（authorityCertIssuer / authorityCertSerialNumber 本属 AKI 却抽成 AIA），oracle 仍验证 $\mathrm{Code}\equiv\mathrm{IR}$，但筛查标记"AIA 原文从未出现"、暴露 $\mathrm{IR}\neq\mathrm{Spec}$；上游补 AKI 子字段重抽后主语归位、并因"共现"语义无对应原子模板而诚实转残差。这印证"筛查—定位—上游修复"闭环，再证瓶颈与修复着力点在抽取端。

### 8.5 SAIV 迭代控制与诚实性证据

SAIV 采用"有下降则接受、无下降则停止"的迭代策略：每轮由 $\rho_R$（§7.5）经 g4-sanity 闸门自动修一批 IR 并重测，只有使预设残差下降或使发射集在双门约束下扩大的修改才进入下一轮。本轮历经干净全量重抽 + 受控原子模板构建（§6）+ 去噪硬化，当前**定版诚实快照**：召回 2077 = 522噪声 + 1555真规则；可 lint 373，zlint 完整覆盖 141 + 部分 29，未覆盖 224；同义发射共计 **88/217 = 40.6%**（det 71 + LLM best-of-N net new 17），双门口径下全部同义。本文报告的是一套可复算的迭代验收纪律和当前诚实快照，而非全局最优或必收敛保证。

迭代过程留下两项可核验的诚实性证据。其一，**$\rho_R$ 在 not_reducible 残差上的产量很低、且大量判 NO_FIX**——这本身是一项诚实发现：该残差大多真正超出当前 DSL 表达力（条件式、跨字段编码、子字段内容），$\rho_R$ 正确地拒修而非臆造修复。其二，一次针对可 lint 标签的反向审计发现分类器 $\phi_C$ 的"结构救援"分支把一批本不可 lint 者（$\mathrm{check\_scope}$ 非单制品、主语未定、或算法委派类）误升为可 lint；将其降级（这正是 §8.1 高精度负向门把可 lint 收紧至 373 的过程）后，**确定性归约 $\mathrm{Code}\equiv\mathrm{IR}$ 的数并不随之下降**——证明"已验证覆盖"从未因误分类而虚高，被误判者全部落在 not_reducible 桶。

这两点共同印证全文的核心定位：本框架的瓶颈与修复着力点都在抽取端（§8.5–§8.6），而 not_reducible 是诚实暴露的**原子模板覆盖**缺口（缺保留 IP / CN-取自-SAN / NFC 归一化 / RDN 次序等原子模板，zlint 多已实现）、而非隐藏的可 lint 性短缺。

## 9. 讨论

### 9.1 跨 PKI 的适用性

本框架的核心机制并不特定于 PKI。Layer 1 的 RFC 2119 关键词集可经配置替换为其他生态的道义关键词（如 ISO 的 shall/should/may）。因此方法适用于同时满足三条件的规范源：**(1)** 以可识别的形式化道义关键词表达强制/推荐；**(2)** 约束目标是结构化、可机器解析的产物（证书、协议消息、配置文件）；**(3)** 具备支持知识图谱与作用域继承的层级化章节结构。这使本框架的方法学价值超出 PKI 单一领域。

### 9.2 对规范作者与工具维护者的建议

对**规范作者**，三条起草原则可显著降低提取歧义：单句单义务（一句至多一个 MUST/SHALL）、以 ASN.1 路径而非代词精确引用字段、用固定模式规范化跨文档引用（使每个引用都能映射为知识图谱上一条类型化边）。对 **lint 维护者**，建议把 `description` 直接写成显式给出字段路径/断言类型/取值/严重级别并引用规范条款的 code_summary——本研究发现大量 lint 描述既非规范引用、也非实现忠实摘要，致使覆盖分析必须先做一步 code_summary 才能对齐，徒增开销与裁决噪声。

### 9.3 局限性与有效性威胁

本文结论严格受限于所用输入表示（结构化 IR）、受限代码空间与验证流程，更适合可在单文档上下文闭合的静态约束，不应外推为"所有 PKI 规范均可完全自动化"。六类边界分述如下：**(i) 方法表达力**——同义判定端点仍由 LLM 实现，77 原子模板对字节级编码、宿主未暴露字段、动态约束等仍有缺口；**(ii) 组件必要性未消融**——知识图谱/受限 DSL/SAIV 的支持分别为工程取舍、架构论证与未消融项，本文不主张图检索相对普通 RAG 的量化优越性；**(iii) 现代 LLM 基线缺位**——直接生成 Go 的对比未做，但证书级 oracle 生成器无关，使其成为定义明确的未来工作；**(iv) 覆盖与泛化边界**——可 lint 总量 373（§6.5）与 codegen 目标 224 不同口径，跨体系泛化本文仅给机制论证；**(v) 端到端口径**——"代码≡规范"仅对发射集成立（§8.5），可 lint 标签未对全部 373 条穷尽人工审计；**(vi) 有效性威胁**——上游 IR 误差会伪装成生成端问题（§8.5），生成 lint 以 `cicasgen_*` 前缀与 zlint 两端互拒以防"自己覆盖自己"，oracle 之外产出诚实归入"未验证"；又，code_summary≡规范 这道同义端点是比对 code_summary 与原文的 LLM 判官、并非 oracle 那种外部且与模型无关的检查，且其"原文"取自抽取时逐字存下的 rule_text（IR 内字段）而非重读规范源文档——故 Layer-1 若把句子截断或漏抽从句，rule_text 与据其解析的结构化 IR 会一致地错、同义判官无从察觉，此捕获保真度是该门的盲区（与"瓶颈在抽取"互为印证）。

## 10. 结论

### 10.1 主要结论

本研究面向 PKI"规范-到-合规检查代码"的端到端自动化，给出贯通"提取 → IR → 可 lint 性判定 → 代码生成 → 验证"的统一框架。实证支持四点结论与一项方法学论断。其一，Web PKI 规范与现有 lint 工具存在显著覆盖缺口：373 条可 lint 中 zlint 完整覆盖 141（另部分 29），余 224 是自动生成的直接目标。其二，可靠提取依赖受约束提取而非端到端直接提示——把 LLM 限为 schema 受限解析器、以确定性检索与确定性可 lint 性判定包裹。其三，真规则中仅约 24%（1555 中 373）可还原为单证书静态 lint，这是对"哪些规范可被静态强制"的量化回答。其四（负向发现）：生成端瓶颈在抽取，det路同义率30.4%几乎全部可追溯到上游IR欠表达（73条DNE+73条NA），LLM路+best-of-N同义发射待重测。方法学论断：验证链路每个算子都应尽可能确定化（最有力实例即证书级 oracle 把忠实性判定确定化），并以"可归约子集闭合 + 不可归约边界披露"取代单一收敛阈值或单一同义率指标。

### 10.2 未来工作

后续工作沿以下方向展开：将自然语言同义判定与符号执行、模型检查等形式化方法结合以建立交叉证据，缓解 $\phi_V$ 端点的判定失真；以单调可加流程持续扩展原子模板词典 $\mathcal{A}$，逐步消除 ASN.1 字节级编码、宿主框架未暴露字段等表达缺口；构建支持引用解析与依赖追踪的跨文档知识表示，并探索将引用解析纳入 $\mathcal{A}$ 的扩展规则；设计面向动态约束（时间、外部状态）的原子模板类与参数化规则表达；以及探索框架无关的 DSL 中间表示，即给定多套 $(\mathcal{A}, \rho)$ 对而保持同一 $\mathcal{T}$，使同一棵 DSL 树可被渲染至多语言宿主框架。

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

[27] B. Peng, Y. Zhu, Y. Liu, X. Bo, H. Shi, C. Hong, Y. Zhang, and S. Tang, "Graph Retrieval-Augmented Generation: A Survey," ACM Trans. Inf. Syst., vol. 44, no. 2, Art. 35, pp. 1–52, 2026.

[28] Y. Dong, C. F. Ruan, Y. Cai, Z. Xu, Y. Zhao, R. Lai, and T. Chen, "XGrammar: Flexible and Efficient Structured Generation Engine for Large Language Models," Proc. Machine Learning and Systems (MLSys), vol. 7, 2025.

[29] D. Banerjee, T. Suresh, S. Ugare, S. Misailovic, and G. Singh, "CRANE: Reasoning with Constrained LLM Generation," arXiv:2502.09061, 2025.

[30] M. Schall and G. de Melo, "The Hidden Cost of Structure: How Constrained Decoding Affects Language Model Performance," in Proc. RANLP, 2025, pp. 1074–1084.

[31] J. Debnath, C. Jenkins, Y. Sun, S. Y. Chau, and O. Chowdhury, "ARMOR: A Formally Verified Implementation of X.509 Certificate Chain Validation," in Proc. IEEE Symposium on Security and Privacy (S&P), 2024, pp. 1462–1480.

[32] M. Chen, J. Tworek, H. Jun, Q. Yuan, H. P. de Oliveira Pinto et al., "Evaluating Large Language Models Trained on Code," arXiv:2107.03374, 2021.

[33] Y. Li, D. Choi, J. Chung, N. Kushman, J. Schrittwieser et al., "Competition-Level Code Generation with AlphaCode," Science, vol. 378, no. 6624, pp. 1092–1097, 2022.

[34] Q. Zheng, X. Xia, X. Zou, Y. Dong, S. Wang et al., "CodeGeeX: A Pre-Trained Model for Code Generation with Multilingual Evaluations on HumanEval-X," in Proc. ACM SIGKDD (KDD), 2023, pp. 5673–5684.

[35] J. Yen, T. Lévai, Q. Ye, X. Ren, R. Govindan, and B. Raghavan, "Semi-Automated Protocol Disambiguation and Code Generation," in Proc. ACM SIGCOMM, 2021, pp. 272–286.

[36] M. L. Pacheco, M. von Hippel, B. Weintraub, D. Goldwasser, and C. Nita-Rotaru, "Automated Attack Synthesis by Extracting Finite State Machines from Protocol Specification Documents," in Proc. IEEE Symposium on Security and Privacy (S&P), 2022, pp. 51–68.

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

所有分量均为冻结有限集合；LLM 在 prompt 区段 C（附录 H）获得各分量全量枚举，故其输出中出现 $\mathcal{V}$ 之外的标识符即触发 $\eta$ 解析错误（命题 1）。

**代表性原子模板（节选）。** 原子模板集 $\mathcal{A}$（$|\mathcal{A}|=77$）按语义簇组织，每个原子模板有类型化签名 $\mathrm{sig}(a)$（§6.3）。下表按簇节选关键原子模板（完整 77 项随代码与数据一并公开）：

| 簇 | 原子模板 | 签名 | 语义 |
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

**共享 Go 渲染样板。** 所有 DSL 树经 $\rho$ 渲染后嵌入下列固定外壳，规则间差异完全集中在 `{{EXECUTE_BODY}}` 与 `{{IMPORTS}}`；`{{PACKAGE}}`/`{{SOURCE}}`/`{{EFFECTIVE_DATE}}`/`{{DESCRIPTION}}`/`{{CITATION}}`/`{{LINT_NAME}}` 由 $\Phi_{\mathrm{post}}$（§6.5）确定性绑定：

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

**后处理元数据映射。** $\Phi_{\mathrm{post}}$ 按下表将可溯源字段确定性注入；义务级别到严重度的映射为 MUST/MUST NOT/SHALL/SHALL NOT/REQUIRED $\mapsto$ `lint.Error`（lint 名前缀 `e_`）、SHOULD/SHOULD NOT/RECOMMENDED $\mapsto$ `lint.Warn`（`w_`）。MAY/OPTIONAL 规则已在 §5 的 $C_1$ 处被排除、不进入 $\Phi_{\mathrm{post}}$，故本系统不产生 `lint.Notice`（`n_`）级输出：

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

$\sigma_{\mathrm{mech}}$（定义见 §6.4）由原子模板-短语字典 $\mathcal{M} : \mathcal{A} \to \mathcal{L}_{\mathrm{NL}}$ 与三组合子归约规则构成。代表性条目：

| 原子模板 | $\mathcal{M}(a)$ 短语模板 |
|---|---|
| `ExtPresent(O)` | "the {O} extension is present" |
| `ExtCritical(O)` | "the {O} extension is present and marked critical" |
| `FieldEq(F, v)` | "{F} equals {v}" |
| `FieldEncodedAs(F, T)` | "{F} is encoded as ASN.1 {T}" |
| `KeyUsageHas(B)` | "the KeyUsage bit {B} is asserted" |
| `ListAllMatch(F, T)` | "every entry of {F} satisfies ({σ_mech(T)})" |
| `SubtreeIPListAnyHasOctetCountAndNotAllZero(F, n)` | "the NameConstraints IP subtree {F} contains a non-zero entry of {n} octets" |

组合子归约：$\sigma_{\mathrm{mech}}(\neg t) =$ "NOT ($\sigma_{\mathrm{mech}}(t)$)"；$\sigma_{\mathrm{mech}}(t_1 \wedge t_2) =$ "($\sigma_{\mathrm{mech}}(t_1)$) AND ($\sigma_{\mathrm{mech}}(t_2)$)"；$\vee$ 同理；原子模板基例 $\sigma_{\mathrm{mech}}(a) = \mathcal{M}(a)$。对条件二元组 $(p,q)$：当 $p = \neg(p')$ 时输出 "WHEN NOT ($\sigma_{\mathrm{mech}}(p')$), THEN $\sigma_{\mathrm{mech}}(q)$"（消除双重否定的 NEG-PRE 模板），否则输出 "WHEN ($\sigma_{\mathrm{mech}}(p)$), THEN $\sigma_{\mathrm{mech}}(q)$"，$p=\perp$ 时输出 $\sigma_{\mathrm{mech}}(q)$ 单句。

**命题 2（$\sigma_{\mathrm{mech}}$ 可逆性）**。*给定 $\sigma_{\mathrm{mech}}(t)$ 的输出，原始 DSL 树 $t$ 在原子模板层等价意义下可机械恢复（同义原子模板被映射到同一短语时不可区分，其余结构保留）；故 $\sigma_{\mathrm{mech}}$ 在验证链路中不构成信息瓶颈。*

### 附录 F：lint 覆盖缺口的四类结构性成因

lint 与规范之间的覆盖缺口并非单一原因，而是 lint 生态中四类结构性因素共同作用的结果。**(C1) 异步演进**：CABF Ballots 与 RFC 勘误的修订速度快于维护者的吸收能力，新增与废止的规范规则都表现为未匹配。**(C2) 多源非规范依据**：相当一部分 lint 检查根植于 issue tracker 决策、根程序实践或 CA 运维经验，构成所分析语料之外、不可达的次级权威。**(C3) 规范文本不完备**：规范源中的自然语言歧义（如"appropriate""reasonable"）由工具维护者解释而非在文本中写明，故不计为覆盖命中。**(C4) 粒度不对称**：规范规则与 lint 检查原子模板之间存在多对多映射，使覆盖完整性难以人工核验。

### 附录 G：典型 lint↔规范对照案例

本附录以 zlint 为例，从 §8.3 的覆盖分析中按 full / partial / none 三类各采样一个代表性案例，展示覆盖分析在不同情形下的判定与受控判官给出的理由。

| lint rule_id | code_summary | 匹配规范规则 | 判定 | 判定原因 |
|---|---|---|---|---|
| `e_ca_common_name_missing` | The CA certificate subject MUST include a commonName attribute. | CABF-Server §7.1.2.10.2：`commonName` \| MUST | **full** | 两者都要求 CA 证书 subject 中存在 commonName，字段与义务级别一致。 |
| `e_ca_key_usage_not_critical` | The root CA and intermediate CA certificate keyUsage extension MUST be marked critical. | CABF-SMIME §7.1.2.3：`keyUsage`（SHALL be present）This extension SHOULD be marked critical | **partial** | lint 对 keyUsage criticality 施加了比规范 SHOULD 更严的 MUST 约束。 |
| `e_cab_dv_subject_invalid_values` | The subscriber certificate subject DN MUST NOT contain attribute types other than countryName and commonName. | —（未召回） | **none** | 在严格语义等价判据下，候选后端池中未召回匹配规则，尽管该 lint 引用了 CABF-BR §7.1.2.7.2。 |

### 附录 H：DSL 合成 Prompt 模板

本附录给出 §6.5 所述受约束 LLM 调用 $\phi_G$ 的实际系统提示与四区段拼接结构。

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

**四区段拼接。** 每次调用的完整 prompt 由四区段依次拼接：**区段 A（Rule Context）**——源 ID、章节号、规则 ID、逐字 `rule_text`（即将作为 `Description` 注入的字面量）与 `source` 元数据；**区段 B（Structured IR）**——扁平展开的 IR 四元/五元组（`subject`、`obligation`、`predicate`、`constraint`、`precondition`）；**区段 C（DSL Schema）**——附录 D 所述 $\mathcal{V}$ 与 $\mathcal{A}$ 的全量枚举（按分量分组的字段名清单与按语义簇分组的原子模板签名表，附每原子模板一行 PKI 语义注释）；**区段 D（Output Protocol）**——上述两种合法 JSON 形态的精确 schema，含字段类型、必选/可选标记与一条 minimal positive 示例。

### 附录 I：SAIV 残差与归因的形式化细节

本附录汇集 §7.4–§7.5 与 §7.7 正文中引用的精确数学形式化，以供需要形式核查的读者查阅。

**SAIV 核心残差的精确式**（直觉与定义见 §7.4 正文）：

- 召回守恒残差：$\mathcal{L}_{\mathrm{recall}} = 1 - \frac{\min(|\mathcal{R}_{\mathrm{kw}}|,\; |\mathcal{R}_N|+|\mathcal{R}_L|+|\mathcal{R}_U|)}{\max(|\mathcal{R}_{\mathrm{kw}}|,\; |\mathcal{R}_N|+|\mathcal{R}_L|+|\mathcal{R}_U|)}$（式 9）
- 代码忠实残差：$\mathcal{L}_{\mathrm{code}} = 1 - \frac{1}{|\mathcal{R}_L|}\sum_{r\in\mathcal{R}_L}\lambda_{\mathrm{code}}(r)$（式 10）
- 总损失：$\mathcal{L}_{\mathrm{total}} = w_R\cdot\mathcal{L}_{\mathrm{recall}} + w_C\cdot\mathcal{L}_{\mathrm{code}}$，$w_R+w_C=1$（式 11）
- 覆盖残差：$\mathcal{L}_{\mathrm{cov}} = 1 - \frac{|\{\,r:\text{本系统为}r\text{发射通过双门的 lint}\;\land\;r\text{对应某条 zlint lint 的 citation 条款}\,\}|}{|\mathcal{C}_{\mathrm{zlint}}(\mathcal{D})|}$（式 11b），分母取 zlint 同源 lint 总数 292（RFC 5280:122，CABF BR:170；含 CRL lint 13）

**阶段归因的四分支规则**（精确条件见 §7.5 正文）：

$$
\mathrm{Stage}^{(t)} = \begin{cases}
\phi_R/\psi_C, & \mathcal{L}_{\mathrm{recall}}^{(t)} > \tau_R \\
\phi_C, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} > \tau_C \\
\phi_G, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} < 1 \\
\phi_V, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} = 1
\end{cases} \tag{12}
$$

其中 $p_{\mathrm{fail}}^{(t)} = \frac{1}{|\mathcal{R}_L|}\sum_{r\in\mathcal{R}_L}\mathbb{1}[\neg\mathrm{compile}(\phi_G(r))]$、$\bar{s}_{\mathrm{struct}}^{(t)} = \frac{1}{|\mathcal{R}_L|}\sum_{r\in\mathcal{R}_L}s_{\mathrm{struct}}(\phi_G(r))$。

**命题 3（残差单调性）的完整陈述与证明**（正文见 §7.7）：

*命题 3（残差单调性）。若 $\phi_J$ 在每条违反上均给出 FLIP 或 SPURIOUS 之一并被采纳，则 L4b 一轮过程后 $N_{\mathrm{viol}}$ 严格下降至 0。*

*证明。* 设违反集 $\mathcal{V}=\{r:\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}\land\psi_C(r)\neq\mathrm{lintable}\}$，$N_{\mathrm{viol}}=|\mathcal{V}|$。对任意 $r\in\mathcal{V}$，$\phi_J$ 必给出且仅给出以下两支之一：
- **FLIP**：采纳后 $\psi_C(r)$ 翻转为 $\mathrm{lintable}$，此时 $\psi_C(r)=\mathrm{lintable}\land\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}$ 仍触发违反式左侧，但违反式右侧不再成立（lintable 的假阴性已修正），故 $r\notin\mathcal{V}$；
- **SPURIOUS**：采纳后 $\mathrm{cov}_{\mathcal{T}}(r)$ 降级为 $\mathrm{none}$，此时违反式左侧 $\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}$ 不再成立，故 $r\notin\mathcal{V}$。

两类修复均移除该 $r$ 而不引入新违反，故 $\mathcal{V}$ 在一轮内严格收缩至空集、$N_{\mathrm{viol}}=0$。$\square$

*注：* FLIP 与 SPURIOUS 不可同时对同一条规则采纳（两者互斥），且采纳后该规则离开 $\mathcal{V}$，不参与后续判定，故该过程有界终止。
