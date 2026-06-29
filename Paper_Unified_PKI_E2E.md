# 从 PKI 标准到合规检查代码：规则提取、可 lint 性判定与可验证代码生成的端到端框架

## 摘要

公钥基础设施（PKI）的证书编码规则分散在 RFC 5280、CA/Browser Forum 基线要求（CABF BR）、ETSI EN 319 与 Mozilla 根存储策略等多份自然语言标准中。自 2025 年起 CA/Browser Forum 要求所有公信 CA 在签发前对证书执行 lint 检查，将规范文本系统转化为可执行的合规代码因而成为 PKI 治理的关键环节。然而现有 lint 工具（如 zlint、pkilint）的每条检查均由专家逐条手写并随规范修订维护，"哪些规范条款能被静态检查、现有工具又覆盖到何种程度"长期缺乏系统答案。

本文的出发点是一个常被忽略的事实：**并非每条带 MUST 的规范都能写成 lint**——许多强义务约束的是 CA 线下行为、证书链或运行时状态，而非单张证书的字节。我们因此把**可 lint 性**（一条规则能否仅凭一张证书的字节被静态裁决）形式化为四个离散 IR 字段上的确定性布尔合取，使判定可复现且可复查参与判定的字段；并在其上构建一个从标准文本到合规检查代码的端到端框架，串联规则提取、中间表示（IR）、可 lint 性判定、代码生成与验证。

总设计原则是：仅在确需语言理解之处使用大语言模型（LLM），其余环节实现为可复现的确定性函数。跨文档上下文由规范知识图谱上的确定性子图检索给出；LLM 只承担受 schema 约束的 IR 解析（四元组 ⟨主体, 义务, 谓词, 约束⟩）。代码生成不输出自由 Go 代码，而把代码生成的值域限制为有限原子模板集（79 个原子模板）与类型化词汇表张成的受限 DSL 树空间，在架构层排除"编造字段/OID"类幻觉（命题 1）。针对"代码是否忠实于规范"这一最难判定，本文不依赖 LLM 投票，而构建**证书级语义 oracle**：为每个原子模板生成"满足/违反"两类受控证书、由真实执行读回状态，从而对仅由已认证原子模板构成的生成 lint 给出与模型无关、可复现的"代码≡IR"执行级验证（受控 fixture 上的验证而非对全体证书的定理，详见 §6.5）。缺乏人工真值时，再由**阶段感知式迭代验证（Stage-Aware Iterative Verification, SAIV）**把召回完整性、代码-规范同义性与双判定源一致性形式化为可计算残差，配以阶段路由与"有下降才接受"的修复策略，在无真值下提供可追溯、可有限终止的质量控制。

在 RFC 5280 与 CABF BR 上的实证如下。关键词召回 2077 条候选，守恒划分得 1555 条真规则、其中 336 条可 lint；zlint 既有实现完整覆盖 132 条，余 204 条为代码生成的直接目标。在这 204 条目标上，"确定性优先、LLM 兜底"两路（均须渲染并通过 `go build`）共生成可编译 lint **175 条（代码生成率 85.8%；确定性 137 + LLM 38）**，其中经去噪多数 LLM 判官判 $\mathrm{Code}\equiv\mathrm{Spec}$ **同义 113 条（同义率 113/175 = 64.6%，分母为能生成可编译 lint 者；not-lintable 规则不计入分母）**。另由证书级 oracle 对其中 124 条独立证得 $\mathrm{Code}\equiv\mathrm{IR}$（确定性、与模型无关的 soundness，非同义判定）。前半段（规则提取与可 lint 性判定）以 zlint 维护者公开的 CABF BR 人工映射表为第三方金标对照，在 BR 1.4.8 上达 κ=0.823、召回 86.9%；后半段（代码生成与同义判定）则把通过同义门的 lint 注入真 zlint 二进制、跑过 1128 张测试证书（§8.5），以三套独立解析器逐条结构审计其每一次有效命中，确认生成 lint 产生了 72 条结构性发现。其中，OV 证书携带 `givenName` 是一项此前缺少直接 zlint 覆盖的真实信号。

**一项贯穿全文的观察是：代码生成后的端到端同义性仍需单独验证。** 在能生成可编译 lint 的目标上，同义率为 64.6%。证书级 oracle 对 124 条生成 lint 证得"代码≡IR"，其中仍有 36 条被判官判为不同义，这说明 $\mathrm{Code}\equiv\mathrm{IR}$ 不能替代 $\mathrm{Code}\equiv\mathrm{Spec}$。本文仅报告这一分歧；最后的 code_summary≡规范 同义端点仍依赖去噪多数判官，如何进一步确定化仍是开放问题。

方法学上，本文提炼出一条不限于 PKI 的设计原则：验证链路上每个环节都应尽可能确定化，证书级 oracle 把原属 LLM 的"忠实性判定"也确定化，即其在验证端的体现。相应地，本文以"可归约子集闭合 + 不可归约边界诚实披露"双指标取代单一收敛阈值。

**关键词**：公钥基础设施；证书合规检查；规范规则提取；中间表示；可 lint 性分析；受限代码生成；证书级语义 oracle；阶段感知式迭代验证

## 1. 引言

### 1.1 研究背景与动机

公钥基础设施（Public Key Infrastructure, PKI）是现代互联网信任的基础：证书颁发机构（CA）签发的 X.509 数字证书支撑着身份认证与加密通信。证书是否被正确签发因而直接关系到 Web PKI 的完整性——违反技术性规范要求的证书会削弱浏览器信任、损害安全通信的可靠性。这类失效并非纯理论风险：2024 年 Chrome 与 Mozilla 在一系列未解决的合规事故后相继宣布不再信任 Entrust 作为公信 CA [13], [12]；更早的 2020 年，Let's Encrypt 因一处 CAA 校验缺陷撤销了约三百万张证书 [14]。

这些事故已转化为政策变化：据 CA/Browser Forum Ballot SC075，公信 CA 自 2025 年 3 月 15 日起需在签发前执行 lint 检查 [15]；Ballot SC-081v3 则规划将 TLS 证书有效期分阶段压缩、最终降至 47 天 [16]。二者共同抬高了签发频率与自动化合规需求。当前合规分析依赖 zlint [7]、pkilint [8]、certlint [9]、x509lint [10] 等静态工具，但它们高度依赖**人工规则工程**——每条检查须由专家随规范修订单独实现并维护；而 X.509 编码规范分散在 RFC 5280 [1]、CABF 基线要求 [2]、ETSI EN 319 412 系列 [3]、Mozilla 根存储策略 [4] 等多份文档、普遍以 RFC 2119 [5] 关键词表达义务级别，手工方式愈发难以规模化。

更根本的是，PKI 生态缺乏一个将规范文本系统性转化为可经静态 lint 检查强制执行的合规逻辑的框架。这一缺口随着 lint 在 PKI 治理中日益核心而愈发关键：规范本身并未区分"可由静态检查强制"与"需要证书之外的运行时或外部证据"两类规则。本研究的目标，即是给出一个从 Web PKI 规范源**提取规范规则、判定其可 lint 性、并自动生成对应可执行检查代码**的端到端框架。

理解这一缺口的关键是一个朴素却常被忽略的区分。同样含 MUST，"证书 MUST 包含 keyUsage 扩展"可仅凭一张证书的字节静态裁决，而"CA MUST 在签发前核验申请人身份"约束的是线下行为、任何静态检查都无从判定。我们称前者具备**可 lint 性**——能否被一个不依赖运行时或外部上下文、仅凭单张证书字节即可裁决的静态检查所表达；它是把规范转化为代码的前置闸门，本文将其形式化为 IR 上的确定性布尔判定（§5）。在此之上，本框架在 RFC 5280 与 CABF BR 上从 2077 条候选判出 **336 条可 lint 规则**，并报告覆盖、生成、同义判定与证书检测结果（§8）。

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

**第二，生成侧——代码空间应在语言层面而非 prompt 层面受限。** 与其用 prompt 反复约束 LLM 不要编造字段，不如使其无从编造：把代码生成的值域定义为一个有限闭合的 DSL 树空间，使编造字段/OID 的幻觉在架构层即被排除（命题 1），不依赖 prompt 约束或 few-shot 引导这类概率性手段。

**第三，验证侧——验证链路上的每个环节都应尽可能确定化。** 在语义等价传递链

$$
\mathrm{Spec} \;\to\; \mathrm{IR} \;\to\; t \in \mathcal{T}_{\mathcal{V}} \;\xrightarrow{\sigma}\; \mathrm{Summary} \;\equiv\; \mathrm{Description}
$$

中，关键词召回、可 lint 性判定、渲染、后处理、机械翻译均由确定性函数实现。尤为关键的是，连"生成代码是否忠实于 IR"这一判定本身也被确定化：可认证子集上由证书级语义 oracle 以真实证书执行给出"代码≡IR"的执行级验证，只有 oracle 不适用的忠实性判断和最终"code_summary≡规范"（机械摘要 $\sigma_{\mathrm{mech}}(t)$ 与原文）同义性把关仍需语义灵活的判官（详见 §6.5）。缺乏人工真值时，再由 SAIV 将多类质量不变量形式化为可计算残差，提供可追溯的迭代控制信号。

### 1.4 主要贡献

**(C1) 基于 IR 的四条件可 lint 性框架。** 将可 lint 性形式化为四个离散 IR 字段上的确定性布尔合取（道义强度、被约束主体、运行时阶段、规则类型），使判定可复现，并可复查参与判定的 IR 字段而非依赖不透明的端到端调用（§5）。该框架连同其上的规则提取，以 zlint 维护者公开的人工映射表作外部对照（BR 1.4.8 上 κ=0.823、召回 86.9%，§8.4）。

**(C2) 受限代码空间、可逆机械翻译与证书级语义 oracle。** 将代码生成模块的值域形式化为 79 个原子模板与类型化词汇表张成的受限 DSL 树空间（给出语法、执行语义与词汇封闭性命题 1），并定义确定性机械翻译函数（全函数、确定、原子模板等价意义下可逆）。其上构建证书级语义 oracle：经逐原子模板认证与结构组合，对仅由已认证原子模板构成的生成 lint 给出"代码≡IR"执行级验证，以与模型无关的可复现判据取代单票 LLM 判别器，并诚实披露可认证子集边界。进一步，把通过同义门的 lint 注入真 zlint 二进制、跑过真证书语料并以三套独立解析器逐条结构审计每一次命中（§8.5）。

**(C3) 阶段感知式迭代验证（SAIV）与多目标残差。** 将召回完整性、代码-规范同义性与双判定源一致性形式化为可计算残差，给出阶段路由规则、修复操作集、有限终止条件与接受门。该框架在无人工标注真值条件下提供质量控制（§7）。

## 2. 研究背景

### 2.1 PKI 标准与静态合规检查

X.509 证书的编码规范由分层的标准与策略框架共同定义。RFC 5280 [1] 给出证书 ASN.1 结构、字段级语义与路径验证算法这一基础层；其上，CABF 基线要求 [2] 对签发公信 TLS 证书的商业 CA 施加操作性与配置性约束；ETSI EN 319 412 系列 [3] 补充了与 eIDAS 框架对齐的欧盟配置档案；Mozilla 根存储策略 [4] 则从浏览器策略层引入额外技术要求。这些规范彼此交叉引用并时有局部覆盖，普遍以 RFC 2119 [5] 关键词表达义务级别（MUST/SHALL 通常映射为 Error，SHOULD/RECOMMENDED 映射为 Warning，MAY/OPTIONAL 一般不宜直接实现为 lint 规则）。

证书合规主要由静态 lint 工具检查（只检视单张证书、不依赖外部验证状态）：zlint [7] 部署最广，将检查组织为带元数据（引用、生效日期、严重级别）的独立 lint（v3 约 400 条）；pkilint [8] 是 Python 嵌套结构校验框架；certlint [9] 与 x509lint [10] 为更早的命令行 linter。每条检查都须人工从规范推导、映射到解析器字段、实现并随规范维护，故各工具覆盖不均衡。两点含义：其一，lint 是嵌入字段路径/谓词/严重级别/作用域的工程产物，而非规范语句的直接拷贝；其二，缺某条 lint 不等于对应规范规则不存在，可能只是尚未被识别为可 lint 或尚未实现。

### 2.2 规范提取与 LLM 辅助代码生成

自动规则提取已见于隐私、法律与协议规范，但与 Web PKI 签发合规本质不同。PolicyLint [18]、PrivacyFlash Pro [19] 分析隐私文本，Hassani 等 [20] 以 LLM 加知识图谱做法律合规提取，但都不映射到 DER 证书字段、也不判某规则能否凭单张证书强制执行；N-Check [21] 把规范形式化为 FOL\* 公式，目标是良构性分析而非 lint 谓词。面向技术规范的 LLM 系统中，PROSPER [22]、ParCleanse [23]、SpecGPT [24] 分别提取 RFC 状态机、协议格式与 3GPP 行为，Wu 等 [25] 以 GraphRAG 式上下文 [26], [27] 对齐 RFC 与内核代码——它们聚焦状态/格式/实现差异，未把"穷尽召回、schema 受限 IR 解析、确定性可 lint 性判定"三者分离处理。

LLM 代码生成进展显著（Codex [32]、AlphaCode [33]、CodeGeeX [34]），但主要面向通用编程，缺乏对领域约束、目标框架接口与可追溯性的显式建模；协议合规方向 SAGE [35]、RFCNLP [36]、PROSPER [22] 提取状态机或生成测试用例，而非面向具体 lint 框架产出可执行代码。输出约束与形式验证类工作与本研究互补：XGrammar [28]、CRANE [29] 以文法约束 LLM 输出，Schall 与 de Melo [30] 指出受限解码可能损害推理，ARMOR [31] 在 Agda 中验证 RFC 5280 路径验证算法——它们改进输出形式或算法保证，但不决定哪些自然语言签发规则应成为静态 lint。

### 2.3 语义对齐与证书合规度量

确保生成代码与规范语义一致是该类任务的核心难点：测试用例难穷尽边界、符号执行易路径爆炸、差异分析需可对照的参考实现，而中间表示方法借 IR 语义桥接间接验证一致性，最适合规范文本到代码的转换。本研究即以 IR 为桥梁，进一步引入基于 code_summary（机械摘要）的同义性归约与确定性机械翻译，使对齐判定既可计算又可追溯。经验设定上，Kumar 等 [11] 在生态尺度度量证书误签发、Zhang 等 [17] 识别国际化 X.509 证书的 Unicode 相关不合规，表明签发失效可度量且具运维重要性；但它们通常从已知 lint 或缺陷类别出发，而非从规范文本系统性推导可 lint 规则全集。

### 2.4 本研究的差异化定位

本研究的差异化定位有四。其一，给出贯通"提取 → IR → 可 lint 性判定 → 代码生成 → 验证"的端到端框架，以结构化四元组 IR 为前后两半的统一接缝，而非孤立地做提取或生成。其二，提取侧把 LLM 限定为受 schema 约束的解析器，并以确定性可溯源检索（沿规范结构的显式边遍历，而非向量相似度或 LLM 推断）组装跨文档上下文——差异在于"受约束 + 可溯源"，本文不主张图检索相对普通 RAG 的量化优越性（难做干净消融，见 §9.5）。其三，生成侧将代码生成模块的值域形式化为有限闭合的受限 DSL 树空间，在语言层排除字段/OID 编造类幻觉（命题 1）。其四，验证侧提出阶段感知式迭代验证，将多类质量不变量形式化为可计算残差，在无人工真值下提供可追溯的阶段路由与停止准则——由此给出一项更一般的设计原则：验证链路上每个环节都应尽可能确定化。

## 3. 方法总览

图 1 给出整体结构：系统以 Web PKI 规范文本为输入，输出可编译、可追溯的 zlint Go 检查代码，并由阶段感知式迭代验证（SAIV）在无人工真值下闭环修复。六阶段分两半——前半（确定性上下文、提取、判定）构成"规范 → 可 lint 规则"，后半（合成、对齐、验证）构成"可 lint 规则 → 可信代码"，以结构化中间表示 IR 与四条件可 lint 性判定为统一接缝。

```mermaid
flowchart LR
  S[Web PKI 规范文本] --> KG[知识图谱构建 §4.1]
  KG --> R[确定性子图检索 §4.2]
  R --> L1["Layer 1 关键词召回 φ_R"]
  L1 --> L2["Layer 2 受控解析 → IR"]
  L2 --> C["四条件可 lint 性判定 φ_C §5"]
  C -->|"可 lint 集 R_L"| G["受限 DSL 树合成 φ_G §6"]
  G --> RHO["渲染 ρ + 后处理 Φ_post"]
  RHO --> V["三层对齐验证 φ_V + 证书级 oracle §6"]
  V -->|残差| SAIV["阶段感知式迭代验证 SAIV §7"]
  SAIV -. "修复信号" .-> L2
```

![](figures/fig9_pipeline_snapshot.png)

_图 1：端到端漏斗快照。A 显示召回与可 lint 化守恒，B 显示 zlint 覆盖与 codegen 定义域，C 显示 codegen、同义发射与证书级 oracle 的关系。_

为便于通读，下表汇总全文使用的主要记号。

| 记号 | 含义 |
|---|---|
| $\Pi=\phi_V\circ\phi_G\circ\psi_C\circ\phi_R$ | 受控规范-代码生成管道（§7.1） |
| $\phi_R$ | 关键词召回模块（Layer 1，§4.3） |
| $\phi_C$ | 四条件二值可 lint 性判定函数（§5） |
| $\psi_C$ | 候选规则三元划分模块：noise / lintable / nonLintable（§7.3） |
| $\phi_G$ | 受限 DSL 树合成模块（§6.4） |
| $\phi_V$ | 三层对齐验证模块（§6.5） |
| $\mathcal{T}_{\mathcal{V}},\ \mathcal{A},\ \mathcal{V}$ | 受限 DSL 树空间 / 原子模板集（$\lvert\mathcal{A}\rvert=79$）/ 类型化词汇表（§6） |
| $\rho,\ \Phi_{\mathrm{post}}$ | 确定性渲染函数 / 可溯源字段后处理（§6.3, §6.6） |
| $\sigma_{\mathrm{mech}}$ | 确定性机械翻译函数（DSL 树 → 英文摘要；定义见 §6.3） |
| $\eta,\ \mu$ | 输出解析函数 / IR 谓词到原子模板的语义映射（§6.4） |
| $\rho_R$ | IR 内容修复操作（§7.5） |
| $\rho_C,\ \rho_G,\ \rho_V,\ \rho_A$ | 分类 / 生成 / 验证 / 离线扩原子模板 修复操作（§7.5） |

## 4. 规则提取

本节描述前半链路：如何在确定性可控的前提下，从分散且交叉引用密集的 Web PKI 规范源中提取规范规则，并转写为结构化中间表示 IR。核心困难在于跨文档引用——孤立地阅读任一段落都不足以还原一条规则的完整语义。本文的应对是分工：以确定性的图遍历组装上下文，以受约束的 LLM 解析语义，从而既不丢失上下文、又不让模型自由发挥。

### 4.1 PKI 知识图谱构建

知识图谱构建器（离线）把异构 Web PKI 规范源归一化为层级结构、为规范/章节/文本单元赋稳定标识，抽取章节引用、RFC 引用与策略交叉链接等**显式引用**并链到对应节点，同时记录证书字段概念及别名（subjectAltName、dNSName、basicConstraints.cA、策略 OID 等），以便把自然语言提及映射到规范证书路径。

本研究将该跨文档网络建模为多边有向图：八类节点（Specification、Section、Definition、CertificateField、Rule、Operation、Value、Concept）与四种 source-backed 关系（CONTAINS、DEFINES、REFERENCES、APPLIES TO）。构建器刻意保守——只存文档结构或文本证据直接支持的关系，冲突/覆盖/可 lint 性等**规范性判断**留给后续确定性阶段（CONFLICTS WITH、OVERRIDES 由规则引擎产生、**不进入检索图**）。故该图是可溯源的上下文索引、而非裁决 oracle（关系类型与检索可入性见附录 B）。

### 4.2 确定性上下文检索

检索以确定性方式组织上下文，而非依赖 LLM 推断关系：给定目标 Section，沿 source-backed 的 CONTAINS、DEFINES、REFERENCES、APPLIES TO 在 $k$-跳邻域内 BFS 扩展，按关系类型优先级装配术语定义、字段元数据与被引章节。不用向量相似度、不调 LLM 推理，故不产生独立判断。

检索阶段额外遵守四条约束：不引入推断规则、只原始规范节点可入检索、推断性关系不入检索、所有上下文须可追溯至规范源——保证"喂给 LLM 的上下文"可审计、可复现，从根本上抑制"据臆造上下文作答"。

### 4.3 双层提取流水线

为在保留 LLM 语义理解能力的同时维持提取过程的可审计性，本研究采用双层结构。

**Layer 1：确定性召回。** Web PKI 规范普遍以 RFC 2119 关键词表达义务强度；RFC 8174 [6] 规定这些关键词仅在大写时具规范效力，从而支持确定性匹配（ETSI EN 319 不遵循该约定，按小写召回）。Layer 1 以三遍运行——直接关键词匹配、嵌套结构的义务继承、非标准 RFC 2119 形式的规范陈述捕获——输出候选规范规则集合 $\mathcal{R}_{\mathrm{kw}}$。

**Layer 2：受控语义解析。** LLM 被限为受约束的语言理解角色：不直接生成 lint 或合规判断，而是把规范文本转写为 JSON 序列化 IR，规范性推理全推迟到确定性阶段。IR 生成采用**分阶段**策略（先判规则类别、再填其余字段，显著降低误差），并受一组确定性约束（schema 校验、规则引擎覆盖确定可判类、源文本对齐校验、ASN.1 路径树约束）在文本层与 schema 层分别抑制"编造原文"与"编造字段层级"两类幻觉。

### 4.4 结构化中间表示

IR 是连接前后两半链路的核心数据结构。其核心为四元组

$$
\mathrm{IR} = \langle \text{subject},\ \text{obligation},\ \text{predicate},\ \text{constraint} \rangle,
$$

其中 subject 为由字段解析器解析得到的证书字段路径（如 `extensions.subjectAltName.dNSName`），obligation 为 RFC 2119 义务关键词，predicate 为断言类型（如 `must_be_present`、`conform_to`、`equal`），constraint 为约束值或模式。四元组之外，IR 还携带若干关键扩展字段，用于支撑可 lint 性判定与下游生成与审计，其中最重要的是 `rule_category`（规则语义类别）、`assertion_subject`（断言主体：证书 / CA / 依赖方 / 外部生态）、`enforcement_phase`（约束所依赖的阶段：编码 / 运行时 / 外部验证），以及 `source_section`、`source_span`、`evidence_text`、`context_nodes` 等溯源字段（关键字段的完整列举见附录 A）。

以 IR 为桥梁相较"从原文端到端直接生成"有三点优势：引用/约束/义务分离存储，提升可追溯性与冲突处理；IR 作为 §5 四条件判定的确定性输入，使判定可复现而非依赖模型；由显式化的 IR（字段路径、断言类型、约束值）生成代码更稳定、可解释。IR 由此支持"一次提取、多处复用"，同时服务可 lint 性分析与代码生成。

## 5. lintability判定

并非每条带 MUST 的规范都能写成 lint 检查。承 §1.1 的对照——"证书 MUST 包含 keyUsage 扩展"可仅凭一张证书裁决，但"CA 必须核验申请人身份"约束的是 CA 线下行为，还有的要比对证书链上的其他证书、查 DNS 记录或撤销历史——后三类都无法仅凭一张证书的字节静态裁决。因此在生成代码之前，必须先回答一个前置问题，即每条规范规则的**可 lint 性**：它能否被一个不依赖外部上下文或运行时行为、仅凭**一张证书**的字节即可裁决的静态检查所表达？（CRL 等其他制品自身的合规检查不在本文范围内。）

本文不让 LLM 直接判定，而把它分解为四个独立布尔条件、各只读一个 IR 字段、全满足才判可 lint，从而在 IR 上确定性计算可 lint 性。三点观察：其一，决定可 lint 性的恰是四类信息——义务道义强度、被约束主体（含数据范围：单证书 vs 跨证书/其他制品）、约束生效阶段、规则类型；其二，四者各可编码为取值于小而封闭集合的单一 IR 字段，故判定退化为四个离散字段的布尔函数；其三，分离后可直接复查参与判定的字段取值，而非只得到不透明的端到端标签。

形式上，本文的**操作性可 lint 标签**定义为以下四个条件的合取，每个条件都是恰好一个 IR 字段的布尔函数：

$$
\mathrm{lintable}(r) \;\Longrightarrow\; C_1(r) \wedge C_2(r) \wedge C_3(r) \wedge \neg C_4(r)
$$

其中

- **$C_1$（道义强度）**：$C_1(r) \equiv \mathrm{is\_normative}(r.\text{obligation})$，即 $r.\text{obligation} \notin \{\text{MAY}, \text{OPTIONAL}\}$；
- **$C_2$（主体边界）**：$C_2(r)$ 由两项联合判定：其一，$r.\text{assertion\_subject} = \text{Certificate}$；其二，$r.\text{subject}$ 路径的根段（第一个路径分量）属于预定义的证书/CRL 结构字段集合。仅 $\text{assertion\_subject} = \text{Certificate}$ 纳入判定——$\text{CA}$ 不在范围内（CA 是颁发证书的机构，其行为不在证书字节中）；$\text{RelyingParty}$ / $\text{Implementation}$ 描述依赖方或软件行为；$\text{CRL}$ 描述证书吊销列表文档（不在本文范围内）；$\text{CrossArtifact}$ 描述需跨制品比对（如"子证书的 SKI 须等于签发者的 AKI"、预证书须与最终证书逐字节一致、序列号跨证书唯一等）。第二项 subject 路径门确保：若 subject 路径指向操作名词（如 domain_validation_record、phone_contact）而非证书字段，该规则描述的是 CA 过程而非证书内容，同样不可 lint。
- **$C_3$（运行时边界）**：$C_3(r) \equiv (r.\text{enforcement\_phase} = \text{Encoding})$，将"可在已签发字节中观测的义务"与"在链处理、名称比较、撤销处理或 CAA 获取等阶段才触发的义务"分开；
- **$C_4$（过程边界，取反）**：$C_4(r) \equiv (r.\text{rule\_category} \in N)$，其中 $N = \{\text{definition}, \text{capability}, \text{algorithm\_ref}, \text{display}, \dots\}$ 为承载术语定义、CA 能力声明、对外部算法规范的委派、UI 呈现等**不对证书编码施加静态检查**的类别集合；可 lint 要求 $r.\text{rule\_category} \notin N$，即 $\neg C_4$。$C_4$ 与 $C_2$ **正交**：$C_4$ 回答"这是哪一**类型**的义务"（定义？能力声明？编码约束？），$C_2$ 回答"裁决它需要**哪些数据**"（仅此一张证书，还是更多）——一条规则可以是编码约束（不在 $N$ 中，即 $\neg C_4$）却仍需访问签发者证书做密钥比对、或与配对的（预）证书逐字节比对（不通过 $C_2$）；这一正交性是 $C_2$ 不可被 $C_3$/$\neg C_4$ 替代的根据。

记 $\phi_C : r \mapsto \mathbb{1}[C_1 \wedge C_2 \wedge C_3 \wedge \neg C_4]$，则 $\mathcal{R}_L = \{r : \phi_C(r) = 1\}$ 即 $\phi_G$ 的定义域。obligation 同时固定严重级别（MUST 类 $\mapsto$ Error，SHOULD 类 $\mapsto$ Warning），故严重级别是对 obligation 的直接读取、而非第二个分类器。三个非道义条件刻画主体（含数据范围）、运行时、过程三条正交边界——其中 $C_2$ 把一类此前依赖人工审计的"静态可观测"边界（$\mathrm{StaticallyObservable}$）前移为提取阶段即确定的 IR 字段 $\mathrm{assertion\_subject}$。由于每个 $C_i$ 都是单一 IR 字段的确定性函数，$\mathrm{lintable}(r)$ 从 IR 计算而非 LLM 预测：同一 IR 每次给出逐位一致的标签；若标签不合预期，可直接检查参与判定的字段取值。

![](figures/fig8_lintability_gate.png)

_图 2：四条件可 lint 性判定的确定性流程。IR 字段先经过四个单字段布尔检查，再由最终合取门给出 lintable / not lintable。_

## 6. 受限代码生成与验证

使用大模型直接生成代码会面临两个问题。其一是**幻觉**。例如把字段名写成另一个恰好存在却语义无关的字段，或把 OID 写错一位。其二是**输出不稳定**。将同一条代码生成提示词输入给大模型，输出通常是不一样的。LLM输出的代码不一定可编译也不一定逻辑正确。本文在**语言设计层面**收紧 $\phi_G$ 的值域——把开放的 Go 代码空间换成一个有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，让 LLM 只能输出该空间内的一棵树，再由确定性函数把树转化为 Go代码。字段/OID 合法性与原子模板类型匹配由 DSL 类型系统在生成时静态保证。代码生成之后我们会通过语义对齐判单代码是否如实反应了原文的含义。

### 6.1 原子模板

原子模板是单证书静态检查的最小单元。PKI 的单证书合规检查大多是若干**原子模板**的逻辑组合——"某扩展是否存在"、"某字段是否等于某常量"、"某列表的每个元素是否匹配某模式"等原子模板，用"与 / 或 / 非"组合即可刻画大多数静态约束。代码 DSL 的抽象语法为：

$$
\mathcal{T} \;::=\; a(\bar{v}) \;\mid\; \neg\, \mathcal{T} \;\mid\; \mathcal{T} \wedge \mathcal{T} \;\mid\; \mathcal{T} \vee \mathcal{T}
\tag{1}
$$

其中 $a \in \mathcal{A}$ 为原子模板谓词，$\bar{v}$ 为其参数列表。$\mathcal{A}$ 是一个**有限闭合**的原子模板集合，共79个（按通用性分为 62 个 GENERIC 与 17 个 NON_GENERIC；分级判据与代表性示例见附录 C）；$\{\neg, \wedge, \vee\}$ 为命题逻辑组合子。一条 lint 规则的代码体建模为有序对 $(p, q) \in \mathcal{T}_\perp \times \mathcal{T}$，其中 $p \in \mathcal{T}_\perp = \mathcal{T} \cup \{\perp\}$ 为可选前提，$q \in \mathcal{T}$ 为主断言，执行语义为：

$$
\lVert (p, q) \rVert(c) \;=\; \begin{cases}
\mathrm{NA}, & p \neq \perp \;\land\; \lVert p \rVert(c) = \mathrm{false} \\
\mathrm{Pass}, & (p = \perp \;\lor\; \lVert p \rVert(c) = \mathrm{true}) \;\land\; \lVert q \rVert(c) = \mathrm{true} \\
\mathrm{Severity}(r), & \text{otherwise}
\end{cases}
\tag{2}
$$

直观地：前提 $p$ 是**规则前提**——当它存在且在 $c$ 上为假时返回 $\mathrm{NA}$（不适用）；前提缺失或成立且 $q$ 成立时返回 $\mathrm{Pass}$；前提成立而 $q$ 不成立则为违反，按义务返回 $\mathrm{Severity}(r)$。因 §5 的 $C_1$ 已排除 MAY/OPTIONAL，进入生成的义务必属 MUST 族或 SHOULD 族，即 $\mathrm{Severity}(r) \in \{\text{Error}, \text{Warn}\}$。显式区分 $\mathrm{NA}$ 与 $\mathrm{Pass}$ 并非冗余：PKI 大量要求是**条件式**（"WHEN $P$, THEN $Q$"），把适用前提建模为 $p$ 可避免"前提不满足却误判违反"，并使前提与断言在后续验证中分别检查。

### 6.2 类型化词汇表与参数封闭性

§6.1 限定了树的*结构*，却没约束原子模板的*参数*——参数若可任填，LLM 仍能写出引用虚构字段或 OID 的"结构合法"之树。本节用一张**类型化词汇表** $\mathcal{V}$ 封住这道缺口：$\mathcal{V}$ 是七类有限集合的不相交并、在系统启动时冻结，每个原子模板参数只能取自其中某一类——证书字段名、DN 字段、OID 常量、KeyUsage 位、ExtKeyUsage 位、ASN.1 编码类型、命名正则（各类规模与样例见附录 C）。

每个原子模板都有一张签名表，规定它每个参数该取自哪一类（或基础类型整数 / 布尔 / 字符串）；调用一个原子模板合法，当且仅当它的每个实参都落在签名规定的那类集合内。记 $\mathcal{T}_{\mathcal{V}}$ 为所有参数都合法的 DSL 树集合，本研究把代码生成模块 $\phi_G$ 的值域严格限定为它：任何落在 $\mathcal{T}_{\mathcal{V}}$ 内的树都不会出现 $\mathcal{V}$ 之外的字段名、OID 或正则；越界的树在解析阶段必然报错、触发修复，不会进入渲染。

### 6.3 渲染与可逆机械翻译

合法 DSL 树 $t$ 要转化成两种制品：可执行的 Go 检查代码，与一句与原文比对的摘要。承担二者的是两个 DSL 树空间上的**确定性全函数，而非 LLM 调用**，故不引入概率失真：渲染函数 $\rho$ 把树转成 Go 检查表达式，机械翻译函数 $\sigma_{\mathrm{mech}}$ 把同一棵树转成一句 PKI 摘要。两个函数共享三项性质，每项都对应验证链上的一个具体作用：

- **类型安全**：$\rho$ 不生成越界字段/OID/参数类型，封闭性从 DSL 树保持到 Go 层。
- **决定性**：$\rho(t)$、$\sigma_{\mathrm{mech}}(t)$ 对相同 $t$ 输出唯一——这使 §6.5 oracle 可把 $\rho(t)$ 当作 $t$ 的固定函数，执行行为不随运行或模型而变。
- **可逆性**：由 $\sigma_{\mathrm{mech}}(t)$ 可机械还原 $t$（同义原子模板映射同一短语时不可区分），故 $\sigma_{\mathrm{mech}}$ 保留 DSL 树结构信息（命题 2）。

两个函数由此**分工**：$\rho$ 通向执行/oracle 验证，$\sigma_{\mathrm{mech}}$ 通向同义性验证（摘要与 `Description` 比对是否语义等价）。同一棵树经两条独立确定性通路受检，是 §6.5 多重保障的结构基础。

### 6.4 IR 谓词到原子模板的映射与受限 LLM 树合成

**从 IR 谓词到原子模板的映射 $\mu$。** 上游 IR 与下游 DSL 用两套词汇：IR 以**抽取阶段的谓词**描述要求（如 `must_be_present`、`encode_as`、`in_range`），DSL 以**原子模板**表达检查，二者并非一一对应。为衔接两者，本研究维护一个多对多映射 $\mu$：给每个 IR 谓词指定一组语义上能承载它的候选原子模板。例如 `must_be_present` 可由 $\{\mathrm{ExtPresent}, \mathrm{FieldNonEmpty}\}$ 承载，`in_range` 可由 $\{\mathrm{IntInRange}, \mathrm{PathLenConstraintHas}, \dots\}$ 承载——取哪个取决于被约束字段的类型。

**用 IR 实例填充原子模板的参数槽。** 选定原子模板只定了"用哪个检查"，还需定"检查谁、比什么"——这些参数值正来自当前规则的 IR：IR 的 **subject**（字段解析器给出的证书字段路径，如 `subjectAltName.dNSName`）填入原子的字段槽，IR 的 **constraint**（约束值或模式，如取值集合、长度区间、正则名）填入值槽。例如规则"subjectAltName 的 dNSName 必须非空"经映射与填充后实例化为 $\mathrm{FieldNonEmpty}(\texttt{DNSNames})$。这与 §6.2 的封闭性互补、各管一层：$\mathcal{V}$ 约束参数的**合法类型**（字段名必须是已注册字段、不得编造），IR 提供参数的**具体取值**（这条规则实际约束的是哪个字段、什么值）。

下文给出 $\phi_G$ 的实现。生成器先尝试确定性合成，返回 $\bot$（不可归约或归约出的树无法编译）时才触发 LLM 合成；**两条路径都以"渲染并通过 `go build`"为接受门**——确定性返回一棵树并不算数，须真能编译，否则视同未解决、转入 LLM。两条路径都受同一套结构检查约束，且都不判定"代码是否忠实于规范"（这由 §6.5 的验证链负责），只把产出约束在可追溯的空间内。

**受限 LLM 合成。** 当确定性合成返回 $\perp$（不可归约）时，生成器转入 LLM 合成——模型拿到规则上下文、结构化 IR、由 $\mu$ 收窄的候选原子模板集，以及 $\mathcal{V}$、$\mathcal{A}$ 的可读枚举与签名表（实际提示的四区段拼接见附录 E），只输出两种结果之一：一棵序列化的 DSL 树，或一个显式的"无模板"弃权标记 $\perp_{\mathrm{NT}}$。后者当且仅当模型判断当前原子模板集与词汇表不足以表达该规则时返回，使该规则转入修复路径而非被勉强渲染成"形式合法但语义错位"的代码。无论走哪一支，凡进入渲染的树都落在 $\mathcal{T}_{\mathcal{V}}$ 内。

![](figures/fig6_restricted_codegen_factory.png)

_图 3：受限代码工厂。IR 经过 $\mu$ 和词汇封闭门进入 $\mathcal{T}_{\mathcal{V}}$，再由确定性渲染 $\rho$ 与机械翻译 $\sigma_{\mathrm{mech}}$ 输出 Go 代码和可逆摘要；只有 $\bot$ 分支才允许进入 LLM 合成。_

### 6.5 三层语义对齐验证

生成的代码是否如实表达了规范？这是全流程最难的判定。本节用由粗到精的三层验证回答它：层 A 看描述是否溯源、层 B 判代码行为是否与规范同义、层 C 查结构能否编译运行。

**层次 A：描述溯源。** 检查 `Description` 能否追溯到源文档。

**层次 B：代码行为摘要的语义对齐。** 这是核心层，把"代码是否实现规范"这一跨模态判定，归约为"两句自然语言是否同义"。做法是：由摘要函数 $\sigma$（系统持有 DSL 树时即其确定化实现 $\sigma_{\mathrm{mech}}$，见 §6.3 与附录 D）把代码翻译成一句"该代码检查什么约束"的摘要，再判它与 `Description` 是否同义、给出置信度 $c_{\mathrm{syn}}$。

**层次 C：编译与结构。** 验证代码可语法解析、函数与元数据字段齐全、依赖正确导入、规则注册完成，确保产物在目标框架内结构合法、可执行。

三层合取为一道布尔验收门（编译 ∧ 结构 ∧ 同义判定通过），层 B 同义判定 $c_{\mathrm{syn}}$ 是核心信号、层 A 溯源作前置快速过滤；任一层不通过即触发 §7 修复闭环。下面两道机制独立于这道门，进一步加固可认证子集。

**证书级语义 oracle（$\mathrm{Code}\equiv\mathrm{IR}$ 的执行级验证，独立于同义判定）。** 为每个原子模板造一对受控 fixture（谓词真/假，按原子模板类参数化、不绑定具体规则），令代码真执行、读回状态，两张都符期望即认证该原子模板。对持 DSL 树 $t$ 的自生成 lint：当 $t$ 仅由已认证原子模板构成且编译通过时，$\rho(t)$ 逐原子忠实，由结构归纳得 $\mathrm{Code}\equiv t$；又因 $t$ 忠实归约自 IR，故 $\mathrm{Code}\equiv\mathrm{IR}$。这是受控 fixture 上的执行级验证，确定、不随模型而变。**关键限定：$\mathrm{Code}\equiv\mathrm{IR}$ 不是规范同义性；最终仍以 $\mathrm{Code}\equiv\mathrm{Spec}$ 判定为准。**

**确定性实体级忠实性筛查（必要条件）。** 对仍走 LLM 判官的部分，再加一道无 LLM 的机械筛查 $\mathrm{Faithful}_{\mathrm{nec}}$：一条 lint 要忠实于规则 $r$，其检查的OID 常量与证书字段都应在 $r$ 文本中被提及——
$$
\mathrm{Faithful}_{\mathrm{nec}}(t, r) \;\Longleftrightarrow\; \forall\, e \in E_{\mathrm{prim}}(t):\ \mathrm{alias}(e) \cap \mathrm{tokens}\bigl(\mathrm{text}(r)\bigr) \neq \varnothing,
$$

其中 $\mathrm{alias}(\cdot)$ 是词干化加一张冻结的标准扩展别名表。判读分 $\mathtt{ENTITY\_OK}$ / $\mathtt{ENTITY\_MISMATCH}$（检查了文本未提及的实体，可疑）/ $\mathtt{NO\_ENTITY}$（不引用实体，不适用）三种。它只作为必要条件筛查；盲区（指代、别名缺口）只会保守地多报 $\mathtt{ENTITY\_MISMATCH}$。

### 6.6 合成算法与样本级局部修复

§6.5 验收门不通过时修复分两级。本小节是**较轻**的样本级局部修复：假定误差仍在该规则的字段或语法层，就地重修、不动全局 $\mathcal{V}$/$\mathcal{A}$/$\phi_C$（更重的管道级留 §7，仅在样本级耗尽后介入）。局部修复操作 $\rho_G^{\mathrm{loc}}$ 含两类子操作：

$$
\rho_G^{\mathrm{loc}}(t, c) \;=\; \begin{cases}
\Phi_{\mathrm{post}}(t, r), & \text{Description / Citation 偏差} \\
\phi_G\bigl(r,\; \mathrm{feedback}(\eta(s), \mathcal{V}, \mathcal{A})\bigr), & \eta(s) = \mathrm{Err} \;\text{或}\; \mathrm{compile}(\rho(t)) = 0
\end{cases}
\tag{3}
$$

第一支是**幂等闭式修复**——对可溯源字段一次性绑定规范原文即止；第二支是**类型反馈式重生成**——把解析错误（哪个原子模板签名不满足）或编译错误结构化注入提示、触发重合成。$K_{\mathrm{loc}}$（默认 3）轮内仍未通过验收门者移交 §7 管道级修复。

算法 1 把上述样本级修复嵌入循环；整个流程不依赖模板分类，只以 $(\mathcal{V}, \mathcal{A})$ 作为代码空间约束。

```
算法 1：DSL 受限合成与验证
输入：可执行规则 r ∈ R_L，词汇表 V，原子模板集 A，LLM 模型 M
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
13:             g ← Verify(code, r)                    // §6.5 三层布尔验收门
14:             if g = PASS then return code
15:             prompt ← prompt ⊕ feedback(g, σ_mech(t))
16: return FAIL("local_repair_exhausted", t)           // 进入 §7 管道级修复
```

算法 1 在 $K_{\mathrm{loc}}$ 轮内终止。区别于"空白重采样式启发式重试"，每轮重试都携带可定位的结构化诊断（类型/编译错误，或 $\sigma_{\mathrm{mech}}(t)$ 与同义反馈）；且在 $\eta$ 与 $\Phi_{\mathrm{post}}$ 的封闭性下，任何返回的代码都同时满足词汇封闭（$t \in \mathcal{T}_{\mathcal{V}}$）、通过编译、通过三层验收门——即"语义可追溯 + 结构可执行 + 类型受约束"。

## 7. 阶段感知式迭代验证框架（SAIV）

第 6 节的方法在单次前向生成下已能产出结构完整的 zlint 代码，但在大规模、无人工真值的场景下仍需显式质量控制。SAIV 不把单一同义率作为收敛标准，而是同时跟踪召回守恒、代码-规范同义性与双判定源一致性，把这些可直接计算的量作为残差信号；修复操作只有在残差下降时才被接受。这样，质量验证由可计算残差与外部证据共同支撑，而不是由人工真值逐条裁定。

### 7.1 形式化定义

受控规范-代码生成管道 $\Pi$ 是四个模块依次串联的复合函数——**提取 $\to$ 分类 $\to$ 生成 $\to$ 验证**：

$$
\Pi = \phi_V \circ \phi_G \circ \psi_C \circ \phi_R
$$

其中召回模块 $\phi_R$（RFC 2119 关键词驱动）找出候选规则，分类模块 $\psi_C$（§5 的四条件可 lint 性判定）筛出可执行规则，生成模块 $\phi_G$（受限于 §6 的 DSL 代码空间 $\mathcal{T}_{\mathcal{V}}$）合成检查代码，验证模块 $\phi_V$（§6 的三层语义对齐）把关。SAIV 根据这些模块产生的可计算信号选择下一轮修复操作。

### 7.2 三个迭代目标（优化标签）

SAIV 借鉴反向传播的思路：先定下整个流程要优化的目标，再根据可计算信号选择下一轮修复操作。本节先给出这三个目标，后续各节（残差、路由、算法）都围绕逼近它们展开。

每个目标都有一个能直接算出来的残差，分别盯住式 4' 切出来的一块规则子集；当三个残差同时为零，整个流程就算收敛。三个残差的形式各不相同：G1 是一个守恒等式、G2 是一个平均损失、G3 是一个违反计数。

- **G1（召回完整性）**：管规则集合是否封闭。由关键词召回的候选必被互斥划分为噪声 / 可执行 / 不可执行（式 4），可执行类再二分为已覆盖 / 未覆盖（式 4'）；任一下游模块的规则级增删都会破坏守恒。残差为召回守恒残差 $\mathcal{L}_{\mathrm{recall}}$，无需人工真值即可计算，当前已闭合（§8.2）。
- **G2（未覆盖规则的代码—规范同义）**：管生成的代码是否如实表达规范。盯未覆盖子集 $\mathcal{R}_L^{\mathrm{uncov}}$，要求代码摘要 $\sigma(\phi_G(r))$ 与规范原文同义（§6.5 传递链）。**同义性对全部 Form A 由层 B 判官判定**（$\mathrm{Code}\equiv\mathrm{Spec}$），证书级 oracle 的 $\mathrm{Code}\equiv\mathrm{IR}$ 是正交的确定性 soundness 信号、不计入同义分子。残差为代码忠实残差 $\mathcal{L}_{\mathrm{code}}$。自动生成的主要价值在补足生态空白，故未覆盖子集是 G2 最重要的观测域。
- **G3（已覆盖规则的反向可执行性）**：管本系统的可 lint 性判定与外部工具是否一致。盯已覆盖子集 $\mathcal{R}_L^{\mathrm{cov}}$，把"外部工具已静态实现某规则"作为它确实可执行的反向证据，二者一致要求违反计数 $N_{\mathrm{viol}}=0$（机制见 §7.5 验证修复）。

| 目标 | 残差 | 主要修复操作 | 修复对象 |
|---|---|---|---|
| G1 召回完整性 | $\mathcal{L}_{\mathrm{recall}}$（式 6） | —（结构不变量，已闭合） | 召回窗口 / 关键词集合（如需） |
| G2 同义性 | $\mathcal{L}_{\mathrm{code}}$（式 7） | $\rho_R$ / $\rho_G$ / $\rho_V$ | IR 内容修正 / DSL 树重合成 / 判定与摘要复核 |
| G3 双判定源一致 | $N_{\mathrm{viol}}$（§7.5） | $\rho_V$ | $\phi_C$ 假阴性 / 外部覆盖标签假阳性 |

三个残差同时为零时 SAIV 收敛。§8 的诚实快照表明 G1 已闭合、G2 未闭合——这正体现框架以可计算残差暴露未闭合处，而非以单一指标掩盖。

![](figures/fig7_saiv_control_console.png)

_图 4：SAIV 控制台。上排显示召回→分类→生成→验证四阶段，下排显示 G1 / G2 / G3 三个残差与对应修复路由；当残差同时低于阈值时终止。_

### 7.3 召回完整性不变量

**定理 1（召回完整性不变量）**。*若 $\phi_R$ 对由 RFC 2119 关键词触发正则匹配，则以下守恒关系成立：*
$$
|\mathcal{R}_{\mathrm{kw}}(\mathcal{D})| = |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U| \tag{4}
$$

式中$\mathcal{R}_N$为噪声、$\mathcal{R}_L$为lintable规则、$\mathcal{R}_U$为not lintable规则。可执行类 $\mathcal{R}_L$ 进一步按"是否已被现有外部 lint 工具实现"二分：

$$
|\mathcal{R}_L| = |\mathcal{R}_L^{\mathrm{cov}}| + |\mathcal{R}_L^{\mathrm{uncov}}| \tag{4'}
$$

其中 $\mathcal{R}_L^{\mathrm{cov}}$ 为已被某lint工具覆盖者、$\mathcal{R}_L^{\mathrm{uncov}}$ 为尚未覆盖者。第一式（式 4）是召回到分类的总量守恒，第二式（式 4'）则把可执行集拆开，以便后续目标分别落位：未覆盖子集 $\mathcal{R}_L^{\mathrm{uncov}}$ 是端到端生成"补生态空白"的最重要观测域（G2 同义性），已覆盖子集 $\mathcal{R}_L^{\mathrm{cov}}$ 则给出反向可执行性的外部证据（G3）。

### 7.4 代码正确性标签与损失函数

设 $r \in \mathcal{R}_L$，$c = \phi_G(r)$。由于 $c$ 的 `Description` 已由确定性后处理与规范原文对齐（§6.6），代码正确性标签 $\lambda_{\mathrm{code}}(r) \in [0,1]$ 由"编译 × 结构得分 × 同义置信度"之积度量；由 §6.5 的语义等价传递链，$\sigma(c)\equiv\mathrm{spec}(r)$ 且 `Description`$\equiv\mathrm{spec}(r)$ 即可推出 $c\equiv\mathrm{spec}(r)$。同义置信度 $c_{\mathrm{syn}}$ 一律由判官给出（$\mathrm{Code}\equiv\mathrm{Spec}$）；证书级 oracle 的 $\mathrm{Code}\equiv\mathrm{IR}$ 不替代该项，而是与之并置报告。

在此标签之上，SAIV 把三类质量信号形式化为可计算残差：**召回守恒残差** $\mathcal{L}_{\mathrm{recall}}$（式 6）以对称归一化度量定理 1 的理想恒等被违反的程度；**代码忠实残差** $\mathcal{L}_{\mathrm{code}}$（式 7）是可 lint 集上正确性标签的平均缺口；二者加权为**总损失** $\mathcal{L}_{\mathrm{total}}$（式 8，默认 $w_R=w_C=0.5$）。第三类是双判定源一致性残差 $N_{\mathrm{viol}}$（§7.5）。

### 7.5 阶段路由与修复操作

**阶段路由。** 每轮用可直接计算的量选择下一步修复操作：召回守恒残差、可 lint 集上的编译失败率、平均结构得分、实体必要条件筛查结果与同义置信度。该路由只决定下一轮尝试哪类修复。

**修复操作。** SAIV 包含 IR 内容修复、分类修复、生成修复与验证修复四类操作。路由器根据上述信号选择下一轮操作；修复仅在指标下降时接受。

- **IR 内容修复 $\rho_R$**：当路由器选择该操作时，把失败轨迹——当前 IR、不可归约类别、机械摘要、判官裁定与理由、同义置信度、本会话已试过的历史 IR——回传 LLM，要求其输出 `REPAIR(ir')` 或 `NO_FIX`。候选修复必须通过 g4-sanity 与后续指标下降门才接受。
- **分类修复**：引入多工具交叉证据——规则若在 zlint、pkilint、certlint、x509lint 中至少一个存在对应实现，则必然 lintable；若被判为 `non_lintable`，即视为假阴性回传分类器重判。
- **生成修复**：先试确定性修复（如 `Description`/`Citation` 字面替换）；失败则把失败码片段与 IR 约束差异、或解析阶段的原子模板签名/封闭性错误作为反馈注入提示、触发 LLM 在 $\mathcal{T}_{\mathcal{V}}$ 内重新合成；若持续弃权，则进入离线词汇扩展通道 $\rho_A$。
- **验证修复**：扩大同义判定的语义邻域（如允许否定/肯定互换、一对多分解），或修正双判定源输出之间的不一致（即下文的 G3 残差修复）。

**G3 残差的双向修复（验证修复的特化）。** §7.5 的分类修复只用了"外部工具实现某规则 $\Rightarrow$ 该规则可执行"这条单向推论；这里把它扩成一个双向、可证伪的残差。给定外部工具覆盖判定 $\mathrm{cov}_{\mathcal{T}} : r \mapsto \{\text{full}, \text{partial}, \text{none}\}$，定义违反集

$$
\mathcal{V} = \{\, r : \mathrm{cov}_{\mathcal{T}}(r) \in \{\text{full}, \text{partial}\} \;\land\; \psi_C(r) \neq \mathrm{lintable} \,\}, \qquad N_{\mathrm{viol}} = |\mathcal{V}|.
$$

即"外部工具说能做、本系统却判不可 lint"的规则。当本系统分类 $\psi_C$ 与外部覆盖 $\mathrm{cov}_{\mathcal{T}}$ 都正确时 $N_{\mathrm{viol}}=0$，故该残差不依赖人工真值。对每条违反，调用一个二元仲裁判官给出两支之一：**翻转**（本系统判错、把该规则改判为 lintable）或**判伪**（外部覆盖是假阳、把它降级为 none）。命题 3 表明：只要每条违反都被判为这两支之一并被采纳，则一轮过后 $\mathcal{V}$ 收缩至空、$N_{\mathrm{viol}}=0$。它只修两个判定源之间的不一致、不动代码或生成模块，故使该残差具备真正的"零点"、可作收敛判据。

### 7.6 迭代算法与终止条件

算法 2 给出完整流程。

```
算法 2：阶段感知式迭代验证（SAIV），自动闸门负责回路内验收
输入：标准文档 D，阈值 θ，最大迭代数 K
输出：最终代码集 C* 与终止状态 status

 1:  R_kw ← φ_R(D);  (R_N, R_L, R_U) ← ψ_C(R_kw)
 2:  C ← {φ_G(r) : r ∈ R_L}
 3:  t ← 0
 4:  repeat
 5:      计算残差 L_recall(6), L_code(7), N_viol(§7.6)
 6:      if 全部残差 < θ then break                       // 多目标同时闭合
 7:      stage ← StageAttribution(...)                    // 式(9)
 8:      if stage = φ_R then                              // IR 内容修复
 9:          for each r routed to ρ_R do
10:              rep ← ρ_R(失败轨迹(r))                    // 自反思，返 REPAIR(ir') 或 NO_FIX
11:              if rep = NO_FIX  or  g4_sanity(rep.ir', text(r)) ≠ ∅ then
12:                  r → R^irred_code                     // 自动闸门否决 ⇒ 诚实留残差
13:              else if 重测(rep.ir') 通过（归约∧认证∧编译∧忠实）then
14:                  IR(r) ← rep.ir'                      // 接受修复
15:      else apply ρ_{stage}∈{ρ_C, ρ_G, ρ_V}             // 并列，按路由分支触发
16:      更新 (R_kw, R_N, R_L, R_U) 与 C
17:      t ← t + 1
18: until t ≥ K 或 本轮无任何残差下降（loop-until-dry）
19: return (C, status ∈ {closed, dry, budget_exhausted})
```

第 8–14 行即 $\rho_R$ 回路：第 11 行的 g4-sanity 是确定性闸门，负责回路内的机械验收；既未被否决又通过下游重测者才接受，其余诚实落入 $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$。这不替代 §8.3 对最终发射集的去噪多数同义判定。

**终止条件**：$\mathcal{L}_{\mathrm{total}}<\theta$（默认 0.05）、达最大迭代 $K=10$、或本轮无残差下降。若每个被采纳的阶段修复操作都单调（减少该阶段误差或不变），则 $\mathcal{L}_{\mathrm{total}}$ 每轮非递增；实际系统用"无下降即停止"策略，故保证有限轮终止，但不保证全局最优（见 §8）。

## 8. 实验评估

本章使用前文提到的方法和框架进行实验，并得出量化结论。除内部分层指标（§8.1–8.3）外，本章给出**两道相互独立的外部验证**，分别检验框架的两个半段：§8.4 以 zlint 维护者的人工金标外部验证**规则提取与可 lint 性判定**（前半段），§8.5 以真证书上的执行外部验证**代码生成与同义判定**（后半段）。

### 8.1 实验设置与结果快照

评测在 RFC 5280与 CABF BR两个标准源的全库重抽结果上进行。NL→IR 抽取器为gpt-5.4。

**表 1：端到端结果当前快照（standard_id ∈ {1, 19}，RFC 5280 + CABF BR）**

| 指标 | 数 | 口径/说明 |
|---|---:|---|
| 召回规则总量 | 2077 | RFC 5280 637 + CABF BR 1440 |
| **可 lint（单证书可观测）** | **336** | 经硬化分类器：负向门排除过程/跨证书/runtime/语义类，并对 13 条误标可 lint 的规则（跨证书/线下验证/外部语义/MAY 许可）修正标签；CRL 文档规则不在本口径 |
| zlint 覆盖（full，已有同源 lint） | **132** | 该规则已被某条同源 zlint lint 实现 |
| **未覆盖可 lint（codegen 定义域）** | **204** | 需本系统生成自有 lint（336 − 132），即下游代码生成 $\phi_G$ 的目标集 |
| **能生成可编译 lint（Form A）** | **175** | 确定性路 137 + LLM 兜底路 38，两路均以"渲染并 `go build` 通过"为接受门；**代码生成率 = 175/204 = 85.8%** |
| 不能生成（无树 / 不编译 / 弃权） | **29** | 确定性归约不出或归约树不编译、LLM 亦弃权或不编译 |
| **同义表达（去噪 5 票 LLM 判官，$\mathrm{Code}\equiv\mathrm{Spec}$）** | **113** | 在 175 条 Form A 中判 EXPRESSES（确定性树 105/137、LLM 树 8/38）；**同义率 = 113/175 = 64.6%** |
| 不同义（DNE） | **62** | 详见下文 |
| *（旁证）证书级 oracle $\mathrm{Code}\equiv\mathrm{IR}$* | *124* | *确定性 soundness、非同义；其中 36 条判官判 DNE，说明 Code≡IR 不能替代 Code≡Spec（§8.3）* |

表 1 同时给出不可生成可编译 lint（29 条）与不同义（62 条）的数量。尤其，36 条经证书级 oracle 证得 $\mathrm{Code}\equiv\mathrm{IR}$ 却被判官判 $\mathrm{Code}\not\equiv\mathrm{Spec}$ 的规则，说明"忠实生成给定 IR"与"忠实表达规范"是两个不同问题。本文仅报告这一分歧；这些残差不是可 lint 性定义本身的反例。

第一层质量信号是 G1 守恒（§7.3 定理 1）：关键词召回的规则总量，在下游任何分类步骤中都不应增减。当前快照下守恒严格成立：

$$
\underbrace{2077}_{\text{召回}} \;=\; \underbrace{522}_{\text{噪声}} + \underbrace{1555}_{\text{真规则}}, \qquad \underbrace{1555}_{\text{真规则}} \;=\; \underbrace{336}_{\text{可 lint}} + \underbrace{1219}_{\text{不可 lint}}.
$$

两式逐项相等，即 G1 残差 $\mathcal{L}_{\mathrm{recall}} = 0$、守恒顶两层闭合（数据见 §8.1，可确定性复算）。可 lint 的 336 条按标准源分为 CABF 227 条与 RFC 5280 109 条；其中 zlint 已完整覆盖 132 条，余 **204 条**即下游代码生成 $\phi_G$ 的定义域。

### 8.2 lint 覆盖分析

要回答"现有工具覆盖了多少可 lint 规则"，关键在于用对判据。本文以"该可 lint 规则是否被某条同源 zlint lint 真正实现"为判据：对每条规则检索候选 zlint lint，再逐字段（subject / obligation / predicate / constraint）比对，给出 full（完整实现）/ partial（部分实现）/ none（无实现）三档裁定——这比仅看"规则所在 section 是否被某条 zlint 引用"更严格（后者会把同节内的不同需求误计为覆盖）。

算法 3 形式化该判定：沿用"把 lint 摘要为反向 IR、再逐字段对齐"的骨架，相对早期版本（嵌入向量 top-K 检索 + 单层判官）作三处确定性修订——候选检索按 source/section（Stage-1，不用嵌入：RFC 章节号稳定、按前缀收窄，CABF 章节随版本漂移、故取全部 CABF lint）、新增"错字段"一致性闸门（Stage-3，只降不升）、覆盖只计 full（Stage-4，partial/none 归 $\phi_G$）；判定按**规则索引**（早期版本按 lint 索引、报"被匹配的 lint 占比"）。其中一致性闸门是放心对 CABF 取全集候选的前提：判官的 align/differ 自标不可靠（曾把 keyUsage 规则误判覆盖于 SAN lint），故改由规则与所匹配 lint 的**主语族**做确定性比对。

```
算法 3：可 lint 规则的 zlint 覆盖对齐判定（规则索引）
输入：可 lint 规则集 B = {b_1,…,b_m}（每条带 IR 四元组 ⟨主体, 义务, 谓词, 约束⟩、source、section）；
      zlint lint 集 L = {ℓ_1,…,ℓ_n}（每条带 description/citation/severity 元数据与 Pass/Error 测试）；
      离线代码摘要器 M_summ、字段级判官 M_judge（temperature=0）
输出：每条规则的覆盖档 verdict(b) ∈ {full, partial, none}，覆盖集 covered 与代码生成定义域 φ_G

 1:  // Stage-0（离线、缓存，与早期版本共用）：把每条 lint 摘要为反向 IR
 2:  for each ℓ ∈ L do
 3:      ℓ.ir ← M_summ(ℓ.src, ℓ.tests, ℓ.meta)        // ⟨主体,义务,谓词,约束⟩ + code_summary
 4:  按 Source 预切候选池：L_RFC ← RFC lint，L_CABF ← CABF lint
 5:  for each b ∈ B do
 6:      // Stage-1：确定性候选检索
 7:      if b.source = RFC then
 8:          C(b) ← { ℓ ∈ L_RFC : SectionPrefixMatch(b.section, ℓ.citedSections) }  // RFC 章节号稳定
 9:      else if b.source = CABF then
10:          C(b) ← L_CABF                             // CABF 章节随版本漂移 ⇒ 取全集
11:      else  C(b) ← ∅
12:      // Stage-2：字段级判官，逐字段比对四元组，跨候选取最优档
13:      (v, ℓ*) ← M_judge(b.ir, C(b))                 // v ∈ {full, partial, none}，按 full > partial > none
14:      // Stage-3：确定性"错字段"一致性闸门（只降不升）
15:      if v ∈ {full, partial} ∧ Family(b.subject) ≠ ∅ ∧ Family(ℓ*.subject) ≠ ∅
16:         ∧ Family(b.subject) ≠ Family(ℓ*.subject) then
17:          v ← none                                  // 主语族具体且不同 ⇒ 错字段假阳，降级
18:      verdict(b) ← v
19:  // Stage-4：确定性聚合，覆盖只计 full
20:  covered ← { b ∈ B : verdict(b) = full } ;  φ_G ← B \ covered
21:  return ({(b, verdict(b)) : b ∈ B}, covered, φ_G)
```

其中 SectionPrefixMatch 在规则章节号与某 lint 引用章节号有公共前缀时为真；Family(·) 把主体路径映射到具体字段族，对模糊/未解析主体返回 ∅ 而不降级（粗主语的真匹配得以保留）。算法仅 Stage-0、Stage-2 调用 LLM（判官 temperature=0，提示含方向反转/字段错位/约束类型混淆三类正反例），摘要离线缓存、CABF 全集候选分批送判官（命中 full 即止），其余确定性，故覆盖数可在固定摘要快照上确定性复算。

336 条可 lint 规则中，**zlint 完整覆盖 132 条、未覆盖 204 条**（表 2）；未覆盖的 204 条即代码生成 $\phi_G$ 的定义域。

**表 2：zlint 同源 lint 数，及其对 336 条可 lint 规则的覆盖（按标准源）**

| 项 | CABF | RFC 5280 | 合计 |
|---|---:|---:|---:|
| *zlint 同源 lint 总数（参照）* | *170* | *122* | *292* |
| *　— 其中证书 lint（单证书口径）* | *164* | *115* | *279* |
| *　— 其中 CRL lint（单证书口径外）* | *6* | *7* | *13* |
| full（完整覆盖） | 79 | 53 | **132** |
| 未覆盖（codegen 定义域） | 148 | 56 | **204** |
| 可 lint 合计 | 227 | 109 | **336** |

前三行（斜体）为 zlint 侧按其 `Source` 元数据字段从项目内置 v3 源码直接计得的 lint 数（单位：lint，13 条 CRL lint 经 `RegisterRevocationListLint` 识别、不属本文单证书口径）；其余各行为我方可 lint 规则的覆盖档（单位：规则）。full 计的是"我方某条规则是否被某条同源 zlint lint 完整实现"，与 zlint lint 总数不构成简单比值（一条 lint 可命中多条规则、反之亦然）。结构性成因见附录 E。

### 8.3 代码生成分层与同义发射（主要结果）

一条可 lint 规则能否被写成同义 lint，按口径分层报告（完整漏斗见 §8.1 表 1）：codegen 定义域 = **204 条**未覆盖目标；生成器以"确定性优先、LLM 兜底"两路合成，两路均须渲染并通过 `go build` 才计入——**能生成可编译 lint（Form A）175 条（确定性 137 + LLM 38），代码生成率 175/204 = 85.8%**；其上由去噪 5 票 LLM 判官判 $\mathrm{Code}\equiv\mathrm{Spec}$，得 EXPRESSES **113 条**，**同义率 = 113/175 = 64.6%**（分母为能生成可编译 lint 者）。两路的同义率分别为：确定性树 105/137 = 76.6%，LLM 兜底树 8/38 = 21.1%。独立地，证书级 oracle 对 124/175 条证得 $\mathrm{Code}\equiv\mathrm{IR}$（确定性 soundness，非同义）；其中 36 条判官判不同义，说明 oracle 只能证明生成代码忠实于给定 IR，不能替代最终规范同义判定。

同义率全程由判官按 $\mathrm{Code}\equiv\mathrm{Spec}$ 判定（去噪 5 票多数表决以抑制单票方差），不因 oracle 认证而短路——这是相较"把 $\mathrm{Code}\equiv\mathrm{IR}$ 当作同义"更保守的口径。判官信号上的方法学加固（reducer 极性修复、obligation-aware 渲染、profile-scope 判定、定向重抽）见上文。最终同义率为 64.6%；确定性树同义率为 76.6%，LLM 兜底树为 21.1%。

### 8.4 lintability外部验证：检验规则提取与可 lint 性判定

本框架的前半段——规则提取与可 lint 性判定——需要用独立外部资料对照。为此我们引入 zlint 维护者公开的 CABF BR 映射表 [26]：该表由 zlint 专家逐条人工标注"某条 BR 要求是否可被静态 lint 表达"，与本文的提取器、IR、可 lint 性判定器互不知情。表中每一个 Yes/No 标签，正对应本文对同一条规则的"提取出该规则 + 判定其可 lint"这一联合输出；二者一致即表明本系统的规则提取与可 lint 性判定与人类专家相符。表覆盖 BR 1.4.8 和 BR 2.0.2 两个版本，分别与本文按相同双层流水线提取的 CABF-Server-1.4.8 后端（422 条）、CABF-Server-2.0.2 后端 [27]（1024 条）进行同版本对照。

**TABLE III：BR 1.4.8 / BR 2.0.2 同版本外部验证**

| 版本         | Sheet 行数 (Yes / No) | 后端规则数 | **召回率** | TP / FN / FP / TN | 一致率 | **Cohen's κ** |    精确率 |        F1 |
| ------------ | --------------------: | ---------: | ---------: | :---------------: | -----: | ------------: | --------: | --------: |
| **BR 1.4.8** |         122 (75 / 47) |        422 |  **86.9%** |  60 / 9 / 0 / 37  |  91.5% |     **0.823** | **1.000** | **0.930** |
| **BR 2.0.2** |        250 (17 / 233) |       1024 |  **86.8%** |  6 / 6 / 1 / 204  |  96.8% |         0.616 |     0.857 |     0.632 |

两版的匹配率几乎一致（86.9% vs 86.8%），但 κ 差异显著。BR 2.0.2 一致率高至 96.8% 是因为该 sheet 的 Yes-标签仅占 6.8%（17/250），朴素 all-No 基线一致率即达 93.2%；κ 在校正这种类别不平衡后给出更真实的判别力评估。BR 1.4.8 sheet 的 Yes/No 分布更均衡（75/47），κ=0.823 更直接地反映了 CICAS 与外部金标的实际一致性。两版上 Yes-precision 均高（≥0.86），Yes-class F1 在更均衡分布下达 0.930。

**这一外部验证检验的是系统前半段。** κ=0.823 与 86.9% 的召回率说明：本文的规则提取（从 422/1024 条后端中识别出哪些是真规范要求）与可 lint 性判定（四条件合取，§5）与 zlint 专家的独立人工判断高度一致。它并不检验下游的代码生成与同义性；后者由 §8.5 的证书检测在真证书上补充检查。

### 8.5 证书检测：在真证书上检验代码生成与同义判定

§8.4 的外部验证只触及流水线前半段；后半段——**代码生成是否产出了正确的检查逻辑、同义判官判出的 $\mathrm{Code}\equiv\mathrm{Spec}$ 是否当真成立**——还需要在**真证书**上检查。理由是：同义判官比对的是 code_summary 与规范文本（§8.3、§9.5(vi)），它判"同义"只意味着两段自然语言读起来等价，并不保证编译出的 lint 在真实证书字节上确实按规范意图触发或放行。证书检测把通过同义门的 lint 注入真 zlint 二进制、跑过真证书语料，用证书上的实际行为检验代码生成与同义判定；一条 `cicasgen_` lint 命中一张证书后，必须经独立结构审计确认其断言的具体结构条件，无法确认或被反驳的命中不计入有效发现。

**装置。** 把同义门通过的 lint 经 in-tree emitter 注入 `zlint/v3/lints/{rfc,cabf_br}` 并 `go build` 出携带这些 lint 的真二进制（机制在后端 `codegen/detection/`，由 `scripts/system_metrics/inject_and_build.py` 驱动；注入门 = 同义 EXPRESSES ∧ σ_mech 不漂移）。语料用 zlint 自带 testdata（1325 PEM，1128 可解析；为对抗样本而非真实流行度）。triage 用两路无 LLM 的 oracle：**upstream 共识**（同一次扫描里是否有 upstream zlint lint 也报这张证书）与 **testdata 意图**（解析 zlint 自己的 `*_test.go`，该证书是 known-bad 还是 positive fixture）；二者皆无信号且发射率低于过严阈值（0.30，同 `atom_oracle.sentinel`）的判 UNCERTAIN，再由 `openssl` 反查结构逐条复核。

**triage 的局限与独立审计（关键）。** triage 的 REAL 判定回答的是一个**较弱**的问题："这张证书是否（对某条 lint）有缺陷"——upstream 共识或 known-bad fixture 都只证明证书整体有问题，**并不证明我们这一条命中所断言的具体缺陷确实存在**。一条丢了前提条件、或代码绑错字段的 lint 可能命中一张因**无关**原因而有缺陷的证书，并被当作 REAL 放过。为堵住这个洞，我们对**每一条**命中（不止 UNCERTAIN）追加一道**独立结构审计**（后端 `codegen/detection/independent_verify.py`）：用 `openssl` 文本 + 原始 DER（对 testdata 的故意畸形样本鲁棒）逐条重新判定该 lint 所断言的**具体结构条件**是否真的出现在证书里，给出 CONFIRMED / REFUTED，完全不依赖 triage；`run.py` 把它设为强制断言门——任一命中被 REFUTED、或审计无法独立判定（NOCHECK）都使实验失败。审计本身又经**三套独立解析器交叉验证**（openssl / Python `cryptography` / `pyasn1` 原始 ASN.1），并以**负对照**（强行装回被隔离的 known-bad lint，要求审计 REFUTE 之）证其有判别力而非橡皮图章。

**结果（表 IV）。** 扫描 1128 证书，按有效发现口径得到 **72** 条 `cicasgen_` 命中。

**TABLE IV：证书检测 SAIV 门（31 lint / 1128 testdata 证书）**

| triage 判定 | 数 | 反查后 |
|---|---:|---|
| REAL（upstream 共识 / known-bad fixture） | 71 | — |
| **SPURIOUS（假阳）** | **0** | — |
| UNCERTAIN（无 oracle 信号、窄发射） | 1 | 1 条经 `openssl` 反查 **CONFIRMED_REAL** |
| **合计** | **72** | **72/72 经独立结构审计确认** |
| *独立结构审计* | | *72/72 CONFIRMED，0 REFUTED/NOCHECK；每条均由 ≥2 套独立解析器一致确认* |

**这一证书级验证检验的是系统后半段。** 72/72 命中全部经三套独立解析器证实其断言的结构条件真实存在于证书中、0 条 REFUTED；负对照（强行装回被隔离的 known-bad lint 要求审计 REFUTE 之）表明该审计门有判别力。该结果说明，在本测试语料触发的有效命中上，发射 lint 的具体结构断言与证书字节一致。

**OV+givenName 检测（2 条，真实信号）：** `illegalChar.pem` 与 `legalChar.pem` 上的 `cicasgen_when_oid_policy_organization_validated_list_contains_29475`——OV 证书（策略 `2.23.140.1.2.2`）携带 `givenName`（CABF BR 7.1.2.7.4 禁止），upstream zlint 无针对 OV 证书 `givenName` 的独立 lint（zlint 的 `e_sub_cert_given_name_surname_contains_correct_policy` 要求 IV 证书中 `givenName` 与 `surname` 共存时必须包含对应 policy OID，但不覆盖 OV 场景）。该检测只依赖证书策略 OID 与 subject 中 `givenName` 两个结构条件。

**Root CA CRLDP 警告（1 条，Warn/advisory）：** `rootCAWithEKU.pem` 上的 `cicasgen_when_root_ca_not_crl_dist_present_29288`——自签 CA/root CA 证书携带 CRL Distribution Points 扩展，而 CABF BR 7.1.2.11.2 对 Root CA Certificates 的 profile 约束是 CRL Distribution Points extension **SHOULD NOT** be present。该 lint 因此返回 `Warn` 而非 `Error`；独立结构审计确认该证书确为 root CA 且存在 CRLDP。upstream zlint 无针对"Root CA 不应含 CRLDP"这一 advisory 约束的等价原生 lint，但这属于 profile hygiene 警告，不是路径验证或密钥安全缺陷。

**严重性口径。** 72 条经确认的命中首先证明的是**结构真实性**：生成 lint 断言的证书结构条件确实存在；它不等价于 72 个同等严重的问题，也不等价于 72 个均为 upstream zlint 覆盖缺口。本文按三个层次解释严重性：规范强度（MUST/MUST NOT 相对 SHOULD/RECOMMENDED）、证书角色与适用 profile（订户/CA/root/OCSP、OV/IV/EV 等），以及安全后果是直接影响路径验证/密钥用途/名称约束，还是主要影响签发 profile、身份语义和 CA 运营合规。按该口径，OV+givenName 属于合规上严重、直接密码学安全后果间接的问题；Root CA CRLDP 属于低一档的 Warn 级 profile 警告。更完整讨论见 §9.4。

为避免把不同问题压成单一严重度，本文按下列矩阵解释证书级发现。

| 评价维度 | 提高严重性的信号 | 本文当前可直接支持的落点 |
|---|---|---|
| 规范强度 | MUST/MUST NOT，且应映射为 `lint.Error` | OV+givenName 为 Error 级禁止性约束；Root CA CRLDP 为 SHOULD NOT/Warn，严重性低一档 |
| 适用对象 | 受信任证书类型中的强制 profile 字段 | OV+givenName 发生在订户 OV 证书 profile 中；Root CA CRLDP 发生在 root CA profile 中 |
| 直接验证影响 | 改变路径构造、名称约束、密钥用途或签名算法语义 | 两类点名发现均不直接改变路径验证或密钥安全 |
| 身份/profile 影响 | 混淆 EV/OV/IV/DV 等证书身份语义或暴露签发模板错误 | OV+givenName 属于身份 profile 边界错误；Root CA CRLDP 属于 root profile hygiene 警告 |
| 实验证据边界 | 可在真证书字节上复核，且不依赖 LLM 判定 | 两张 OV 证书与一张 root CA 证书经结构审计确认；不支持现实生态发生率估计 |

## 9. 讨论

### 9.1 跨 PKI 的适用性

本框架的核心机制并不特定于 PKI：Layer 1 的 RFC 2119 关键词集可经配置替换为其他生态的道义关键词（如 ISO 的 shall/should/may）。方法适用于同时满足三条件的规范源：**(1)** 以可识别的形式化道义关键词表达强制/推荐；**(2)** 约束目标是结构化、可机器解析的产物（证书、协议消息、配置文件）；**(3)** 具备支持知识图谱与作用域继承的层级化章节结构。这使其方法学价值超出 PKI 单一领域。

### 9.2 对规范作者与工具维护者的建议

对**规范作者**，三条起草原则可降低提取歧义：单句单义务、以 ASN.1 路径而非代词精确引用字段、用固定模式规范化跨文档引用。对 **lint 维护者**，建议把 `description` 直接写成显式给出字段路径/断言类型/取值/严重级别并引用规范条款的 code_summary——本研究发现大量 lint 描述既非规范引用、也非实现忠实摘要，致使覆盖分析必须先做一步 code_summary 才能对齐，徒增开销与裁决噪声。

### 9.3 跨标准覆盖与 source 分区

覆盖分析还暴露出一个口径问题：发射集 31 条 lint 中有 **9 条**，其规范原文出自 CABF BR、却已被 zlint 中既有的 **RFC 5280** lint 实现。逐条核对 zlint v3 源码确认如下。

| CABF BR 规则（生成 lint 来源） | 条数 | 实现它的 zlint lint（原生 source/citation） |
|---|---:|---|
| `issuerUniqueID` / `subjectUniqueID` MUST NOT be present（7.1.2.1/2/8） | 6 | `e_cert_contains_unique_identifier`（RFC 5280:4.1.2.8） |
| `signatureAlgorithm` byte-for-byte 匹配 `tbsCertificate.signature`（7.1.2.2） | 1 | `e_cert_sig_alg_not_match_tbs_sig_alg`（RFC 5280:4.1.1.2） |
| 订户/OCSP 证书 `pathLenConstraint` MUST NOT be present（7.1.2.7.8/8.4） | 2 | `e_path_len_constraint_improperly_included`（RFC 5280:4.2.1.9） |

成因是合规口径的跨标准继承：CABF BR §7.1.2 开篇声明其证书 profile "incorporate, and are derived from RFC 5280"，且 RFC 5280 施加的规范性要求同样适用。uniqueID 禁止、signatureAlgorithm 一致、pathLenConstraint 限制等本是 RFC 5280 要求，被 CABF BR 以 profile 表格形式再次列明。zlint 据 RFC 5280 实现了对应 lint（其 `Source` 字段为 `RFC5280`），但 §8.2 的覆盖判定按规则 source 缩小候选；CABF BR 规则只与 CABF-BR source 的 lint 比对，从不进入 RFC 5280 lint 的候选池，于是这 9 条被判 none、误入 codegen 定义域并最终发射。须强调：被漏判的是"覆盖它的 lint 的 source"（RFC 5280），而非"生成 lint 的 source"；后者仍是 CABF BR（发射集 31 条的 `manifest_source` 全为 CABF-BR）。

### 9.4 新增 lint 发现的严重性

新增 lint 的发现不能只按命中数解释。本文采用三层口径：**结构真实性**（证书字节是否真的含有该结构条件）、**规范严重性**（MUST/MUST NOT 与 SHOULD/RECOMMENDED、证书角色和适用 profile）、**安全后果**（是否直接影响路径验证、密钥用途或名称约束，还是主要影响签发 profile、身份语义和 CA 运营合规）。§8.5 的 72/72 只证明第一层；严重性判断必须落到具体规则。

在当前可由证书级实验直接支持的新增覆盖缺口中，最明确的是 **OV+givenName**。它违反的是 CABF BR 7.1.2.7.4 的 OV profile 禁止性约束，适用于订户 OV 证书；因此在 lint/CA 合规语境下应视为 Error 级的签发 profile 违规，预签发 lint 有实际价值。其风险不是私钥泄露或路径验证绕过，而是身份 profile 边界被打破：OV 证书面向组织身份，`givenName` 属于自然人身份属性，错误混入会削弱证书 profile 的可解释性，并暴露 CA 模板或验证流程没有按 OV/IV/EV 分离。对依赖 subject 字段做自动分类、审计或合规报表的下游系统，这类 profile 违规也可能产生误导。因此本文将其定位为**合规严重、直接密码学安全后果间接**的问题；它低于密钥用途、名称约束、路径长度等会直接改变验证语义的缺陷，但并非表面格式问题。

相比之下，Root CA CRLDP 是 **Warn/advisory** 级 profile hygiene 问题：它说明生成 lint 也覆盖到 SHOULD NOT 类约束，并在真证书上发现 root CA profile 与建议性要求不一致；但其规范强度低于 OV+givenName，也不应被表述为严重安全漏洞。

其余命中应谨慎解释：zlint testdata 是对抗/回归语料，不是 Web PKI 流行度样本，故 72 条不支持现实生态发生率估计；且 §9.3 表明，部分由 CABF BR 文本生成的 lint 实际已被 RFC 5280 原生 lint 覆盖。本文因此不把所有命中都宣称为新的严重漏洞，而把实验证据限定为两点：**(1)** 生成 lint 在真证书上触发时，其结构断言经独立审计为真；**(2)** 至少 OV+givenName 这一类 BR 禁止性 profile 约束是 upstream zlint 缺少直接覆盖、且具备现实合规意义的新增问题；Root CA CRLDP 则是低一档但同样可复核的 Warn 级 advisory 覆盖缺口。

### 9.5 局限性与有效性威胁

本文结论严格受限于所用输入表示（结构化 IR）、受限代码空间与验证流程，更适合可在单文档上下文闭合的静态约束，不应外推为"所有 PKI 规范均可完全自动化"。七类边界：**(i) 方法表达力**——同义判定端点仍由 LLM 实现，79 原子模板对字节级编码、宿主未暴露字段、动态约束等仍有缺口；**(ii) 组件必要性未消融**——知识图谱/受限 DSL/SAIV 的支持分别为工程取舍、架构论证与未消融项，本文不主张图检索相对普通 RAG 的量化优越性；**(iii) 现代 LLM 基线缺位**——直接生成 Go 的对比未做，但证书级 oracle 生成器无关，使其成为定义明确的未来工作；**(iv) 覆盖与泛化边界**——可 lint 总量 336 与 codegen 目标 204 不同口径，跨体系泛化本文仅给机制论证；**(v) 端到端口径**——"代码≡规范"仅对发射集成立（§8.3），可 lint 标签未对全部 336 条穷尽人工审计；**(vi) 同义端点盲区**——code_summary≡规范 是比对 code_summary 与原文的 LLM 判官、非 oracle 那种与模型无关的检查，且其"原文"取自抽取时逐字存下的 rule_text（IR 内字段）而非重读规范源；因此若原始片段或 IR 已经遗漏语义，同义判官未必能独立发现。**(vii) 覆盖判定按 source 分区候选**——§8.2 对 CABF BR 规则只检索 CABF-BR source 的 zlint lint，切断了跨标准继承的覆盖关系：至少 9 条出自 CABF BR、实由 zlint 既有 RFC 5280 lint 实现的规则因此被误判为未覆盖、误入 codegen 定义域（§9.3）。这低估了既有工具的真实覆盖、并使覆盖缺口数偏大。此外生成 lint 以 `cicasgen_*` 前缀与 zlint 两端互拒以防"自己覆盖自己"。

## 10. 结论

本研究面向 PKI"规范-到-合规检查代码"的端到端自动化，给出贯通"提取 → IR → 可 lint 性判定 → 代码生成 → 验证"的统一框架。实证支持四点结论与一项方法学论断。其一，Web PKI 规范与现有 lint 工具存在显著覆盖缺口：336 条可 lint 中 zlint 完整覆盖 132，余 204 是自动生成的直接目标。其二，本系统把 LLM 限为 schema 受限解析器，并以确定性检索与确定性可 lint 性判定包裹。其三，真规则中仅约 22%（1555 中 336）可还原为单证书静态 lint，这是对"哪些规范可被静态强制"的量化回答。其四（负向发现）：即使生成代码可编译且部分样本满足 $\mathrm{Code}\equiv\mathrm{IR}$，最终 $\mathrm{Code}\equiv\mathrm{Spec}$ 仍存在明显同义残差，不能用 IR 级 soundness 替代规范级同义性。方法学论断：验证链路每个环节都应尽可能确定化（最有力实例即证书级 oracle 把忠实性判定确定化），并以"可归约子集闭合 + 不可归约边界披露"取代单一收敛阈值或单一同义率指标。外部对照方面，zlint 人工金标用于检验规则提取与可 lint 性判定（BR 1.4.8 上 κ=0.823），真证书执行用于审计发射 lint 的有效命中（72/72 经独立结构审计确认）。

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

系统内部使用一个机器可读的 IR 对象（JSON 序列化）。除 §4.4 核心四元组外，其关键字段如下；其余字段支持溯源、归一化、匹配与下游产物生成。可 lint 性判定（§5）只直接使用 obligation、assertion_subject、enforcement_phase、rule_category 四个字段。

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

### 附录 C：受限代码空间 $\mathcal{T}_{\mathcal{V}}$ 的构造细节

**词汇表 $\mathcal{V}$ 的七个分量。** $\mathcal{V}$ 是七类在系统启动时冻结的有限集合的不相交并（§6.2）：证书字段 $\mathcal{F}_{\mathrm{cert}}$（~40，如 `c.Version`、`c.DNSNames`、`c.IPAddresses`）、DN 字段 $\mathcal{F}_{\mathrm{dn}}$（~15，如 `Subject.CommonName`、`Subject.Country`）、OID 常量 $\mathcal{O}$（~30，对应 zlint `util.*OID`）、KeyUsage 位 $\mathcal{B}_{\mathrm{KU}}$（9）、ExtKeyUsage 位 $\mathcal{B}_{\mathrm{EKU}}$（~10）、ASN.1 编码类型 $\mathcal{E}_{\mathrm{ASN1}}$（5，如 `UTF8String`、`PrintableString`、`IA5String`）、命名正则 $\mathcal{R}_{\mathrm{regex}}$（~20，每项为已审核的字面 RE2 模式）。所有分量均为冻结有限集合；LLM 在 prompt 中获得各分量全量枚举，故其输出中出现 $\mathcal{V}$ 之外的标识符即触发 $\eta$ 解析错误（命题 1）。

**代表性原子模板（节选）。** 原子模板集 $\mathcal{A}$（$|\mathcal{A}|=79$）按语义簇组织，每个原子模板有类型化签名 $\mathrm{sig}(a)$（§6.2）。下表按簇节选关键原子模板（完整 79 项随代码与数据一并公开）：

| 簇 | 原子模板 | 签名 | 语义 |
|---|---|---|---|
| I 扩展存在性 | `ExtPresent` / `ExtCritical` | $(\mathcal{O})$ | 扩展 OID 存在 / 存在且 Critical 位置位 |
| II 宏属性 | `IsCA` / `KeyUsageHas` / `ExtKeyUsageHas` | $()$ / $(\mathcal{B}_{\mathrm{KU}})$ / $(\mathcal{B}_{\mathrm{EKU}})$ | BasicConstraints.cA=true / KeyUsage 位 / EKU 项 |
| III 字段值/形态 | `FieldEq` / `FieldMatchesRegex` / `FieldEncodedAs` | $(\mathcal{F}, \cdot)$ | 字段等于字面量 / 匹配命名正则 / ASN.1 编码类型 |
| IV 列表/字节级 | `ListAllMatch` / `OidListContains` / `BytesContainsOidDer` | $(\mathcal{F}, \cdot)$ | 列表全部满足子树 / 含命名 OID / 字节含 OID 的 DER |
| V NameConstraints | `SubtreeIPListAnyHasOctetCountAndNotAllZero` | $(\mathcal{F}, \mathbb{Z})$ | NC IP 子树存在指定字节数且非全零项 |
| VI 特殊结构 | `DomainComponentOrdered` | $()$ | domainComponent 按 RFC 4519 反向排列 |

组合子 $\{\neg, \wedge, \vee\}$ 三个，语义遵循经典命题逻辑。

**原子模板的通用性分级（GENERIC / NON_GENERIC）。** 原子模板按两条正交判据分级（与参数个数无关）：一个原子模板是 **GENERIC** 当且仅当 (1) 它表达一类*通用* PKI 概念——可跨规则复用的一类证书属性判定——且 (2) 它参数化于字段/值、不绑定任何特定 rule_id 或语料特有 OID/单一条款；否则为 **NON_GENERIC**（其逻辑特化于某扩展的内部结构或单一 RFC/CABF 条款，即便带参数，语义也钉死在该构造上）。零参原子模板可属任一类（`IsCA` 为 GENERIC，`NotAfterIsNoExpirySentinel` 为 NON_GENERIC）。该分级在代码中固化为 `GENERIC_ATOMS` / `NON_GENERIC_ATOMS` 两个集合并带分区完整性断言，可确定性复算。

$\mathcal{A}$ 的 79 个原子模板中 **62 个 GENERIC、17 个 NON_GENERIC**。下表只列出 NON_GENERIC 的代表性示例；完整清单随代码与数据公开。

| 代表性 NON_GENERIC 原子模板 | 特化对象 | 语义 |
|---|---|---|
| `SigAlgMatchesTBSSignature` | 证书签名算法字段 | 外层 `signatureAlgorithm` 与 `tbsCertificate.signature` 逐字节一致 |
| `NotAfterIsNoExpirySentinel` | 有效期哨兵值 | `notAfter` 是否为特定 no-expiry 哨兵时间 |
| `DomainComponentOrdered` | Subject DN 的 `domainComponent` | domainComponent 序列是否按 RFC 4519 约定排列 |
| `CertPolicyExplicitTextHasEncodingTagInSet` | certificatePolicies 的 explicitText | explicitText 是否使用允许的 ASN.1 字符串编码 |
| `CRLDPHasNameRelative` | CRL Distribution Points | distributionPoint 是否使用 nameRelativeToCRLIssuer 形式 |
| `SubtreeIPListAnyHasOctetCountAndNotAllZero` | NameConstraints IP 子树 | IP 子树是否存在指定字节数且非全零的项 |
| `WildcardFilter` | DNS 名称模式 | 域名通配符是否满足特化过滤规则 |

允许 NON_GENERIC 原子模板进入代码生成（它们对应真实的 PKI 构造，非语料注水），但要求显式标记并披露其占比：**113 条同义发射 lint 中，绝大多数完全由 GENERIC 原子模板构成，仅少数依赖至少一个 NON_GENERIC 原子模板**。

**渲染与元数据绑定。** 所有 DSL 树经 $\rho$ 渲染后嵌入一个固定的 zlint Go 外壳（`RegisterCertificateLint` 注册、`CheckApplies`/`Execute` 方法对），规则间差异完全集中在检查体与导入；$\Phi_{\mathrm{post}}$（§6.6）确定性绑定 `Description`/`Citation`/`Name` 与各规范源的 `PACKAGE`/`SOURCE`/`EFFECTIVE_DATE` 元数据（如 RFC5280$\mapsto$`RFC5280`、CABF-TLS-BR$\mapsto$`CABFBaselineRequirements` 等）。义务级别到严重度的映射为 MUST/MUST NOT/SHALL/SHALL NOT/REQUIRED $\mapsto$ `lint.Error`（lint 名前缀 `e_`）、SHOULD/SHOULD NOT/RECOMMENDED $\mapsto$ `lint.Warn`（`w_`）；MAY/OPTIONAL 已在 §5 的 $C_1$ 处被排除，故本系统不产生 `lint.Notice` 级输出。

### 附录 D：机械翻译函数 $\sigma_{\mathrm{mech}}$ 的短语字典（节选）

$\sigma_{\mathrm{mech}}$（定义见 §6.3）由原子模板-短语字典 $\mathcal{M} : \mathcal{A} \to \mathcal{L}_{\mathrm{NL}}$ 与三组合子归约规则构成。代表性条目：

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

**命题 2（$\sigma_{\mathrm{mech}}$ 可逆性）**。*给定 $\sigma_{\mathrm{mech}}(t)$ 的输出，原始 DSL 树 $t$ 在原子模板层等价意义下可机械恢复（同义原子模板被映射到同一短语时不可区分，其余结构保留）；故 $\sigma_{\mathrm{mech}}$ 在验证链路中保留 DSL 树结构信息。*

### 附录 E：DSL 合成 Prompt 模板

§6.4 所述受约束 LLM 调用 $\phi_G$ 的系统提示明确四条硬约束（违反即被解析函数 $\eta$ 自动拒绝）：(1) 每个原子模板名须出现在所供目录 $\mathcal{A}$ 中；(2) 每个叶参数须为声明类型的字面量或出现在词汇表 $\mathcal{V}$ 中的名字，禁止编造标识符；(3) 输出须为一棵 DSL 树的 JSON（含 `predicate`/`precondition`/`severity`/`label`）或一个 `{"no_template": true, "reason": ...}` 弃权标记，其余形态一律解析失败；(4) `Description`/`Citation`/`Name` 不由 LLM 生成，由后处理器 $\Phi_{\mathrm{post}}$ 确定性绑定。

每次调用的完整 prompt 由四区段依次拼接：**区段 A（Rule Context）**——源 ID、章节号、规则 ID、逐字 `rule_text` 与 `source` 元数据；**区段 B（Structured IR）**——扁平展开的 IR 四/五元组；**区段 C（DSL Schema）**——实现中的 $\mathcal{V}$ 与 $\mathcal{A}$ 目录（按分量分组的字段名清单与按语义簇分组的原子模板签名表，附每原子模板一行 PKI 语义注释；论文附录 C 仅列代表性示例）；**区段 D（Output Protocol）**——两种合法 JSON 形态的精确 schema 与一条 minimal positive 示例。

### 附录 G：SAIV 残差与阶段路由的形式化细节

本附录汇集 §7.4–§7.6 正文中引用的精确数学形式化，以供需要形式核查的读者查阅。

**SAIV 核心残差的精确式**（直觉与定义见 §7.3–§7.4 正文）：

代码正确性标签（式 5）：
$$
\lambda_{\mathrm{code}}(r) = \mathbb{1}[\mathrm{compile}(c)] \cdot s_{\mathrm{struct}}(c) \cdot c_{\mathrm{syn}}(\sigma(c),\; \mathrm{spec}(r)) \tag{5}
$$

召回守恒残差（式 6）：
$$
\mathcal{L}_{\mathrm{recall}} = 1 - \frac{\min(|\mathcal{R}_{\mathrm{kw}}|,\; |\mathcal{R}_N|+|\mathcal{R}_L|+|\mathcal{R}_U|)}{\max(|\mathcal{R}_{\mathrm{kw}}|,\; |\mathcal{R}_N|+|\mathcal{R}_L|+|\mathcal{R}_U|)} \tag{6}
$$

代码忠实残差（式 7）：
$$
\mathcal{L}_{\mathrm{code}} = 1 - \frac{1}{|\mathcal{R}_L|}\sum_{r\in\mathcal{R}_L}\lambda_{\mathrm{code}}(r) \tag{7}
$$

总损失（式 8，$w_R+w_C=1$）：
$$
\mathcal{L}_{\mathrm{total}} = w_R\cdot\mathcal{L}_{\mathrm{recall}} + w_C\cdot\mathcal{L}_{\mathrm{code}} \tag{8}
$$

**阶段路由的四分支规则**（精确条件见 §7.5 正文）：

$$
\mathrm{Stage}^{(t)} = \begin{cases}
\phi_R/\psi_C, & \mathcal{L}_{\mathrm{recall}}^{(t)} > \tau_R \\
\phi_C, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} > \tau_C \\
\phi_G, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} < 1 \\
\phi_V, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} = 1
\end{cases} \tag{9}
$$

其中 $p_{\mathrm{fail}}^{(t)} = \frac{1}{|\mathcal{R}_L|}\sum_{r\in\mathcal{R}_L}\mathbb{1}[\neg\mathrm{compile}(\phi_G(r))]$、$\bar{s}_{\mathrm{struct}}^{(t)} = \frac{1}{|\mathcal{R}_L|}\sum_{r\in\mathcal{R}_L}s_{\mathrm{struct}}(\phi_G(r))$。

**命题 3（残差单调性）的完整陈述与证明**（正文见 §7.5）：

*命题 3（残差单调性）。若二元仲裁判官 $\phi_J$ 在每条违反上均给出 FLIP（翻转）或 SPURIOUS（判伪）之一并被采纳，则一轮过程后 $N_{\mathrm{viol}}$ 严格下降至 0。*

*证明。* 设违反集 $\mathcal{V}=\{r:\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}\land\psi_C(r)\neq\mathrm{lintable}\}$，$N_{\mathrm{viol}}=|\mathcal{V}|$。对任意 $r\in\mathcal{V}$，$\phi_J$ 必给出且仅给出以下两支之一：
- **FLIP**：采纳后 $\psi_C(r)$ 翻转为 $\mathrm{lintable}$，此时 $\psi_C(r)=\mathrm{lintable}\land\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}$ 仍触发违反式左侧，但违反式右侧不再成立（lintable 的假阴性已修正），故 $r\notin\mathcal{V}$；
- **SPURIOUS**：采纳后 $\mathrm{cov}_{\mathcal{T}}(r)$ 降级为 $\mathrm{none}$，此时违反式左侧 $\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}$ 不再成立，故 $r\notin\mathcal{V}$。

两类修复均移除该 $r$ 而不引入新违反，故 $\mathcal{V}$ 在一轮内严格收缩至空集、$N_{\mathrm{viol}}=0$。$\square$

*注：* FLIP 与 SPURIOUS 不可同时对同一条规则采纳（两者互斥），且采纳后该规则离开 $\mathcal{V}$，不参与后续判定，故该过程有界终止。
