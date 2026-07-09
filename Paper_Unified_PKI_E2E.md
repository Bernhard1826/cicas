# 从 PKI 标准到合规检查代码：规则提取、lintability 判定与可验证代码生成的端到端框架

## 摘要

公钥基础设施（PKI）的证书编码规则分散在 RFC 5280、CA/Browser Forum 基线要求（CABF BR）等多份自然语言标准中，而公信 CA 的预签发 lint 要求正在把这些规则转化为可执行检查。现有工具主要依赖专家逐条手写 lint，因而长期缺少两个系统性答案：哪些规范规则能仅凭单张证书静态裁决，又有哪些可执行规则被现有工具遗漏。

本文围绕这一缺口提出一个从规范文本到 zlint 检查代码的端到端框架。核心做法是先把规则解析为结构化中间表示，再用确定性条件判定其**lintability**，只对单证书可观测的规则生成代码。生成阶段不输出自由 Go 代码，而被限制在类型化的 DSL 与有限原子模板空间内；验证阶段则同时使用同义判定、编译检查、真证书执行和证书级执行验证（借助受控证书样本核验代码的执行行为），区分"代码忠实于 IR"与"代码忠实于原始规范"这两个不同问题。

在 RFC 5280 与 CABF BR 上，本文识别出 248 条单证书 lintable 规则，其中 90 条未被 zlint 原生 lint 完整覆盖。系统为这些未覆盖规则生成 90 条可编译 lint，全部通过最终发射代码的严格规范同义判定并可注入 zlint。关键发现是：证书级执行验证能为一部分生成代码提供与模型无关的 IR 级忠实性证据，但这并不自动推出规范级同义性。因此，规范到代码的瓶颈不能只看代码是否可编译或是否忠实于中间表示，最终仍必须验证发射代码行为是否表达了规范本身；不能严格同义的规则需回到 IR 与 lintability 边界重新判定，而不是留在代码生成分母中。

外部验证从两个方向支撑这一结论：前半段以 zlint 维护者的人工映射表检验规则提取与 lintability 判定，后半段把通过同义门的 lint 注入真实 zlint 执行并逐条审计有效命中。方法学上，本文主张把验证链路中能确定化的环节尽量确定化，并用"可归约子集的闭合 + 不可归约边界的披露"（即：能生成忠实 lint 的规则力求全覆盖，无法生成的则如实标注）取代单一的生成率或同义率指标。

**关键词**：公钥基础设施；证书合规检查；规范规则提取；中间表示；lintability 分析；受限代码生成；证书级执行验证；阶段感知式迭代验证

## 1. 引言

### 1.1 研究背景与动机

公钥基础设施（Public Key Infrastructure, PKI）是现代互联网信任的基础：证书颁发机构（CA）签发的 X.509 数字证书支撑着身份认证与加密通信。证书是否被正确签发因而直接关系到 Web PKI 的完整性——违反技术性规范要求的证书会削弱浏览器信任、损害安全通信的可靠性。这类失效并非纯理论风险：2024 年 Chrome 与 Mozilla 在一系列未解决的合规事故后相继宣布不再信任 Entrust 作为公信 CA [13], [12]；更早的 2020 年，Let's Encrypt 因一处 CAA 校验缺陷撤销了约三百万张证书 [14]。

这些事故已转化为政策变化：据 CA/Browser Forum Ballot SC075，公信 CA 自 2025 年 3 月 15 日起需在签发前执行 lint 检查 [15]；Ballot SC-081v3 则规划将 TLS 证书有效期分阶段压缩、最终降至 47 天 [16]。二者共同抬高了签发频率与自动化合规需求。当前合规分析依赖 zlint [7]、pkilint [8]、certlint [9]、x509lint [10] 等静态工具，但它们高度依赖**人工规则工程**——每条检查须由专家随规范修订单独实现并维护；而 X.509 编码规范分散在 RFC 5280 [1]、CABF 基线要求 [2]、ETSI EN 319 412 系列 [3]、Mozilla 根存储策略 [4] 等多份文档、普遍以 RFC 2119 [5] 关键词表达义务级别，手工方式愈发难以规模化。

更根本的是，PKI 生态缺乏一个框架，能把规范文本系统性地转化为可由静态 lint 检查强制执行的合规逻辑。这一缺口随着 lint 在 PKI 治理中日益核心而愈发关键：规范本身并未区分"可由静态检查强制"与"需要证书之外的运行时或外部证据"两类规则。本研究的目标，即是给出一个从 Web PKI 规范源**提取规范规则、判定其 lintability、并自动生成对应可执行检查代码**的端到端框架。

理解这一缺口的关键是一个朴素却常被忽略的区分。同样含 MUST，"证书 MUST 包含 keyUsage 扩展"可仅凭一张证书的字节静态裁决，而"CA MUST 在签发前核验申请人身份"约束的是线下行为、任何静态检查都无从判定。本文称前者具备**lintability**——能否被一个不依赖运行时或外部上下文、仅凭单张证书字节即可裁决的静态检查所表达；它是把规范转化为代码的前置闸门，本文将其形式化为 IR 上的确定性布尔判定（§5）。

本文的中心问题不是"LLM 能否写出一段看似合理的 lint"，而是：在没有逐条人工真值的情况下，如何把规范规则、lintability 边界、生成代码和验证证据放在同一条可复核链路上。围绕这一问题，本文在 RFC 5280 与 CABF BR 上报告三类结果：lintable 规则全集及其 zlint 覆盖缺口，未覆盖规则的受限代码生成结果，以及代码忠实于 IR 与忠实于规范之间的分歧（§8）。最后一类结果构成本文的主要负向发现：IR 级忠实性是有价值的验证信号，但不能替代规范级同义性。

### 1.2 研究问题与挑战

将规范文本端到端地转换为可执行、可验证的合规代码，至少面临五方面挑战。

**(挑战一) 跨文档引用与间接约束。** Web PKI 规范源大量交叉引用与继承——如 CABF BR §7.1.2.7.12 在 RFC 5280 §4.2.1.6 之上进一步收紧、要求订户证书含 subjectAltName 扩展——孤立分析单一文档不足以还原规则真实语义。

**(挑战二) LLM 的不可控性与幻觉。** LLM 的非确定性与幻觉与合规分析所需的可复现性相冲突，提取须可审计、可控，而非端到端黑箱推理。

**(挑战三) lintability 判定本身非平凡。** 出现 MUST/SHALL 并不意味着可被翻译为确定性静态检查——许多强义务约束的是 CA 行为、链处理或运行时状态而非证书编码，lintability 须被显式刻画。

**(挑战四) 规范与代码之间的语义鸿沟。** 规范以抽象自然语言表达约束、可执行代码须落实为具体字段路径与控制流，二者的鸿沟是开放式代码生成漏检与误报的根源。

**(挑战五) 缺乏独立真值。** 大规模生成缺乏现成可信的人工真值来逐条判定"代码是否忠实于规范"，验证须在**无独立真值**下提供可计算、可复算、可追溯的质量信号。

### 1.3 核心思想

把规范文本转化为可信代码，难点不在让 LLM 生成一段代码，而在让整条链路的每个判断都能被复查。本文把端到端问题拆成三道边界。

**第一是 lintability 边界。** LLM 只负责把候选规范句解析为受 schema 约束的 IR；"这条规则能否仅凭单张证书静态裁决"则由 IR 字段上的确定性条件给出。这样，模型不直接决定可执行性，审计者也能追问某条规则为什么被纳入或排除。

**第二是代码空间边界。** 生成器不直接写自由 Go 代码，而只能选择和组合已登记的原子模板、字段和常量，再由确定性渲染器输出 zlint 代码。这使字段名、OID、参数类型等容易出错的部分先在语言层受限，而不是只靠提示词约束。

**第三是验证边界。** 本文把"代码忠实于 IR"和"代码忠实于规范"分开验证：前者在可认证子集上由证书级执行验证（在受控证书上真实运行代码）给出确定性证据，后者仍通过代码摘要与规范文本的同义判定把关，并用真证书执行审计其有效命中。SAIV 进一步把召回守恒、代码同义性和外部覆盖一致性组织成可计算残差，用来说明哪些部分已经闭合、哪些部分仍须诚实保留。

### 1.4 主要贡献

本文的贡献按上述三道边界组织。

**(C1) lintability 边界与覆盖缺口。** 本文给出基于 IR 字段的 lintability 判定框架，并在 RFC 5280 与 CABF BR 上量化出单证书可观测规则及其 zlint 覆盖缺口；前半段结果用 zlint 维护者公开的人工映射表作外部对照（§5, §8.3）。

**(C2) 受限生成与分层验证。** 本文把代码生成限制在类型化 DSL 与原子模板空间内，并用确定性渲染、机械摘要、编译检查、同义判定与证书级执行验证对生成结果分层把关。该设计明确区分 IR 级忠实性与规范级同义性，避免把可编译或可执行误认为规范正确（§6, §8.1, §8.4）。

**(C3) 无人工真值下的残差核算。** 本文提出 SAIV，将召回守恒、代码-规范同义性、外部覆盖一致性组织为可计算残差，并在实验中报告哪些残差已经闭合、哪些仍由同义端点或跨标准覆盖口径限制（§7--§9）。

## 2. 研究背景

### 2.1 PKI 标准与静态合规检查

X.509 证书的编码规范由分层的标准与策略框架共同定义。RFC 5280 [1] 给出证书 ASN.1 结构、字段级语义与路径验证算法这一基础层；其上，CABF 基线要求 [2] 对签发公信 TLS 证书的商业 CA 施加操作性与配置性约束；ETSI EN 319 412 系列 [3] 补充了与 eIDAS 框架对齐的欧盟配置档案；Mozilla 根存储策略 [4] 则从浏览器策略层引入额外技术要求。这些规范彼此交叉引用并时有局部覆盖，普遍以 RFC 2119 [5] 关键词表达义务级别（MUST/SHALL 通常映射为 Error，SHOULD/RECOMMENDED 映射为 Warning，MAY/OPTIONAL 一般不宜直接实现为 lint 规则）。

证书合规主要由静态 lint 工具检查（只检视单张证书、不依赖外部验证状态）：zlint [7] 部署最广，将检查组织为带元数据（引用、生效日期、严重级别）的独立 lint（v3 约 400 条）；pkilint [8] 是 Python 嵌套结构校验框架；certlint [9] 与 x509lint [10] 为更早的命令行 linter。每条检查都须人工从规范推导、映射到解析器字段、实现并随规范维护，故各工具覆盖不均衡。两点含义：其一，lint 是嵌入字段路径/谓词/严重级别/作用域的工程产物，而非规范语句的直接拷贝；其二，缺某条 lint 不等于对应规范规则不存在，可能只是尚未被识别为 lintable 或尚未实现。

### 2.2 规范提取与 LLM 辅助代码生成

自动规则提取已见于隐私、法律与协议规范，但与 Web PKI 签发合规本质不同。PolicyLint [18]、PrivacyFlash Pro [19] 分析隐私文本，Hassani 等 [20] 以 LLM 加知识图谱做法律合规提取，但都不映射到 DER 证书字段、也不判某规则能否凭单张证书强制执行；N-Check [21] 把规范形式化为 FOL\* 公式，目标是良构性分析而非 lint 谓词。面向技术规范的 LLM 系统中，PROSPER [22]、ParCleanse [23]、SpecGPT [24] 分别提取 RFC 状态机、协议格式与 3GPP 行为，Wu 等 [25] 以 GraphRAG 式上下文 [26], [27] 对齐 RFC 与内核代码——它们聚焦状态/格式/实现差异，未把"穷尽召回、schema 受限 IR 解析、确定性 lintability 判定"三者分离处理。

LLM 代码生成进展显著（Codex [32]、AlphaCode [33]、CodeGeeX [34]），但主要面向通用编程，缺乏对领域约束、目标框架接口与可追溯性的显式建模；协议合规方向 SAGE [35]、RFCNLP [36]、PROSPER [22] 提取状态机或生成测试用例，而非面向具体 lint 框架产出可执行代码。输出约束与形式验证类工作与本研究互补：XGrammar [28]、CRANE [29] 以文法约束 LLM 输出，Schall 与 de Melo [30] 指出受限解码可能损害推理，ARMOR [31] 在 Agda 中验证 RFC 5280 路径验证算法——它们改进输出形式或算法保证，但不决定哪些自然语言签发规则应成为静态 lint。

### 2.3 语义对齐与证书合规度量

确保生成代码与规范语义一致是该类任务的核心难点：测试用例难穷尽边界、符号执行易路径爆炸、差异分析需可对照的参考实现，而中间表示方法借 IR 语义桥接间接验证一致性，最适合规范文本到代码的转换。本研究即以 IR 为桥梁，进一步引入基于 code_summary（机械摘要）的同义性归约与确定性机械翻译，使对齐判定既可计算又可追溯。经验设定上，Kumar 等 [11] 在生态尺度度量证书误签发、Zhang 等 [17] 识别国际化 X.509 证书的 Unicode 相关不合规，表明签发失效可度量且具运维重要性；但它们通常从已知 lint 或缺陷类别出发，而非从规范文本系统性推导 lintable 规则全集。

### 2.4 本研究的差异化定位

相较既有规范提取、代码生成或形式验证工作，本文的差异化定位在于把三道边界放入同一条可复核链路。首先，提取侧把 LLM 限定为受 schema 约束的解析器，并用确定性、可溯源的图检索组装跨文档上下文；本文不主张图检索相对普通 RAG 的量化优越性（难做干净消融，见 §9.4），而强调其可审计性。其次，生成侧将代码生成模块限制在有限闭合的 DSL 树空间内，在语言层排除字段/OID 编造类错误。最后，验证侧把 IR 级忠实性、规范级同义性和外部执行证据分开报告，并用 SAIV 的残差核算说明哪些部分已经闭合、哪些仍未闭合。

## 3. 方法总览

图 1 给出整体结构：系统以 Web PKI 规范文本为输入，输出可编译、可追溯的 zlint Go 检查代码，并由阶段感知式迭代验证（SAIV）在无人工真值下闭环修复。六阶段分两半——前半（确定性上下文、提取、判定）回答"哪些规范规则可被单证书 lint 强制"，后半（合成、对齐、验证）回答"这些规则能否被写成忠实的 zlint 检查"。结构化 IR 是两半之间的接口，lintability 判定则是进入代码生成前的闸门。

```mermaid
flowchart LR
  S[Web PKI 规范文本] --> KG[知识图谱构建 §4.1]
  KG --> R[确定性子图检索 §4.2]
  R --> L1["Layer 1 关键词召回"]
  L1 --> L2["Layer 2 受控解析 → IR"]
  L2 --> C["四条件 lintability 判定 §5"]
  C -->|"lintable 规则"| G["受限 DSL 树合成 §6"]
  G --> RHO["确定性渲染 + 后处理"]
  RHO --> V["三层对齐验证 + 证书级执行验证 §6"]
  V -->|残差| SAIV["阶段感知式迭代验证 SAIV §7"]
  SAIV -. "修复信号" .-> L2
```

![](figures/fig9_pipeline_snapshot.png)

_图 1：端到端漏斗快照。A 显示召回与 lintable 化守恒，B 显示 zlint 覆盖与 codegen 定义域，C 显示 codegen、同义发射与证书级执行验证的关系。_

## 4. 规则提取

本节描述前半链路：如何在确定性可控的前提下，从分散且交叉引用密集的 Web PKI 规范源中提取规范规则，并转写为结构化中间表示 IR。核心困难在于跨文档引用——孤立地阅读任一段落都不足以还原一条规则的完整语义。本文的应对是分工：以确定性的图遍历组装上下文，以受约束的 LLM 解析语义，从而既不丢失上下文、又不让模型自由发挥。

### 4.1 PKI 知识图谱构建

知识图谱构建器（离线）把异构 Web PKI 规范源归一化为层级结构、为规范/章节/文本单元赋稳定标识，抽取章节引用、RFC 引用与策略交叉链接等**显式引用**并链到对应节点，同时记录证书字段概念及别名（subjectAltName、dNSName、basicConstraints.cA、策略 OID 等），以便把自然语言提及映射到规范证书路径。

本研究将该跨文档网络建模为多边有向图：八类节点（Specification、Section、Definition、CertificateField、Rule、Operation、Value、Concept）与四种 source-backed 关系（CONTAINS、DEFINES、REFERENCES、APPLIES TO）。构建器刻意保守——只存文档结构或文本证据直接支持的关系，冲突/覆盖/lintability 等**规范性判断**留给后续确定性阶段（CONFLICTS WITH、OVERRIDES 由规则引擎产生、**不进入检索图**）。故该图是可溯源的上下文索引，而非做出规范性裁决的权威来源（关系类型与检索可入性见附录 B）。

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

其中 subject 为由字段解析器解析得到的证书字段路径（如 `extensions.subjectAltName.dNSName`），obligation 为 RFC 2119 义务关键词，predicate 为断言类型（如 `must_be_present`、`conform_to`、`equal`），constraint 为约束值或模式。四元组之外，IR 还携带若干关键扩展字段，用于支撑 lintability 判定与下游生成与审计，其中最重要的是 `rule_category`（规则语义类别）、`assertion_subject`（断言主体：证书 / CA / 依赖方 / 外部生态）、`enforcement_phase`（约束所依赖的阶段：编码 / 运行时 / 外部验证），以及 `source_section`、`source_span`、`evidence_text`、`context_nodes` 等溯源字段（关键字段的完整列举见附录 A）。

以 IR 为桥梁相较"从原文端到端直接生成"有三点优势：引用/约束/义务分离存储，提升可追溯性与冲突处理；IR 作为 §5 四条件判定的确定性输入，使判定可复现而非依赖模型；由显式化的 IR（字段路径、断言类型、约束值）生成代码更稳定、可解释。IR 由此支持"一次提取、多处复用"，同时服务 lintability 分析与代码生成。

## 5. lintability 判定

并非每条带 MUST 的规范都能写成 lint 检查。承 §1.1 的对照——"证书 MUST 包含 keyUsage 扩展"可仅凭一张证书裁决，但"CA 必须核验申请人身份"约束的是 CA 线下行为，还有的要比对证书链上的其他证书、查 DNS 记录或撤销历史——后三类都无法仅凭一张证书的字节静态裁决。因此在生成代码之前，必须先回答一个前置问题，即每条规范规则的**lintability**：它能否被一个不依赖外部上下文或运行时行为、仅凭**一张证书**的字节即可裁决的静态检查所表达？（CRL 等其他制品自身的合规检查不在本文范围内。）

本文不让 LLM 直接判定，而把它分解为四个独立布尔条件、各只读一个 IR 字段、全满足才判定为 lintable，从而在 IR 上确定性计算 lintability。三点观察：其一，决定 lintability 的恰是四类信息——义务道义强度、被约束主体（含数据范围：单证书 vs 跨证书/其他制品）、约束生效阶段、规则类型；其二，四者各可编码为取值于小而封闭集合的单一 IR 字段，故判定退化为四个离散字段的布尔函数；其三，分离后可直接复查参与判定的字段取值，而非只得到不透明的端到端标签。

形式上，本文的**操作性 lintability 标签**定义为以下四个条件的合取，每个条件都是恰好一个 IR 字段的布尔函数：

$$
\mathrm{lintable}(r) \;\equiv\; C_1(r) \wedge C_2(r) \wedge C_3(r) \wedge \neg C_4(r)
$$

其中

- **$C_1$（道义强度）**：$C_1(r) \equiv \mathrm{is\_normative}(r.\text{obligation})$，即 $r.\text{obligation} \notin \{\text{MAY}, \text{OPTIONAL}\}$；
- **$C_2$（主体边界）**：$C_2(r)$ 由两项联合判定：其一，$r.\text{assertion\_subject} = \text{Certificate}$；其二，$r.\text{subject}$ 路径的根段（第一个路径分量）属于预定义的证书/CRL 结构字段集合。就第一项而言，仅 $\text{assertion\_subject} = \text{Certificate}$ 纳入判定，其余取值均被排除。具体地：$\text{CA}$ 是颁发证书的机构，其行为不在证书字节中；$\text{RelyingParty}$ / $\text{Implementation}$ 描述依赖方或软件行为；$\text{CRL}$ 描述证书吊销列表文档（不在本文范围内）；$\text{CrossArtifact}$ 描述需跨制品比对的约束（如"子证书的 SKI 须等于签发者的 AKI"、预证书须与最终证书逐字节一致、序列号跨证书唯一等）。第二项则由 subject 路径门把关：若 subject 路径指向操作名词（如 domain_validation_record、phone_contact）而非证书字段，该规则描述的是 CA 过程而非证书内容，同样不满足 lintability。
- **$C_3$（运行时边界）**：$C_3(r) \equiv (r.\text{enforcement\_phase} = \text{Encoding})$，将"可在已签发字节中观测的义务"与"在链处理、名称比较、撤销处理或 CAA 获取等阶段才触发的义务"分开；
- **$C_4$（过程边界，取反）**：$C_4(r) \equiv (r.\text{rule\_category} \in N)$，其中 $N = \{\text{definition}, \text{capability}, \text{algorithm\_ref}, \text{display}, \dots\}$ 为承载术语定义、CA 能力声明、对外部算法规范的委派、UI 呈现等**不对证书编码施加静态检查**的类别集合；lintable 要求 $r.\text{rule\_category} \notin N$，即 $\neg C_4$。$C_4$ 与 $C_2$ **正交**：$C_4$ 回答"这是哪一**类型**的义务"（定义？能力声明？编码约束？），$C_2$ 回答"裁决它需要**哪些数据**"（仅此一张证书，还是更多）——一条规则可以是编码约束（不在 $N$ 中，即 $\neg C_4$）却仍需访问签发者证书做密钥比对、或与配对的（预）证书逐字节比对（不通过 $C_2$）；这一正交性是 $C_2$ 不可被 $C_3$/$\neg C_4$ 替代的根据。

记 $\phi_C : r \mapsto \mathbb{1}[C_1 \wedge C_2 \wedge C_3 \wedge \neg C_4]$（$\mathbb{1}[\cdot]$ 为指示函数：方括号内条件为真取 1、否则取 0），则 $\mathcal{R}_L = \{r : \phi_C(r) = 1\}$ 即进入代码生成阶段的规则集合（其中未被现有 lint 工具覆盖的子集才是 $\phi_G$ 实际生成的目标，见 §8）。obligation 同时固定严重级别（MUST 类 $\mapsto$ Error，SHOULD 类 $\mapsto$ Warning），故严重级别是对 obligation 的直接读取、而非第二个分类器。三个非道义条件刻画主体（含数据范围）、运行时、过程三条正交边界——其中 $C_2$ 把一类此前依赖人工审计的"静态可观测"边界前移为提取阶段即确定的 IR 字段 $\mathrm{assertion\_subject}$。由于每个 $C_i$ 都是单一 IR 字段的确定性函数，$\mathrm{lintable}(r)$ 从 IR 计算而非 LLM 预测：同一 IR 每次给出逐位一致的标签；若标签不合预期，可直接检查参与判定的字段取值。

![](figures/fig8_lintability_gate.png)

_图 2：四条件 lintability 判定的确定性流程。IR 字段先经过四个单字段布尔检查，再由最终合取门给出 lintable / not lintable。_

## 6. 受限代码生成与验证

以大语言模型直接生成检查代码面临两方面固有困难。其一是**幻觉**：模型可能将字段名误写为另一个恰好存在却语义无关的字段，或使 OID 出现单位错误。其二是**输出不稳定**：相同的代码生成提示在多次调用下往往产生不同输出，且生成结果既不保证可编译、也不保证逻辑正确。为消除这两类不确定性，本文将规则的代码体约束在一个有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$ 内：每条规则的代码体只能是该空间中的一棵树，再经确定性函数渲染为 Go 代码。

### 6.1 原子模板与 IR 填充

原子模板是单证书静态检查的最小单元。PKI 的单证书合规检查大多是若干**原子模板**的逻辑组合——"某扩展是否存在"、"某字段是否等于某常量"、"某列表的每个元素是否匹配某模式"等原子模板，用"与 / 或 / 非"组合即可刻画大多数静态约束。代码 DSL 的抽象语法为：

$$
\mathcal{T} \;::=\; a(\bar{v}) \;\mid\; \neg\, \mathcal{T} \;\mid\; \mathcal{T} \wedge \mathcal{T} \;\mid\; \mathcal{T} \vee \mathcal{T}
\tag{1}
$$

其中 $a \in \mathcal{A}$ 为原子模板谓词，$\bar{v}$ 为其参数列表。$\mathcal{A}$ 是一个**有限闭合**的原子模板集合，系统登记的原子模板全集共 136 个，按通用性分为 82 个 GENERIC 与 54 个 NON_GENERIC；本次 90 条 final-shipping strict 发射 lint 实际触达其中 52 个唯一原子模板（28 个 GENERIC、24 个 NON_GENERIC），其余模板保留为生成器可用词汇而非本次结果分子。分级判据与代表性示例见附录 C；$\{\neg, \wedge, \vee\}$ 为命题逻辑组合。一条 lint 规则的代码体建模为有序对 $(p, q) \in \mathcal{T}_\varepsilon \times \mathcal{T}$，其中 $q \in \mathcal{T}$ 为主断言、$p \in \mathcal{T}_\varepsilon = \mathcal{T} \cup \{\varepsilon\}$ 为可选前提（$\varepsilon$ 是"无前提"占位符，是一个正常取值，与 §6.4 表"合成失败"的 $\bot$ 不同）。下式中 $c$ 为单张证书；$\lVert u \rVert(c) \in \{\mathrm{true}, \mathrm{false}\}$ 记 DSL 树或前提 $u$ 在 $c$ 上求值的布尔结果（原子模板按其语义求值，$\neg/\wedge/\vee$ 按经典命题逻辑）。执行语义为：

$$
\lVert (p, q) \rVert(c) \;=\; \begin{cases}
\mathrm{NA}, & p \neq \varepsilon \;\land\; \lVert p \rVert(c) = \mathrm{false} \\
\mathrm{Pass}, & (p = \varepsilon \;\lor\; \lVert p \rVert(c) = \mathrm{true}) \;\land\; \lVert q \rVert(c) = \mathrm{true} \\
\mathrm{Severity}(r), & \text{otherwise}
\end{cases}
\tag{2}
$$

前提 $p$ 是**规则前提**——当它存在且在 $c$ 上为假时返回 $\mathrm{NA}$（不适用）；前提缺失或成立且 $q$ 成立时返回 $\mathrm{Pass}$；前提成立而 $q$ 不成立则为违反，按义务返回 $\mathrm{Severity}(r)$。因 §5 的 $C_1$ 已排除 MAY/OPTIONAL，进入生成的义务必属 MUST 族或 SHOULD 族，即 $\mathrm{Severity}(r) \in \{\text{Error}, \text{Warn}\}$。

**IR 填充原子模板的参数槽。** 选定原子模板只定了"用哪个检查"，还需定"检查谁、比什么"——这些参数值正来自当前规则的 IR：IR 的 **subject**（字段解析器给出的证书字段路径，如 `subjectAltName.dNSName`）填入原子的字段槽，IR 的 **constraint**（约束值或模式，如取值集合、长度区间、正则名）填入值槽。例如规则"subjectAltName 的 dNSName 必须非空"经映射与填充后实例化为 $\mathrm{FieldNonEmpty}(\texttt{DNSNames})$。

**从 IR 谓词到原子模板的映射 $\mu$。** 上游 IR 与下游 DSL 用两套词汇：IR 以**抽取阶段的谓词**描述要求（如 `must_be_present`、`encode_as`、`in_range`），DSL 以**原子模板**表达检查，二者并非一一对应。为衔接两者，本研究维护一个多对多映射 $\mu$：给每个 IR 谓词指定一组语义上能承载它的候选原子模板。例如 `must_be_present` 可由 $\{\mathrm{ExtPresent}, \mathrm{FieldNonEmpty}\}$ 对应，`in_range` 可由 $\{\mathrm{IntInRange}, \mathrm{PathLenConstraintHas}, \dots\}$ 对应——取哪个取决于被约束字段的类型。

### 6.2 类型化词汇表与参数封闭性

§6.1 描述了原子模板与 IR 填充如何将 IR 中的 subject 与 constraint 填入原子模板的参数槽——但 IR 提供的只是"这条规则实际约束的是哪个字段、什么值"，并未约束这些值的*合法类型*（IR 中的 subject 路径若指向一个不存在的字段，或在填充一个要求整数的参数槽时填入一个字符串，仍会产生结构合法但语义错位的树）。本节用一张**类型化词汇表** $\mathcal{V}$ 封住这道缺口：$\mathcal{V}$ 是七类有限集合的不相交并、在系统启动时冻结，每个原子模板参数只能取自其中某一类——证书字段名、DN 字段、OID 常量、KeyUsage 位、ExtKeyUsage 位、ASN.1 编码类型、命名正则（各类规模与样例见附录 C）。

每个原子模板都有一张签名表，规定它每个参数该取自哪一类（或基础类型整数 / 布尔 / 字符串）；调用一个原子模板合法，当且仅当它的每个实参都落在签名规定的那类集合内。记 $\mathcal{T}_{\mathcal{V}}$ 为所有参数都合法的 DSL 树集合，本研究把代码生成模块 $\phi_G$ 的值域严格限定为：任何落在 $\mathcal{T}_{\mathcal{V}}$ 内的树都不会出现 $\mathcal{V}$ 之外的字段名、OID 或正则；越界的树在解析阶段必然报错、触发修复，不会进入代码生成。

### 6.3 代码生成与可逆机械翻译

一棵合法 DSL 树 $t$ 需转化为两种产物：可执行的 Go 检查代码，以及一句概括其检查逻辑的代码摘要（code_summary）。二者的转化均由**确定性全函数完成，不调用 LLM**：渲染函数 $\rho$ 将树映射为 Go 代码，机械翻译函数 $\sigma_{\mathrm{mech}}$ 将同一棵树映射为一句 code_summary。两个函数共享以下三项性质，每项均对应验证链上的一个具体作用：

- **类型安全**：$\rho$ 不生成越界的字段、OID 或参数类型，封闭性由 DSL 树层保持至 Go 代码层。
- **决定性**：对相同的 $t$，$\rho(t)$ 与 $\sigma_{\mathrm{mech}}(t)$ 的输出唯一——这使 §6.5 的证书级执行验证可将 $\rho(t)$ 视为 $t$ 的固定函数，其执行行为不随运行次数或模型而变。
- **可逆性**：由 $\sigma_{\mathrm{mech}}(t)$ 可机械地还原 $t$（当同义原子模板被映射到同一短语时，二者不可区分），故 $\sigma_{\mathrm{mech}}$ 在验证链路中保留了 DSL 树的结构信息（命题 2，证明见附录 D）。

由此，$\rho$ 的产物通向可执行代码与证书级执行验证（§6.5），$\sigma_{\mathrm{mech}}$ 的产物通向同义性验证——即将 code_summary 与规范原文比对、判断二者是否语义等价。

### 6.4 树合成：确定性主路径与受限 LLM 回退

上文描述了 §6.1 的 IR 填充与 §6.2 的参数封闭性如何把一棵 DSL 树约束在 $\mathcal{T}_{\mathcal{V}}$ 内，但"哪种原子模板承载哪个 IR 谓词"以及"能否把 IR 的所有 subject/constraint 填入所选原子模板"仍需合成。本节给出 $\phi_G$ 的实现：生成器先尝试确定性合成，返回 $\bot$（此处 $\bot$ 表"合成失败 / 无结果"，区别于 §6.1 表"无前提"的正常取值 $\varepsilon$）时才触发 LLM 合成。两条路径都以"渲染并通过 `go build`"为接受门——确定性合成即便返回一棵树也不足够，须真能通过编译，否则视同未解决、转入 LLM 合成。两条路径都受同一套结构检查约束，且都不判定"代码是否忠实于规范"（这由 §6.5 的验证链负责），只把产出约束在可追溯的空间内。

**确定性主路径。** 当 IR 谓词能经 $\mu$ 选定原子模板、且其 subject 与 constraint 能填满该原子模板的参数槽时，生成器即按预定义规则确定性地**归约**出一棵 DSL 树——此处"归约"指依固定规则将 IR 逐步推导为一棵 DSL 树，全程不调用 LLM。本研究多数 lintable 规则由这条确定性路径覆盖。

**受限 LLM 合成。** 当确定性合成返回失败时，生成器转入 LLM 合成——模型获得规则上下文、结构化 IR、候选原子模板集，以及 $\mathcal{V}$、$\mathcal{A}$ 的可读枚举与签名表（实际提示的四区段拼接见附录 E），只输出两种结果之一：一棵序列化的 DSL 树，或一个显式的"无模板"弃权标记 $\perp_{\mathrm{NT}}$（$\perp_{\mathrm{NT}}$ 与合成失败 $\bot$ 同属"无可用结果"，故共用 $\bot$ 形；而 $\varepsilon$ 表示正常的"无前提"）。LLM 原始输出先经解析函数 $\eta$ 校验——$\eta$ 将其解析为合法 DSL 树 $t \in \mathcal{T}_{\mathcal{V}}$、类型错误或 $\perp_{\mathrm{NT}}$，任何 $\mathcal{V}/\mathcal{A}$ 之外的标识符在此被拒；通过后的树经渲染 $\rho$，再由确定性后处理器 $\Phi_{\mathrm{post}}$ 绑定 `Description`/`Citation`/`Name` 及各规范源元数据（细节见附录 C、E）。

![](figures/fig6_restricted_codegen_factory.png)

_图 3：受限代码工厂。IR 经过 $\mu$ 和词汇封闭门进入 $\mathcal{T}_{\mathcal{V}}$，再由确定性渲染 $\rho$ 与机械翻译 $\sigma_{\mathrm{mech}}$ 输出 Go 代码和可逆摘要；只有 $\bot$ 分支才允许进入 LLM 合成。_

### 6.5 三层语义对齐验证

生成的代码是否如实表达了规范，是全流程中最困难的判定。本节以由粗到精的三个层次回答这一问题：层 A 检验描述是否可溯源，层 B 判定代码行为是否与规范同义，层 C 检查代码能否编译且结构完整。

**层次 A：描述溯源。** 检查 `Description` 能否追溯到源文档。

**层次 B：代码行为摘要的语义对齐。** 这是核心层，它把"代码是否实现规范"这一跨模态判定，转化为"两句自然语言是否同义"这一同模态判定：先按 §6.3 的 $\sigma_{\mathrm{mech}}$（短语字典见附录 D）将代码翻译为一句"该代码检查何种约束"的 code_summary，再判定它与 `Description` 是否同义。

**层次 C：编译与结构。** 验证代码可被语法解析、函数与元数据字段完整、依赖正确导入、规则注册完成，确保产物在目标框架内结构合法、可执行。

三层以合取构成一道布尔验收门（编译 ∧ 结构完整 ∧ 同义判定通过）：层 B 的同义判定是核心信号，层 A 的溯源作为前置过滤；任一层不通过即触发 §7 的修复闭环。

**证书级执行验证：$\mathrm{Code}\equiv\mathrm{IR}$ 的执行级证据。** 层 B 的同义判定由 LLM 给出、无法完全确定化；作为补充，本文引入一项**与模型无关的确定性验证**，用以核验"生成代码是否忠实执行了它所对应的 DSL 树"（记作 $\mathrm{Code}\equiv\mathrm{IR}$）。其思想借自软件测试中的**测试预言（test oracle）**——用一组已知正确答案的样本来核对被测代码。具体分两步。

*第一步，认证单个原子模板。* 为每个原子模板构造一对受控证书样本（fixture）：一张应使该原子模板的谓词为真，另一张应使其为假。样本按原子模板的参数类型构造，不绑定任何具体规则。将渲染出的代码在两张证书上真实执行并读回判定结果；当且仅当两张证书上的结果都与预期一致时，认定该原子模板**通过认证**。

*第二步，由原子模板推广到整棵树。* 对一条持有 DSL 树 $t$ 的生成 lint，若 $t$ 仅由已认证的原子模板构成且整体编译通过，则可对树结构作归纳：叶节点（原子模板）的忠实性已由第一步保证，组合子 $\neg/\wedge/\vee$ 按经典命题逻辑求值、逐层保持忠实，故渲染代码 $\rho(t)$ 忠实执行整棵树，即 $\mathrm{Code}\equiv t$；又因 $t$ 由 IR 确定性归约而来，故 $\mathrm{Code}\equiv\mathrm{IR}$。

该验证在受控证书样本上进行，结果确定、不随运行次数或模型而变。**须强调其边界：$\mathrm{Code}\equiv\mathrm{IR}$ 只表明代码忠实于中间表示 IR，并不等于代码忠实于规范原文；若 IR 本身已偏离规范，该验证无从发现。因此最终仍以 $\mathrm{Code}\equiv\mathrm{Spec}$（层 B 同义判定）为准。**

## 7. 阶段感知式迭代验证框架（SAIV）

为在无人工真值的条件下协调各模块并保障其输出质量，本文提出**阶段感知式迭代验证框架**（Stage-Aware Iterative Verification, SAIV）。其基本思路是：预先设定若干可量化的目标，以每个目标的可计算**残差**度量当前状态与理想状态的差距；当残差未达阈值时，依据残差信号定位出现问题的模块并施加相应修复，随后进入下一轮迭代，直至各残差同时收敛。

### 7.1 形式化定义

全流程 $\Pi$ 是四个模块依次串联的复合函数——**提取 $\to$ 分类 $\to$ 生成 $\to$ 验证**：

$$
\Pi = \phi_V \circ \phi_G \circ \phi_C \circ \phi_R
$$

其中提取模块 $\phi_R$ 提取出中间表示，分类模块 $\phi_C$（§5 的四条件 lintability 判定）筛出 lintable 规则，生成模块 $\phi_G$（受限于 §6 的 DSL 代码空间 $\mathcal{T}_{\mathcal{V}}$）合成检查代码，验证模块 $\phi_V$（§6 的三层语义对齐）负责验收。这里 $\phi_C$ 是 §5 定义的**单规则**lintability 谓词（$r \mapsto \{0,1\}$）；算法 1 中出现的 $\psi_C$ 则是它的**集合级**提升：先从关键词召回集 $\mathcal{R}_{\mathrm{kw}}$ 剔除 Layer-1 假阳性、得到噪声集 $\mathcal{R}_N$，再对其余真实规则逐条施加 $\phi_C$，输出三分区 $(\mathcal{R}_N, \mathcal{R}_L, \mathcal{R}_U)$。SAIV 依据这些模块产生的可计算信号选择下一轮修复操作。

### 7.2 三个迭代目标（优化标签）

SAIV 借鉴反向传播的思路：先定下整个流程要优化的目标，再根据可计算信号选择下一轮修复操作。本节先给出这三个目标，后续各节都围绕逼近它们展开。

每个目标都有一个能直接算出来的残差，当三个残差同时为零，整个流程就算收敛。三个残差的形式各不相同：

- **G1（召回完整性）**：

  **定理 1（召回完整性不变量）**。*若 $\phi_R$ 对由 RFC 2119 关键词触发正则匹配，则以下守恒关系成立：*
  $$
  |\mathcal{R}_{\mathrm{kw}}(\mathcal{D})| = |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U| \tag{3}
  $$

  式中 $\mathcal{D}$ 为标准文档语料（算法 1 的代码块内以 ASCII 记作 D），$\mathcal{R}_N$ 为噪声（虽含 RFC 2119 关键词但不是真正的规则）、$\mathcal{R}_L$ 为 lintable 规则、$\mathcal{R}_U$ 为 not lintable 规则。可执行类 $\mathcal{R}_L$ 进一步按"是否已被现有外部 lint 工具实现"二分：

  $$
  |\mathcal{R}_L| = |\mathcal{R}_L^{\mathrm{cov}}| + |\mathcal{R}_L^{\mathrm{uncov}}| \tag{4}
  $$

  其中 $\mathcal{R}_L^{\mathrm{cov}}$ 为已被某 lint 工具覆盖的规则、$\mathcal{R}_L^{\mathrm{uncov}}$ 为尚未覆盖的规则。第一式（式 3）是召回到分类的总量守恒，第二式（式 4）则把可执行集拆开，以便后续目标分别实现：未覆盖子集 $\mathcal{R}_L^{\mathrm{uncov}}$ 是生成"补生态空白"的最重要观测域，已覆盖子集 $\mathcal{R}_L^{\mathrm{cov}}$ 则给出反向可执行性的外部证据。

  残差为召回守恒残差 $\mathcal{L}_{\mathrm{recall}}$，无需人工真值即可计算，当前已闭合（§8.1）。

- **G2（未覆盖规则的代码—规范同义）**：对于未覆盖子集 $\mathcal{R}_L^{\mathrm{uncov}}$，要求代码摘要 $\sigma_{\mathrm{mech}}(t_r)$（规则 $r$ 的 DSL 树 $t_r$ 的 code_summary，$\sigma_{\mathrm{mech}}$ 见 §6.3）与规范原文同义。残差为代码忠实残差 $\mathcal{L}_{\mathrm{code}}$。

- **G3（已覆盖规则的反向可执行性）**：规则若在 zlint 等 lint 工具中存在对应实现，则必然 lintable，目标是违反计数 $N_{\mathrm{viol}}=0$。

在此标签之上，SAIV 把三类质量信号形式化为可计算残差：**召回守恒残差** $\mathcal{L}_{\mathrm{recall}}$（附录 F 式 6）以对称归一化度量定理 1 的理想恒等被违反的程度；**代码忠实残差** $\mathcal{L}_{\mathrm{code}}$（附录 F 式 7）是 lintable 集上正确性标签的平均缺口；二者加权为**总损失** $\mathcal{L}_{\mathrm{total}}$（附录 F 式 8，默认 $w_R=w_C=0.5$）。第三类是双判定源一致性残差 $N_{\mathrm{viol}}$（§7.4）。

| 目标 | 残差 | 主要修复方向 | 修复对象 |
|---|---|---|---|
| G1 召回完整性 | $\mathcal{L}_{\mathrm{recall}}$（附录 F 式 6） | — | 召回逻辑 |
| G2 同义性 | $\mathcal{L}_{\mathrm{code}}$（附录 F 式 7） | IR 内容、DSL 生成、验证判定三类修复 | IR 内容修正 / DSL 树重合成 / 判定与摘要复核 |
| G3 双判定源一致 | $N_{\mathrm{viol}}$（§7.4） | 验证判定一致性修复 | $\phi_C$ 假阴性 / 外部覆盖标签假阳性 |

表中只给出目标到修复方向的对应关系；具体修复操作及其记号在 §7.3 中定义。

![](figures/fig7_saiv_control_console.png)

_图 4：SAIV 控制台。上排显示召回→分类→生成→验证四阶段，下排显示 G1 / G2 / G3 三个残差与对应修复路由；当残差同时低于阈值时终止。_

### 7.3 阶段路由与修复操作

**阶段路由。** 每轮用可直接计算的量选择下一步修复操作：召回守恒残差、lintable 集上的编译失败率、平均结构得分、实体必要条件筛查结果与同义置信度。该路由只决定下一轮尝试哪类修复。

**修复操作。** SAIV 包含 IR 内容修复、分类修复、生成修复与验证修复四类操作，分别记为 $\mathcal{P}_R / \mathcal{P}_C / \mathcal{P}_G / \mathcal{P}_V$（下标与被修模块 $\phi_\bullet$ 一一对应；修复算子 $\mathcal{P}$ 与 §6.3 的渲染函数 $\rho$ 是不同符号，须加区分）。路由器根据上述信号选择下一轮操作；修复仅在指标下降时接受。

- **IR 内容修复 $\mathcal{P}_R$**：当路由器选择该操作时，把失败轨迹——当前 IR、不可归约类别、机械摘要、评判器裁定与理由、同义置信度、本会话已试过的历史 IR——回传 LLM，要求其输出 `REPAIR(ir')` 或 `NO_FIX`。
- **分类修复 $\mathcal{P}_C$**：修复四条件框架对应字段的提取，重新提取 IR，修复 lintability 判断。
- **生成修复 $\mathcal{P}_G$**：先试确定性修复；失败则把失败码片段与 IR 约束差异、或解析阶段的原子模板签名/封闭性错误作为反馈注入提示、触发 LLM 在 $\mathcal{T}_{\mathcal{V}}$ 内重新合成；若持续弃权，则进入离线词汇扩展通道 $\mathcal{P}_A$——分析弃权原因、在受控数据集上训练新原子模板候选、经证书级执行验证认证后并入 $\mathcal{A}$。
- **验证修复 $\mathcal{P}_V$**：扩大同义判定的语义邻域，如允许否定/肯定互换、一对多分解，或修正双判定源输出之间的不一致。

### 7.4 迭代算法与终止条件

算法 1 给出完整流程。

```
算法 1：阶段感知式迭代验证（SAIV），自动闸门负责回路内验收
输入：标准文档 D，阈值 θ，最大迭代数 K
输出：最终代码集 C* 与终止状态 status

 1:  R_kw ← φ_R(D);  (R_N, R_L, R_U) ← ψ_C(R_kw)              // R_U = not lintable
 2:  (R_L^cov, R_L^uncov) ← Coverage(R_L)                     // 算法 2；仅未覆盖子集需自生成
 3:  C ← {φ_G(r) : r ∈ R_L^uncov}
 4:  t ← 0
 5:  repeat
 6:      计算残差 L_recall(式6), L_code(式7), N_viol(§7.4)
 7:      if 全部残差 < θ then break                       // 多目标同时闭合
 8:      stage ← StageAttribution(...)                    // 式(9)
 9:      if stage = φ_R then                              // IR 内容修复
10:          for each r routed to P_R do
11:              rep ← P_R(失败轨迹(r))                    // 自反思，返 REPAIR(ir') 或 NO_FIX
12:              if rep = NO_FIX  or  对照原文重抽结构校验(rep.ir', text(r)) ≠ ∅ then
13:                  将 r 记入不可归约集 R_irred           // 自动闸门否决 ⇒ 诚实保留为残差
14:              else if 重测(rep.ir') 通过（归约 ∧ 认证 ∧ 编译 ∧ 忠实）then
15:                  IR(r) ← rep.ir'                      // 接受修复
16:      else apply P_stage ∈ {P_C, P_G, P_V}             // 并列，按路由分支触发
17:      更新 (R_N, R_L, R_U, R_L^uncov) 与 C
18:      t ← t + 1
19: until t ≥ K 或 本轮无任何残差下降（loop-until-dry）
20: return (C, status ∈ {closed, dry, max_iter})
```

**终止条件**：$\mathcal{L}_{\mathrm{total}}<\theta$（默认 0.05）、达最大迭代 $K=10$、或本轮无残差下降。若每个被采纳的阶段修复操作都单调（减少该阶段误差或不变），则 $\mathcal{L}_{\mathrm{total}}$ 每轮非递增；实际系统用"无下降即停止"策略，故保证有限轮终止，但不保证全局最优（见 §8）。

## 8. 实验评估

本章使用前文提到的方法和框架进行实验，并得出量化结论。除内部分层指标（§8.1–8.2）外，本章给出**两道相互独立的外部验证**，分别检验框架的两个半段：§8.3 以 zlint 维护者的人工金标外部验证**规则提取与 lintability 判定**，§8.4 以真证书上的执行外部验证**代码生成与同义判定**。

### 8.1 实验设置与结果快照

评测在 RFC 5280 与 CABF BR 两个标准源的全库重抽结果上进行。实验中所使用的 LLM 为 GPT-5.4。

**表 1：端到端结果当前快照（RFC 5280 + CABF BR）**

| 指标 | 数 | 口径/说明 |
|---|---:|---|
| 召回规则总量 | 2077 | RFC 5280 637 + CABF BR 1440 |
| **lintable（单证书可观测）** | **248** | 当前重抽取/重判定后的 lintability 口径：CABF 170 + RFC 5280 78；过程、跨证书、运行时、外部语义和 MAY/OPTIONAL 许可类规则不进入分母；CRL 文档规则不在本口径 |
| zlint 覆盖（full，原生 lint） | **158** | 该规则已被某条 zlint 原生 certificate lint 完整实现；CABF BR 规则允许由继承适用的 RFC 5280 lint 覆盖 |
| **未覆盖 lintable（codegen 定义域）** | **90** | 需本系统生成自有 lint（248 − 158），即下游代码生成 $\phi_G$ 的目标集；CABF 64 + RFC 5280 26 |
| **能生成可编译 lint** | **90** | 两路均以"渲染并 `go build` 通过"为接受门；**代码生成率 = 90/90 = 100.0%** |
| 其中：确定性生成 | **87** | 由受限 DSL 规则、原子模板和确定性渲染直接生成 |
| 其中：LLM 回退生成 | **3** | 确定性路径不能直接闭合时调用 LLM 生成 DSL 树，仍需通过受限 DSL 与编译门 |
| 不能生成（无树 / 不编译 / 弃权） | **0** | 当前定义域内无生成失败 |
| **最终发射严格同义（$\mathrm{Code}_{\mathrm{zlint}}\equiv\mathrm{Spec}$）** | **90** | 以最终注入 zlint 的 `CheckApplies`、`Execute`、severity/date 元数据整体对比原文规则和上下文；**final shipping strict 同义率 = 90/90 = 100.0%** |
| 最终发射不同义（DNE） | **0** | 当前 codegen 定义域内无最终发射不同义残差 |
| 发射 lint 实际触达原子模板 | **52** | 90 条发射 lint 的主断言与前提中出现的唯一原子模板数；28 个 GENERIC、24 个 NON_GENERIC；登记全集 136 个中其余 84 个未被本次发射集触达 |
| 发射 lint 原子使用：GENERIC-only | **53** | 规则的主断言与前提只使用 GENERIC 原子模板 |
| 发射 lint 原子使用：GENERIC + NON_GENERIC | **5** | 同一规则同时使用 GENERIC 与 NON_GENERIC 原子模板 |
| 发射 lint 原子使用：NON_GENERIC-only | **32** | 规则的主断言与前提只使用 NON_GENERIC 原子模板 |
| *（旁证）证书级执行验证 $\mathrm{Code}\equiv\mathrm{IR}$* | *37* | *IR 级忠实性证据、非同义率分子；正文同义率只采用最终发射代码与原文规则的严格判定* |

表 1 的代码生成率和同义率均以后端当前定义域逐条核算，不使用旧的 row-level 片段同义口径。row-level 评判只保留为调试诊断；论文口径下，只有最终编译进 zlint 的发射代码整体表达原文规则时，才计入 $\mathrm{Code}_{\mathrm{zlint}}\equiv\mathrm{Spec}$。R31068 原先暴露出"已存在 `rfc822Name` 后检查编码"不能表达"Internet mail address 必须选择 `rfc822Name` GeneralName"的问题；该条已按重新提取/重新判定 lintability 的路径归入 not lintable，因为单张证书暴露的是已选择的 GeneralName tag 和值，而非签发者在编码前的外部身份意图。

第一层质量信号是 G1 守恒（§7.2 定理 1）：关键词召回的规则总量，在下游任何分类步骤中都不应增减。当前快照下守恒严格成立：

$$
\underbrace{2077}_{\text{召回}} \;=\; \underbrace{522}_{\text{噪声}} + \underbrace{1555}_{\text{真规则}}, \qquad \underbrace{1555}_{\text{真规则}} \;=\; \underbrace{248}_{\text{lintable}} + \underbrace{1307}_{\text{not lintable}}.
$$

两式逐项相等，即 G1 残差 $\mathcal{L}_{\mathrm{recall}} = 0$、守恒顶两层闭合（数据见 §8.1，可确定性复算）。lintable 的 248 条按标准源分为 CABF 170 条与 RFC 5280 78 条；其中 zlint 已完整覆盖 158 条，余 **90 条**即下游代码生成 $\phi_G$ 的定义域。

### 8.2 lint 覆盖分析

要回答"现有工具覆盖了多少 lintable 规则"，关键在于用对判据。本文以"该 lintable 规则是否被某条 zlint 原生 certificate lint 真正实现"为判据，而非要求规则来源与 lint 的 `Source` 元数据完全相同。若 CABF BR 规则语义继承自 RFC 5280 且已被 RFC 5280 原生 lint 完整实现，则计为已有工具覆盖。对每条规则检索候选 zlint lint，再逐字段（subject / obligation / predicate / constraint）比对，给出 full（完整实现）/ partial（部分实现）/ none（无实现）三档裁定。

算法 2 形式化该判定：把 lint 摘要为反向 IR、再逐字段对齐，候选检索按 source/section 并显式允许 CABF BR 规则进入 RFC 5280 候选池（Stage-1）、新增"错字段"一致性闸门（Stage-3，只降不升）、覆盖只计 full（Stage-4，partial/none 归 $\phi_G$）。

```
算法 2：lintable 规则的 zlint 覆盖对齐判定（规则索引）
输入：lintable 规则集 B = {b_1,…,b_m}（每条带 IR 四元组 ⟨主体, 义务, 谓词, 约束⟩、source、section）；
      zlint lint 集 L = {ℓ_1,…,ℓ_n}（每条带 description/citation/severity 元数据与 Pass/Error 测试）；
      离线代码摘要器 M_summ、字段级评判器 M_judge（temperature=0）
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
10:          C(b) ← L_CABF ∪ L_RFC                     // CABF profile 继承 RFC 5280，允许跨标准覆盖
11:      else  C(b) ← ∅
12:      // Stage-2：字段级评判器，逐字段比对四元组，跨候选取最优档
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

其中 SectionPrefixMatch 在规则章节号与某 lint 引用章节号有公共前缀时为真；Family(·) 把主体路径映射到具体字段族，对模糊/未解析主体返回 ∅ 而不降级（粗主语的真匹配得以保留）。算法仅 Stage-0、Stage-2 调用 LLM（评判器 temperature=0，提示含方向反转/字段错位/约束类型混淆三类正反例），摘要离线缓存、CABF 全集候选分批送评判器，其余确定性。

248 条 lintable 规则中，**zlint 完整覆盖 158 条、未覆盖 90 条**（表 2）；未覆盖的 90 条即代码生成 $\phi_G$ 的定义域。

**表 2：zlint 原生 lint 数，及其对 248 条 lintable 规则的覆盖（按规则源）**

| 项 | CABF | RFC 5280 | 合计 |
|---|---:|---:|---:|
| *zlint 原生 lint 总数（参照）* | *170* | *122* | *292* |
| *　— 其中证书 lint（单证书口径）* | *164* | *115* | *279* |
| *　— 其中 CRL lint（单证书口径外）* | *6* | *7* | *13* |
| full（完整覆盖） | 106 | 52 | **158** |
| 未覆盖（codegen 定义域） | 64 | 26 | **90** |
| lintable 合计 | 170 | 78 | **248** |

前三行（斜体）为 zlint 侧按其 `Source` 元数据字段从项目内置 v3 源码直接计得的 lint 数（单位：lint，13 条 CRL lint 经 `RegisterRevocationListLint` 识别、不属本文单证书口径）；其余各行为我方 lintable 规则的覆盖档（单位：规则）。full 计的是"我方某条规则是否被某条 zlint 原生 lint 完整实现"，不要求同源；与 zlint lint 总数不构成简单比值主要原因是一条 lint 可命中多条规则。

### 8.3 lintability 外部验证：检验规则提取与 lintability 判定

本框架的前半段——规则提取与 lintability 判定——需要用独立外部资料对照。为此，本文引入 zlint 维护者公开的 CABF BR 映射表 [37]：该表由 zlint 专家逐条人工标注"某条 BR 要求是否可被静态 lint 表达"，与本文的提取器、IR、lintability 判定器互不知情。表中每一个 Yes/No 标签，正对应本文对同一条规则的"提取出该规则 + 判定其是否 lintable"这一联合输出；二者一致即表明本系统的规则提取与 lintability 判定与人类专家相符。表覆盖 BR 1.4.8 和 BR 2.0.2 两个版本，分别与本文按相同双层流水线提取的 CABF-Server-1.4.8 后端（422 条）、CABF-Server-2.0.2 后端 [38]（1024 条）进行同版本对照。

**表 3：BR 1.4.8 / BR 2.0.2 同版本外部验证**

| 版本         | Sheet 行数 (Yes / No) | 后端规则数 | **匹配覆盖率** | Yes 召回率 | TP / FN / FP / TN | 一致率 | **Cohen's κ** | Yes 精确率 |        F1 |
| ------------ | --------------------: | ---------: | -------------: | ---------: | :---------------: | -----: | ------------: | ---------: | --------: |
| **BR 1.4.8** |         122 (75 / 47) |        422 |      **86.9%** |      87.0% |  60 / 9 / 0 / 37  |  91.5% |     **0.823** |      1.000 |     0.930 |
| **BR 2.0.2** |        250 (17 / 233) |       1024 |      **86.8%** |      50.0% |  6 / 6 / 1 / 204  |  96.8% |         0.616 |      0.857 |     0.632 |

匹配覆盖率指 sheet 行能够路由到同版本后端规则的比例；TP/FN/FP/TN、κ、Yes 精确率、Yes 召回率与 F1 均只在这些已匹配行上计算。两版的匹配覆盖率几乎一致（86.9% vs 86.8%），但分类表现并不相同：BR 1.4.8 的 Yes 召回率为 87.0%，BR 2.0.2 则为 50.0%。BR 2.0.2 一致率高至 96.8% 是因为该 sheet 的 Yes-标签仅占 6.8%（17/250），朴素 all-No 基线一致率即达 93.2%；κ 在校正这种类别不平衡后给出更真实的判别力评估。BR 1.4.8 sheet 的 Yes/No 分布更均衡（75/47），κ=0.823 更直接地反映了 CICAS 与外部金标的实际一致性。两版上 Yes-precision 均高（≥0.86），但 BR 2.0.2 的 Yes-class F1 受较低召回率影响降至 0.632。

**这一外部验证检验的是系统前半段。** BR 1.4.8 上 κ=0.823、Yes 召回率 87.0%，说明本文的规则提取（从 422/1024 条后端中识别出哪些是真规范要求）与 lintability 判定（四条件合取，§5）与 zlint 专家的独立人工判断高度一致；BR 2.0.2 上的 50.0% Yes 召回率则表明较新 BR 版本中仍存在明显假阴性空间。该验证并不检验下游的代码生成与同义性；后者由 §8.4 的证书检测在真证书上补充检查。

### 8.4 证书检测

把 final-shipping strict 同义门通过的 90 条 `cicasgen_` lint 注入 zlint 二进制、检测证书，检验代码生成与同义判定。本文只把满足三项条件的命中计为有效问题：最终 zlint 代码语义已回到原文核对；证书运行产生非 pass 结果；独立结构审计能从 DER/openssl 重新推出同一缺陷。对外部语料，还要求没有原生 zlint lint 同时标记该证书，从而避免把已有工具覆盖误记为新生成 lint 的发现。表中计数单位为"证书 × lint" finding；若同一证书违反两条规则，计为两项问题。

zlint 自带 testdata 用作门禁语料而非现实生态估计：1128 张可解析证书上产生 2627 条 `cicasgen_` 原始命中，其中 299 条经独立审计确认（251 条 Error、48 条 Warn），2328 条为 `NOCHECK`，不纳入可靠问题声称。外部语料包括 Tranco Top 1M 域名 TLS 握手链去重后的 47,791 张 PEM，以及近期 CT 日志样本去重后的 63,327 张 PEM。Tranco 上原始 `cicasgen_` 命中 44,020 条，经 no-upstream 独立审计后严格确认 6 条；CT 上原始命中 57,558 条，经同一口径严格确认 1 条。两份外部语料按来源相加为 7 条严格确认 finding；合并去重后为 6 个证书-lint finding、5 张唯一证书，其中 1 条 Root CA CRLDP 警告同时出现在 Tranco 与 CT。

**表 4：三类证书语料中的严格确认问题（按严重度从高到低）**

| 严重度 | 问题类型与对应原文义务 | testdata 独立确认 | Tranco 严格确认 | CT 严格确认 | 外部合并去重 | 证据边界 |
|---|---|---:|---:|---:|---:|---|
| Error | 订户证书 Certificate Policies 必须包含 exactly one CABF Reserved Certificate Policy Identifier（BR §7.1.2.7.9） | 113 | 1 | 0 | 1 | Tranco 中 1 张 leaf 证书缺少 CABF reserved policy OID；无原生 zlint 重叠 |
| Error | AKI 禁止出现 `authorityCertSerialNumber` / `authorityCertIssuer`（BR §7.1.2.11.1） | 32 | 2 | 0 | 2 | Tranco 中同一张 CA 证书同时违反两个 AKI 子字段约束；无原生 zlint 重叠 |
| Error | 订户证书 Certificate Policies 禁止 `anyPolicy`（BR §7.1.2.7.9） | 26 | 0 | 0 | 0 | 仅在 testdata 夹具中确认 |
| Error | IV/OV subject profile 字段约束：`surname`、`givenName`、`localityName` / `stateOrProvinceName` 条件出现或禁止出现（BR §7.1.2.7.3-§7.1.2.7.4） | 57 | 0 | 0 | 0 | 仅在 testdata 夹具中确认 |
| Error | 其他结构性强制约束：SAN critical、`signatureAlgorithm` 与 `tbsCertificate.signature` 一致、订户 `pathLenConstraint` 禁止出现、空 Certificate Policies、v1 uniqueID 禁止出现（RFC 5280 / BR） | 23 | 0 | 0 | 0 | 仅在 testdata 夹具中确认 |
| Warn | 仅含基本字段的证书版本 SHOULD 为 v1（RFC 5280 §4.1.2.1） | 47 | 0 | 0 | 0 | 建议性规则，作为 `lint.Warn` 报告；不表述为硬错误 |
| Warn | Root CA Certificate SHOULD NOT 包含 CRL Distribution Points（BR §7.1.2.11.2） | 1 | 3 | 1 | 3 | 外部为 advisory profile 警告；CT 的 1 条与 Tranco 中同一 Root CA 证书重复 |

因此，若按严格确认口径计数，testdata 中有 299 条夹具级问题，Tranco 中有 6 条真实证书问题，CT 中有 1 条真实证书问题；外部真实证书合并去重后为 6 条问题。raw 命中率只用于发现待审计候选，不用于论文中的缺陷数量结论。

## 9. 讨论

### 9.1 跨 PKI 的适用性

本框架的核心机制并不特定于 PKI：Layer 1 的 RFC 2119 关键词集可经配置替换为其他生态的道义关键词（如 ISO 的 shall/should/may）。方法适用于同时满足三条件的规范源：**(1)** 以可识别的形式化道义关键词表达强制/推荐；**(2)** 约束目标是结构化、可机器解析的产物（证书、协议消息、配置文件）；**(3)** 具备支持知识图谱与作用域继承的层级化章节结构。这使其方法学价值超出 PKI 单一领域。

### 9.2 对规范作者与工具维护者的建议

对**规范作者**，三条起草原则可降低提取歧义：单句单义务、以 ASN.1 路径而非代词精确引用字段、用固定模式规范化跨文档引用。对 **lint 维护者**，建议把 `description` 直接写成显式给出字段路径/断言类型/取值/严重级别并引用规范条款的 code_summary——本研究发现大量 lint 描述既非规范引用、也非实现忠实摘要，致使覆盖分析必须先做一步 code_summary 才能对齐，额外增加开销与裁决噪声。

### 9.3 跨标准覆盖口径

覆盖分析曾暴露出一个重要口径风险：若只按 `Source` 元数据做同源候选检索，部分出自 CABF BR 的规则会被误判为未覆盖，尽管其语义已由 zlint 中既有的 **RFC 5280** lint 实现。当前 §8.2 的覆盖判定已显式允许 CABF BR 规则进入 RFC 5280 候选池；下表列出该修正覆盖的代表性跨标准继承情形。

| CABF BR 规则（跨标准覆盖） | 条数 | 实现它的 zlint lint（原生 source/citation） |
|---|---:|---|
| `issuerUniqueID` / `subjectUniqueID` MUST NOT be present（7.1.2.1/2/8） | 6 | `e_cert_contains_unique_identifier`（RFC 5280:4.1.2.8） |
| `signatureAlgorithm` byte-for-byte 匹配 `tbsCertificate.signature`（7.1.2.2） | 1 | `e_cert_sig_alg_not_match_tbs_sig_alg`（RFC 5280:4.1.1.2） |
| 订户/OCSP 证书 `pathLenConstraint` MUST NOT be present（7.1.2.7.8/8.4） | 2 | `e_path_len_constraint_improperly_included`（RFC 5280:4.2.1.9） |

成因是合规口径的跨标准继承：CABF BR §7.1.2 开篇声明其证书 profile "incorporate, and are derived from RFC 5280"，且 RFC 5280 施加的规范性要求同样适用。uniqueID 禁止、signatureAlgorithm 一致、pathLenConstraint 限制等本是 RFC 5280 要求，被 CABF BR 以 profile 表格形式再次列明。当前算法把这类 RFC 5280 原生 lint 视作 CABF BR 规则的有效候选，因而这些规则不再误入 codegen 定义域。该设计同时要求字段级覆盖评判仍回到原文主体、义务、谓词与约束逐项比对，避免把"同一标准族"误当成"同一规则"。

### 9.4 局限性与有效性威胁

本文结论严格受限于所用输入表示（结构化 IR）、受限代码空间与验证流程，更适合可在单文档上下文闭合的静态约束，不应外推为"所有 PKI 规范均可完全自动化"。七类边界：**(i) 方法表达力**——同义判定端点仍由 LLM 实现，系统登记的 136 个原子模板中本次发射集实际触达 52 个，对字节级编码、宿主未暴露字段、动态约束等仍有缺口；**(ii) 组件必要性未消融**——知识图谱/受限 DSL/SAIV 的支持分别为工程取舍、架构论证与未消融项，本文不主张图检索相对普通 RAG 的量化优越性；**(iii) 现代 LLM 基线缺位**——直接生成 Go 的对比未做，但证书级执行验证与具体生成器无关，使其成为定义明确的未来工作；**(iv) 覆盖与泛化边界**——lintable 总量 248 与 codegen 目标 90 不同口径，跨体系泛化本文仅给机制论证；**(v) 端到端口径**——"代码≡规范"仅对 90 条 final-shipping strict 发射 lint 成立（§8.1、§8.4），lintability 标签未对全部 248 条穷尽人工审计；**(vi) 同义端点盲区**——最终发射代码同义由比对 zlint 代码摘要与原文的 LLM 评判器给出，并非证书级执行验证那种与模型无关的检查，且其"原文"取自抽取时逐字记录的 rule_text 与源上下文；因此若原始片段或 IR 已遗漏语义，同义评判器未必能独立发现。**(vii) 跨标准覆盖边界**——§8.2 已允许 CABF BR 规则由 RFC 5280 原生 lint 覆盖，但该判断仍依赖字段级语义比对；若源上下文或反向 IR 摘要缺失关键条件，覆盖档仍可能被高估或低估。此外生成 lint 以 `cicasgen_*` 前缀与 zlint 两端互拒以防"自己覆盖自己"。

## 10. 结论

本文研究 PKI 规范到合规检查代码的端到端自动化，核心问题是如何在缺少逐条人工真值时，把规范规则、lintability 边界、生成代码和验证证据放在一条可复核链路上。实验表明，RFC 5280 与 CABF BR 中只有一部分真规则可还原为单证书静态 lint；在这些规则中，现有 zlint 仍存在可量化的原生覆盖缺口，本文系统可为未覆盖规则生成一批可编译、可审计的候选 lint。

最重要的结论是负向的：$\mathrm{Code}\equiv\mathrm{IR}$ 与 $\mathrm{Code}\equiv\mathrm{Spec}$ 不能混为一谈。证书级执行验证能把可认证子集上的 IR 级忠实性确定化，但最终代码是否表达规范本身仍需要独立同义判定和执行证据支撑。外部验证分别覆盖这条链路的两半：zlint 人工金标检验规则提取与 lintability 判定，真证书执行检验发射 lint 的结构命中。由此，本文的方法学主张是：验证链路中能确定化的环节应尽量确定化，同时必须诚实披露不能归约、不能消融或仍依赖语义评判器的边界。

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

系统内部使用一个机器可读的 IR 对象（JSON 序列化）。除 §4.4 核心四元组外，其关键字段如下；其余字段支持溯源、归一化、匹配与下游产物生成。lintability 判定（§5）只直接使用 obligation、assertion_subject、enforcement_phase、rule_category 四个字段。

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

**命题 1（词汇封闭性）**：若 DSL 树 $t$ 的某个叶参数标识符不属于 $\mathcal{V}$ 中签名所要求的分量，则解析函数 $\eta$ 必判其为错误、$t \notin \mathcal{T}_{\mathcal{V}}$；等价地，任何 $t \in \mathcal{T}_{\mathcal{V}}$ 都不含 $\mathcal{V}$ 之外的字段名、OID 或正则。该性质由 $\mathcal{V}$ 的有限枚举与每个原子模板的类型化签名 $\mathrm{sig}(a)$（§6.2）确定性保证。

**代表性原子模板。** 原子模板集 $\mathcal{A}$（登记全集 $|\mathcal{A}|=136$）按语义簇组织，每个原子模板有类型化签名 $\mathrm{sig}(a)$（§6.2）。下表按簇节选关键原子模板（完整 136 项随代码与数据一并公开）；本次 90 条 final-shipping strict 发射 lint 实际触达其中 52 项。

| 簇 | 原子模板 | 签名 | 语义 |
|---|---|---|---|
| I 扩展存在性 | `ExtPresent` / `ExtCritical` | $(\mathcal{O})$ | 扩展 OID 存在 / 存在且 Critical 位置位 |
| II 宏属性 | `IsCA` / `KeyUsageHas` / `ExtKeyUsageHas` | $()$ / $(\mathcal{B}_{\mathrm{KU}})$ / $(\mathcal{B}_{\mathrm{EKU}})$ | BasicConstraints.cA=true / KeyUsage 位 / EKU 项 |
| III 字段值/形态 | `FieldEq` / `FieldMatchesRegex` / `FieldEncodedAs` | $(\mathcal{F}, \cdot)$ | 字段等于字面量 / 匹配命名正则 / ASN.1 编码类型 |
| IV 列表/字节级 | `ListAllMatch` / `OidListContains` / `BytesContainsOidDer` | $(\mathcal{F}, \cdot)$ | 列表全部满足子树 / 含命名 OID / 字节含 OID 的 DER |
| V NameConstraints | `SubtreeIPListAnyHasOctetCountAndNotAllZero` | $(\mathcal{F}, \mathbb{Z})$ | NC IP 子树存在指定字节数且非全零项 |
| VI 特殊结构 | `DomainComponentOrdered` | $()$ | domainComponent 按 RFC 4519 反向排列 |

组合子 $\{\neg, \wedge, \vee\}$ 三个，语义遵循经典命题逻辑。

**原子模板的通用性分级（GENERIC / NON_GENERIC）。** 原子模板按两条正交判据分级（与参数个数无关）：一个原子模板是 **GENERIC** 当且仅当 (1) 它表达一类*通用* PKI 概念——可跨规则复用的一类证书属性判定——且 (2) 它参数化于字段/值、不绑定任何特定 rule_id 或语料特有 OID/单一条款；否则为 **NON_GENERIC**（其逻辑特化于某扩展的内部结构或单一 RFC/CABF 条款，即便带参数，语义也固定于该构造）。零参原子模板可属任一类（`IsCA` 为 GENERIC，`NotAfterIsNoExpirySentinel` 为 NON_GENERIC）。该分级在代码中固化为 `GENERIC_ATOMS` / `NON_GENERIC_ATOMS` 两个集合并带分区完整性断言，可确定性复算。

$\mathcal{A}$ 的 136 个登记原子模板中 **82 个 GENERIC、54 个 NON_GENERIC**；本次 90 条 final-shipping strict 发射 lint 实际触达 **52 个唯一原子模板**，其中 **28 个 GENERIC、24 个 NON_GENERIC**。下表只列出 NON_GENERIC 的代表性示例；完整清单随代码与数据公开。

| 代表性 NON_GENERIC 原子模板 | 特化对象 | 语义 |
|---|---|---|
| `SigAlgMatchesTBSSignature` | 证书签名算法字段 | 外层 `signatureAlgorithm` 与 `tbsCertificate.signature` 逐字节一致 |
| `NotAfterIsNoExpirySentinel` | 有效期哨兵值 | `notAfter` 是否为特定 no-expiry 哨兵时间 |
| `DomainComponentOrdered` | Subject DN 的 `domainComponent` | domainComponent 序列是否按 RFC 4519 约定排列 |
| `CertPolicyExplicitTextHasEncodingTagInSet` | certificatePolicies 的 explicitText | explicitText 是否使用允许的 ASN.1 字符串编码 |
| `CRLDPHasNameRelative` | CRL Distribution Points | distributionPoint 是否使用 nameRelativeToCRLIssuer 形式 |
| `SubtreeIPListAnyHasOctetCountAndNotAllZero` | NameConstraints IP 子树 | IP 子树是否存在指定字节数且非全零的项 |
| `WildcardFilter` | DNS 名称模式 | 域名通配符是否满足特化过滤规则 |

允许 NON_GENERIC 原子模板进入代码生成（它们对应真实的 PKI 构造，并非为扩充语料而人为堆砌），但要求显式标记并披露其占比：**90 条 final-shipping strict 发射 lint 中，53 条完全由 GENERIC 原子模板构成，5 条同时使用 GENERIC 与 NON_GENERIC 原子模板，32 条完全由 NON_GENERIC 原子模板构成**。

**渲染与元数据绑定。** 所有 DSL 树经 $\rho$ 渲染后嵌入一个固定的 zlint Go 外壳（`RegisterCertificateLint` 注册、`CheckApplies`/`Execute` 方法对），规则间差异完全集中在检查体与导入；$\Phi_{\mathrm{post}}$（§6.4）确定性绑定 `Description`/`Citation`/`Name` 与各规范源的 `PACKAGE`/`SOURCE`/`EFFECTIVE_DATE` 元数据（如 RFC5280$\mapsto$`RFC5280`、CABF-TLS-BR$\mapsto$`CABFBaselineRequirements` 等）。义务级别到严重度的映射为 MUST/MUST NOT/SHALL/SHALL NOT/REQUIRED $\mapsto$ `lint.Error`（lint 名前缀 `e_`）、SHOULD/SHOULD NOT/RECOMMENDED $\mapsto$ `lint.Warn`（`w_`）；MAY/OPTIONAL 已在 §5 的 $C_1$ 处被排除，故本系统不产生 `lint.Notice` 级输出。

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

组合子归约：$\sigma_{\mathrm{mech}}(\neg t) =$ "NOT ($\sigma_{\mathrm{mech}}(t)$)"；$\sigma_{\mathrm{mech}}(t_1 \wedge t_2) =$ "($\sigma_{\mathrm{mech}}(t_1)$) AND ($\sigma_{\mathrm{mech}}(t_2)$)"；$\vee$ 同理；原子模板基例 $\sigma_{\mathrm{mech}}(a) = \mathcal{M}(a)$。对条件二元组 $(p,q)$：当 $p = \neg(p')$ 时输出 "WHEN NOT ($\sigma_{\mathrm{mech}}(p')$), THEN $\sigma_{\mathrm{mech}}(q)$"（消除双重否定的 NEG-PRE 模板），否则输出 "WHEN ($\sigma_{\mathrm{mech}}(p)$), THEN $\sigma_{\mathrm{mech}}(q)$"，$p=\varepsilon$ 时输出 $\sigma_{\mathrm{mech}}(q)$ 单句。

**命题 2（$\sigma_{\mathrm{mech}}$ 可逆性）**。*给定 $\sigma_{\mathrm{mech}}(t)$ 的输出，原始 DSL 树 $t$ 在原子模板层等价意义下可机械恢复（同义原子模板被映射到同一短语时不可区分，其余结构保留）；故 $\sigma_{\mathrm{mech}}$ 在验证链路中保留 DSL 树结构信息。*

### 附录 E：DSL 合成 Prompt 模板

§6.4 所述受约束 LLM 调用 $\phi_G$ 的系统提示明确四条硬约束（违反即被解析函数 $\eta$ 自动拒绝）：(1) 每个原子模板名须出现在所供目录 $\mathcal{A}$ 中；(2) 每个叶参数须为声明类型的字面量或出现在词汇表 $\mathcal{V}$ 中的名字，禁止编造标识符；(3) 输出须为一棵 DSL 树的 JSON（含 `predicate`/`precondition`/`severity`/`label`）或一个 `{"no_template": true, "reason": ...}` 弃权标记，其余形态一律解析失败；(4) `Description`/`Citation`/`Name` 不由 LLM 生成，由后处理器 $\Phi_{\mathrm{post}}$ 确定性绑定。

每次调用的完整 prompt 由四区段依次拼接：**区段 A（Rule Context）**——源 ID、章节号、规则 ID、逐字 `rule_text` 与 `source` 元数据；**区段 B（Structured IR）**——扁平展开的 IR 四/五元组；**区段 C（DSL Schema）**——实现中的 $\mathcal{V}$ 与 $\mathcal{A}$ 目录（按分量分组的字段名清单与按语义簇分组的原子模板签名表，附每原子模板一行 PKI 语义注释；论文附录 C 仅列代表性示例）；**区段 D（Output Protocol）**——两种合法 JSON 形态的精确 schema 与一条 minimal positive 示例。

### 附录 F：SAIV 残差与阶段路由的形式化细节

本附录汇集 §7.3–§7.4 正文中引用的精确数学形式化，以供需要形式核查的读者查阅。

**SAIV 核心残差的精确式**（直觉与定义见 §7.3–§7.4 正文）：

代码正确性标签（式 5）。记 $t_r$ 为规则 $r$ 合成的 DSL 树、$\mathrm{code}(r)=\rho(t_r)$ 为其渲染出的 Go 代码；$\mathbb{1}[\cdot]$ 为指示函数，$\mathrm{compile}(\cdot)\in\{0,1\}$ 为是否编译通过，$s_{\mathrm{struct}}(\cdot)\in[0,1]$ 为结构完整度得分，$\mathrm{syn}(\cdot,\cdot)\in\{0,1\}$ 为同义评判器输出，$\sigma_{\mathrm{mech}}(t_r)$ 为 code_summary（§6.3），$\mathrm{spec}(r)$ 为规则 $r$ 的规范原文：
$$
\lambda_{\mathrm{code}}(r) = \mathbb{1}[\mathrm{compile}(\mathrm{code}(r))] \cdot s_{\mathrm{struct}}(\mathrm{code}(r)) \cdot \mathrm{syn}(\sigma_{\mathrm{mech}}(t_r),\; \mathrm{spec}(r)) \tag{5}
$$

召回守恒残差（式 6）：
$$
\mathcal{L}_{\mathrm{recall}} = 1 - \frac{\min(|\mathcal{R}_{\mathrm{kw}}|,\; |\mathcal{R}_N|+|\mathcal{R}_L|+|\mathcal{R}_U|)}{\max(|\mathcal{R}_{\mathrm{kw}}|,\; |\mathcal{R}_N|+|\mathcal{R}_L|+|\mathcal{R}_U|)} \tag{6}
$$

代码忠实残差（式 7）：
$$
\mathcal{L}_{\mathrm{code}} = 1 - \frac{1}{|\mathcal{R}_L^{\mathrm{uncov}}|}\sum_{r\in\mathcal{R}_L^{\mathrm{uncov}}}\lambda_{\mathrm{code}}(r) \tag{7}
$$

总损失（式 8，$w_R+w_C=1$）：
$$
\mathcal{L}_{\mathrm{total}} = w_R\cdot\mathcal{L}_{\mathrm{recall}} + w_C\cdot\mathcal{L}_{\mathrm{code}} \tag{8}
$$

**阶段路由的四分支规则**（精确条件见 §7.4 正文）：

$$
\mathrm{Stage}^{(t)} = \begin{cases}
\phi_R, & \mathcal{L}_{\mathrm{recall}}^{(t)} > \tau_R \\
\phi_C, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} > \tau_C \\
\phi_G, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} < 1 \\
\phi_V, & \text{否则}
\end{cases} \tag{9}
$$

四支自上而下按优先级匹配、$\phi_V$ 为默认支。其中 $p_{\mathrm{fail}}^{(t)} = \frac{1}{|\mathcal{R}_L^{\mathrm{uncov}}|}\sum_{r\in\mathcal{R}_L^{\mathrm{uncov}}}\mathbb{1}[\neg\mathrm{compile}(\phi_G(r))]$、$\bar{s}_{\mathrm{struct}}^{(t)} = \frac{1}{|\mathcal{R}_L^{\mathrm{uncov}}|}\sum_{r\in\mathcal{R}_L^{\mathrm{uncov}}}s_{\mathrm{struct}}(\phi_G(r))$（此处 $\phi_G(r)$ 即上文的 $\mathrm{code}(r)$）。注意路由阈值 $\tau_R, \tau_C$ 决定"下一轮修哪个模块"，与 §7.4 的终止阈值 $\theta$（作用于总损失 $\mathcal{L}_{\mathrm{total}}$、默认 0.05）是不同的量。

**命题 3（残差单调性）的完整陈述与证明**（正文见 §7.4）：

*命题 3（残差单调性）。若二元仲裁器 $\phi_J$ 在每条违反上均给出 FLIP（翻转）或 SPURIOUS（判伪）之一并被采纳，则一轮过程后 $N_{\mathrm{viol}}$ 严格下降至 0。*

*证明。* 记 $\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial},\text{none}\}$ 为规则 $r$ 被外部工具（zlint）覆盖的档位（§8.2 算法 2），$\phi_C$ 为 §5 的 lintability 谓词。设违反集 $\mathcal{W}=\{r:\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}\land\phi_C(r)\neq\mathrm{lintable}\}$（此处用 $\mathcal{W}$ 而非 $\mathcal{V}$，以免与 §6.2 的词汇表 $\mathcal{V}$ 混淆），$N_{\mathrm{viol}}=|\mathcal{W}|$。对任意 $r\in\mathcal{W}$，$\phi_J$ 必给出且仅给出以下两支之一：
- **FLIP**：采纳后 $\phi_C(r)$ 翻转为 $\mathrm{lintable}$，此时 $\phi_C(r)=\mathrm{lintable}\land\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}$ 仍触发违反式左侧，但违反式右侧不再成立（lintable 的假阴性已修正），故 $r\notin\mathcal{W}$；
- **SPURIOUS**：采纳后 $\mathrm{cov}_{\mathcal{T}}(r)$ 降级为 $\mathrm{none}$，此时违反式左侧 $\mathrm{cov}_{\mathcal{T}}(r)\in\{\text{full},\text{partial}\}$ 不再成立，故 $r\notin\mathcal{W}$。

两类修复均移除该 $r$ 而不引入新违反，故 $\mathcal{W}$ 在一轮内严格收缩至空集、$N_{\mathrm{viol}}=0$。$\square$

*注：* FLIP 与 SPURIOUS 不可同时对同一条规则采纳（两者互斥），且采纳后该规则离开 $\mathcal{W}$，不参与后续判定，故该过程有界终止。
