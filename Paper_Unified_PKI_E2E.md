# 从 PKI 标准到合规检查代码：规则提取、可 lint 性判定与可验证代码生成的端到端框架

<!--
合并稿骨架 — 由 Paper2_PKI_Lint_Code_Generation.md（后半段：受限DSL+SAIV）
吸收前作 "LLM-Assisted Normative Rule Extraction and Lintability"（DLEP/CICAS，前半段：提取→IR→lintability）合成。
硬约束：(1) 删除一切人工标注相关内容，由 SAIV 无真值验证取代；(2) 突出学术价值、不写工程实现细节。
统一主线：标准文档 →[KG+确定性GraphRAG]→ 候选规则 →[Layer2 LLM→IR]→ IR →[五条件]→ lintability(𝓡_L)
        →[φ_G 受限DSL]→ DSL树 →[ρ]→ Go代码  ⟲ SAIV(G1/G2/G3)
-->

## 摘要

公钥基础设施（PKI）的证书编码规则，散落在 RFC 5280、CA/Browser Forum 基线要求（CABF BR）、ETSI EN 319 与 Mozilla 根存储策略等多份自然语言标准中。自 2025 年起 CA/Browser Forum 强制要求所有公信 CA 在签发前对证书执行 lint 检查，把这些规范文本系统性地转化为可执行的合规代码因而成为 PKI 治理的关键一环；但现有 lint 工具（zlint、pkilint 等）全靠专家逐条手写并随规范修订持续维护，"哪些规范条款能被静态检查、现有工具又覆盖到什么程度"长期没有系统答案。

本研究给出一个**从标准文本直达合规检查代码的端到端框架**，完整串起"规则提取 → 中间表示（IR）→ 可 lint 性判定 → 代码生成 → 验证"五个环节。其设计贯穿一条主线：**让大语言模型（LLM）只在真正需要语言理解的地方出现，验证链路上其余每一步都尽量做成可复现的确定性函数**。具体地：(1) 跨文档上下文不交给 LLM 去猜，而由 PKI 规范知识图谱上的确定性子图检索给出可溯源上下文，LLM 仅被限定为"把规则填进固定 schema 的语义解析器"，输出结构化 IR（核心四元组 ⟨主体, 义务, 谓词, 约束⟩）；(2) 可 lint 性被形式化为五个离散 IR 字段上的一个确定性布尔函数 $C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$，判定可复现、任何误判都能追溯到唯一一个字段；(3) 代码生成不写自由形式的 Go 代码，而是把生成算子 $\phi_G$ 的值域**在语言设计层面**限制为由有限原子集 $\mathcal{A}$（$|\mathcal{A}|=68$）与类型化词汇表 $\mathcal{V}$ 张成的受限 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$——"编造不存在的字段或 OID"这类幻觉因此在架构层就被关闭（命题 1）；(4) 针对"生成代码是否忠实于规范"这个最难的判定，本研究不再让另一个 LLM 投票，而是构建**证书级语义 oracle**：为每个原子造出"满足/违反"两张受控证书、让真实证书执行并读回判定状态，从而对仅由已认证原子构成的生成 lint **确定性地、与模型无关地*验证* $\mathrm{Code}\equiv\mathrm{IR}$**——把同义性判据从不可复现的单票 LLM 判别器升级为可复现的执行级验证（须界定：这是受控 fixture 上的执行级验证而非对全体证书的定理性证明，外延受可认证子集所限，详见 §7.1）。

针对大规模代码生成普遍缺乏人工真值这一根本困难，本研究提出**阶段归因式迭代验证框架（Stage-Attribution Iterative Verification, SAIV）**：把"召回完整性"（G1）、"lint 覆盖度"（Gcov，相对 zlint 既有实现的端到端覆盖广度，分母取 zlint 实测 RFC 5280=113 / CABF BR=133）、"代码-规范同义性"（G2）与"双判定源一致性"（G3）形式化为可计算残差，配上阶段归因规则与单调修复算子，在**无人工标注真值**的条件下提供可收敛、可追溯的质量控制。其**首要修复算子 $\rho_R$（IR 内容自反思修复）经确定性 g4-sanity 闸门全自动运行、无需逐条人工确认**——这把"发现 IR 抽错 → 自动重抽修正"变成迭代回路内的一个算子，而非依赖人工的离线动作，从而使论文意义上的"迭代"名实相符。

在 RFC 5280 与 CABF BR 上的实证表明：关键词召回 2091 条候选，经守恒划分得 1581 条真规则、其中 370 条可 lint；zlint 既有实现按其自带 citation 覆盖了其中 177 条。对未被覆盖的目标做受限 DSL 代码生成后，证书级 oracle 以**零判官**、与所用模型无关地确定性*验证*了 179 条 $\mathrm{Code}\equiv\mathrm{IR}$，而一个单票 LLM 判别器会"接受"一个更大却含风险的超集——印证了单票判据的不可靠。逐条人工裁定的真实同义率约 50%（该值系**未过滤产出在最难的"未覆盖∧可渲染"子集上**的测值，非发射集质量），其余不同义**全部追溯到上游抽取**（如主语错抽、把子字段当成整个扩展），在代码生成端无捷径可补——这一**误差定位本身即是一项发现：在本框架下，瓶颈在 $\mathrm{Spec}\to\mathrm{IR}$ 抽取、而非 $\mathrm{IR}\to\mathrm{Code}$ 生成**。据此本研究主张**把同义性当作发射门而非事后指标**：只发射经 $\mathrm{Code}\equiv\mathrm{IR}$（证书级 oracle）与 $\mathrm{IR}\equiv\mathrm{Spec}$（同义判定）双重验证的 lint，使发射集**100% 同义 by construction**；收敛即迭代修上游抽取、把残差转为同义，而发射集始终维持 100%。须诚实界定端到端口径：$\mathrm{Code}\equiv\mathrm{IR}$ 为自动保证，而 $\mathrm{IR}\equiv\mathrm{Spec}$ 当前由人工裁定把关，故端到端 $\mathrm{Code}\equiv\mathrm{Spec}$ 仅对发射集成立，其 $\mathrm{IR}\equiv\mathrm{Spec}$ 的自动化正是本框架定位出的首要开放问题。

方法学层面，本研究提炼出一条不限于 PKI 的设计原则——**阶段归因式验证链路上的每个算子都应尽可能确定化**（证书级 oracle 把原本属于 LLM 的"忠实性判定"也确定化，正是这一原则推到验证端的体现）——并以"可归约子集闭合 + 不可归约边界诚实披露"双指标取代单一收敛阈值，为基于受限词汇的"规范-到-代码"生成提供可复现的诚实边界声明范式。

**关键词**：公钥基础设施；证书合规检查；规范规则提取；中间表示；可 lint 性分析；受限代码生成；证书级语义 oracle；阶段归因式迭代验证

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

把规范文本变成可信代码，难点不在"让 LLM 写一段代码"，而在"让整条流水线可复现、可审计、可验证"。本研究的方法学由三条相互支撑的设计原则组成，一句话概括就是：**只在非用 LLM 不可的地方用 LLM，其余每一步都尽量做成确定性函数**。

**第一，提取侧——确定性检索 + LLM 受限角色。** 跨文档上下文的组装不交给 LLM 推断，而由知识图谱上的确定性子图遍历给出可溯源上下文；LLM 的职责被严格限定为"将候选规则解析为受 schema 约束的结构化 IR"，所有规范性判断（可执行性、覆盖、冲突）都推迟到后续确定性阶段。这使提取过程可审计、可复现。

**第二，生成侧——代码空间应在语言层面而非 prompt 层面受限。** 与其用 prompt 反复叮嘱 LLM"别编造字段"，不如让它根本无从编造：将生成算子 $\phi_G$ 的值域定义为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，使"LLM 编造不存在的字段或 OID"这一类幻觉在架构层即被关闭（命题 1），而非依赖 prompt 约束或 few-shot 引导这类概率性手段。

**第三，验证侧——验证链路上的每个算子都应尽可能确定化。** 在语义等价传递链

$$
\mathrm{Spec} \;\to\; \mathrm{IR} \;\to\; t \in \mathcal{T}_{\mathcal{V}} \;\xrightarrow{\sigma}\; \mathrm{Summary} \;\equiv\; \mathrm{Description}
$$

中，关键词召回 $\phi_R$、渲染 $\rho$、后处理 $\Phi_{\mathrm{post}}$、机械翻译 $\sigma_{\mathrm{mech}}$ 等算子均由确定性函数实现；最关键的一步是，连"生成代码是否忠实于规范"这个判定本身也被确定化——在**可认证子集**上由一道**证书级语义 oracle** 以真实证书的执行结果给出 $\mathrm{Code}\equiv\mathrm{IR}$ 的执行级*验证*（可复现、与模型无关，非对全体证书的定理性证明），而非靠 LLM 投票，仅在该 oracle 不适用的子集上才退回到 $\phi_C$、$\phi_V$ 等确需语义灵活性的 LLM 端点。这印证了一个更深的观察：确定性的着力点可以从生成端迁移到验证端——把生成保持为单一、受限的 LLM 通路，而让 $\mathrm{Code}\equiv\mathrm{IR}$ 的保证由可执行的 oracle 在验证端重新建立（详见 §9）。在缺乏人工真值的前提下，则由**阶段归因式迭代验证框架（SAIV）**将三类质量不变量形式化为可计算残差，提供收敛性与可追溯性。

### 1.4 主要贡献

本研究的贡献可归纳为六点，贯通"提取—判定—生成—验证"全链路。

**(C1) 面向跨文档引用的知识图谱与确定性检索。** 由 Web PKI 规范源构建多边有向知识图谱（章节、定义、证书字段与跨文档继承关系），并设计仅沿显式 source-backed 边做有界遍历的确定性 GraphRAG 检索机制，为规则提取提供可溯源、可复现且不引入 LLM 臆造的上下文（§4.1–4.2）。

**(C2) 双层提取与结构化中间表示。** 提出双层提取流水线：Layer 1 以 RFC 2119 关键词与正则做确定性召回，Layer 2 将 LLM 限定为受 schema 约束的语义解析器，把候选规则转写为结构化 IR（核心四元组 ⟨主体, 义务, 谓词, 约束⟩）。IR 将语义提取与下游任务解耦，支持"一次提取、多处复用"（§4.3–4.4）。

**(C3) 基于 IR 的五条件可 lint 性框架。** 将可 lint 性形式化为对五个离散 IR 字段的确定性布尔函数 $C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$，使判定可复现，且任何误判都可追溯到唯一一个 IR 字段，而非归因于不透明的端到端调用（§5）。

**(C4) 受限代码空间、可逆机械翻译与证书级语义 oracle。** 将 $\phi_G$ 的值域严格形式化为原子集 $\mathcal{A}$（$|\mathcal{A}|=68$）与类型化词汇表 $\mathcal{V}$ 张成的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，给出语法、执行语义、词汇封闭性命题（命题 1）与树规模上界；并给出确定性机械翻译算子 $\sigma_{\mathrm{mech}}:\mathcal{T}_{\mathcal{V}}\to\mathcal{L}_{\mathrm{NL}}$，满足全函数性、决定性与原子等价意义下的可逆性，将验证链路上的概率失真压缩至 $\phi_C$、$\phi_V$ 两个端点。在此受限空间之上进一步构建**证书级语义 oracle**——经逐原子忠实性认证（受控证书 fixture）与结构组合，对仅由已认证原子构成的生成 lint 确定性地证明 $\mathrm{Code}\equiv\mathrm{IR}$，把同义性判据由单票 LLM 判别器替换为可复现的执行级证明，并诚实披露其"可认证子集"边界（§6–7）。这道 oracle 是本研究最核心的方法学贡献之一：它让"代码忠实于规范"成为可被真实证书*执行验证*的命题，而非另一次 LLM 投票。

**(C5) 阶段归因式迭代验证（SAIV）与多目标残差。** 将"召回完整性"（G1）、"lint 覆盖度"（Gcov，相对 zlint 的端到端覆盖广度，分母为 zlint 实测 RFC 5280=113 / CABF BR=133）、"代码-规范同义性"（G2）、"双判定源一致性"（G3）形式化为可计算残差，给出阶段归因规则、修复算子谱与收敛性论证；其中**首要修复算子 $\rho_R$（IR 内容自反思修复）经确定性 g4-sanity 闸门全自动运行、无需逐条人工确认**，并以 L4b 双向 FLIP-or-SPURIOUS 机制使 G3 残差单调降至 0。该框架在**无人工标注真值**条件下提供质量控制，结构性地取代了对人工真值的依赖（§8）。

**(C6) 大规模实证与诚实边界声明。** 在 RFC 5280 与 CABF BR 上召回 2091 条候选、经守恒划分得 1581 条真规则、其中 370 条可 lint；zlint 既有实现按 citation 覆盖其中 177 条。对未覆盖目标完成端到端代码生成后，由证书级 oracle 以零判官确定性证明 179 条 $\mathrm{Code}\equiv\mathrm{IR}$；逐条人工裁定的真实同义率约 50%，其余约 60 条不同义全部追溯到上游抽取。本研究据此提出"**同义性作为发射门**"的范式，并以"可归约子集闭合 + 不可归约残差边界披露"双指标取代单一收敛阈值，给出可复现的诚实边界声明（§9）。

### 1.5 论文结构

本文余下部分安排如下。第 2 节梳理相关工作并界定本研究的差异化定位；第 3 节给出端到端方法总览；第 4 节描述规范规则提取与中间表示（知识图谱、确定性检索、双层提取、结构化 IR）；第 5 节形式化基于 IR 的五条件可 lint 性判定；第 6 节给出受限 DSL 代码空间与 LLM 引导合成；第 7 节描述三层语义对齐验证与机械翻译算子；第 8 节形式化阶段归因式迭代验证框架（SAIV）；第 9 节给出实验设置与实证结果；第 10 节讨论关键发现、对规范作者与工具维护者的启示及有效性威胁；第 11 节总结全文。

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

与上述工作相比，本研究的差异化定位体现在四个方面。**其一**，本研究并不孤立地做提取或生成，而是给出贯通"提取 → IR → 可 lint 性判定 → 代码生成 → 验证"的端到端框架，并以结构化四元组 IR 作为前后两半的统一接缝。**其二**，在提取侧把 LLM 限定为受 schema 约束的解析器、并以确定性的**可溯源检索**（沿规范结构的显式边遍历，而非向量相似度或 LLM 推断）组装跨文档上下文，使提取可审计、可复现，区别于端到端黑箱提取；须强调这里的差异化在于"受约束 + 可溯源"，**而非主张某种图检索结构相对普通 RAG 的量化优越性**——后者难以做干净消融、本文不作此主张（见 §10.4）。**其三**，在生成侧将 $\phi_G$ 的值域形式化为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，在语言层关闭字段/OID 编造类幻觉（命题 1），与基于 prompt 约束或 few-shot 引导的方法形成本质区别。**其四**，在验证侧提出阶段归因式迭代验证框架，将三类质量不变量形式化为可计算残差，在无人工真值条件下提供可追溯性与（在单调修复假设下的）收敛性论证，并由确定性机械翻译算子 $\sigma_{\mathrm{mech}}$ 将概率失真压缩至两个必要的语义端点——这给出一项更一般的设计原则：**验证链路上的每个算子都应尽可能确定化**。

## 3. 方法总览

图 1 给出本研究端到端框架的整体结构。系统以 Web PKI 规范文本为输入，以可编译、可追溯的 zlint Go 检查代码为输出，并由阶段归因式验证框架（SAIV）在无人工真值条件下闭环修复。整体流程由六个阶段组成，前三个阶段（确定性上下文 + 提取 + 判定）构成"规范 → 可 lint 规则"的前半链路，后三个阶段（合成 + 对齐 + 验证）构成"可 lint 规则 → 可信代码"的后半链路，二者以**结构化中间表示 IR**与**五条件可 lint 性判定**为统一接缝。

1. **知识图谱构建（离线，§4.1）。** 将异构规范源归一化为带稳定标识的层级结构，抽取章节包含、定义、跨文档引用与字段概念等显式关系，形成可溯源的检索基底。
2. **确定性上下文检索（§4.2）。** 以知识图谱为固定输入，对每个目标章节做有界子图遍历，组装术语定义、字段元数据与被引章节作为提取上下文；该过程不使用向量相似度，也不调用 LLM，从而不引入臆造上下文。
3. **双层提取与 IR 构建（§4.3–4.4）。** Layer 1 以 RFC 2119 关键词与正则做确定性召回得到候选规则集合 $\mathcal{R}_{\mathrm{kw}}$；Layer 2 将 LLM 限定为受 schema 约束的语义解析器，把每条候选规则转写为结构化 IR。
4. **五条件可 lint 性判定（§5）。** 由分类算子 $\phi_C$ 依据五个离散 IR 字段的确定性布尔函数 $C(r)=C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$，将每条规则映射至可执行（可 lint）集合 $\mathcal{R}_L$。$\mathcal{R}_L$ 即下游代码生成的定义域。
5. **受限 DSL 合成（§6）。** 生成算子 $\phi_G$ 在形式化的原子 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$ 内合成 DSL 树 $t$，再经确定性渲染算子 $\rho$ 与可溯源字段后处理 $\Phi_{\mathrm{post}}$ 物化为 Go 代码。
6. **三层对齐验证（§7）。** 通过描述溯源性、基于 $\sigma_{\mathrm{mech}}$ 机械翻译摘要与 `Description` 的同义性判定、以及结构与编译检查，综合输出对齐得分 $S_{\mathrm{align}}$；对由已认证原子构成的可认证子集，另由证书级语义 oracle 经真实证书执行确定性*验证* $\mathrm{Code}\equiv\mathrm{IR}$（执行级验证，非定理性证明），无需 LLM 判官。

当样本级对齐不达阈值时，系统进入 §7 的样本级局部修复；当需要在大规模、无独立真值的场景下定位并修复系统性误差来源时，则进入第 8 节的阶段归因式管道级验证与修复框架（SAIV），将"召回完整性、代码-规范同义性、双判定源一致性"三类不变量作为可计算残差，沿管道反向归因并触发阶段性修复。

## 4. 规范规则提取与中间表示

本节描述前半链路：如何在确定性可控的前提下，从分散且交叉引用密集的 Web PKI 规范源中提取规范规则，并将其转写为结构化中间表示 IR。这里的核心困难是，PKI 标准像一份满是"详见某文档第 X.Y 节"的合同——孤立地读任何一段都不足以还原一条规则的完整含义。本研究的应对是分工：把"找齐上下文"交给确定性的图遍历，把"读懂语义"交给受约束的 LLM，二者各司其职，从而既不丢上下文、又不让模型自由发挥。

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

并非每条带 MUST 的规范都能写成 lint 检查。有的 MUST 约束的是 CA 的线下行为（如"CA 必须核验申请人身份"），有的要比对证书链上的其他证书，有的要查 DNS 记录或撤销历史——这些都无法仅凭一张证书的字节静态裁决。因此在生成代码之前，必须先回答一个前置问题，即每条规范规则的**可 lint 性**：它能否被一个不依赖外部上下文或运行时行为、仅凭**单一制品**（一张证书或一份 CRL）即可裁决的静态检查所表达？

本研究不让 LLM 直接拍板，而是把这个判断拆成**五道独立的"是非题"，每道题只读 IR 里的一个字段，像过安检一样逐道闸门放行——五道全过才算可 lint**，从而在 IR 上**确定性地计算**可 lint 性。这样设计基于三点观察：其一，实践中决定一条规则可 lint 性的恰是五类信息——义务的道义强度、被约束的主体、约束生效的阶段、规则的类型，以及裁决该约束所需的**数据范围**（单一制品 vs 跨制品/外部状态）；其二，这五者中的每一个都可编码为取值于一个小而封闭集合的单一 IR 字段，于是可 lint 性判定退化为五个离散字段的布尔函数；其三，分离这五个条件，使任何错误标签都可追溯到恰好一个 IR 字段，而非归因于不透明的端到端调用。

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

记 $\phi_C : r \mapsto \mathbb{1}[C_1 \wedge C_2 \wedge C_3 \wedge C_4 \wedge \neg C_5]$，则可 lint 规则集合 $\mathcal{R}_L = \{r : \phi_C(r) = 1\}$ 即后续代码生成阶段 $\phi_G$ 的定义域。obligation 字段同时固定了 lint 的严重级别（MUST 类 $\mapsto$ Error，SHOULD 类 $\mapsto$ Warning），因此严重级别不是第二个分类器，而是对 obligation 的直接读取。四个非道义条件 $C_2$、$C_3$、$C_4$、$\neg C_5$ 刻画了四条正交边界——主体边界、运行时边界、数据边界（单一制品）与过程边界。值得注意的是，$C_4$ 把原先只在审计阶段事后判定的 $\mathrm{StaticallyObservable}$ 谓词（其 $\mathrm{verif}_{\mathrm{scope}}=\mathrm{observable}$ 分量）提升为提取阶段即确定的一等 IR 字段 $\mathrm{check\_scope}$；$C_2$（主体）与 $C_4$（范围）合取后即与 $\mathrm{StaticallyObservable}$ 在提取时重合，从而把一类此前依赖人工审计的边界判断前移为可复现的确定性计算。由于每个 $C_i$ 都是单一 IR 字段的确定性函数，$\mathrm{lintable}(r)$ 是从 IR 计算得到而非由 LLM 预测的：相同的规则 IR 在每次运行上都给出逐位一致的标签，且任何误判都可追溯到 Layer 2 某一个具体的字段赋值。这一可追溯性正是第 8 节阶段归因式验证得以沿管道反向归因的前提。

## 6. 受限 DSL 代码空间与 LLM 引导合成

本节描述后半链路的核心：如何在**语言设计层面**限制代码生成算子 $\phi_G$ 的值域，使生成结果既不产生编造字段/OID 的幻觉，又使"代码语义等价于规范语义"成为可计算的判定问题。

### 6.1 受限代码空间的动机

直接将 $\phi_G$ 实现为"$r \mapsto$ 自由形式 Go 代码"会面临两类风险：**(i) 幻觉风险**——LLM 可能输出引用证书结构中不存在字段、调用不存在标准库函数或编造 OID 常量的代码，且这类错误在编译层难以全部捕获；**(ii) 验证不可计算性**——开放代码空间下，证明"代码语义等价于规范语义"需要程序分析或动态符号执行，远超工程可行性。本研究的核心方法学回应是**在语言设计层面限制 $\phi_G$ 的值域**：将 Go 代码空间替换为一个有限闭合的 DSL 树空间 $\mathcal{T}$，并由确定性渲染函数 $\rho:\mathcal{T}\to\mathrm{Go}$ 完成代码物化。LLM 仅需输出一棵合法的 DSL 树，所有"字段名是否合法 / OID 是否存在 / 比较算子是否类型匹配"等正确性属性，均由 DSL 的类型系统在生成时即被静态保证。一个贴切的类比是：与其给 LLM 一张白纸任其自由作画（自由 Go 代码），不如给它一套乐高积木（受限原子）——它只能拼出积木允许的形状，却**拼不出不存在的零件**。这把"防幻觉"从靠提示词反复叮嘱的概率手段，变成了由语言本身保证的架构属性。需诚实说明本文对受限 DSL 之必要性的论证性质：它是**架构性/by-construction 的**（命题 1 在语言层关闭字段/OID 编造，并使"代码语义等价于规范"成为可计算判定；后文 §9.4 的 179 条离线编译零幻觉是其经验印证），而**非**来自与"直接生成 Go"的受控基线对比——后者本文未跑、列为 future work（§10.4）。恰因 §7.1 的证书级 oracle 对任意生成器通用，这一对比可在同一目标集上廉价、可复现地补做。

### 6.2 原子 DSL：语法与原子集

定义代码 DSL 的抽象语法为：

$$
\mathcal{T} \;::=\; a(\bar{v}) \;\mid\; \neg\, \mathcal{T} \;\mid\; \mathcal{T} \wedge \mathcal{T} \;\mid\; \mathcal{T} \vee \mathcal{T}
\tag{1}
$$

其中 $a \in \mathcal{A}$ 为原子谓词，$\bar{v}$ 为该原子的参数列表。$\mathcal{A}$ 是一个**有限闭合**的原子集合：本文版本下 $|\mathcal{A}| = 68$，每个原子对应一类语义上不可再分的证书属性判定（如"扩展存在"、"字段等于常量"、"列表中每元素匹配某正则"等）；$\{\neg, \wedge, \vee\}$ 为命题逻辑组合子，完整 $\mathcal{A}$ 的枚举见附录 D。一条 lint 规则的代码体被建模为有序对 $(p, q) \in \mathcal{T}_\perp \times \mathcal{T}$，其中 $p \in \mathcal{T}_\perp = \mathcal{T} \cup \{\perp\}$ 为可选前提条件，$q \in \mathcal{T}$ 为主断言，其执行语义为：

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

其中 $\rho$ 将 DSL 树渲染为类型正确的 Go 表达式，$\sigma_{\mathrm{mech}}$ 将 DSL 树机械翻译为 PKI 英文摘要（详见 §8.9）。两个函数共享三项性质：**类型安全**（$\rho$ 输出 100% 通过 Go 编译器解析与类型检查）；**决定性**（对相同输入 $t$，$\rho(t)$ 与 $\sigma_{\mathrm{mech}}(t)$ 输出唯一）；**可逆性（在原子等价意义下）**（给定 $\sigma_{\mathrm{mech}}(t)$ 可机械还原 $t$，即 $\sigma_{\mathrm{mech}}$ 在反向验证链路上不引入信息瓶颈，详见 §8.9 命题 2）。

### 6.5 从 IR 谓词到原子的语义映射

为衔接上游 IR 与 DSL，本研究维护一个**多对多语义映射** $\mu : \mathrm{Pred}_{\mathrm{IR}} \rightrightarrows 2^{\mathcal{A}}$：对规则 IR 中出现的每个谓词（如 `must_be_present`、`encode_as`、`in_range`），$\mu$ 给出语义上可承载它的候选原子子集，连同 $\mathcal{V}$ 与原子签名表进入 §6.6 的合成提示，把 LLM 的选择空间从全集 $\mathcal{A}$ 收窄到相关候选。$\mu$ 只是**提示性约束**——不直接装配输出、不进入 $\rho$ 渲染，最终的原子选择与组合结构仍由 LLM 给出并经封闭性强制与证书级 oracle 校验；其多对多性质保证"一个 IR 谓词可由不同原子组合实现"的表达冗余。

### 6.6 受限 LLM 树合成与 IR-字段溯源守卫

**全 LLM 树合成。** 给定可执行规则 $r \in \mathcal{R}_L$（$\mathcal{R}_L$ 由 §5 的五条件判定给出），代码生成算子 $\phi_G$ 实现为一次**受限 LLM 树合成**：模型在得到规则上下文、结构化 IR、由 §6.5 映射 $\mu$ 收窄的候选原子集合，以及词汇表 $\mathcal{V}$ 与原子集 $\mathcal{A}$ 的可读枚举与签名表（实际系统提示与四区段拼接见附录 H）之后，仅返回一棵 DSL 树的序列化或一个显式弃权标记：

$$
\phi_G : r \;\longmapsto\; t \in \mathcal{T}_{\mathcal{V}} \cup \{\perp_{\mathrm{NT}}\}, \qquad t \;=\; \eta\bigl(M.\mathrm{generate}(\mathrm{prompt}(r,\,\mathcal{V},\,\mathcal{A},\,\mu))\bigr)
\tag{5}
$$

其中 $\perp_{\mathrm{NT}}$ 是显式的"无模板"标记，由 LLM 自主返回——当且仅当模型判断当前 $(\mathcal{A}, \mathcal{V})$ 不足以表达 $r$ 的语义时返回，此时该规则进入修复路径而非渲染，使 $\phi_G$ 不必产生"形式合法但语义错位"的输出。所有"会被检查"的部分都被约束落在 $\mathcal{T}_{\mathcal{V}}$ 之内（命题 1）。在执行体上 $\phi_G$ 是受约束的 LLM 调用，对**所有**可执行规则走同一条通路——不再有按规则区分的确定性主路或模板分类。

**IR-字段溯源守卫。** 在全 LLM 合成下，生成端的结构性 soundness 机制是 IR-字段溯源守卫 $\mathrm{IRGuard}$：它复用字段解析器把 LLM 树中出现的每个证书字段 / 扩展 OID 规范化为其 DSL 身份（扩展按数值 OID 归一），并核验它们都被本规则的 IR 所涵盖。引用了 IR 之外字段的树被标记为**字段漂移**，连同诊断回传 LLM 触发重写（至多 $K$ 轮）。该守卫刻意保守——因 IR 解析本身会漏抽子字段（IR 记整个扩展、而 LLM 正确地引用其某个子字段，二者实为同一扩展），硬性拒绝将误伤约两成的好树——故它定位漂移并驱动修复，而非充当不可逆否决。真正的语义忠实性（$\mathrm{Code}\equiv\mathrm{IR}$）则不由生成端担保，而留待 §7.1 的证书级语义 oracle 在可认证子集上以真实证书执行*验证*。

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

其中 $\mathrm{Code} \equiv \mathrm{Summary}$ 由摘要算子 $\sigma$ 的忠实性提供，$\mathrm{Summary} \equiv \mathrm{Description}$ 由同义性置信度 $c_{\mathrm{syn}}$ 验证，$\mathrm{Description} \equiv \mathrm{Specification}$ 由 §6.6 的确定性后处理（从规范原文注入 `Description`）保证。三项前提依赖不同机制，使整条等价链的失效点可分段归因。需要强调：层次 B 是面向**一般情形**（含外部既有 lint、以及本系统中不可认证的子集）的同义性判定路径；对本系统自身生成、可被下述**证书级语义 oracle** 认证的子集，$\mathrm{Code} \equiv \mathrm{IR}$ 由 oracle 经执行直接*验证*，无需经由 $\sigma$ 摘要这一跳，亦无需 LLM 判官。

**层次 C：编译与结构验证。** 该层执行结构性检查：验证代码可被语法解析、必要的检查函数与元数据字段（描述、引用等）完整存在、所用依赖均被正确导入、且规则注册已完成。与前两层相比，该层偏向可执行性验证，确保生成结果不仅语义可解释，且在目标框架内具备基本结构合法性。

**综合对齐得分。** 五个维度加权平均给出：

$$
S_{\mathrm{align}} = 0.15 \cdot \mathbb{1}[\mathrm{compile}] + 0.10 \cdot \mathbb{1}[\mathrm{struct}] + 0.15 \cdot s_{\mathrm{desc}} + 0.50 \cdot c_{\mathrm{syn}} + 0.10 \cdot s_{\mathrm{revIR}}
$$

其中 $s_{\mathrm{desc}} \in [0,1]$ 为描述溯源性得分，$c_{\mathrm{syn}} \in [0,1]$ 为同义性置信度，$s_{\mathrm{revIR}} \in [0,1]$ 为逆向 IR 一致性得分——由生成代码反向抽取一份 IR、与原 IR 逐字段比对得到的匹配率，是一项轻量的往返（round-trip）一致性校验。同义性置信度占 50% 权重，构成综合判定的主要依据。当 $S_{\mathrm{align}} < \theta$（默认 $\theta = 0.7$）时，系统触发 §8 的阶段归因式修复机制。需说明：该加权得分驱动 §7.2–§8 的修复闭环（其阈值 $\theta$ 决定是否继续修复）；而 §9.4 旗舰结果中"同义可证"子集的接受，并不取决于该标量，而由下述**证书级语义 oracle** 以二值 $\mathrm{Code}\equiv\mathrm{IR}$ *验证*独立给出。

**证书级语义 oracle（$\mathrm{Code}\equiv\mathrm{IR}$ 的执行级确定性验证）。** 这是本研究最核心的方法学装置。须先界定其证据地位：它是一个**以受控 fixture 真实执行为依据、可复现且与所用模型无关的执行级等价*验证***，而非对全体证书空间的定理性证明，外延受"可认证子集"所限。层次 B 的同义性判定由 LLM 判官 $\phi_V$ 给出，是单票、非确定、且会对"前提被丢弃的过严 lint"误盖橡皮章的。本研究的关键一步是把这个判定本身也确定化：与其再问一个 LLM"这段代码对不对"，不如为待检原子各造两张证书——一张使其谓词成立（应放行 $\mathrm{Pass}$）、一张使其不成立（应报错 $\mathrm{Error}$）——把代码真正执行、看结果是否符合预期。对**由本系统自身生成、因而持有 DSL 树 $t$** 的 lint，即以一道确定性的**证书级语义 oracle** 取代该判官，分两步：**(i) 逐原子忠实性认证**——对每个原子 $a \in \mathcal{A}$，由证书工厂合成一对受控 fixture（一张使 $a$ 的谓词为真、一张为假），执行并读回 lint 判定状态，当且仅当两张都得到期望状态时 $a$ 被**认证**；fixture 按原子类参数化于 $\mathcal{V}$，绝不绑定某一具体规则。**(ii) 结构组合的同义保证**——一棵仅由已认证原子构成、且编译通过的 DSL 树 $t$，其渲染代码 $\rho(t)$ 对 $t$ **逐原子忠实**，故由结构归纳建立 $\mathrm{Code}\equiv t$（条件于各原子已通过 fixture 认证）；又因 $t$ 是该规则 IR 的忠实归约，从而**验证** $\mathrm{Code}\equiv\mathrm{IR}$——**无需任何判官**。其证据结构须强调：单原子忠实性是受控 fixture 上的*经验认证*、整树忠实性才由结构归纳建立，故整条等价是**执行级验证**而非形式化定理，可靠性以"fixture 能否真区分满足/违反"为前提。满足该条件的规则记为**同义可证（synonymy-guaranteed）**，其 $S_{\mathrm{align}}$ 中的 $c_{\mathrm{syn}}$ 项被直接短路为通过；不在可认证子集内者（树含未认证原子或不可确定性归约）回退到层次 B 的 LLM 判官，并被显式标注"未证"、与"已验证"分账报告（§9.4）。该 oracle 是**确定性**的：同义可证集合不依赖生成或判定所用模型。须与 §8 的 G3"双判定源一致性"区分——后者指 $\phi_C$ 与外部工具覆盖 $\mathrm{cov}_{\mathcal{T}}$ 之间的一致性，与此处以真实证书执行为真值*验证* $\mathrm{Code}\equiv\mathrm{IR}$ 是两回事。

**oracle 的边界与过严哨兵（诚实声明）。** 该 oracle 的覆盖是有界的——只有能用证书工厂造出"满足/违反"区分对的原子才可认证，需跨证书上下文、密码学事实（如模数素性）或字节级编码的原子无法认证（边界详见 §10.4）。此外 oracle 附带一道**过严哨兵**：把同义可证的 lint 在真实证书语料上运行，若在大比例有效证书上误报 $\mathrm{Error}$，即疑为"前提被丢弃"的过严 lint——这是 $\mathrm{IR}\neq\mathrm{Spec}$ 的**上游**信号而非 $\mathrm{Code}\neq\mathrm{IR}$；该哨兵当前因真实语料过窄而仅作报告、不计入判据。

**确定性实体级忠实性筛查（必要条件）。** 证书级 oracle 给出 $\mathrm{Code}\equiv\mathrm{IR}$ 的*充分*验证、但只覆盖可认证子集；对其余仍由 LLM 判官判定的 lint，本研究再引入一道**无 LLM 的实体级忠实性筛查** $\mathrm{Faithful}_{\mathrm{nec}}$，作为一个与 oracle、判官皆独立的可机械计算*必要*条件。其依据是一个 sound 的**必要条件**：一条操作于 PKI 实体集 $E(t)$（DSL 树 $t$ 的谓词中出现的 OID 常量与证书字段）的 lint，忠实于规则 $r$ 的前提是——$t$ 所检查的每个主要实体都在 $r$ 的文本中被提及：

$$
\mathrm{Faithful}_{\mathrm{nec}}(t, r) \;\Longleftrightarrow\; \forall\, e \in E_{\mathrm{prim}}(t):\ \mathrm{alias}(e) \cap \mathrm{tokens}\bigl(\mathrm{text}(r)\bigr) \neq \varnothing,
$$

其中 $\mathrm{alias}(\cdot)$ 是一座由自动词干化与一张冻结的标准扩展别名表构成的桥。筛查给出三种判读：$\mathtt{ENTITY\_OK}$（每个实体都在文本中点名）、$\mathtt{ENTITY\_MISMATCH}$（lint 检查了文本从未提及的实体——可疑）、$\mathtt{NO\_ENTITY}$（谓词不引用任何 OID/字段实体，如纯结构检查，判定不适用）。该筛查**不是**完全语义等价证明（后者不可判定），而是一个可机械计算的必要条件，专门捕获"分段/指代把错误主语交给代码生成"的失效模式。由于它确定性且与判官独立，可与非确定性的层次 B 相互交叉验证——二者分歧之处，要么定位到指代盲区（实体在节标题而非句中），要么定位到真正的主语错抽。其已知盲区有二：指代（"this extension"）与别名表的词表缺口，两者都表现为**保守地多报** $\mathtt{ENTITY\_MISMATCH}$ 而非漏报，与 IR-字段溯源守卫同向偏保守。

### 7.2 样本级局部修复算子

记 $\rho_G^{\mathrm{loc}}$ 为作用于单条规则的局部修复算子，含两类子操作：

$$
\rho_G^{\mathrm{loc}}(t, c) \;=\; \begin{cases}
\Phi_{\mathrm{post}}(t, r), & \text{Description / Citation 偏差} \\
\phi_G\bigl(r,\; \mathrm{feedback}(\eta(s), \mathcal{V}, \mathcal{A})\bigr), & \eta(s) = \mathrm{Err} \;\text{或}\; \mathrm{compile}(\rho(t)) = 0
\end{cases}
\tag{6}
$$

第一支为**幂等闭式修复**：对可溯源字段调用 §6.6 的 $\Phi_{\mathrm{post}}$ 一次即终止，复杂度 $O(1)$；第二支为**类型反馈式重生成**：将解析错误（哪一原子签名不满足）或编译错误以结构化形式注入提示，触发 LLM 重新合成 DSL 树。$\rho_G^{\mathrm{loc}}$ 的迭代上界为 $K_{\mathrm{loc}}$（默认 3）。在该上界内仍未达到 $S_{\mathrm{align}} \geq \theta$ 的样本进入 §8 的管道级修复——此时错误源已不在样本本身的字段或语法层，而需沿管道 $\Pi = \phi_V \circ \phi_G \circ \phi_C \circ \phi_R$ 反向归因。两层修复的分工对应**算子-管道两级**：$\rho_G^{\mathrm{loc}}$ 不改变 $\mathcal{V}$、$\mathcal{A}$ 与 $\phi_C$ 的输出，§8 的 $\rho_R / \rho_C / \rho_G / \rho_V$ 才允许触及这些更上游的对象。

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

LLM 在得到原子集 $\mathcal{A}$ 与词汇表 $\mathcal{V}$ 后，输出 DSL 树（主断言为"DNSNames 列表中每一项匹配 ACE-或-ASCII 标签正则"）。经 $\eta$ 解析为合法 $t \in \mathcal{T}_{\mathcal{V}}$ 后，$\rho$ 渲染为检查体，$\Phi_{\mathrm{post}}$ 注入 `Description / Citation / Source / Name` 等可溯源字段。$\sigma_{\mathrm{mech}}(t)$ 输出机械摘要 _"every entry in DNSNames matches the ACE-or-ASCII label regex"_，$\phi_V$ 比对该摘要与原文 `Description` 得 $c_{\mathrm{syn}} = 0.92$，综合对齐得分 $S_{\mathrm{align}} = 0.96 > 0.7$，验证通过。注意整个流程中 LLM 输出的所有命名均落在 $\mathcal{V} \cup \mathcal{A}$ 之内——若 LLM 编造一个不存在的字段（如 `cert.IDN_Names`），$\eta$ 会拒绝并触发反馈式重生成，该幻觉路径在架构层即被关闭。

## 8. 阶段归因式迭代验证框架（SAIV）

### 8.1 动机与问题陈述

第 6–7 节给出的方法在单次前向生成下已能产出结构完整的 zlint 代码，但在缺少独立人工真值的大规模场景中，系统仍面临若干不可回避的质量风险，且其**根源高度集中于最上游的 NL$\to$IR 提取**：**最致命的一类**是 IR 内容本身抽错——主语、谓词极性、约束或前提被误抽，则下游的分类、生成、验证全部作用在错误对象上、无一幸免（§9.5–§9.6 的实证表明当前底三层缺陷几乎全部源于此）；**其余两类**分别是可执行性分类出错（若误判为 `non_lintable`，其后所有检查失去对象）与代码生成在字段访问路径、边界条件或触发逻辑上偏离原文。至于召回**数量**是否完整，则是一个可由结构不变量（G1，§8.3）独立闭合的问题，不与上述内容风险混为一谈。**因此质量控制的首要着力点是 IR 内容，其修复算子 $\rho_R$（§8.7）也据此置于修复序列最前。**

传统自动合规代码生成多采用"单向前向 + 启发式重试"模式，其反馈信号要么是单一标量（如编译是否通过）、要么是粗糙的布尔指示，难以定位具体出错阶段。为此，本研究构造一个**沿管道反向定位误差来源、并触发阶段性修复**的迭代验证机制——**阶段归因式迭代验证（SAIV）**。"阶段归因"之名直指其核心动作：当端到端质量不达标时，先判定误差最可能来自召回、分类、生成还是验证哪一阶段，再对该阶段定向修复。该机制并不学习参数，而是将若干可直接计算的不变量作为端到端损失信号，**在无独立真值条件下提供可收敛、可追溯的质量控制**。这一点至关重要：它使整条管道的质量保证不再依赖于对每条规则的人工标注，而是由结构性不变量（规则集合守恒）与客观外部证据（工具实现存在性）共同支撑——质量验证因此由可计算残差承担，而非由独立的人工真值集合承担。

### 8.2 形式化定义

定义受控规范-代码生成管道 $\Pi$ 为四阶段复合函数：

$$
\Pi = \phi_V \circ \phi_G \circ \phi_C \circ \phi_R
$$

其中 $\phi_R$ 为 RFC 2119 关键词驱动的规则召回模块（对 ETSI 标准族则采用等价关键词集合 $\mathcal{K}_{\mathrm{ETSI}}$ 作为召回算子 $\phi_R^{\mathrm{ETSI}}$）、$\phi_C$ 为五条件可执行性分类模块（§5）、$\phi_G$ 为受限于 DSL 代码空间 $\mathcal{T}_{\mathcal{V}}$（§6）的 LLM 合成模块、$\phi_V$ 为三层语义对齐验证模块（§7）。给定标准文档 $\mathcal{D}$，令 $\mathcal{R}_{\mathrm{kw}}(\mathcal{D})$ 为 $\phi_R$ 召回的候选规则集合；对每条 $r \in \mathcal{R}_{\mathrm{kw}}$，$\phi_C$ 将其映射至互斥三元分类空间 $\{\mathrm{noise}, \mathrm{lintable}, \mathrm{nonLintable}\}$，记由此得到的三个子集为 $\mathcal{R}_N$（噪声）、$\mathcal{R}_L$（可执行）、$\mathcal{R}_U$（不可执行但具规范性义务）。

### 8.3 召回完整性不变量

**定理 1（召回完整性不变量）**。*若 $\phi_R$ 对非 ETSI 标准族仅由 RFC 2119 关键词触发，且 $\phi_C$ 为 $\mathcal{R}_{\mathrm{kw}}$ 上的互斥穷尽划分，则以下守恒关系成立：*

$$
|\mathcal{R}_{\mathrm{kw}}(\mathcal{D})| = |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U| \tag{7}
$$

直观含义是：一旦关键词召回完成，规则总量在下游任何分类步骤中都不应增加或减少。式 (7) 因此构成一个**结构性闭合条件**：若在任意阶段观测到等式不成立，则必可断定某下游模块引入了规则级别的增删误差。**该性质无需任何人工真值即可计算**，因此可在缺乏 ground truth 的大规模场景下作为第一级质量信号。对于 ETSI 标准族，不变量相应替换为 $|\mathcal{R}_{\mathrm{kw}}^{\mathrm{ETSI}}(\mathcal{D})| = |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U|$，其余推理不变。

### 8.4 代码正确性标签

设 $r \in \mathcal{R}_L$，$c = \phi_G(r)$。由于 $c$ 的 `Description` 已由确定性后处理与规范原文 $\mathrm{spec}(r)$ 对齐（§6.6），代码正确性标签 $\lambda_{\mathrm{code}}(r) \in [0,1]$ 由以下乘积度量：

$$
\lambda_{\mathrm{code}}(r) = \mathbb{1}[\mathrm{compile}(c)] \cdot s_{\mathrm{struct}}(c) \cdot c_{\mathrm{syn}}(\sigma(c),\; \mathrm{spec}(r)) \tag{8}
$$

基于 §7.1 的语义等价传递链，若 $\sigma(c) \equiv \mathrm{spec}(r)$ 且 `Description` $\equiv \mathrm{spec}(r)$，则可在不实际解析 Go 代码语义的前提下推得 $c \equiv \mathrm{spec}(r)$。对由证书级语义 oracle 认证为同义可证的 $r$，式 (8) 中的 $c_{\mathrm{syn}}$ 项以 oracle 的二值 $\mathrm{Code}\equiv\mathrm{IR}$ 验证取代（取 $1$），$\lambda_{\mathrm{code}}$ 退化为 $\mathbb{1}[\mathrm{compile}(c)]\cdot s_{\mathrm{struct}}(c)$ 与该验证的合取，不再经由非确定的 $c_{\mathrm{syn}}$。

### 8.5 损失函数

将上述标签组合为端到端损失：

$$
\mathcal{L}_{\mathrm{recall}}(\mathcal{D}) = 1 - \frac{\min(|\mathcal{R}_{\mathrm{kw}}|, |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U|)}{\max(|\mathcal{R}_{\mathrm{kw}}|, |\mathcal{R}_N| + |\mathcal{R}_L| + |\mathcal{R}_U|)} \tag{9}
$$

$$
\mathcal{L}_{\mathrm{code}}(\mathcal{D}) = 1 - \frac{1}{|\mathcal{R}_L|} \sum_{r \in \mathcal{R}_L} \lambda_{\mathrm{code}}(r) \tag{10}
$$

$$
\mathcal{L}_{\mathrm{total}}(\mathcal{D}) = w_R \cdot \mathcal{L}_{\mathrm{recall}} + w_C \cdot \mathcal{L}_{\mathrm{code}}, \quad w_R + w_C = 1 \tag{11}
$$

默认 $w_R = w_C = 0.5$。定理 1 描述的是 $\phi_C$ 作为互斥穷尽划分时的**理想恒等**，而 $\mathcal{L}_{\mathrm{recall}}$ 是对该不变量在**实际运行**中被违反程度的经验度量——现实中 $\phi_C$ 由 LLM 辅助实现，可能因漏判或幻觉破坏等式。对称归一化形式可同时惩罚两个误差方向：$|\mathcal{R}_{\mathrm{kw}}|$ 大于划分之和意味着分类模块丢弃了部分召回规则，反之意味着产生了额外的规则级条目。

**覆盖度目标（lint 覆盖残差 $\mathcal{L}_{\mathrm{cov}}$）。** 上述两项损失刻画"召回是否守恒"（G1）与"可 lint 规则是否被忠实写成代码"（G2），但**未**刻画一个同样关键的工程目标：本系统在**非硬编码**前提下，究竟能覆盖多少现有静态检查工具已实现的规则。以 zlint 为参照系——其在目标标准族的 lint 数是可直接查得的客观基准（v3.6.1：RFC 5280 共 **113** 条、CABF BR 共 **133** 条，合计 246 条）——定义覆盖残差

$$
\mathcal{L}_{\mathrm{cov}}(\mathcal{D}) = 1 - \frac{\bigl|\{\, r : \text{本系统为 } r \text{ 生成同义可证 lint} \;\land\; r \text{ 对应某条 zlint lint 的 citation 条款} \,\}\bigr|}{|\mathcal{C}_{\mathrm{zlint}}(\mathcal{D})|} \tag{11b}
$$

其中分母 $|\mathcal{C}_{\mathrm{zlint}}|$ 取 zlint 在该标准族的 lint 总数（113 / 133）。$\mathcal{L}_{\mathrm{cov}} \to 0$ 的含义是：**在不硬编码任一具体 lint 的前提下，本系统由规范文本端到端生成的覆盖广度逼近 zlint**。"非硬编码"由 §10.4 的 `cicasgen_*` 防火墙保证——生成 lint 与 zlint 原生实现两端互拒，故覆盖只计真正端到端产出。该残差与 G2 互补且方向正交：G2 管"已写出的代码对不对"，$\mathcal{L}_{\mathrm{cov}}$ 管"该写的还有多少没写出"——后者正是 $\rho_R$（把更多规则的 IR 修对、从而可归约可生成）与离线词汇扩展 $\rho_A$ 共同驱动下降的目标。当前快照 $\mathcal{L}_{\mathrm{cov}}$ 远未闭合（覆盖约 50%，见 §9.3），与 G2、同义性并列为迭代的主要开放目标。

### 8.6 阶段归因规则

先引入两个辅助量。**编译失败率** $p_{\mathrm{fail}}^{(t)} = \frac{1}{|\mathcal{R}_L|} \sum_{r \in \mathcal{R}_L} \mathbb{1}[\neg\mathrm{compile}(\phi_G(r))]$；**平均结构得分** $\bar{s}_{\mathrm{struct}}^{(t)} = \frac{1}{|\mathcal{R}_L|} \sum_{r \in \mathcal{R}_L} s_{\mathrm{struct}}(\phi_G(r))$。据此，第 $t$ 轮的阶段归因规则为：

$$
\mathrm{Stage}^{(t)} = \begin{cases}
\phi_R, & \mathcal{L}_{\mathrm{recall}}^{(t)} > \tau_R \\
\phi_C, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} > \tau_C \\
\phi_G, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} < 1 \\
\phi_V, & \mathcal{L}_{\mathrm{recall}}^{(t)} \leq \tau_R \;\land\; p_{\mathrm{fail}}^{(t)} \leq \tau_C \;\land\; \mathcal{L}_{\mathrm{code}}^{(t)} > \tau_C \;\land\; \bar{s}_{\mathrm{struct}}^{(t)} = 1
\end{cases}
\tag{12}
$$

四条分支两两互斥，构成对观测状态空间的完备划分（默认 $\tau_R = \tau_C = 0.10$）：**首先**检查结构性不变量是否违反——若违反，任何下游修复均无意义，必须回到 $\phi_R$；**其次**若结构不变量满足但编译失败率超 $\tau_C$，错误多来自 $\phi_C$ 误分类；**第三**，若编译普遍通过但语义对齐低且平均结构得分 $<1$，错误位于 $\phi_G$ 本身；**最后**，若结构完整且编译通过但同义率偏低，可能源于 $\phi_V$ 的判定偏差。

**G1 闭合后的重定向：$\phi_R$ 分支即 $\rho_R$（IR 内容修复）。** 上式第一分支原以召回数量缺口 $\mathcal{L}_{\mathrm{recall}}$ 为触发；但当 G1 已作为结构不变量闭合（$\mathcal{L}_{\mathrm{recall}}\approx 0$，§9.2），归因到最上游 $\phi_R$ 阶段的误差便不再是召回**数量**问题，而是其产出的 **IR 内容**问题（错主语 / 谓词极性 / 约束 / 前提）。因此该分支的修复算子由旧的"召回修复"重定向为 $\rho_R$（§8.7 的 IR 内容自反思修复）。为在无人工真值下触发它，引入一个确定性的 IR-内容信号——可归约 lint 中被 §7.1 实体级筛查 $\mathrm{Faithful}_{\mathrm{nec}}$ 判为 $\mathtt{ENTITY\_MISMATCH}$（且非指代）的比例，以及持续 $\perp_{\mathrm{NT}}$ 的不可归约比例——二者偏高即归因 $\phi_R$、触发 $\rho_R$。由于 $\rho_R$ 触及最上游对象、其错误会使一切下游修复失去意义，**它在归因序中被置于最前**（与 §8.7 一致）；$\rho_C/\rho_G/\rho_V$ 则按上式其余分支并列触发。

### 8.7 阶段修复算子

针对每一被归因阶段，设计一组阶段内修复算子。**其中 $\rho_R$（IR 内容自反思修复）排在最前、也最关键**：管道最上游的 NL$\to$IR 提取一旦出错（主语错抽、谓词极性反转、约束散文化、前提丢失），其下游的分类、生成、验证便全部失去正确对象——§9.5–§9.6 的实证表明，当前底三层（覆盖 / 代码生成 / 同义性）未闭合的缺陷**几乎全部**可追溯至此。因此 $\rho_R$ 是**首要修复算子**；其余 $\rho_C, \rho_G, \rho_V$ 为分阶段修复算子，彼此**并列、无优先级高低之分**，由 §8.6 的阶段归因决定本轮触发哪一个。只有 $\rho_R$ 改动 IR 本身，其余三者皆在 IR 给定的前提下工作。

- **$\rho_R$（IR 内容自反思修复，首要算子）**：当 $\phi_G$ 在 $K_{\mathrm{loc}}$ 轮内持续返回 $\perp_{\mathrm{NT}}$（IR 不可归约）、或 G2 同义性持续低于阈值时，将下游完整失败轨迹——当前 IR、不可归约类别、$\sigma_{\mathrm{mech}}$ 摘要、判官裁定与理由、同义置信度、以及本会话已尝试过的历史 IR——构成一条**反向失败信号**回传 LLM，令其自我诊断并决定：**(a)** 更正 IR 的 subject / predicate / constraint / precondition（连同"取自原文、支持该修正的证据子串"一并输出），或 **(b)** 声明 `NO_FIX`——确认 IR 已正确而当前词汇 $(\mathcal{A}, \mathcal{V})$ 确不足以表达该规则。$\rho_R$ **不是**盲目重试（同提示 → 同错），也**不是**静态规则修补，而是一次看得见完整下游证据的反思调用；它修复的是管道最上游的 NL$\to$IR 阶段，这也是 SAIV 首次真正闭合从规范文本到代码的**完整链路**。

  **g4-sanity 自动闸门（取代人工确认）。** $\rho_R$ 返回的新 IR 须经一道**确定性、无需真值、无需人工**的事后闸门方可进入后续流程，三项检查为：(i) subject 可被字段解析器解析为 $\mathcal{V}$ 内合法路径；(ii) `constraint` 字面值作为子串出现于原文（经 OID/hex 归一化）；(iii) `predicate` 极性与原文 RFC 2119 关键词一致。任一失败即视为引入幻觉而拒绝——被拒的 IR 连同违规原因可回传 $\rho_R$ 再反思一轮（上界 $K_{\mathrm{IR}}$，默认 2），仍不过则该规则归入**不可归约残差** $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$。**关键点：g4-sanity 是一道机械可计算的闸门、而非人工审核，正是它使 $\rho_R$ 乃至整个 SAIV 迭代得以全自动运行。** 它把"发现 IR 错 → 改抽取 → 重抽"从一个需逐条人工确认的离线动作，变成迭代回路内的一个自动算子——这一点决定性：若每轮 IR 修复都要人工拍板，论文意义上的"迭代"便名存实亡。$\rho_R$ + g4-sanity 因此既是方法学算子、也是工程上**可全自动执行**的回路（流程见 §8.8 的算法 2）。

- **$\rho_C$（分类修复）**：引入多工具交叉证据——若规则在 zlint、pkilint、certlint、x509lint 至少一个中存在对应实现，则必然可执行；若被判为 `non_lintable`，即视为假阴性回传 $\phi_C$ 重判。

- **$\rho_G$（生成修复）**：先尝试确定性修复（如 `Description`/`Citation` 字面替换）；若失败，将失败码片段与 IR 约束差异、或解析阶段的原子签名/封闭性错误作为反馈注入提示，触发 LLM 在 $\mathcal{T}_{\mathcal{V}}$ 内重新合成；若持续返回 $\perp_{\mathrm{NT}}$，则该规则进入离线词汇扩展通道 $\rho_A$（离线聚合反复返回 $\perp_{\mathrm{NT}}$ 的规则、按同质簇设计新原子，且仅向上单调扩张词汇表，不破坏既有代码的可比性）。

- **$\rho_V$（验证修复）**：扩大同义判定的语义邻域（如允许否定/肯定互换、一对多分解），或修正双判定源输出之间的不一致（§8.10 的 L4b 二元判官）。

四个算子各司其职：$\rho_R$ 作为**首要算子**触及最上游的 NL$\to$IR 对象；$\rho_C / \rho_G / \rho_V$ 则**彼此并列、无优先级高低**，仅视误差被 §8.6 归因到哪一阶段而触发，分别作用于分类、生成、验证。$\rho_R$ 居首是**结构性**理由——一切下游修复都以 IR 正确为前提，而非因它在某条优先级链条上排序更前。

### 8.8 迭代算法与终止条件

算法 2 给出完整流程。

```
算法 2：阶段归因式迭代验证（SAIV），ρ_R 为首要算子、g4 自动闸门取代人工
输入：标准文档 D，阈值 θ，最大迭代数 K
输出：最终代码集 C* 与收敛标志 converged

 1:  (R_kw, R_N, R_L, R_U) ← Π(D)
 2:  C ← {φ_G(r) : r ∈ R_L}
 3:  t ← 0
 4:  repeat
 5:      计算残差 L_recall(9), L_cov(11b), L_code(10), N_viol(§8.10)
 6:      if 全部残差 < θ then break                       // 多目标同时闭合
 7:      stage ← StageAttribution(...)                    // 式(12)；G1 已闭合 ⇒ 首查 IR 内容
 8:      if stage = φ_R then                              // 首要算子 ρ_R：IR 内容自反思修复
 9:          for each r 失败于 IR 内容（⊥_NT，或 Faithful_nec=ENTITY_MISMATCH 且非指代）do
10:              rep ← ρ_R(失败轨迹(r))                    // 自反思，返 REPAIR(ir') 或 NO_FIX
11:              if rep = NO_FIX  or  g4_sanity(rep.ir', text(r)) ≠ ∅ then
12:                  r → R^irred_code                     // 自动闸门否决 ⇒ 诚实留残差（无人工）
13:              else if 重测(rep.ir') 通过（归约∧认证∧编译∧忠实）then
14:                  IR(r) ← rep.ir'                      // 接受修复
15:      else apply ρ_{stage}∈{ρ_C, ρ_G, ρ_V}             // 并列，按归因分支触发
16:      更新 (R_kw, R_N, R_L, R_U) 与 C
17:      t ← t + 1
18: until t ≥ K 或 本轮无任何残差下降（loop-until-dry）
19: return (C, 全部残差 < θ)
```

第 8–14 行即 §8.7 的 $\rho_R$ 全自动回路：**全程无人工**，第 11 行的 g4-sanity 是确定性闸门、取代了人工 review；既不被否决又通过下游重测者方才接受，其余诚实落入 $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$。

**终止条件**：$\mathcal{L}_{\mathrm{total}} < \theta$（默认 $\theta = 0.05$）或达到最大迭代数 $K = 10$；若连续两轮归因阶段相同且损失未下降，终止并标记为局部不收敛。**收敛性**：由于每一阶段修复算子均为单调操作（要么严格减少该阶段误差项，要么保持不变），且 $\mathcal{L}_{\mathrm{total}}$ 每轮非递增，故序列 $\{\mathcal{L}_{\mathrm{total}}^{(t)}\}$ 必然收敛；该收敛点不保证全局最优，实证中亦观察到部分样本收敛于次优解（见 §9）。

### 8.9 机械翻译算子 $\sigma_{\mathrm{mech}}$：代码摘要的确定化替代

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

**命题 2（$\sigma_{\mathrm{mech}}$ 可逆性）**。*给定 $\sigma_{\mathrm{mech}}(t)$ 的输出，原始 DSL 树 $t$ 在原子层等价意义下可机械恢复（同义原子被映射到同一短语时不可区分，其余结构保留）。该性质保证 $\sigma_{\mathrm{mech}}$ 在验证链路中不构成信息瓶颈。*

**对验证链路的意义。** 引入 $\sigma_{\mathrm{mech}}$ 后，语义传递链 $\mathrm{Spec} \to \mathrm{IR} \to t \xrightarrow{\sigma_{\mathrm{mech}}} \mathrm{Summary} \equiv \mathrm{Description}$ 中，LLM 仅在 $\phi_C$、$\phi_V$ 两端出现，其余环节均为确定性算子。由此链路上的概率失真被压缩至**原子词典 $\mathcal{M}$ 的选择**这一离线设计问题，而不再随每条规则的判定独立采样。需强调 $\sigma_{\mathrm{mech}}$ 仅适用于**由本系统自身代码生成器产出的 lint**（其前提是持有 DSL 树）；对纯人工编写或来自外部仓库的既有 lint，仍需 LLM-$\sigma$ 提取语义。

### 8.10 不变量残差 L4b 修复

前文 $\rho_C$（§8.7）采用了"实现存在性 $\Rightarrow$ 可执行性"的单向推论——某规则只要被任一外部工具实现为静态检查，即必可执行。本节将其扩展为一个**双向 falsifiable 残差**，并给出基于二元判官的修复机制。给定外部工具集 $\mathcal{T}$ 及覆盖判定 $\mathrm{cov}_{\mathcal{T}} : r \mapsto \{\text{full}, \text{partial}, \text{none}\}$，定义违反集合 $\mathcal{V} = \{ r : \mathrm{cov}_{\mathcal{T}}(r) \in \{\text{full}, \text{partial}\} \land \phi_C(r) \neq \mathrm{lintable} \}$，记 $N_{\mathrm{viol}} = |\mathcal{V}|$。若 $\phi_C$ 与 $\mathrm{cov}_{\mathcal{T}}$ 同时正确则 $N_{\mathrm{viol}} = 0$，因此 $N_{\mathrm{viol}}$ 构成一个不依赖人工真值的可计算残差。

**FLIP-or-SPURIOUS 二元判官。** 对每条 $r \in \mathcal{V}$ 调用仲裁判官 $\phi_J : r \to \{\mathrm{FLIP}, \mathrm{SPURIOUS}\}$，输入为规则原文与覆盖证据：**FLIP** 表示 $\phi_C(r)$ 错判，应翻转为 lintable；**SPURIOUS** 表示 $\mathrm{cov}_{\mathcal{T}}(r)$ 为假阳，应降级为 none。任一支被采纳后对应标签被修正，$r$ 离开 $\mathcal{V}$。

**命题 3（残差单调性）**。*若 $\phi_J$ 在每条违反上均给出 FLIP 或 SPURIOUS 之一并被采纳，则 L4b 一轮过程后 $N_{\mathrm{viol}}$ 严格下降至 0。* 证明梗概：FLIP 使 $\phi_C(r) = \mathrm{lintable}$（违反式右侧成立），SPURIOUS 使 $\mathrm{cov}_{\mathcal{T}}(r) = \mathrm{none}$（违反式左侧不再触发），两类修复均移除该 $r$ 而不引入新违反，$\mathcal{V}$ 严格收缩至空集。

L4b 在 §8.7 的修复算子分类下属于 $\rho_V$ 的一种特化：它不调整代码本身或生成模块，而是修正双判定源输出之间的不一致；触发条件为 $N_{\mathrm{viol}} > 0$，终止条件为 $N_{\mathrm{viol}} = 0$。该扩展使上述单向推论的 falsifiable 残差具备真正的"零点"，从而可作为收敛判据。

### 8.11 多目标残差总览

为便于工程落地，前述形式化不变量可重述为若干目标，每一目标对应一个可计算残差，框架的收敛态由各残差同时为零刻画：**G1 召回完整性**（残差 $\mathcal{L}_{\mathrm{recall}}$，式 9，已作为结构性不变量闭合）、**Gcov lint 覆盖度**（残差 $\mathcal{L}_{\mathrm{cov}}$，式 11b，相对 zlint 113/133 的端到端覆盖广度）、**G2 代码-规范同义性**（残差 $\mathcal{L}_{\mathrm{code}}$，式 10，未覆盖子集是其最重要观测域）、**G3 双判定源一致性**（残差 $N_{\mathrm{viol}}$，由 §8.10 的 L4b 二元判官归零）。它们数学形式不同构（守恒等式 / 覆盖比 / 连续平均损失 / 集合基数），职责互补；其中 **Gcov 与 G2 是当前的开放目标，$\rho_R$（IR 内容自反思修复）是驱动二者闭合的首要算子**：

| 目标 | 残差 | 主要修复算子 | 修复对象 |
|---|---|---|---|
| G1 召回完整性 | $\mathcal{L}_{\mathrm{recall}}$（式 9） | —（结构不变量，已闭合） | 召回窗口 / 关键词集合（如需） |
| Gcov 覆盖度 | $\mathcal{L}_{\mathrm{cov}}$（式 11b） | **$\rho_R$（首要）**；$\rho_A$ | IR 内容修正（→ 更多规则可归约可生成）/ 离线扩原子 |
| G2 同义性 | $\mathcal{L}_{\mathrm{code}}$（式 10） | **$\rho_R$（首要）**；$\rho_G$ | IR 内容修正 / DSL 树重合成 / $\sigma_{\mathrm{mech}}$ 替换 |
| G3 双判定源一致 | $N_{\mathrm{viol}}$（§8.10） | $\rho_V$（L4b 二元判官） | $\phi_C$ 假阴性 / $\mathrm{cov}$ 假阳性 |

当 $\mathcal{L}_{\mathrm{recall}} = \mathcal{L}_{\mathrm{cov}} = \mathcal{L}_{\mathrm{code}} = N_{\mathrm{viol}} = 0$ 时 SAIV 进入闭合态。§9 的诚实快照表明：当前 G1 已闭合，而覆盖（Gcov）、代码生成与同义性（G2）这底三层尚未闭合——这恰体现了本框架以可计算残差**如实暴露**未闭合处、而非以单一指标掩盖之的价值。$\rho_R$ 作为首要算子，其设计纪律是**在拿不准时诚实多判 NO_FIX、而非臆造修复**——宁可诚实暴露残差、不以幻觉抬数；这与 §9.5–§9.6 关于"残差几乎全在上游抽取"的发现一致。

## 9. 实验与实证评估

本节按"无独立人工真值"的原则组织实证：所有质量信号都来自结构性不变量、确定性复算、外部工具的客观证据，或逐条人工裁定，而非对单条规则的人工标注真值。评测范围取**当前最干净的一轮全库重抽**——RFC 5280 与 CABF BR（standard_id ∈ {1, 19}）——并诚实地分层报告：守恒方程的顶两层已闭合，而覆盖、代码生成、同义性这底三层尚未闭合。本节即给出这一**诚实快照**，既展示框架已做到什么，也明确暴露未闭合处及其根因。

### 9.1 实验设置

评测在 RFC 5280（standard_id = 1）与 CABF BR（standard_id = 19）两个标准源的全库重抽结果上进行。NL→IR 抽取器为 GLM-Z1-9B-0414（一个 9B 量级的小模型——这一点对解读 §9.5 的同义率很关键）；代码生成为 §6.6 的受限 LLM 树合成；目标框架为 zlint v3；同义性判官仅在证书级 oracle 不适用的子集上启用。所有覆盖与同义性数字均经**逐条人工裁定**或确定性复算校准（裁定工件随代码公开），并可在干净数据上确定性复算。需特别说明：本快照是后续"全量重抽"工程之前的诚实基线，**不掩盖**底三层尚未闭合这一事实。

**关于"独立真值"的澄清（评测并非系统自评自）。** 须把 SAIV 的两种用途分开：其**迭代回路**确实不需要人工真值——由 g4-sanity 确定性闸门（§8.7）取代人工确认，这是方法学主张；但本节的**评测有效性**并不靠系统给自己打分，而是建立在三道**彼此独立、皆为外部来源**的参照之上：(i) **zlint 自带的 `Source` + `Citation` 元数据**（第三方工具声明其每条 lint 实现了哪一条款，§9.3 用作覆盖 ground-truth）；(ii) **以真实证书执行结果为真值的证书级 oracle**（其判定来自 zcrypto 解析 + zlint 运行时读回 `Status`，与生成代码所用 LLM 无关，§9.4）；(iii) **纯 tree-vs-text 的人工同义裁定**（§9.5，独立于生成器与判官）。三者无一是"用本系统的输出去验证本系统的输出"。本评测**未**做的两件事（纯属未跑、非否定其价值）：未与"现代 LLM 直接生成 Go lint"（GPT-4.1 / Claude / Gemini）做基线对比，亦未对 KG/确定性检索、DSL、SAIV 各组件做受控消融——其可行性、设计与作为 future work 的定位见 §10.4。

### 9.2 召回与可 lint 性的守恒漏斗（G1）

第一层质量信号是 G1 守恒（§8.3 定理 1）：关键词召回的规则总量，在下游任何分类步骤中都不应增减。当前快照下守恒严格成立：

$$
\underbrace{2091}_{\text{召回}} \;=\; \underbrace{510}_{\text{噪声}} + \underbrace{1581}_{\text{真规则}}, \qquad \underbrace{1581}_{\text{真规则}} \;=\; \underbrace{370}_{\text{可 lint}} + \underbrace{1211}_{\text{不可 lint}}.
$$

两式逐项相等，即 G1 残差 $\mathcal{L}_{\mathrm{recall}} = 0$、守恒顶两层闭合。可 lint 的 370 条按标准源分为 CABF 251 条与 RFC 5280 119 条；这 370 条即下游代码生成 $\phi_G$ 的定义域。

### 9.3 lint 覆盖：以 zlint 自带 citation 为 ground-truth

要回答"现有工具覆盖了多少可 lint 规则"，关键在于用对判据。早期仅以 DSL 树语义匹配（`relate`）得覆盖 109 条；但 zlint 每条 lint 都自带 `Source`（RFC5280 / CABF…）与 `Citation`（其所实现的具体条款）——**这才是覆盖的第一手证据**。以"规则所在 section 被同源 zlint lint 的 citation 引用"为判据，覆盖达 **177 条**（CABF 91 + RFC 86），远高于语义匹配的 109（表 1）。

**表 1：zlint citation 覆盖 vs 语义匹配覆盖（370 条可 lint）**

| 口径 | CABF | RFC 5280 | 合计 |
|---|---:|---:|---:|
| citation 覆盖（section 被同源 zlint 引用） | 91 | 86 | **177** |
| `relate` 语义覆盖 | 72 | 37 | **109** |
| 差额（citation 覆盖但语义未匹配） | — | — | **117** |

二者 117 条差额经逐条归因：**63 条**我方无可比 DSL 树（codegen 缺口或退化 IR，而 zlint 往往是覆盖的，如 §4.1.2.5 → `e_utc_time_not_in_zulu`）；**50 条**同 section 但多为该节内**别的**需求（section 共享 ≠ 需求覆盖；少数是同需求而我方树抽错，如 §4.2.1.4"策略 OID 不得重复"↔ `e_ext_cert_policy_duplicate`，因我方把 uniqueness 误抽成 count 而失配）；**4 条** zlint 有 lint 但其 DSL 未被抽取（多为算法委派类不可归约）。故真实覆盖被语义匹配显著低估：未匹配上的 DSL 树并不等于 zlint 无此 lint。

**两个方向勿混淆——覆盖度作为迭代目标（Gcov）。** 上表回答的是"zlint 覆盖了我方多少条规则"（177/370）。而 §8.5 的覆盖残差 $\mathcal{L}_{\mathrm{cov}}$ 度量的是**反方向**——在**非硬编码**前提下，本系统端到端生成的 lint 复现了 zlint 自身多少**广度**：分母取 zlint 在该标准族的 lint 实测总数（v3.6.1：RFC 5280=113、CABF BR=133，合计 246），分子为"本系统生成同义可证 lint 且对应某条 zlint citation 条款"者。这个反方向才是迭代要逼近闭合的目标。上文 §4.2.1.4"策略 OID 不得重复"的失配，根因正是 IR 把 uniqueness 误抽成 count——这类正是 $\rho_R$ 可自动修复、从而推动 $\mathcal{L}_{\mathrm{cov}}$ 下降的对象。

### 9.4 代码生成分层与证书级 oracle（旗舰结果）

"一条可 lint 规则能否被写成代码"并非非黑即白，而是随严格度分层（表 2）。最严的一档——**确定性归约 + 渲染 + 全部原子已认证 + 编译通过**——有 179 条；放宽到"能渲染成 Go 树"为 213 条，再放宽到"归约器产出 well-formed 树"为 219 条。其中**未被 zlint citation 覆盖**者分别为 88 / 104 / 110——即本系统相对现有生态的"净新增"领地，随口径在 88–110 之间，而非单一数字。

**表 2：代码生成分层及其未覆盖子集**

| "能写成代码"的定义 | 总数 | ∧ 未被 zlint 覆盖 |
|---|---:|---:|
| 最严：确定性归约 + 原子认证 + 编译 | 179 | 88 |
| 中：能渲染成 Go 树 | 213 | 104 |
| 宽：归约器产出 well-formed 树 | 219 | 110 |

**最严一档的 179 条，正是证书级 oracle（§7.1）以零判官确定性、与所用模型无关地*验证* $\mathrm{Code}\equiv\mathrm{IR}$ 的集合——这是本研究的旗舰结果。** 这 179 条的忠实性不依赖任何 LLM 投票，而由"每个原子都通过受控证书 fixture 认证 + 整树编译通过"经结构归纳给出（其执行级验证而非定理的证据地位见 §7.1）；更换生成器或判官模型都不改变这一验证子集。与之对照，一个单票 LLM 判别器会"接受"一个明显更大、却**未经此验证**的超集（其可靠性问题见 §9.5 的校准）；二者之差正是单票判据的风险所在。**这个固定、与模型无关的 $\mathrm{Code}\equiv\mathrm{IR}$ 参照系，正是后文得以把残余误差*定位*到抽取阶段（§9.5–§9.6）的前提**——当代码对 IR 的忠实性被独立钉死，凡仍出错者必出在 IR 本身。

### 9.5 同义性作为发射门（手裁校准）

oracle *验证*的是 $\mathrm{Code}\equiv\mathrm{IR}$（代码忠实于 IR）；但系统的最终价值在于 $\mathrm{Code}\equiv\mathrm{Spec}$（代码忠实于**原文**），这还要求 $\mathrm{IR}\equiv\mathrm{Spec}$。本研究为此对"能渲染 ∧ 未覆盖"的子集做**逐条人工裁定**（纯 tree-vs-text、无 LLM）——这是一份**独立于本系统生成器与判官的人工参照**（连同 §9.3 用作覆盖判据的 zlint 自带 Source+Citation 元数据、§9.4 以真实证书执行为真值的 oracle，构成本评测三道彼此独立、皆非"系统自评自"的外部信号）——得到真实同义率：认证 88 子集 **44 / 88 = 50%**，扩到全 104 条仍为 44 / 104 = 42%（新增的 16 条 render-but-uncertified 全部不同义，印证认证门与同义性正相关、正确滤除了不 sound 者）。

须正确解读这个 50%，以免误读为"系统有一半代码是错的"：**其一（选择偏差）**，它测的是**最难子集**——"未被 zlint 覆盖 ∧ 可渲染"本就富集连 zlint 都未实现的硬骨头，并非 370 条可 lint 规则的平均水平；**其二（瓶颈在抽取、且抽取器是小模型）**，这 50% 反映的是 $\mathrm{Spec}\to\mathrm{IR}$ 抽取质量而非 $\mathrm{IR}\to\mathrm{Code}$ 生成质量（见下"约 60 条全在上游"），而本快照所用抽取器是一个 **9B 量级的小模型**（GLM-Z1-9B-0414，§9.1），故该数是此抽取器在难子集上的**未过滤产出**质量、而非框架天花板——更换更强抽取器是直接且尚未穷尽的杠杆（§10.4）；**其三（不以未过滤产出交付）**，系统经发射门后交付集 100% 同义 by construction（见本节末）。

这一步同时校准了 LLM 同义判官的可靠性：判官初判仅 34%（30 / 88），但经核对其中相当一部分是假阴性——既有渲染端模板缺口导致的错误摘要，也有判官对表格残片、指代、版本编码的系统性误判（如 "cA MUST be set TRUE" ↔ `IsCA()` 实为同义却被判否）。这再次印证 §7.1 的论断：单票 LLM 判官不可靠，必须由确定性 oracle 与人工裁定双向校准。此处同义性按**二元判定**处理（表达 / 没表达，无中间档），判官三档中的 partial 一律归入"没表达"。

**约 60 条真·不同义缺陷全部源于上游抽取。** 把上述不同义样本逐条核实表明：归约器忠实地把**错 IR** 映成**错树**（归约器本身 sound，对退化原子一律返回 honest None），病根**全部在抽取端**。这与 §9.6 的 R24081 同源：oracle 仍可*验证* $\mathrm{Code}\equiv\mathrm{IR}$，但 $\mathrm{IR}\neq\mathrm{Spec}$。故唯一出路是**改抽取 + 重抽**，而非在归约器上打补丁。

**方法学结论：同义性应作为发射门，而非事后指标。** 系统的价值在于忠实翻译——一条不同义的 lint 就是一件**错件**。因此正确目标不是"把同义率从 50% 抬到 60%"，而是**只发射经双重验证的 lint**：$\mathrm{Code}\equiv\mathrm{IR}$ 由 §7.1 的证书级 oracle 执行级*验证*、$\mathrm{IR}\equiv\mathrm{Spec}$ 由同义判定把关，二者皆过才发射，其余诚实地拒发为残差。如此发射集**100% 同义 by construction**（当前约 44 条），而"收敛"的定义也随之改变——不再是"同义率趋近某阈值"，而是"迭代修上游抽取、把残差逐批转为同义，发射集随之增长且始终维持 100% 同义"。这里需区分两类残差：约 60 条是**可归约但暂未修**（下一步重抽即可消除），与**真·不可归约**残差（受双轴纪律所限，如 PKI 外部 primitive 的 Unicode NFC / IDN→ACE、逐字节 hex 字面、语料内单形态规则）截然不同；后者构成本框架"以受限词汇换可验证性"之代价的诚实边界。

### 9.6 确定性忠实性筛查的交叉验证

作为与 oracle、判官皆独立的第三重确定性检查，本研究对生成产出运行 §7.1 的实体级筛查 $\mathrm{Faithful}_{\mathrm{nec}}$。其代表案例 R24081 经审计确认根因是**上游 IR 主语错抽**（authorityCertIssuer / authorityCertSerialNumber 本属 AKI 字段，却被抽成 AIA 扩展）：oracle 仍可*验证* $\mathrm{Code}\equiv\mathrm{IR}$（代码忠实于那条**错** IR），但筛查标记出"AIA 在原文中从未出现"，从而暴露 $\mathrm{IR}\neq\mathrm{Spec}$。据此做的上游修复（为字段 schema 补齐缺失的 AKI 子字段）使其重抽后主语正确归位、并因"共现"语义无对应原子而诚实转为残差。这正印证了"**筛查 → 定位 → 上游修复**"的闭环，也再次说明本框架的瓶颈与修复着力点都在抽取端，而非代码生成或验证端。

### 9.7 SAIV 迭代轨迹（每轮记录）

SAIV 的价值在于其残差**随迭代单调收敛**。为如实记录这一过程，本研究自一次干净的全量重抽（锚点修复版）起，对每一轮迭代记录各层守恒/质量指标，形成可复现、可绘图的收敛轨迹（表 3）。第 0 轮为重抽后的基线；其后每轮施加首要算子 $\rho_R$（IR 内容自反思修复，§8.7），自动修复一批 IR 并重测下游。

当前守恒漏斗（第 0 轮基线）：关键词召回 **2091** 条，经受控提取得 IR **2080** 条（11 条因端点空响应未出 IR，已确定性重试至残 11）；其中可 lint **445** 条、非可 lint 1635 条。G1 数量守恒严格成立（2091 = 2080 + 11；2080 = 445 + 1635）。

**表 3：SAIV 迭代轨迹（同一干净重抽语料上逐轮记录）**

| 轮次 | 可 lint | code≡IR 可证（编译过） | 覆盖 Gcov（/zlint 246） | 同义率 IR≡Spec | 本轮 $\rho_R$ 自动修复 | 备注 |
|---:|---:|---:|---:|---:|---:|---|
| 0（锚点全量重抽基线） | 445 | 190 | ⟦测量中⟧ | ⟦测量中⟧ | — | 2080 ok/2091；空-200 重试 131→11 |
| 1（$\rho_R$ over not_reducible 245） | 445 | **194** | ⟦测量中⟧ | ⟦测量中⟧ | +4 | 199 NO_FIX（多为条件式/跨字段/超 DSL，诚实拒修）、1 g4 拒 |

对照重构前的旧基线（可 lint 370、code≡IR 179）：锚点修复 + obligation 确定化使可 lint 升至 445（无 MAY/OPTIONAL 混入，仍为 MUST/SHOULD 族）、code≡IR 可证升至 190；首轮 $\rho_R$ 再自动 +4。$\rho_R$ 在 not_reducible 残差上的产量较低（4/245），其本身即一项诚实发现：该残差大多**真正超出当前 DSL 表达力**（条件式、跨字段编码、子字段），$\rho_R$ 正确地诚实判 NO_FIX 而非臆造修复；IR 内容修复的高产区在"可归约但谓词/约束抽细错"一类（如 uniqueness 误抽为 count），属后续轮次。表 3 将随每轮迭代追加，轮数足够后即可绘出各残差的收敛曲线。覆盖 Gcov 与同义率两列待全量重抽后以新数据重算回填（二者皆为确定性、可复现测量）。

## 10. 讨论与有效性威胁

### 10.1 关键发现

**把"忠实性判定"本身确定化，是核心方法学发现。** 验证生成代码是否忠实于规范，传统做法或靠人工（不可规模化）、或靠另一个 LLM 投票（不可复现）；本研究把这一判定**确定化**——证书级 oracle 以真实证书的执行结果取代投票，给出零判官、与所用模型无关的 $\mathrm{Code}\equiv\mathrm{IR}$ 执行级*验证*（§9.4）。同一思路贯穿全链路（受限 DSL 在语言层关闭字段/OID 编造，$\sigma_{\mathrm{mech}}$ 以结构归纳消除 LLM 摘要的极性失真），由此提炼出一条不限于 PKI 的设计原则：**验证链路上每个算子都应尽可能确定化，确定性的着力点可从生成端迁移到验证端**。

**同义性应作为发射门，而非事后指标。** 未覆盖子集真实同义率约 50%（§9.5）不应被读作"一半代码是错的"：几乎所有不同义都源于**上游 IR 抽取**（主语错抽、子字段当成整个扩展）而非代码生成——归约器忠实地把错 IR 映成错树。故正确姿态不是"把同义率调高一点"，而是只发射经 $\mathrm{Code}\equiv\mathrm{IR}$ 与 $\mathrm{IR}\equiv\mathrm{Spec}$ 双重验证的 lint，使发射集 **100% 同义 by construction**，残差由上游重抽逐批转化；"收敛"因此被重新定义为发射集在保持 100% 同义下持续增长。

### 10.2 跨 PKI 的适用性

本框架的核心机制并不特定于 PKI。Layer 1 的 RFC 2119 关键词集可经配置替换为其他生态的道义关键词（如 ISO 的 shall/should/may）。因此方法适用于同时满足三条件的规范源：**(1)** 以可识别的形式化道义关键词表达强制/推荐；**(2)** 约束目标是结构化、可机器解析的产物（证书、协议消息、配置文件）；**(3)** 具备支持知识图谱与作用域继承的层级化章节结构。这使本框架的方法学价值超出 PKI 单一领域。

### 10.3 对规范作者与工具维护者的建议

对**规范作者**，三条起草原则可显著降低提取歧义：单句单义务（一句至多一个 MUST/SHALL）、以 ASN.1 路径而非代词精确引用字段、用固定模式规范化跨文档引用（使每个引用都能映射为知识图谱上一条类型化边）。对 **lint 维护者**，建议把 `description` 直接写成显式给出字段路径/断言类型/取值/严重级别并引用规范条款的代码摘要——本研究发现大量 lint 描述既非规范引用、也非实现忠实摘要，致使覆盖分析必须先做一步代码摘要才能对齐，徒增开销与裁决噪声。

### 10.4 局限性与有效性威胁

**方法局限与结论范围。** 同义判定端点 $\phi_V$ 仍由 LLM 实现，更稳健的路径应将其与形式化验证或测试用例结合；原子集 $|\mathcal{A}|=68$ 对 ASN.1 字节级编码、宿主框架未暴露字段、多分支严重度等仍有缺口，需经离线 $\rho_A$ 单调扩展；跨文档引用与动态约束（"有效期不得超过 N 天"）支持有限。故本文结论严格受限于所用输入表示（结构化 IR）、受限代码空间（$\mathcal{T}_{\mathcal{V}}$）与验证流程，更适合可在单文档上下文闭合的静态约束，不应外推为"所有 PKI 规范均可完全自动化"或对所有标准族/语境稳定泛化。

**组件必要性未经消融（尤其检索机制）。** 本文给出的是一个端到端可工作的系统，但**并未**对各组件做受控消融，故对"必要性"的主张须分层诚实界定。**(i) 知识图谱与确定性检索：本文不主张其相对普通 RAG 的必要性或优越性。** 一方面，检索质量只通过下游 IR 忠实性间接显现，而后者由抽取器主导（§9.5），使"固定语料、仅替换检索"的干净消融高度受混淆、难以给出可信的量化对比；另一方面，本文采用确定性子图检索的初衷是**可溯源与可复现**（不引入向量相似度或 LLM 臆造上下文），这是一项工程取舍而非经实验验证的贡献，其相对普通 RAG 的增益留作 future work。**(ii) 受限 DSL（相对直接生成 Go）：必要性是*架构性*论证而非实验结论。** 命题 1 在语言层关闭字段/OID 编造、并使"代码语义等价于规范"成为可计算判定，配合 179 条离线编译零幻觉的观测，构成 by-construction 的理由；但本文**未**跑"直接生成 Go"的对照（见下条）。**(iii) SAIV：** 形式化框架与 g4-sanity 全自动闸门已被证实可运行，但"有无 SAIV"在规模上的效果消融未在本文报告。

**现代 LLM 基线的缺位，以及 oracle 使之廉价。** 一个自然的问题是：让前沿模型直接生成 Go lint，效果如何？本文**未**做此基线对比，这是当前最重要的实证缺口之一。但须指出一个使该对比变得廉价且可复现的事实：本文的证书级 oracle 是**生成器无关**的——它对*任意*来源（含"直接生成 Go"、含不同前沿模型）的 lint 都能以同一执行级判据验证 $\mathrm{Code}\equiv\mathrm{IR}$。因此"用 oracle 在同一 179/370 目标集上评测直接生成基线的通过率"是一项定义明确的 future work，而非方法学上的障碍；其结论也将直接检验本文的核心观察——*生成不是瓶颈、抽取才是*。

**覆盖规模与泛化的边界。** 179 这一数字受 oracle 的**可认证性**所限，而非可 lint 规则的上界：只有能用证书工厂造出"满足/违反"区分对的原子才可认证，需跨证书上下文、密码学事实（如模数素性）或字节级编码的原子无法认证（本节末三条边界）。故 179 是*可被 oracle 执行验证*的子集规模，与可 lint 总量（370）是不同口径，二者之差并非"生成失败"而是"暂不可被该 oracle 验证"。至于跨体系泛化——Mozilla / Microsoft 根程序、ETSI EN 319、国密 GM/T——本文仅给出机制层面的适用性论证（§10.2），**未**在这些体系上做实证；其道义关键词集、字段 schema 与原子覆盖均需重新适配，故不应将 RFC 5280/CABF BR 上的结论外推为对所有标准族稳定泛化。

**端到端正确性的精确口径。** 须明确区分两条腿：$\mathrm{Code}\equiv\mathrm{IR}$ 由证书级 oracle 在可认证子集上**确定性、可复现、与模型无关地自动验证**；而 $\mathrm{IR}\equiv\mathrm{Spec}$ 当前由逐条人工同义裁定把关、尚未自动化。因此端到端 $\mathrm{Code}\equiv\mathrm{Spec}$ 的保证**仅对经双重门的发射集成立**，且其中 $\mathrm{IR}\equiv\mathrm{Spec}$ 一支是人工的。本文不声称已自动求解 $\mathrm{Spec}\to\mathrm{IR}$；恰恰相反，本文的一项发现是：当生成端被 oracle 钉死后，残余误差**全部**落在 $\mathrm{Spec}\to\mathrm{IR}$ 抽取，从而把"端到端自动化"的未决核心精确**定位**到这一上游阶段（$\rho_R$ + g4-sanity 是朝其自动化迈出的第一步，但远未闭合）。

**可 lint 性分类（370 条）的校验方式。** 370 条的可 lint 性标签并非以逐条人工真值校验，而是：**(i)** 以**外部工具实现存在性**作单向交叉验证（若 zlint/pkilint/certlint/x509lint 任一已将某规则实现为静态检查，则其必可 lint——这是不依赖人工标注、且语言无关的假阴性探测器）；**(ii)** 对其中*已生成代码*的子集（如 §9.5 的 88/104）做**独立人工同义裁定**。本文**没有**对全部 370 条分类做穷尽的独立人工审计，故该分类的精确率（相对其召回率）只受部分外部约束，是一处诚实的开放点。

**内部有效性。** 最大威胁是上游 IR 误差传播——抽错的规则边界/字段/约束会沿 $\phi_C/\phi_G/\phi_V$ 传播并伪装成生成端问题；§9.5、§9.6 表明当前几乎所有缺陷都可追溯至此，故修复着力点明确在抽取端，§8.7 的 $\rho_R$（IR 内容自反思修复，首要算子）为之提供运行时可证伪窗口。同义判官 $\phi_V$ 非人工真值，以置信度阈值过滤并主要作诊断信号；对 prompt 的敏感性以固定模板与记录模型版本缓解。

**外部有效性。** 实证仅覆盖 RFC 5280 与 CABF BR，未含国密 GM/T 等体系；生成代码面向 zlint，跨框架迁移非即插即用；已验证规则相对完整规范仍属子集。

**构念有效性。** 编译通过只衡量"能否被框架接受"而非语义忠实；对齐得分权重（0.15/0.10/0.15/0.50/0.10）为经验值；覆盖率依赖 LLM 辅助匹配，应作近似而非生态真值。两点须强调：其一，为防"自己覆盖自己"的循环虚高，生成 lint 以 `cicasgen_*` 前缀加横幅与 zlint 原生代码显式区隔、并被语料抽取器与覆盖匹配器两端拒收，保证"已覆盖"只计第三方实现；其二，证书级 oracle 的*验证*受三条边界约束——仅覆盖能造出"满足/违反"区分对的可认证子集（约 179/370）、是受控 fixture 上的经验测试而非定理、且与 lint 端共享 `util.*` OID 表（盲于 OID 身份层错误）——其外产出诚实归入"未验证"。

## 11. 结论

### 11.1 研究总结

本研究面向 PKI"规范-到-合规检查代码"的端到端自动化，给出一个贯通"规则提取 → 中间表示 → 可 lint 性判定 → 代码生成 → 验证"的统一框架，以结构化 IR 与五条件可 lint 性判定为前后两半的统一接缝。前半链路以确定性知识图谱检索 + 受 schema 约束的 LLM 语义解析保证提取可审计、可复现；后半链路在语言设计层面把代码空间限制为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$（命题 1 关闭字段/OID 编造类幻觉），并以**证书级语义 oracle** 对生成 lint 经真实证书执行*验证* $\mathrm{Code}\equiv\mathrm{IR}$（执行级验证，边界见 §7.1/§10.4）。阶段归因式迭代验证（SAIV）则将召回完整性、代码-规范同义性与双判定源一致性作为可计算残差，在**无人工标注真值**下提供沿管道反向定位与定向修复的收敛性保证。各环节的形式化与实证见 §4–§9。

### 11.2 主要结论

实证支持三点经验结论与一项方法学论断。**其一**，Web PKI 规范源与现有静态 lint 工具之间存在显著的**覆盖缺口**：即便以最有利于现有工具的 citation 判据，370 条可 lint 规则中 zlint 也仅覆盖 177 条，余下约 193 条缺乏实现、构成自动生成的直接目标。**其二**，可靠的规则提取依赖**受约束的提取**而非端到端直接提示——将 LLM 限定为受 schema 约束的解析器、并以确定性检索与确定性可 lint 性判定包裹之，是提取可审计、可复现的关键。**其三**，Web PKI 规范规则中仅有一小部分（RFC 5280 与 CABF BR 的 1581 条真规则中约 23%、即 370 条）可被还原为单制品静态 lint 检查，这一比例本身即是对"哪些规范可被静态强制"这一长期模糊问题的量化回答。**其四（瓶颈定位，一项诚实的负向发现）**，当生成端被 oracle 钉死为可复现、与模型无关的 $\mathrm{Code}\equiv\mathrm{IR}$ 之后，残余的不忠实**全部**落在 $\mathrm{Spec}\to\mathrm{IR}$ 抽取而非 $\mathrm{IR}\to\mathrm{Code}$ 生成——故就当前数据而言，*生成不是难点、抽取才是*；本框架的价值之一正是以确定性仪器把这一未决核心**定位**到上游。相应地，端到端正确性须诚实界定口径：$\mathrm{Code}\equiv\mathrm{IR}$ 为自动保证，$\mathrm{IR}\equiv\mathrm{Spec}$ 当前由人工裁定把关，故 $\mathrm{Code}\equiv\mathrm{Spec}$ 仅对发射集成立、其 $\mathrm{IR}\equiv\mathrm{Spec}$ 一支的自动化是首要未来工作。在方法学层面，本研究给出并以实证支持一项一般性原则——**验证链路上的每个算子都应尽可能确定化**，其最有力的实例即证书级语义 oracle 把"忠实性判定"也确定化为可执行、与所用模型无关的 $\mathrm{Code}\equiv\mathrm{IR}$ *验证*——并以"可归约子集闭合 + 不可归约边界披露"双指标取代单一收敛阈值，为基于受限词汇的规范-到-代码生成提供了可复现的诚实边界声明范式。

### 11.3 未来工作

后续工作沿以下方向展开：将自然语言同义判定与符号执行、模型检查等形式化方法结合以建立交叉证据，缓解 $\phi_V$ 端点的判定失真；以单调可加流程持续扩展原子词典 $\mathcal{A}$，逐步消除 ASN.1 字节级编码、宿主框架未暴露字段等表达缺口；构建支持引用解析与依赖追踪的跨文档知识表示，并探索将引用解析纳入 $\mathcal{A}$ 的扩展规则；设计面向动态约束（时间、外部状态）的原子类与参数化规则表达；以及探索框架无关的 DSL 中间表示，即给定多套 $(\mathcal{A}, \rho)$ 对而保持同一 $\mathcal{T}$，使同一棵 DSL 树可被渲染至多语言宿主框架。

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

所有分量均为冻结有限集合；LLM 在 prompt 区段 C（附录 H）获得各分量全量枚举，故其输出中出现 $\mathcal{V}$ 之外的标识符即触发 $\eta$ 解析错误（命题 1）。

**代表性原子（节选）。** 原子集 $\mathcal{A}$（$|\mathcal{A}|=68$）按语义簇组织，每个原子有类型化签名 $\mathrm{sig}(a)$（§6.3）。下表按簇节选关键原子（完整 68 项随代码与数据一并公开）：

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

**共享 Go 渲染样板。** 所有 DSL 树经 $\rho$ 渲染后嵌入下列固定外壳，规则间差异完全集中在 `{{EXECUTE_BODY}}` 与 `{{IMPORTS}}`；`{{PACKAGE}}`/`{{SOURCE}}`/`{{EFFECTIVE_DATE}}`/`{{DESCRIPTION}}`/`{{CITATION}}`/`{{LINT_NAME}}` 由 $\Phi_{\mathrm{post}}$（§6.6）确定性绑定：

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

$\sigma_{\mathrm{mech}}$（§8.9）由原子-短语字典 $\mu : \mathcal{A} \to \mathcal{L}_{\mathrm{NL}}$ 与三组合子归约规则构成。代表性条目：

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

lint 与规范之间的覆盖缺口并非单一原因，而是 lint 生态中四类结构性因素共同作用的结果。**(C1) 异步演进**：CABF Ballots 与 RFC 勘误的修订速度快于维护者的吸收能力，新增与废止的规范规则都表现为未匹配。**(C2) 多源非规范依据**：相当一部分 lint 检查根植于 issue tracker 决策、根程序实践或 CA 运维经验，构成所分析语料之外、不可达的次级权威。**(C3) 规范文本不完备**：规范源中的自然语言歧义（如"appropriate""reasonable"）由工具维护者解释而非在文本中写明，故不计为覆盖命中。**(C4) 粒度不对称**：规范规则与 lint 检查原子之间存在多对多映射，使覆盖完整性难以人工核验。

### 附录 G：典型 lint↔规范对照案例

本附录以 zlint 为例，从 §9.3 的覆盖分析中按 full / partial / none 三类各采样一个代表性案例，展示覆盖分析在不同情形下的判定与受控判官给出的理由。

| lint rule_id | code_summary | 匹配规范规则 | 判定 | 判定原因 |
|---|---|---|---|---|
| `e_ca_common_name_missing` | The CA certificate subject MUST include a commonName attribute. | CABF-Server §7.1.2.10.2：`commonName` \| MUST | **full** | 两者都要求 CA 证书 subject 中存在 commonName，字段与义务级别一致。 |
| `e_ca_key_usage_not_critical` | The root CA and intermediate CA certificate keyUsage extension MUST be marked critical. | CABF-SMIME §7.1.2.3：`keyUsage`（SHALL be present）This extension SHOULD be marked critical | **partial** | lint 对 keyUsage criticality 施加了比规范 SHOULD 更严的 MUST 约束。 |
| `e_cab_dv_subject_invalid_values` | The subscriber certificate subject DN MUST NOT contain attribute types other than countryName and commonName. | —（未召回） | **none** | 在严格语义等价判据下，候选后端池中未召回匹配规则，尽管该 lint 引用了 CABF-BR §7.1.2.7.2。 |

### 附录 H：DSL 合成 Prompt 模板

本附录给出 §6.6 所述受约束 LLM 调用 $\phi_G$ 的实际系统提示与四区段拼接结构。

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
