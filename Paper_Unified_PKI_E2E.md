# 从 PKI 标准到合规检查代码：规则提取、可 lint 性判定与可验证代码生成的端到端框架

## 摘要

公钥基础设施（PKI）的证书编码规则分散在 RFC 5280、CA/Browser Forum 基线要求（CABF BR）、ETSI EN 319 与 Mozilla 根存储策略等多份自然语言标准中。自 2025 年起 CA/Browser Forum 要求所有公信 CA 在签发前对证书执行 lint 检查，将规范文本系统转化为可执行的合规代码因而成为 PKI 治理的关键环节。然而现有 lint 工具（如 zlint、pkilint）的每条检查均由专家逐条手写并随规范修订维护，"哪些规范条款能被静态检查、现有工具又覆盖到何种程度"长期缺乏系统答案。

本文提出一个从标准文本到合规检查代码的端到端框架，串联规则提取、中间表示（IR）、可 lint 性判定、代码生成与验证五个环节。其设计原则是：仅在确需语言理解之处使用大语言模型（LLM），验证链路上的其余环节尽量实现为可复现的确定性函数。具体而言：(1) 跨文档上下文不依赖 LLM 推断，而由 PKI 规范知识图谱上的确定性子图检索给出可溯源上下文；LLM 仅承担受 schema 约束的语义解析角色，将规则转写为结构化 IR（核心四元组 ⟨主体, 义务, 谓词, 约束⟩）。(2) 可 lint 性被形式化为五个离散 IR 字段上的确定性布尔函数 $C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$，判定可复现，任何误判都可追溯到唯一字段。(3) 代码生成不输出自由形式的 Go 代码，而在语言设计层面将生成算子 $\phi_G$ 的值域限制为有限原子集 $\mathcal{A}$（$|\mathcal{A}|=68$）与类型化词汇表 $\mathcal{V}$ 张成的受限 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，使"编造不存在的字段或 OID"这类幻觉在架构层被排除（命题 1）。(4) 针对"生成代码是否忠实于规范"这一最难的判定，本文不依赖另一个 LLM 投票，而构建证书级语义 oracle：为每个原子生成"满足/违反"两类受控证书，由真实证书执行并读回判定状态，从而对仅由已认证原子构成的生成 lint 给出与模型无关、可复现的 $\mathrm{Code}\equiv\mathrm{IR}$ 执行级验证。须界定：这是受控 fixture 上的执行级验证，而非对全体证书的定理性证明，其外延受可认证子集所限（详见 §7.1）。

针对大规模代码生成缺乏人工真值这一根本困难，本文提出阶段归因式迭代验证（Stage-Attribution Iterative Verification, SAIV）框架，将召回完整性（G1）、lint 覆盖度（Gcov，相对 zlint 既有实现的端到端覆盖广度，分母取 zlint 实测 RFC 5280=131、CABF BR=170，合计 301，均含 CRL lint）、代码-规范同义性（G2）与双判定源一致性（G3）形式化为可计算残差，并配以阶段归因规则与单调修复算子，在无人工标注真值的条件下提供可收敛、可追溯的质量控制。其首要修复算子 $\rho_R$（IR 内容自反思修复）经确定性 g4-sanity 闸门全自动运行、无需逐条人工确认，从而将"发现 IR 抽错并自动重抽修正"纳入迭代回路，使框架的迭代性名实相符。

在 RFC 5280 与 CABF BR 上的实证表明：关键词召回 2077 条候选，经守恒划分得 1601 条真规则，其中 464 条可 lint；zlint 既有实现完整覆盖其中 158 条、部分覆盖 38 条，余 306 条未覆盖、构成代码生成的直接目标。对全部可 lint 规则，确定性归约即得 254 条满足 $\mathrm{Code}\equiv\mathrm{IR}$ 的 DSL 树（由证书级 oracle 以与所用模型无关的方式验证，其中 190 条编译通过）；相较之下，单票 LLM 判别器会接受一个更大却含风险的超集，可靠性不足。经 $\mathrm{Code}\equiv\mathrm{IR}$（证书级 oracle）与 $\mathrm{IR}\equiv\mathrm{Spec}$（去噪 5 票同义判官）双门筛选后发射 83 条 lint，发射集在构造上即 100% 同义；未经此筛选时，最难的"未覆盖 ∧ 可渲染"子集上原始同义率约 24–27%，并非框架上界；其余不同义样本全部可追溯到上游抽取（如主语错抽、把子字段当成整个扩展），在代码生成端无从弥补。这一误差定位本身即是一项发现：在本框架下，瓶颈在 $\mathrm{Spec}\to\mathrm{IR}$ 抽取，而非 $\mathrm{IR}\to\mathrm{Code}$ 生成。据此本文主张以同义性作为发射判据，仅发射经 $\mathrm{Code}\equiv\mathrm{IR}$（证书级 oracle）与 $\mathrm{IR}\equiv\mathrm{Spec}$（同义判定）双重验证的 lint，使发射集在构造上即 100% 同义；收敛随之被重新定义为迭代修复上游抽取、把残差逐批转为同义，而发射集始终保持 100%。其中 $\mathrm{Code}\equiv\mathrm{IR}$ 为自动验证，$\mathrm{IR}\equiv\mathrm{Spec}$ 当前由人工裁定把关，故端到端 $\mathrm{Code}\equiv\mathrm{Spec}$ 仅对发射集成立，其 $\mathrm{IR}\equiv\mathrm{Spec}$ 的自动化是本框架定位出的首要开放问题。

方法学上，本文提炼出一条不限于 PKI 的设计原则——验证链路上的每个算子都应尽可能确定化；证书级 oracle 将原本属于 LLM 的"忠实性判定"也确定化，正是该原则在验证端的体现——并以"可归约子集闭合 + 不可归约边界诚实披露"双指标取代单一收敛阈值，为基于受限词汇的"规范到代码"生成提供可复现的诚实边界声明范式。

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

**(挑战五) 缺乏独立真值。** 大规模合规代码生成场景中并不存在现成的、可信的人工真值来逐条判定"生成代码是否忠实于规范"。验证机制必须能够在**无独立真值**的条件下提供可计算、可收敛、可追溯的质量信号。

### 1.3 核心思想

把规范文本转化为可信代码，难点不在让 LLM 生成一段代码，而在让整条流水线可复现、可审计、可验证。本文的方法学由三条相互支撑的设计原则构成，可概括为：仅在确需 LLM 之处使用 LLM，其余环节尽量实现为确定性函数。

**第一，提取侧——确定性检索 + LLM 受限角色。** 跨文档上下文的组装不交给 LLM 推断，而由知识图谱上的确定性子图遍历给出可溯源上下文；LLM 的职责被严格限定为"将候选规则解析为受 schema 约束的结构化 IR"，所有规范性判断（可执行性、覆盖、冲突）都推迟到后续确定性阶段。这使提取过程可审计、可复现。

**第二，生成侧——代码空间应在语言层面而非 prompt 层面受限。** 与其用 prompt 反复约束 LLM 不要编造字段，不如使其无从编造：将生成算子 $\phi_G$ 的值域定义为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，使编造不存在字段或 OID 的幻觉在架构层即被排除（命题 1），而不依赖 prompt 约束或 few-shot 引导这类概率性手段。

**第三，验证侧——验证链路上的每个算子都应尽可能确定化。** 在语义等价传递链

$$
\mathrm{Spec} \;\to\; \mathrm{IR} \;\to\; t \in \mathcal{T}_{\mathcal{V}} \;\xrightarrow{\sigma}\; \mathrm{Summary} \;\equiv\; \mathrm{Description}
$$

中，关键词召回 $\phi_R$、渲染 $\rho$、后处理 $\Phi_{\mathrm{post}}$、机械翻译 $\sigma_{\mathrm{mech}}$ 均由确定性函数实现；尤为关键的是，连"生成代码是否忠实于规范"这一判定本身也被确定化——在可认证子集上由证书级语义 oracle 以真实证书的执行结果给出 $\mathrm{Code}\equiv\mathrm{IR}$ 的执行级验证，而非依赖 LLM 投票，仅在 oracle 不适用的子集上才退回 $\phi_C$、$\phi_V$ 等需要语义灵活性的 LLM 端点（详见 §7.1）。这印证了一个更一般的观察：确定性的着力点可由生成端迁移到验证端。在缺乏人工真值的前提下，再由阶段归因式迭代验证（SAIV）将多类质量不变量形式化为可计算残差，提供收敛性与可追溯性。

### 1.4 主要贡献

**(C1) 基于 IR 的五条件可 lint 性框架。** 将可 lint 性形式化为五个离散 IR 字段上的确定性布尔函数 $C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$，使判定可复现，任何误判可追溯到唯一 IR 字段而非不透明的端到端调用（§5）。

**(C2) 受限代码空间、可逆机械翻译与证书级语义 oracle。** 将 $\phi_G$ 的值域形式化为原子集 $\mathcal{A}$（$|\mathcal{A}|=68$）与类型化词汇表 $\mathcal{V}$ 张成的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，给出语法、执行语义与词汇封闭性命题（命题 1），并定义确定性机械翻译算子 $\sigma_{\mathrm{mech}}$（全函数、确定、原子等价意义下可逆）。在此空间之上构建证书级语义 oracle：经逐原子忠实性认证与结构组合，对仅由已认证原子构成的生成 lint 给出 $\mathrm{Code}\equiv\mathrm{IR}$ 的执行级验证，从而以与模型无关的可复现判据取代单票 LLM 判别器，并诚实披露其可认证子集边界（§6–7）。

**(C3) 阶段归因式迭代验证（SAIV）与多目标残差。** 将召回完整性（G1）、lint 覆盖度（Gcov，分母为 zlint 实测 RFC 5280=131、CABF BR=170，合计 301，均含 CRL lint）、代码-规范同义性（G2）与双判定源一致性（G3）形式化为可计算残差，给出阶段归因规则、修复算子谱与收敛性论证；首要修复算子 $\rho_R$（IR 内容自反思修复）经确定性 g4-sanity 闸门全自动运行，L4b 双向 FLIP-or-SPURIOUS 机制使 G3 残差单调降至 0。该框架在无人工标注真值条件下提供质量控制，结构性地取代了对人工真值的依赖（§8）。

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

与上述工作相比，本研究的差异化定位体现在四个方面。其一，本文不孤立地做提取或生成，而是给出贯通"提取 → IR → 可 lint 性判定 → 代码生成 → 验证"的端到端框架，以结构化四元组 IR 作为前后两半的统一接缝。其二，在提取侧把 LLM 限定为受 schema 约束的解析器，并以确定性的可溯源检索（沿规范结构的显式边遍历，而非向量相似度或 LLM 推断）组装跨文档上下文，区别于端到端黑箱提取；须强调差异化在于"受约束 + 可溯源"，而非主张某种图检索相对普通 RAG 的量化优越性——后者难以做干净消融、本文不作此主张（见 §10.4）。其三，在生成侧将 $\phi_G$ 的值域形式化为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，在语言层排除字段/OID 编造类幻觉（命题 1）。其四，在验证侧提出阶段归因式迭代验证框架，将多类质量不变量形式化为可计算残差，在无人工真值条件下提供可追溯性与（单调修复假设下的）收敛性，并由确定性机械翻译算子 $\sigma_{\mathrm{mech}}$ 将概率失真压缩至两个必要的语义端点——由此给出一项更一般的设计原则：验证链路上每个算子都应尽可能确定化。

## 3. 方法总览

图 1 给出本框架的整体结构。系统以 Web PKI 规范文本为输入，输出可编译、可追溯的 zlint Go 检查代码，并由阶段归因式迭代验证（SAIV）在无人工真值条件下闭环修复。流程由六个阶段组成：前三个阶段（确定性上下文、提取、判定）构成"规范 → 可 lint 规则"的前半链路，后三个阶段（合成、对齐、验证）构成"可 lint 规则 → 可信代码"的后半链路；二者以结构化中间表示 IR 与五条件可 lint 性判定为统一接缝。

```mermaid
flowchart LR
  S[Web PKI 规范文本] --> KG[知识图谱构建 §4.1]
  KG --> R[确定性子图检索 §4.2]
  R --> L1["Layer 1 关键词召回 φ_R"]
  L1 --> L2["Layer 2 受控解析 → IR"]
  L2 --> C["五条件可 lint 性判定 φ_C §5"]
  C -->|"可 lint 集 R_L"| G["受限 DSL 树合成 φ_G §6"]
  G --> RHO["渲染 ρ + 后处理 Φ_post"]
  RHO --> V["三层对齐验证 φ_V + 证书级 oracle §7"]
  V -->|残差| SAIV["阶段归因式迭代验证 SAIV §8"]
  SAIV -. "ρ_R 修复上游 IR" .-> L2
```

**图 1：** 从 PKI 规范文本到可信 zlint 检查代码的端到端框架。前半链路（§4–5）产出可 lint 规则，后半链路（§6–7）合成并验证代码；SAIV（§8）以可计算残差沿管道反向归因，由首要算子 $\rho_R$ 修复上游 IR 后闭环。

1. **知识图谱构建（离线，§4.1）。** 将异构规范源归一化为带稳定标识的层级结构，抽取章节包含、定义、跨文档引用与字段概念等显式关系，形成可溯源的检索基底。
2. **确定性上下文检索（§4.2）。** 以知识图谱为固定输入，对每个目标章节做有界子图遍历，组装术语定义、字段元数据与被引章节作为提取上下文；该过程不使用向量相似度，也不调用 LLM，从而不引入臆造上下文。
3. **双层提取与 IR 构建（§4.3–4.4）。** Layer 1 以 RFC 2119 关键词与正则做确定性召回得到候选规则集合 $\mathcal{R}_{\mathrm{kw}}$；Layer 2 将 LLM 限定为受 schema 约束的语义解析器，把每条候选规则转写为结构化 IR。
4. **五条件可 lint 性判定（§5）。** 由分类算子 $\phi_C$ 依据五个离散 IR 字段的确定性布尔函数 $C(r)=C_1\wedge C_2\wedge C_3\wedge C_4\wedge\neg C_5$，将每条规则映射至可执行（可 lint）集合 $\mathcal{R}_L$。$\mathcal{R}_L$ 即下游代码生成的定义域。
5. **受限 DSL 合成（§6）。** 生成算子 $\phi_G$ 在形式化的原子 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$ 内合成 DSL 树 $t$，再经确定性渲染算子 $\rho$ 与可溯源字段后处理 $\Phi_{\mathrm{post}}$ 物化为 Go 代码。
6. **三层对齐验证（§7）。** 通过描述溯源性、基于 $\sigma_{\mathrm{mech}}$ 机械翻译摘要与 `Description` 的同义性判定、以及结构与编译检查，综合输出对齐得分 $S_{\mathrm{align}}$；对由已认证原子构成的可认证子集，另由证书级语义 oracle 经真实证书执行确定性*验证* $\mathrm{Code}\equiv\mathrm{IR}$（执行级验证，非定理性证明），无需 LLM 判官。

当样本级对齐不达阈值时，系统进入 §7 的样本级局部修复；当需要在大规模、无独立真值的场景下定位并修复系统性误差来源时，则进入第 8 节的阶段归因式管道级验证与修复框架（SAIV），将召回完整性、代码-规范同义性、双判定源一致性等不变量作为可计算残差，沿管道反向归因并触发阶段性修复。

为便于通读，下表汇总全文使用的主要算子与集合记号。

| 记号 | 含义 |
|---|---|
| $\Pi=\phi_V\circ\phi_G\circ\phi_C\circ\phi_R$ | 受控规范-代码生成管道（§8.2） |
| $\phi_R$ | 关键词召回算子（Layer 1，§4.3） |
| $\phi_C$ | 五条件可 lint 性分类算子（§5） |
| $\phi_G$ | 受限 DSL 树合成算子（§6.6） |
| $\phi_V$ | 三层对齐验证算子（§7） |
| $\mathcal{T}_{\mathcal{V}},\ \mathcal{A},\ \mathcal{V}$ | 受限 DSL 树空间 / 原子集（$\lvert\mathcal{A}\rvert=68$）/ 类型化词汇表（§6） |
| $\rho,\ \Phi_{\mathrm{post}}$ | 确定性渲染算子 / 可溯源字段后处理（§6.6） |
| $\sigma_{\mathrm{mech}}$ | 确定性机械翻译算子（DSL 树 → 英文摘要；定义见 §6.4，构造见 §8.9） |
| $\eta,\ \mu$ | 输出解析算子 / IR 谓词到原子的语义映射（§6.5–6.6） |
| $\rho_R$ | 首要修复算子：IR 内容自反思修复（§8.7） |
| $\rho_C,\ \rho_G,\ \rho_V,\ \rho_A$ | 分类 / 生成 / 验证 / 离线扩原子 修复算子（§8.7） |

## 4. 规范规则提取与中间表示

本节描述前半链路：如何在确定性可控的前提下，从分散且交叉引用密集的 Web PKI 规范源中提取规范规则，并转写为结构化中间表示 IR。核心困难在于跨文档引用——孤立地阅读任一段落都不足以还原一条规则的完整语义。本文的应对是分工：以确定性的图遍历组装上下文，以受约束的 LLM 解析语义，从而既不丢失上下文、又不让模型自由发挥。

### 4.1 PKI 知识图谱构建

知识图谱构建器是离线组件，将异构的 Web PKI 规范源转换为供后续检索使用的基底。它把文档归一化为层级结构，为规范、章节、标题与文本单元赋予稳定标识；随后抽取章节引用、RFC 引用与策略交叉链接等**显式引用**，并在目标可被无歧义解析时将其链接到对应节点；同时记录证书字段概念及其别名（如 subjectAltName、dNSName、basicConstraints.cA 与策略 OID），以便在后续提取中把自然语言提及映射到规范的证书路径。

PKI 规范构成一个高度互联的跨文档网络——例如 RFC 5280 引用多份 RFC，CABF BR 又直接依赖 RFC 5280 的字段定义。本研究将该知识建模为多边有向图，含八类节点（Specification、Section、Definition、CertificateField、Rule、Operation、Value、Concept）与四种 source-backed 关系（CONTAINS、DEFINES、REFERENCES、APPLIES TO）。该构建器刻意保持保守：只存储由文档结构或文本证据直接支持的关系，而把冲突、覆盖、可 lint 性等**规范性判断**留给后续确定性阶段。诸如 CONFLICTS WITH、OVERRIDES 等规范性判断关系由规则引擎独立产生，**不进入检索图**。由此得到的图是一个可溯源的上下文索引，而非裁决 oracle：它帮助提取器定位定义、继承约束与被引规则，但并不决定某条要求是否可 lint。各关系类型及其检索可入性详见附录 B。

### 4.2 确定性上下文检索

为应对跨文档引用，本研究以确定性方式组织上下文，而非依赖 LLM 推断关系。检索模块将知识图谱（§4.1）视为固定输入，通过有界子图查询获取上下文：给定一个目标 Section 节点，沿 source-backed 的 CONTAINS、DEFINES、REFERENCES、APPLIES TO 关系在其 $k$-跳邻域内做 BFS 扩展，再按关系类型优先级装配出术语定义、字段元数据与被引章节。整个检索过程既不使用向量相似度也不调用 LLM 推理，因而不产生任何独立判断。

检索阶段额外遵守四条约束（GR-1 至 GR-4）：不允许引入任何被推断出的规范规则；只有原始规范节点可进入检索；任何推断性关系不得进入检索；所有上下文必须可追溯至规范源。这些约束保证了"提供给 LLM 的上下文"本身是可审计、可复现的，从根本上抑制了"模型据臆造上下文作答"的风险。

### 4.3 双层提取流水线

为在保留 LLM 语义理解能力的同时维持提取过程的可审计性，本研究采用双层结构。

**Layer 1：确定性召回。** Web PKI 规范普遍以 RFC 2119 关键词表达规范性要求，可按义务强度分层（强制类 MUST/SHALL/REQUIRED、禁止类 MUST NOT/SHALL NOT、推荐类 SHOULD/SHOULD NOT/RECOMMENDED、可选类 MAY/OPTIONAL）。RFC 8174 [6] 进一步规定这些关键词仅在大写时具规范效力，从而支持确定性的关键词匹配；ETSI EN 319 不遵循该约定，其候选则通过小写匹配召回。为最大化召回，Layer 1 以三遍方式运行：第一遍直接匹配 RFC 2119 关键词；第二遍识别嵌套结构，使从属规则继承父级义务等级；第三遍捕获不遵循标准 RFC 2119 形式的规范性陈述。Layer 1 的输出是候选规范规则集合 $\mathcal{R}_{\mathrm{kw}}$。

**Layer 2：受控语义解析。** Layer 2 使用 LLM，但将其限定为受约束的语言理解角色：模型并不直接生成 lint 规则或合规判断，而是把规范文本转写为 JSON 序列化的中间表示 IR，所有规范性推理都推迟到后续确定性阶段。该设计将 LLM 的职责收敛为 schema 受限的语义解释。为提升分类字段的稳定性，IR 生成采用**分阶段**策略：模型先判定规则类别，再填充其余字段——相较一次性生成全部字段，这显著降低了误差。Layer 2 同时受一组确定性约束的约束：输出必须严格符合预定义 IR schema，否则被拒并重提；在可确定性判定的情形下由规则引擎覆盖 LLM 分类（如"in step"→`algorithm_ref`、"is defined as"→`definition`）；每条 IR 都附带索引到源文本的引用片段，并由文本对齐校验器核验其文本字段确实源自该片段，未能对齐者作为幻觉被丢弃；当 IR 涉及证书 subject DN 之下的属性时，其路径必须落在由 RFC 5280 ASN.1 定义构建的规范路径树上，由确定性字段解析器注入并校验。这些约束分别在 IR 的文本层与 schema 层抑制了"编造原文"与"编造不存在字段层级"两类幻觉（六项约束的完整列举见附录 C）。

### 4.4 结构化中间表示

IR 是连接前后两半链路的核心数据结构。其核心为四元组

$$
\mathrm{IR} = \langle \text{subject},\ \text{obligation},\ \text{predicate},\ \text{constraint} \rangle,
$$

其中 subject 为由字段解析器解析得到的证书字段路径（如 `extensions.subjectAltName.dNSName`），obligation 为 RFC 2119 义务关键词，predicate 为断言类型（如 `must_be_present`、`conform_to`、`equal`），constraint 为约束值或模式。四元组之外，IR 还携带若干关键扩展字段，用于支撑可 lint 性判定与下游生成与审计，其中最重要的是 `rule_category`（规则语义类别）、`assertion_subject`（断言主体：证书 / CA / 依赖方 / 外部生态）、`enforcement_phase`（约束所依赖的阶段：编码 / 运行时 / 外部验证），以及 `source_section`、`source_span`、`evidence_text`、`context_nodes` 等溯源字段（关键字段的完整列举见附录 A）。

以 IR 为桥梁带来三点相较"从原文端到端直接生成 lint 检查"的优势：其一，引用、约束与义务信息被分离存储，提升可追溯性与冲突处理能力；其二，IR 作为 §5 五条件可 lint 性判定的确定性输入，使判定可复现而非依赖模型；其三，一旦规则被判为可 lint，由结构化 IR（字段路径、断言类型、约束值均已显式化）生成代码更稳定、更可解释。IR 由此支持"一次提取、多处复用"——同一提取结果可同时服务于可 lint 性分析与代码生成等多个下游任务。

## 5. 可 lint 性判定

并非每条带 MUST 的规范都能写成 lint 检查。有的 MUST 约束的是 CA 的线下行为（如"CA 必须核验申请人身份"），有的要比对证书链上的其他证书，有的要查 DNS 记录或撤销历史——这些都无法仅凭一张证书的字节静态裁决。因此在生成代码之前，必须先回答一个前置问题，即每条规范规则的**可 lint 性**：它能否被一个不依赖外部上下文或运行时行为、仅凭**单一制品**（一张证书或一份 CRL）即可裁决的静态检查所表达？

本文不让 LLM 直接判定，而是把判断分解为五个独立的布尔条件，每个条件只读取 IR 的一个字段，五个条件全部满足才判为可 lint，从而在 IR 上确定性地计算可 lint 性。这一设计基于三点观察：其一，实践中决定一条规则可 lint 性的恰是五类信息——义务的道义强度、被约束的主体、约束生效的阶段、规则的类型，以及裁决该约束所需的数据范围（单一制品 vs 跨制品/外部状态）；其二，这五者各自都可编码为取值于一个小而封闭集合的单一 IR 字段，于是可 lint 性判定退化为五个离散字段的布尔函数；其三，分离这五个条件，使任何错误标签都可追溯到恰好一个 IR 字段，而非归因于不透明的端到端调用。

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

第 5 节已把每条规范规则判为可 lint 或不可 lint，给定一条可 lint 规则 $r\in\mathcal{R}_L$，如何由生成算子 $\phi_G$ 产出一段既能编译、又忠实于规范语义的检查代码？若把 $\phi_G$ 直接实现为"规则 $\mapsto$ 自由形式 Go 代码"，会同时撞上两堵墙：其一，LLM 可能编造不存在的字段、OID 或标准库调用（幻觉），而这类错误未必都能在编译期暴露；其二，在开放的代码空间上证明"代码语义等价于规范语义"需要程序分析或符号执行，工程上不可行。本文的核心方法学回应不是在提示词层面劝阻模型，而是在**语言设计层面**收紧 $\phi_G$ 的值域：把开放的 Go 代码空间替换为一个有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$，令 LLM 只能输出该空间内的一棵树，再由确定性算子把树物化为 Go。如此一来，防幻觉从"靠提示约束的概率手段"变为"被语言本身排除的架构属性"，而"代码 $\equiv$ 规范"也从不可计算的程序分析问题，降格为可在 $\mathcal{T}_{\mathcal{V}}$ 上判定的结构问题（其判定见第 7 节）。

### 6.1 受限代码空间的动机

§6 开篇所述的两堵墙值得各举一例以见其具体形态。**幻觉风险**：自由形式的 Go 生成可能产出形如 `cert.IDN_Names` 的字段访问，而解析库（zcrypto）的证书结构体中根本不存在该字段；或调用一个签名对不上的标准库函数、引用一个并不对应任何已注册扩展的 OID 字面量。这类错误中，类型不匹配者尚可被 Go 编译器拒绝，但"把字段名拼成另一个恰好也存在、却语义无关的字段"或"OID 数值写错一位"之类的错误能够通过编译，潜伏为静默的语义偏差。**验证不可计算性**：即便代码通过编译，编译通过也只保证语法与类型合法，绝不蕴含"它所检查的正是规范所要求的约束"；要在开放代码空间上确证后者，一般需要程序分析或动态符号执行，其代价远超在大规模规则集上逐条施行的工程边界。

本文的回应是在语言层限制 $\phi_G$ 的值域——将开放 Go 代码空间替换为有限闭合的 DSL 树空间 $\mathcal{T}$，由确定性渲染函数 $\rho:\mathcal{T}\to\mathrm{Go}$ 完成代码物化。于是 LLM 不再直接书写 Go，而只需输出一棵合法的 DSL 树；字段名合法性、OID 存在性、比较算子的类型匹配等正确性属性，均由 DSL 的类型系统在生成时静态保证。模型只能从词汇表内既有的原子与字段中选择并组合，无法引入词汇表之外的字段或 OID（§6.3 命题 1）。其效果是把防幻觉从"依赖提示词约束的概率手段"转化为"由语言本身保证的架构属性"——前述第一类风险中那些能通过编译的静默偏差，也因字段与 OID 一律取自冻结词汇表而被压缩到可枚举、可审计的范围。

### 6.2 原子 DSL：语法与原子集

原子 DSL 的设计取舍是：在足以表达单制品静态检查的前提下把语言压到尽可能小，以保证树空间有限、可静态分析。观察到 PKI 的单证书 / 单 CRL 合规检查几乎都是若干**原子证书属性判定**的命题逻辑组合——"某扩展是否存在"、"某字段是否等于给定常量"、"某列表的每个元素是否匹配某模式"等原子，经"与 / 或 / 非"组合即可刻画绝大多数静态约束。据此定义代码 DSL 的抽象语法为：

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

这一三分语义的直观读法是：前提 $p$ 充当**规则适用性闸门**——当 $p$ 存在且在证书 $c$ 上为假时，说明该规则的适用条件未触发，返回 $\mathrm{NA}$（不适用，既非通过也非违反）；当无前提、或前提成立且主断言 $q$ 成立时返回 $\mathrm{Pass}$；其余情形（前提成立而主断言不成立）即判定违反，按规则义务级别返回相应严重级别 $\mathrm{Severity}(r)$。其中 $c$ 为待检查证书。因 §5 的 $C_1$ 已将 MAY/OPTIONAL 排除在可 lint 集合 $\mathcal{R}_L$ 之外，凡进入代码生成的规则其义务必属 MUST 族或 SHOULD 族，故 $\mathrm{Severity}(r) \in \{\text{Error}, \text{Warn}\}$，由义务级别确定性映射给出（MUST/MUST NOT/SHALL/SHALL NOT/REQUIRED $\mapsto$ Error；SHOULD/SHOULD NOT/RECOMMENDED $\mapsto$ Warn）；MAY/OPTIONAL 规则在 $C_1$ 处即被滤除。显式区分 $\mathrm{NA}$ 与 $\mathrm{Pass}$ 并非冗余：PKI 规范中大量要求是**条件式**的（形如"WHEN $P$, THEN $Q$"，如"若证书含 basicConstraints 扩展且 cA 为真，则 pathLenConstraint 须满足某约束"），把适用前提显式建模为 $p$ 可避免"前提不满足却误判为违反"这一常见错误，也使前提与断言在后续验证中能分别归因。

### 6.3 类型化词汇表与参数封闭性

§6.2 把树的*结构*限定为原子的命题逻辑组合，但尚未约束原子的*参数*取值——若参数可任意填写，LLM 仍能写出引用虚构字段或 OID 的"结构合法"之树。§6.3 用一张**类型化词汇表**封住这道缺口：令每个原子参数都只能取自一个预先冻结的有限集合。设 $\mathcal{V}$ 为系统所携带的类型化词汇表，是若干有限集合的不相交并：

$$
\mathcal{V} \;=\; \mathcal{F}_{\mathrm{cert}} \;\sqcup\; \mathcal{F}_{\mathrm{dn}} \;\sqcup\; \mathcal{O} \;\sqcup\; \mathcal{B}_{\mathrm{KU}} \;\sqcup\; \mathcal{B}_{\mathrm{EKU}} \;\sqcup\; \mathcal{E}_{\mathrm{ASN1}} \;\sqcup\; \mathcal{R}_{\mathrm{regex}}
\tag{3}
$$

各分量分别是证书字段名、DN 字段、OID 常量、KeyUsage 位、ExtKeyUsage 位、ASN.1 编码类型与命名正则集合，均在系统启动时被冻结（各分量的近似大小与代表性内容列于附录 D）。每个原子 $a \in \mathcal{A}$ 有签名 $\mathrm{sig}(a) = (\tau_1, \dots, \tau_{n_a})$，其中 $\tau_i$ 是 $\mathcal{V}$ 的某一分量或基础类型 $\{\mathbb{Z}, \mathbb{B}, \mathrm{String}\}$；原子调用 $a(v_1, \dots, v_{n_a})$ 合法当且仅当每个 $v_i$ 隶属于 $\tau_i$ 所规定的集合。记 $\mathcal{T}_{\mathcal{V}}$ 为所有参数均落在 $\mathcal{V}$ 内的合法 DSL 树集合。本研究将 $\phi_G$ 的值域严格限定为 $\mathcal{T}_{\mathcal{V}}$，这提供如下封闭性命题。

**命题 1（词汇封闭性）**。*对任意 LLM 输出 $t$，若 $t \in \mathcal{T}_{\mathcal{V}}$，则 $t$ 中不出现 $\mathcal{V}$ 之外的字段名、OID 或正则；若 $t \notin \mathcal{T}_{\mathcal{V}}$，则解析阶段必然报错并触发修复，不会进入 $\rho$ 渲染。*

该命题在架构层面消除了"LLM 编造证书字段或 OID"这一整类幻觉，且其保证不依赖任何运行期检测或人工审查：词汇表在系统启动时即被冻结，凡参数越界的原子调用都不属于 $\mathcal{T}_{\mathcal{V}}$，会在解析算子 $\eta$（§6.6）处即被判为 $\mathrm{Err}$，连同"哪一参数不在哪一词汇分量内"的诊断反馈给 LLM 触发重写，根本不会进入 $\rho$ 渲染。换言之，命题 1 把 §6.1 所述第一堵墙（幻觉）从"事后尽力捕获"前移为"事前结构排除"。其代价是 $\phi_G$ 的表达力被限制在 $\mathcal{V}$ 与 $\mathcal{A}$ 所张成的范围之内——这一表达力边界并非缺陷而是被显式刻画的对象：它正是 §6.5 的语义映射 $\mu$ 试图在该范围内充分利用、§10.4 的覆盖残差又试图度量其外延的那条边界。

### 6.4 渲染与可逆机械翻译

一棵合法的 DSL 树 $t$ 本身只是中间结构，要发挥作用须被**物化**为两种制品：一是最终交付、可在 zlint 框架内运行的 Go 检查代码，二是一句可供人、LLM 与规范原文比对的自然语言摘要——前者是系统的产出，后者是验证它的依据。本小节定义承担这两项物化的两个算子；二者的共同要害在于它们都是 DSL 树空间上的**确定性全函数、而非 LLM 调用**，因而不会在下游引入任何概率性失真。定义两个全函数：

$$
\rho : \mathcal{T}_{\mathcal{V}} \to \mathrm{Go}, \qquad \sigma_{\mathrm{mech}} : \mathcal{T}_{\mathcal{V}} \to \mathcal{L}_{\mathrm{NL}}
\tag{4}
$$

其中 $\rho$ 把 DSL 树渲染为类型一致的 Go 表达式（系统的可执行产出，其渲染所嵌入的固定 Go 宿主外壳见附录 D），$\sigma_{\mathrm{mech}}$ 把同一棵树机械翻译为一句 PKI 英文摘要（验证所用的自然语言陈述，构造细节见 §8.9）。两个函数共享三项性质，且每项性质都对应验证链路上的一个具体作用：

- **类型安全**：在原子签名与词汇表覆盖范围内，$\rho$ 不生成越界的字段、OID 或参数类型——这把 §6.3 命题 1 的词汇封闭性从 DSL 树一路保持到 Go 表达式层（完整宿主文件的可编译性仍由 §7.1 / 算法 1 的编译检查最终确认）。
- **决定性**：对相同输入 $t$，$\rho(t)$ 与 $\sigma_{\mathrm{mech}}(t)$ 的输出唯一。正是这一点使 §7.1 的证书级 oracle 可以把 $\rho(t)$ 当作 $t$ 的一个固定函数来推理——同一棵由已认证原子构成的树，其渲染代码的执行行为不随运行次数或所用模型而变。
- **可逆性（原子等价意义下）**：给定 $\sigma_{\mathrm{mech}}(t)$ 可机械还原出 $t$（同义原子映射到同一短语时不可区分，其余结构保留）。这保证 $\sigma_{\mathrm{mech}}$ 在"代码 $\to$ 摘要 $\to$ 与规范比对"的反向验证链路上不构成信息瓶颈（§8.9 命题 2）。

两个算子由此形成**分工**：$\rho$ 通向第 7 节的执行 / oracle 验证通路——代码被真实证书运行、由执行结果裁断；$\sigma_{\mathrm{mech}}$ 通向同义性验证通路——摘要与 `Description` 比对其语义是否等价。同一棵树经两条彼此独立的确定性通路接受检验，构成第 7 节多重保障的结构基础。

### 6.5 从 IR 谓词到原子的语义映射

上游 IR 与下游 DSL 说的是两套词汇：IR 以**抽取阶段的谓词**描述要求（如 `must_be_present`、`encode_as`、`in_range`），DSL 则以**原子**表达检查，二者并非一一对应。为衔接两者，本研究维护一个多对多语义映射

$$
\mu : \mathrm{Pred}_{\mathrm{IR}} \rightrightarrows 2^{\mathcal{A}},
$$

对规则 IR 中出现的每个谓词，$\mu$ 给出语义上可承载它的候选原子子集。例如 `must_be_present` 可由 $\{\mathrm{ExtPresent}, \mathrm{FieldNonEmpty}\}$ 承载，`in_range` 可由 $\{\mathrm{IntInRange}, \mathrm{PathLenConstraintHas}, \dots\}$ 承载——究竟取哪一个，取决于被约束字段的类型。该候选子集连同词汇表 $\mathcal{V}$ 与原子签名表一并进入 §6.6 的合成提示，把 LLM 的选择空间从全集 $\mathcal{A}$（$\lvert\mathcal{A}\rvert=68$）收窄到与当前规则相关的少数候选，既降低误选概率、又缩短提示长度。

须强调 $\mu$ 的角色仅是**提示性约束**：它不直接装配输出，也不进入 $\rho$ 渲染；最终选用哪个原子、如何组合，仍由 LLM 给出，并随后经 §6.6 的封闭性强制与 §7.1 的证书级 oracle 校验。之所以采用"提示"而非"把 $\mu$ 实现为确定性的谓词 $\to$ 原子翻译"，是因为后者在面对需要跨原子组合、或依赖上下文区分字段类型的情形时过于脆弱；而"LLM 在硬约束下做组合"既保留了表达灵活性、又不牺牲 soundness——soundness 由下游的封闭性强制与 oracle 兜底，而不由 $\mu$ 承担。其多对多性质是双向的：一个 IR 谓词可由不同原子组合实现（表达冗余，为修复留出备选路径），一个原子也可服务于多个 IR 谓词。

### 6.6 受限 LLM 树合成与 IR-字段溯源守卫

本小节给出 $\phi_G$ 的具体实现，以及在"全 LLM 合成"下保证生成端结构性 soundness 的三道机制；三者分工明确：**IR-字段溯源守卫**约束树只引用本规则 IR 所涵盖的字段（防主语漂移），**解析与封闭性强制**把输出钉死在 $\mathcal{T}_{\mathcal{V}}$ 之内（防字段 / OID 编造），**可溯源字段的确定性绑定**用规范原文字面值填充 `Description` / `Citation` / `Name`（保证 $\mathrm{Description}\equiv\mathrm{Specification}$）。需特别区分：这三道机制都**不**判定"代码语义是否忠实于规范"——后者留给 §7.1 的证书级 oracle 以真实证书执行*验证*；它们只负责把生成结果约束在一个结构上可验证、可追溯的空间内。

**全 LLM 树合成。** 给定可执行规则 $r \in \mathcal{R}_L$（$\mathcal{R}_L$ 由 §5 的五条件判定给出），代码生成算子 $\phi_G$ 实现为一次**受限 LLM 树合成**：模型在得到规则上下文、结构化 IR、由 §6.5 映射 $\mu$ 收窄的候选原子集合，以及词汇表 $\mathcal{V}$ 与原子集 $\mathcal{A}$ 的可读枚举与签名表（实际系统提示与四区段拼接见附录 H）之后，仅返回一棵 DSL 树的序列化或一个显式弃权标记：

$$
\phi_G : r \;\longmapsto\; t \in \mathcal{T}_{\mathcal{V}} \cup \{\perp_{\mathrm{NT}}\}, \qquad t \;=\; \eta\bigl(M.\mathrm{generate}(\mathrm{prompt}(r,\,\mathcal{V},\,\mathcal{A},\,\mu))\bigr)
\tag{5}
$$

其中 $\perp_{\mathrm{NT}}$ 是显式的"无模板"标记，由 LLM 自主返回——当且仅当模型判断当前 $(\mathcal{A}, \mathcal{V})$ 不足以表达 $r$ 的语义时返回，此时该规则进入修复路径而非渲染，使 $\phi_G$ 不必产生"形式合法但语义错位"的输出。所有"会被检查"的部分都被约束落在 $\mathcal{T}_{\mathcal{V}}$ 之内（命题 1）。

**IR-字段溯源守卫。** 在全 LLM 合成下，生成端的结构性 soundness 机制是 IR-字段溯源守卫 $\mathrm{IRGuard}$：它复用字段解析器把 LLM 树中出现的每个证书字段 / 扩展 OID 规范化为其 DSL 身份（扩展按数值 OID 归一），并核验它们都被本规则的 IR 所涵盖。引用了 IR 之外字段的树被标记为**字段漂移**，连同诊断回传 LLM 触发重写（至多 $K$ 轮）。该守卫刻意保守——因 IR 解析本身会漏抽子字段（IR 记整个扩展、而 LLM 正确地引用其某个子字段，二者实为同一扩展），硬性拒绝将误伤约两成的好树——故它定位漂移并驱动修复，而非充当不可逆否决。真正的语义忠实性（$\mathrm{Code}\equiv\mathrm{IR}$）则不由生成端担保，而留待 §7.1 的证书级语义 oracle 在可认证子集上以真实证书执行*验证*。

**解析与封闭性强制。** 解析算子 $\eta : \mathrm{string} \to \mathcal{T}_{\mathcal{V}} \cup \{\perp_{\mathrm{NT}}, \mathrm{Err}\}$ 将合法序列化映射为 $t$、弃权映射为 $\perp_{\mathrm{NT}}$、解析失败或越界参数映射为 $\mathrm{Err}$；遇 $\mathrm{Err}$ 时把"哪一原子签名不匹配、哪一 OID 未注册"注入下一轮提示，触发受反馈引导的重新生成。这把 LLM 的幻觉表面积严格压缩在原子参数选择与组合结构两个维度，不允许新增未注册谓词或字段。

**可溯源字段的确定性绑定。** 记 $\Phi_{\mathrm{post}} : \mathcal{T}_{\mathcal{V}} \times r \to \mathrm{Go}$ 为后处理-渲染复合算子，在 $\rho$ 渲染出检查体之后，将 `Description`、`Citation`、`Name` 三个**可溯源字段**强制绑定为规范原文与规则元数据的字面值：

$$
\Phi_{\mathrm{post}}(t, r) \;=\; \rho(t) \;\oplus\; \mathrm{Bind}\bigl(\text{Description} \mapsto \mathrm{rule\_text}(r),\; \text{Citation} \mapsto \mathrm{section}(r),\; \text{Name} \mapsto \mathrm{lint\_id}(r)\bigr)
$$

该确定性绑定在架构层面保证 $\mathrm{Description} \equiv \mathrm{Specification}$ 这一前提（§7.1 等价链中的最右支），而无需依赖 LLM 自我约束；义务级别到严重度的完整映射、以及各规范源的 `PACKAGE` / `SOURCE` / `EFFECTIVE_DATE` 元数据绑定表见附录 D。

## 7. 三层语义对齐验证与机械翻译算子

第 6 节产出了一棵词汇封闭、可渲染为 Go 的 DSL 树 $t$ 及其代码 $\rho(t)$，但尚未回答最关键的问题：这段代码是否真的实现了规范要求？困难在于"代码 $\equiv$ 规范"在一般情形下不可判定，朴素地由 LLM 直接裁断"代码是否实现规范"，又要求模型同时推演 Go 执行语义与规范约束语义，跨模态且不可复核。本节的策略是把这一判定拆成一道**由低成本到高成本递进的级联**，并对其中最关键的一环施以确定化。

§7.1 是本节主体：它给出三层语义对齐验证与综合对齐得分 $S_{\mathrm{align}}$，并在其上引入一道**证书级语义 oracle**——对由本系统自身生成、因而持有 DSL 树的可认证子集，用真实证书的执行结果取代验证中最关键、却最不可靠的一环（LLM 判官），把同义性判定本身确定化，另辅以一道无 LLM 的实体级忠实性筛查作交叉校验。§7.2 给出当对齐不达阈值时作用于单条规则的样本级局部修复算子，§7.3 把合成与验证串成端到端算法，§7.4 以一个完整实例贯通第 6–7 节的全部机制。

### 7.1 三层语义对齐验证

三层验证按成本递增排列，构成由粗到精的过滤：**层次 A**（描述溯源）最廉价，只看 `Description` 能否回溯到原文；**层次 B**（同义性）是核心，把"代码是否实现规范"这一跨模态判定归约为"两句自然语言是否同义"；**层次 C**（编译与结构）确认产物在目标框架内可执行。三层加权汇总为对齐得分 $S_{\mathrm{align}}$，驱动 §7.2 起的修复闭环。但层次 B 依赖一次 LLM 判官、是单票且非确定的，故本小节随后引入一道**证书级语义 oracle**：对系统自身生成、因而持有 DSL 树的可认证子集，用真实证书的执行结果取代该判官，把同义性判定本身也确定化；再以一道无 LLM 的**实体级忠实性筛查**作为与之独立的交叉校验。

**层次 A：描述溯源性验证。** 该层检查生成代码的 `Description` 字段是否可追溯到源文档，采用由严到宽的三种匹配（逐字符精确、连续子串、句子级语义等价）。由于只关注描述与来源的关系而不解释代码逻辑，验证成本最低，适合作第一道快速过滤器。

**层次 B：基于代码摘要的语义对齐验证。** 传统方法直接判定"代码是否实现规范"，需同时理解代码执行语义与规范约束语义；本研究将该跨模态判定归约为自然语言同义性判定。流程为：从生成代码中提取 `Description`；由摘要算子 $\sigma$ 生成代码摘要（$\sigma$ 在本系统持有 DSL 树时的确定化实现即机械翻译算子 $\sigma_{\mathrm{mech}}$，其定义与性质见 §6.4、构造见 §8.9），以一句自然语言概括"该代码检查了什么约束"；再判定代码摘要与 `Description` 是否语义等价并输出置信度 $c_{\mathrm{syn}}$。其优势在于 LLM 只需比较两条自然语言陈述而无需推演完整 Go 执行语义，摘要对人类可读，且同义性失败时可由"代码实际表达"与"规范要求"之差为修复提供精确诊断信号。该方法的理论基础是语义等价的传递性：
$$
\mathrm{Code} \equiv \mathrm{Summary} \;\land\; \mathrm{Summary} \equiv \mathrm{Description} \;\land\; \mathrm{Description} \equiv \mathrm{Specification} \;\Rightarrow\; \mathrm{Code} \equiv \mathrm{Specification}
$$

其中 $\mathrm{Code} \equiv \mathrm{Summary}$ 由摘要算子 $\sigma$ 的忠实性提供，$\mathrm{Summary} \equiv \mathrm{Description}$ 由同义性置信度 $c_{\mathrm{syn}}$ 验证，$\mathrm{Description} \equiv \mathrm{Specification}$ 由 §6.6 的确定性后处理（从规范原文注入 `Description`）保证。三项前提依赖不同机制，使整条等价链的失效点可分段归因。需要强调：层次 B 是面向**一般情形**（含外部既有 lint、以及本系统中不可认证的子集）的同义性判定路径；对本系统自身生成、可被下述**证书级语义 oracle** 认证的子集，$\mathrm{Code} \equiv \mathrm{IR}$ 由 oracle 经执行直接*验证*，无需经由 $\sigma$ 摘要这一跳，亦无需 LLM 判官。

**层次 C：编译与结构验证。** 该层执行结构性检查：验证代码可被语法解析、必要的检查函数与元数据字段（描述、引用等）完整存在、所用依赖均被正确导入、且规则注册已完成。与前两层相比，该层偏向可执行性验证，确保生成结果不仅语义可解释，且在目标框架内具备基本结构合法性。

**综合对齐得分。** 五个维度加权平均给出：
$$
S_{\mathrm{align}} = 0.15 \cdot \mathbb{1}[\mathrm{compile}] + 0.10 \cdot \mathbb{1}[\mathrm{struct}] + 0.15 \cdot s_{\mathrm{desc}} + 0.50 \cdot c_{\mathrm{syn}} + 0.10 \cdot s_{\mathrm{revIR}}
$$

其中 $s_{\mathrm{desc}} \in [0,1]$ 为描述溯源性得分，$c_{\mathrm{syn}} \in [0,1]$ 为同义性置信度，$s_{\mathrm{revIR}} \in [0,1]$ 为逆向 IR 一致性得分——由生成代码反向抽取一份 IR、与原 IR 逐字段比对得到的匹配率，是一项轻量的往返（round-trip）一致性校验。同义性置信度占 50% 权重，构成综合判定的主要依据。当 $S_{\mathrm{align}} < \theta$（默认 $\theta = 0.7$）时，系统触发 §8 的阶段归因式修复机制。需说明：该加权得分驱动 §7.2–§8 的修复闭环（其阈值 $\theta$ 决定是否继续修复）；而 §9.4 主要结果中"同义可证"子集的接受并不取决于该标量，而由下述证书级语义 oracle 以二值 $\mathrm{Code}\equiv\mathrm{IR}$ 验证独立给出。

**证书级语义 oracle（$\mathrm{Code}\equiv\mathrm{IR}$ 的执行级验证）。** 这是本框架的核心方法学装置，须先界定其证据地位：它以受控 fixture 的真实执行为依据，给出可复现、与所用模型无关的执行级等价验证，而非对全体证书空间的定理性证明，外延受可认证子集所限。层次 B 的同义性判定由 LLM 判官 $\phi_V$ 给出，是单票、非确定的，且会对"前提被丢弃的过严 lint"误判通过。本框架的关键一步是将这一判定本身也确定化：与其再问一个 LLM 代码是否正确，不如为待检原子各构造两张证书——一张使其谓词成立（应返回 $\mathrm{Pass}$）、一张使其不成立（应返回该规则的 $\mathrm{Severity}(r)$）——令代码真正执行并比对结果。对由本系统自身生成、因而持有 DSL 树 $t$ 的 lint，即以一道确定性的证书级语义 oracle 取代该判官，分两步。(i) 逐原子忠实性认证：对每个原子 $a \in \mathcal{A}$，由证书工厂合成一对受控 fixture（分别使 $a$ 的谓词为真、为假），执行并读回 lint 判定状态，当且仅当两张都得到期望状态时 $a$ 被认证；fixture 按原子类参数化于 $\mathcal{V}$，不绑定任何具体规则。(ii) 结构组合的同义保证：一棵仅由已认证原子构成且编译通过的 DSL 树 $t$，其渲染代码 $\rho(t)$ 对 $t$ 逐原子忠实，故由结构归纳得 $\mathrm{Code}\equiv t$（条件于各原子已通过 fixture 认证）；又因 $t$ 是该规则 IR 的忠实归约，从而验证 $\mathrm{Code}\equiv\mathrm{IR}$，无需任何判官。其证据结构须强调：单原子忠实性是受控 fixture 上的经验认证，整树忠实性由结构归纳建立，故整条等价是执行级验证而非形式化定理，可靠性以 fixture 能否真正区分满足与违反为前提。满足该条件的规则记为同义可证（synonymy-guaranteed），其 $S_{\mathrm{align}}$ 中的 $c_{\mathrm{syn}}$ 项被直接短路为通过；不在可认证子集内者（树含未认证原子或不可确定性归约）回退到层次 B 的 LLM 判官，并被显式标注"未证"、与"已验证"分账报告（§9.4）。该 oracle 是确定性的：同义可证集合不依赖生成或判定所用模型。它须与 §8 的 G3（双判定源一致性）区分——后者指 $\phi_C$ 与外部工具覆盖 $\mathrm{cov}_{\mathcal{T}}$ 之间的一致性，与此处以真实证书执行为真值验证 $\mathrm{Code}\equiv\mathrm{IR}$ 是两回事。

**oracle 的边界与过严检测（诚实声明）。** 该 oracle 的覆盖是有界的：只有能用证书工厂造出"满足/违反"区分对的原子才可认证，而需跨证书上下文、密码学事实（如模数素性）或字节级编码的原子无法认证（边界详见 §10.4）。此外 oracle 附带一道过严检测：将同义可证的 lint 在真实证书语料上运行，若在大比例有效证书上误报 $\mathrm{Error}$，即疑为前提被丢弃的过严 lint——这是 $\mathrm{IR}\neq\mathrm{Spec}$ 的上游信号，而非 $\mathrm{Code}\neq\mathrm{IR}$；该检测当前因真实语料过窄而仅作报告、不计入判据。

**确定性实体级忠实性筛查（必要条件）。** 证书级 oracle 给出 $\mathrm{Code}\equiv\mathrm{IR}$ 的充分验证、但只覆盖可认证子集；对其余仍由 LLM 判官判定的 lint，本文再引入一道无 LLM 的实体级忠实性筛查 $\mathrm{Faithful}_{\mathrm{nec}}$，作为与 oracle、判官皆独立的可机械计算必要条件。其依据是：一条操作于 PKI 实体集 $E(t)$（DSL 树 $t$ 谓词中出现的 OID 常量与证书字段）的 lint，忠实于规则 $r$ 的前提是——$t$ 检查的每个主要实体都在 $r$ 的文本中被提及：

$$
\mathrm{Faithful}_{\mathrm{nec}}(t, r) \;\Longleftrightarrow\; \forall\, e \in E_{\mathrm{prim}}(t):\ \mathrm{alias}(e) \cap \mathrm{tokens}\bigl(\mathrm{text}(r)\bigr) \neq \varnothing,
$$

其中 $\mathrm{alias}(\cdot)$ 是一座由自动词干化与一张冻结的标准扩展别名表构成的桥。筛查给出三种判读：$\mathtt{ENTITY\_OK}$（每个实体都在文本中点名）、$\mathtt{ENTITY\_MISMATCH}$（lint 检查了文本从未提及的实体，可疑）、$\mathtt{NO\_ENTITY}$（谓词不引用任何 OID/字段实体，判定不适用）。它不是完全语义等价证明（后者不可判定），而是一个可机械计算的必要条件，专门捕获"分段/指代把错误主语交给代码生成"的失效模式。因其确定性且与判官独立，可与层次 B 交叉验证——分歧处要么定位到指代盲区（实体在节标题而非句中）、要么定位到真正的主语错抽。其已知盲区（指代如 "this extension"、别名表词表缺口）均表现为保守多报 $\mathtt{ENTITY\_MISMATCH}$ 而非漏报，与 IR-字段溯源守卫同向偏保守。

### 7.2 样本级局部修复算子

当 $S_{\mathrm{align}} < \theta$ 时，修复分两个层级。本小节是其中**较轻**的一级——**样本级局部修复**：误差被假定仍局限在这一条规则的字段或语法层面，因而只需就地重修这条规则，不触动全局的词汇表 $\mathcal{V}$、原子集 $\mathcal{A}$ 或分类器 $\phi_C$。更重的一级（管道级修复）留到 §8，仅在样本级修复耗尽后才介入。记 $\rho_G^{\mathrm{loc}}$ 为作用于单条规则的局部修复算子，含两类子操作：

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

该算法的控制流可一言概括：在至多 $K_{\mathrm{loc}}$ 轮的循环内反复向 LLM 索取一棵 DSL 树，并按解析结果 $\eta(s)$ 三态分流——弃权标记 $\perp_{\mathrm{NT}}$ 直接以"无模板"失败退出（交由 §8 上游处理）；越界 / 解析错误 $\mathrm{Err}$ 把具体的类型诊断追加进提示后重试；合法树 $t$ 则渲染、编译，再计算对齐得分，达阈值即返回、否则带着摘要 $\sigma_{\mathrm{mech}}(t)$ 与得分反馈再试。循环共有三个出口：达标返回（第 14 行）、显式弃权（第 5 行）、轮次耗尽转入管道级修复（第 16 行）。每一次重试都携带结构化诊断而非空白重采样，这正是它区别于"启发式重试"的关键。

算法 1 在 $K_{\mathrm{loc}}$ 内终止，每条规则的主要开销为 LLM 调用。在 $\eta$ 与 $\Phi_{\mathrm{post}}$ 的封闭性保证下，进入第 14 行返回分支的代码同时满足：(i) $t \in \mathcal{T}_{\mathcal{V}}$（词汇封闭）；(ii) $\rho(t)$ 通过 Go 编译；(iii) $\sigma_{\mathrm{mech}}(t)$ 与 $\mathrm{spec}(r)$ 经 $\phi_V$ 判定同义置信度满足 $S_{\mathrm{align}} \geq \theta$（在 $\theta = 0.7$ 时蕴含 $c_{\mathrm{syn}} \geq 0.4$）。这三项构成对返回代码"语义可追溯 + 结构可执行 + 类型受约束"的下界保证。

### 7.4 端到端示例

为把第 6–7 节的算子串成一条可追踪的链，以下用一条真实规则走完整个流程。以 RFC 5280 §4.2.1.9 关于 dNSName 编码的规则为例。规范原文："Conforming implementations MUST convert internationalized domain names to the ASCII Compatible Encoding (ACE) format ... before storage in the dNSName field." 经受控提取得到 IR：

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

LLM 在得到原子集 $\mathcal{A}$ 与词汇表 $\mathcal{V}$ 后，输出 DSL 树（主断言为"DNSNames 列表中每一项匹配 ACE-或-ASCII 标签正则"）。经 $\eta$ 解析为合法 $t \in \mathcal{T}_{\mathcal{V}}$ 后，$\rho$ 渲染为检查体，$\Phi_{\mathrm{post}}$ 注入 `Description / Citation / Source / Name` 等可溯源字段。$\sigma_{\mathrm{mech}}(t)$ 输出机械摘要 _"every entry in DNSNames matches the ACE-or-ASCII label regex"_，$\phi_V$ 比对该摘要与原文 `Description` 得 $c_{\mathrm{syn}} = 0.92$，综合对齐得分 $S_{\mathrm{align}} = 0.96 > 0.7$，验证通过。注意整个流程中 LLM 输出的所有命名均落在 $\mathcal{V} \cup \mathcal{A}$ 之内——若 LLM 编造一个不存在的字段（如 `cert.IDN_Names`），$\eta$ 会拒绝并触发反馈式重生成，该幻觉路径在架构层即被关闭。至此该规则历经 $r \to \mathrm{IR} \xrightarrow{\mu,\,\mathcal{V},\,\mathcal{A}} t \xrightarrow{\rho,\,\Phi_{\mathrm{post}}} \mathrm{Go} \xrightarrow{\sigma_{\mathrm{mech}}} \text{摘要} \xrightarrow{\phi_V} S_{\mathrm{align}}$ 各算子，无一处依赖模板分类，也无一处允许词汇表之外的命名进入产物——这正是第 6–7 节"受限合成 + 多重验证"在单条规则上的具体落地。

## 8. 阶段归因式迭代验证框架（SAIV）

### 8.1 动机与问题陈述

第 6–7 节的方法在单次前向生成下已能产出结构完整的 zlint 代码，但在缺乏独立人工真值的大规模场景中仍面临质量风险，且其根源高度集中于最上游的 NL$\to$IR 提取：最致命的一类是 IR 内容本身抽错（主语、谓词极性、约束或前提被误抽），则下游的分类、生成、验证全部作用在错误对象上（§9.5–§9.6 表明当前底三层缺陷几乎全部源于此）；其余两类是可执行性分类出错与代码生成偏离原文。至于召回数量是否完整，则由结构不变量 G1（§8.3）独立闭合，不与内容风险混为一谈。故质量控制的首要着力点是 IR 内容，其修复算子 $\rho_R$ 据此置于修复序列最前。

传统自动合规代码生成多采用"单向前向 + 启发式重试"模式，其反馈信号或为单一标量、或为粗糙布尔指示，难以定位出错阶段。为此本文构造一个沿管道反向定位误差来源、并触发阶段性修复的迭代机制——阶段归因式迭代验证（SAIV）：当端到端质量不达标时，先判定误差最可能来自召回、分类、生成还是验证哪一阶段，再对该阶段定向修复。该机制不学习参数，而是将若干可直接计算的不变量作为损失信号，由结构性不变量与客观外部证据（工具实现存在性）共同支撑，使质量验证由可计算残差承担、而非由人工真值集合承担。

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

直观含义是：一旦关键词召回完成，规则总量在下游任何分类步骤中都不应增加或减少。式 (7) 因此构成一个**结构性闭合条件**：若在任意阶段观测到等式不成立，则必可断定某下游模块引入了规则级别的增删误差。**该性质无需任何人工真值即可计算**，因此可在缺乏独立真值的大规模场景下作为第一级质量信号。

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

**覆盖度目标（lint 覆盖残差 $\mathcal{L}_{\mathrm{cov}}$）。** 上述两项损失刻画"召回是否守恒"（G1）与"可 lint 规则是否被忠实写成代码"（G2），但**未**刻画一个同样关键的工程目标：本系统在**非硬编码**前提下，究竟能覆盖多少现有静态检查工具已实现的规则。以 zlint 为参照系——其在目标标准族的 lint 数是可直接查得的客观基准（项目内置 zlint 源码：RFC 5280 共 **131** 条（122 证书 lint + 9 CRL lint）、CABF BR 共 **170** 条（154 证书 lint + 16 CRL lint），合计 **301** 条）——定义覆盖残差

$$
\mathcal{L}_{\mathrm{cov}}(\mathcal{D}) = 1 - \frac{\bigl|\{\, r : \text{本系统为 } r \text{ 生成同义可证 lint} \;\land\; r \text{ 对应某条 zlint lint 的 citation 条款} \,\}\bigr|}{|\mathcal{C}_{\mathrm{zlint}}(\mathcal{D})|} \tag{11b}
$$

其中分母 $|\mathcal{C}_{\mathrm{zlint}}|$ 取 zlint 在该标准族的 lint 总数（131 / 170，合计 301，按项目内置 zlint 源码 lints/rfc 与 lints/cabf_br 的非 _test.go lint 文件实测，均含 CRL lint）。$\mathcal{L}_{\mathrm{cov}} \to 0$ 的含义是：**在不硬编码任一具体 lint 的前提下，本系统由规范文本端到端生成的覆盖广度逼近 zlint**。"非硬编码"由 §10.4 的 `cicasgen_*` 防火墙保证——生成 lint 与 zlint 原生实现两端互拒，故覆盖只计真正端到端产出。该残差与 G2 互补且方向正交：G2 管"已写出的代码对不对"，$\mathcal{L}_{\mathrm{cov}}$ 管"该写的还有多少没写出"——后者正是 $\rho_R$（把更多规则的 IR 修对、从而可归约可生成）与离线词汇扩展 $\rho_A$ 共同驱动下降的目标。当前快照 $\mathcal{L}_{\mathrm{cov}}$ 远未闭合（见 §9.1a 与 §9.3），与 G2、同义性并列为迭代的主要开放目标。

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

**G1 闭合后的重定向：$\phi_R$ 分支即 $\rho_R$。** 第一分支原以召回数量缺口 $\mathcal{L}_{\mathrm{recall}}$ 触发；但当 G1 已作为结构不变量闭合（$\mathcal{L}_{\mathrm{recall}}\approx 0$，§9.2），归因到最上游 $\phi_R$ 的误差便不再是召回数量问题，而是其产出的 IR 内容问题（错主语 / 谓词极性 / 约束 / 前提）。故该分支的修复算子由"召回修复"重定向为 $\rho_R$（§8.7）。其无人工真值的触发信号是两个确定性比例：可归约 lint 中被 §7.1 实体级筛查判为 $\mathtt{ENTITY\_MISMATCH}$（且非指代）者，以及持续 $\perp_{\mathrm{NT}}$ 的不可归约者；二者偏高即归因 $\phi_R$、触发 $\rho_R$。$\rho_C/\rho_G/\rho_V$ 则按其余分支并列触发。

### 8.7 阶段修复算子

针对每一被归因阶段，设计一组阶段内修复算子；其中 $\rho_R$（IR 内容自反思修复）最为关键。管道最上游的 NL$\to$IR 提取一旦出错（主语错抽、谓词极性反转、约束散文化、前提丢失），下游的分类、生成、验证便全部失去正确对象——§9.5–§9.6 表明当前底三层（覆盖 / 代码生成 / 同义性）未闭合的缺陷几乎全部可追溯至此。因此 $\rho_R$ 是首要修复算子，且唯一改动 IR 本身；其余 $\rho_C, \rho_G, \rho_V$ 彼此并列、无优先级之分，由 §8.6 的阶段归因决定本轮触发哪一个，均在 IR 给定的前提下工作。

- **$\rho_R$（IR 内容自反思修复，首要算子）**：当 $\phi_G$ 在 $K_{\mathrm{loc}}$ 轮内持续返回 $\perp_{\mathrm{NT}}$（IR 不可归约）、或 G2 同义性持续低于阈值时，将下游完整失败轨迹——当前 IR、不可归约类别、$\sigma_{\mathrm{mech}}$ 摘要、判官裁定与理由、同义置信度、以及本会话已尝试过的历史 IR——构成一条**反向失败信号**回传 LLM，令其自我诊断并决定：**(a)** 更正 IR 的 subject / predicate / constraint / precondition（连同"取自原文、支持该修正的证据子串"一并输出），或 **(b)** 声明 `NO_FIX`——确认 IR 已正确而当前词汇 $(\mathcal{A}, \mathcal{V})$ 确不足以表达该规则。$\rho_R$ **不是**盲目重试（同提示 → 同错），也**不是**静态规则修补，而是一次看得见完整下游证据的反思调用；它修复的是管道最上游的 NL$\to$IR 阶段，这也是 SAIV 首次真正闭合从规范文本到代码的**完整链路**。

  **g4-sanity 自动闸门。** $\rho_R$ 返回的新 IR 须经一道确定性、无需人工的事后闸门方可进入后续流程，三项检查为：(i) subject 可被字段解析器解析为 $\mathcal{V}$ 内合法路径；(ii) `constraint` 字面值（经 OID/hex 归一化后）作为子串出现于原文；(iii) `predicate` 极性与原文 RFC 2119 关键词一致。任一失败即视为幻觉而拒绝——被拒的 IR 连同原因可回传 $\rho_R$ 再反思一轮（上界 $K_{\mathrm{IR}}$，默认 2），仍不过则归入不可归约残差 $\mathcal{R}^{\mathrm{irred}}_{\mathrm{code}}$。正是这道机械可计算的闸门取代了人工审核，使 $\rho_R$ 乃至整个 SAIV 迭代得以全自动运行：它把"发现 IR 错 → 改抽取 → 重抽"从需逐条人工确认的离线动作变为回路内的自动算子（流程见 §8.8 的算法 2）。

- **$\rho_C$（分类修复）**：引入多工具交叉证据——若规则在 zlint、pkilint、certlint、x509lint 至少一个中存在对应实现，则必然可执行；若被判为 `non_lintable`，即视为假阴性回传 $\phi_C$ 重判。

- **$\rho_G$（生成修复）**：先尝试确定性修复（如 `Description`/`Citation` 字面替换）；若失败，将失败码片段与 IR 约束差异、或解析阶段的原子签名/封闭性错误作为反馈注入提示，触发 LLM 在 $\mathcal{T}_{\mathcal{V}}$ 内重新合成；若持续返回 $\perp_{\mathrm{NT}}$，则该规则进入离线词汇扩展通道 $\rho_A$（离线聚合反复返回 $\perp_{\mathrm{NT}}$ 的规则、按同质簇设计新原子，且仅向上单调扩张词汇表，不破坏既有代码的可比性）。

- **$\rho_V$（验证修复）**：扩大同义判定的语义邻域（如允许否定/肯定互换、一对多分解），或修正双判定源输出之间的不一致（§8.10 的 L4b 二元判官）。

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

机械翻译算子 $\sigma_{\mathrm{mech}}$ 已在 §6.4 作为与渲染算子 $\rho$ 并列的确定性物化算子引入，其类型安全、决定性与可逆性三项性质亦在该处给出（可逆性即下文命题 2），并将构造细节前指至本小节；本小节即补足该构造，并先交代引入它的动机。作为对照，§7.1 把通用摘要算子 $\sigma$ 实现为 LLM 调用。当上游代码生成由原子 DSL 树驱动时，$\sigma$ 的输入并非任意 Go 源码，而是一类**可结构化拆解**的代码体，此时由 LLM 实现 $\sigma$ 会引入一类可被消除的系统性失真。

**条件分支上的系统性 NA-反转失真。** 考察"若 $\neg P$ 则返回 NA；若 $P\wedge Q$ 则 Pass；否则报错"这一检查体，它表达"当 $P$（规则适用）时 $Q$ 必须成立、$P$ 不成立时返回 NA"的条件语义，对应原文"WHEN $P$, THEN $Q$"的蕴含结构。经验观测发现，由 LLM 实现的 $\sigma$ 倾向于将 $P$ 直接复述为"WHEN"分句内容，丢失"$\neg P \Rightarrow \mathrm{NA}$"的极性反转；即便提示中显式给出对照示例并要求取反，重复试验仍稳定复现该失真，故它不属于 prompt 工程可消除的范畴，而是 $\sigma$ 由概率模型实现时的固有偏差。

**$\sigma_{\mathrm{mech}}$ 的定义。** 当代码生成端持有结构化 DSL 树 $t$ 时，可绕过 Go 源码直接对 $t$ 实施结构归纳翻译 $\sigma_{\mathrm{mech}} : \mathcal{T} \to \mathcal{L}_{\mathrm{NL}}$。它由两组规则给出：(i) **基例（原子）**——对每个原子 $a \in \mathcal{A}$，由闭合词典 $\mathcal{M} : \mathcal{A} \to \mathcal{L}_{\mathrm{NL}}$ 指派一个固定 PKI 语义短语，即 $\sigma_{\mathrm{mech}}(a) = \mathcal{M}(a)$；(ii) **递归（组合子）**——$\sigma_{\mathrm{mech}}(\neg t) = $ "NOT ($\sigma_{\mathrm{mech}}(t)$)"、$\sigma_{\mathrm{mech}}(t_1 \wedge t_2) = $ "($\sigma_{\mathrm{mech}}(t_1)$) AND ($\sigma_{\mathrm{mech}}(t_2)$)"、$\sigma_{\mathrm{mech}}(t_1 \vee t_2) = $ "($\sigma_{\mathrm{mech}}(t_1)$) OR ($\sigma_{\mathrm{mech}}(t_2)$)"。对含条件前提的二元组，当 $\mathrm{pre} = \neg(\mathrm{pre.inner})$ 时显式生成 "WHEN NOT ($\sigma_{\mathrm{mech}}(\mathrm{pre.inner})$), THEN $\sigma_{\mathrm{mech}}(\mathrm{pred})$"（短语字典节选见附录 E）。

**关键性质。** $\sigma_{\mathrm{mech}}$ 具三项性质：**全函数性与确定性**（在合法 DSL 树空间上为全函数且不引入概率项，相同输入恒产生相同输出）；**极性正确性**（条件前提为否定时显式生成 "WHEN NOT" 形式，消除 LLM-$\sigma$ 的 NA-反转失真）；**可逆性**（命题 2）。

**命题 2（$\sigma_{\mathrm{mech}}$ 可逆性）**。*给定 $\sigma_{\mathrm{mech}}(t)$ 的输出，原始 DSL 树 $t$ 在原子层等价意义下可机械恢复（同义原子被映射到同一短语时不可区分，其余结构保留）。该性质保证 $\sigma_{\mathrm{mech}}$ 在验证链路中不构成信息瓶颈。*

**对验证链路的意义。** 引入 $\sigma_{\mathrm{mech}}$ 后，语义传递链 $\mathrm{Spec} \to \mathrm{IR} \to t \xrightarrow{\sigma_{\mathrm{mech}}} \mathrm{Summary} \equiv \mathrm{Description}$ 中，LLM 仅在 $\phi_C$、$\phi_V$ 两端出现，其余环节均为确定性算子。由此链路上的概率失真被压缩至**原子词典 $\mathcal{M}$ 的选择**这一离线设计问题，而不再随每条规则的判定独立采样。需强调 $\sigma_{\mathrm{mech}}$ 仅适用于**由本系统自身代码生成器产出的 lint**（其前提是持有 DSL 树）；对纯人工编写或来自外部仓库的既有 lint，仍需 LLM-$\sigma$ 提取语义。

### 8.10 不变量残差 L4b 修复

前文 $\rho_C$（§8.7）采用了"实现存在性 $\Rightarrow$ 可执行性"的单向推论——某规则只要被任一外部工具实现为静态检查，即必可执行。本节将其扩展为一个**双向 falsifiable 残差**，并给出基于二元判官的修复机制。给定外部工具集 $\mathcal{T}$ 及覆盖判定 $\mathrm{cov}_{\mathcal{T}} : r \mapsto \{\text{full}, \text{partial}, \text{none}\}$，定义违反集合 $\mathcal{V} = \{ r : \mathrm{cov}_{\mathcal{T}}(r) \in \{\text{full}, \text{partial}\} \land \phi_C(r) \neq \mathrm{lintable} \}$，记 $N_{\mathrm{viol}} = |\mathcal{V}|$。若 $\phi_C$ 与 $\mathrm{cov}_{\mathcal{T}}$ 同时正确则 $N_{\mathrm{viol}} = 0$，因此 $N_{\mathrm{viol}}$ 构成一个不依赖人工真值的可计算残差。

**FLIP-or-SPURIOUS 二元判官。** 对每条 $r \in \mathcal{V}$ 调用仲裁判官 $\phi_J : r \to \{\mathrm{FLIP}, \mathrm{SPURIOUS}\}$，输入为规则原文与覆盖证据：**FLIP** 表示 $\phi_C(r)$ 错判，应翻转为 lintable；**SPURIOUS** 表示 $\mathrm{cov}_{\mathcal{T}}(r)$ 为假阳，应降级为 none。任一支被采纳后对应标签被修正，$r$ 离开 $\mathcal{V}$。

**命题 3（残差单调性）**。*若 $\phi_J$ 在每条违反上均给出 FLIP 或 SPURIOUS 之一并被采纳，则 L4b 一轮过程后 $N_{\mathrm{viol}}$ 严格下降至 0。* 证明梗概：FLIP 使 $\phi_C(r) = \mathrm{lintable}$（违反式右侧成立），SPURIOUS 使 $\mathrm{cov}_{\mathcal{T}}(r) = \mathrm{none}$（违反式左侧不再触发），两类修复均移除该 $r$ 而不引入新违反，$\mathcal{V}$ 严格收缩至空集。

L4b 在 §8.7 的修复算子分类下属于 $\rho_V$ 的一种特化：它不调整代码本身或生成模块，而是修正双判定源输出之间的不一致；触发条件为 $N_{\mathrm{viol}} > 0$，终止条件为 $N_{\mathrm{viol}} = 0$。该扩展使上述单向推论的 falsifiable 残差具备真正的"零点"，从而可作为收敛判据。

### 8.11 多目标残差总览

为便于工程落地，前述不变量可重述为四个目标，框架的收敛态由各残差同时为零刻画。四者数学形式不同构（守恒等式 / 覆盖比 / 连续平均损失 / 集合基数），职责互补；其中 Gcov 与 G2 是当前的开放目标，$\rho_R$（IR 内容自反思修复）是驱动二者闭合的首要算子。

| 目标 | 残差 | 主要修复算子 | 修复对象 |
|---|---|---|---|
| G1 召回完整性 | $\mathcal{L}_{\mathrm{recall}}$（式 9） | —（结构不变量，已闭合） | 召回窗口 / 关键词集合（如需） |
| Gcov 覆盖度 | $\mathcal{L}_{\mathrm{cov}}$（式 11b） | **$\rho_R$（首要）**；$\rho_A$ | IR 内容修正（→ 更多规则可归约可生成）/ 离线扩原子 |
| G2 同义性 | $\mathcal{L}_{\mathrm{code}}$（式 10） | **$\rho_R$（首要）**；$\rho_G$ | IR 内容修正 / DSL 树重合成 / $\sigma_{\mathrm{mech}}$ 替换 |
| G3 双判定源一致 | $N_{\mathrm{viol}}$（§8.10） | $\rho_V$（L4b 二元判官） | $\phi_C$ 假阴性 / $\mathrm{cov}$ 假阳性 |

当 $\mathcal{L}_{\mathrm{recall}} = \mathcal{L}_{\mathrm{cov}} = \mathcal{L}_{\mathrm{code}} = N_{\mathrm{viol}} = 0$ 时 SAIV 进入闭合态。§9 的诚实快照表明当前 G1 已闭合，而覆盖（Gcov）、代码生成与同义性（G2）这底三层尚未闭合——这正体现框架以可计算残差如实暴露未闭合处、而非以单一指标掩盖之的价值。$\rho_R$ 的设计纪律是在拿不准时诚实多判 NO_FIX、而非臆造修复，与 §9.5–§9.6 关于残差几乎全在上游抽取的发现一致。

## 9. 实验与实证评估

本节按"无独立人工真值"的原则组织实证：所有质量信号都来自结构性不变量、确定性复算、外部工具的客观证据，或逐条人工裁定，而非对单条规则的人工标注真值。评测范围取**当前最干净的一轮全库重抽**——RFC 5280 与 CABF BR（standard_id ∈ {1, 19}）——并诚实地分层报告：守恒方程的顶两层已闭合，而覆盖、代码生成、同义性这底三层尚未闭合。本节即给出这一**诚实快照**，既展示框架已做到什么，也明确暴露未闭合处及其根因。

### 9.1 实验设置

评测在 RFC 5280（standard_id = 1）与 CABF BR（standard_id = 19）两个标准源的全库重抽结果上进行。NL→IR 抽取器为 GLM-Z1-9B-0414（一个 9B 量级的小模型；更换更强抽取器 gpt-5.4 并未抬高 §9.5 的同义率，说明该率由抽取任务难度而非模型规模所界）；代码生成为 §6.6 的受限 LLM 树合成；目标框架为 zlint v3；同义性判官仅在证书级 oracle 不适用的子集上启用，且取去噪 5 票多数。所有覆盖与同义性数字均经**逐条人工裁定**或确定性复算校准（裁定工件随代码公开），并可在干净数据上确定性复算。需特别说明：本快照是后续"全量重抽"工程之前的诚实基线，**不掩盖**底三层尚未闭合这一事实。

**评测并非系统自评。** 须区分 SAIV 的两种用途：其迭代回路确实不需要人工真值（由 g4-sanity 闸门取代人工确认）；但本节的评测有效性建立在三道彼此独立的外部参照上：(i) zlint 自带的 `Source` + `Citation` 元数据（第三方声明其每条 lint 实现哪一条款，§9.3 的覆盖判据）；(ii) 以真实证书执行为真值的证书级 oracle（判定来自 zcrypto 解析与 zlint 读回 `Status`，与生成所用 LLM 无关，§9.4）；(iii) 纯 tree-vs-text 的人工同义裁定（§9.5）。三者皆非"以系统输出验证系统输出"。本评测未做的两件事——与现代 LLM 直接生成 Go 的基线对比、各组件受控消融——其定位见 §10.4。

### 9.1a 当前定版快照（2026-06-19，方法学硬化后，可一句命令复算）

本小节给出最新一轮全库重抽 + 方法学硬化后的一致快照，回填并取代 §9.7 轨迹中标记 ⟦测量中⟧ 的占位。三项硬化使本快照较此前更可信：(i) **去噪同义判官**——同义判官单票存在约 11% 噪声（同一输入两跑 18/166 翻转），故所有同义判定改取 5 票多数（denoised），单票数据不再作发射依据；(ii) **lintability 高精度负向门**——在抽取源头把 CA 记录/签发过程、跨证书（"signing key"）、runtime、真实世界语义内容（"须含申请人真实地址"）类判为非可 lint，使"被送进 codegen 的不可 lint 规则"在源头被拦（538→464）；(iii) **best-of-N 采样**——LLM 路对每条残差采样 N 个候选树，经证书级 oracle + 去噪判官择优，把 LLM 的组合自由转为覆盖而不破坏 100% 同义门。

**表 1a：端到端结果当前快照（standard_id ∈ {1, 19}，RFC 5280 + CABF BR）**

| 指标 | 数 | 口径/说明 |
|---|---:|---|
| 召回规则总量 | 2077 | RFC 5280 637 + CABF BR 1440 |
| **可 lint（单证书可观测）** | **464** | 经硬化分类器；负向门把过程/跨证书/runtime/语义类剔除（538→464） |
| zlint 覆盖（full，已有同源 lint） | **158** | 该规则已被某条同源 zlint lint 实现 |
| zlint 覆盖（partial） | **38** | 部分实现 |
| 未覆盖可 lint（codegen 定义域） | **306** | 需本系统生成自有 lint |
| 生成 DSL 树：确定性归约 $\mathrm{Code}\equiv\mathrm{IR}$（全 464 可 lint） | **254** | 占可 lint 55%，构造性忠实（另 CRL 可归约 17、render-refused 25、not_reducible 159、uncertified 9） |
| codegen 目标上编译通过的 DSL 树 | **190** | 确定性 162 + LLM 28 |
| **同义发射（去噪 5 票 + 证书级 oracle 双门，cert-sound）** | **83** | **确定性路 57 + LLM 路 26**（tree-pipeline 7 + best-of-N 19） |

**读法。** (1) 漏斗：2077 召回 → 464 可 lint → 其中完整覆盖 158、部分覆盖 38、未覆盖 268；非完整覆盖者（partial + none = 306）即 codegen 定义域（full 158 + 需生成 306 = 464）。(2) "能生成 DSL 树"：在全 464 可 lint 上，**254 条经确定性归约即得 $\mathrm{Code}\equiv\mathrm{IR}$ 的树**（归约器 sound，构造性忠实）。(3) 在未覆盖 codegen 目标上，190 条 DSL 树编译通过（确定性 162 / LLM 28）。(4) **同义**：经 $\mathrm{Code}\equiv\mathrm{IR}$（真证书 fixture 认证 + 编译）∧ $\mathrm{IR}\equiv\mathrm{Spec}$（去噪 5 票判官）双门后，**83 条同义发射**（确定性路 57、LLM 路 26），发射集构造性 100% 同义。(5) 确定性路 ≫ LLM 路（57 vs 26）这一反直觉结果的根因见 §9.4/§9.5：归约器树**构造性忠实于 IR**，而 LLM 的组合自由易漂移（编译通过 ≠ 同义）；best-of-N 正是把"LLM 多采样 + 严格门择优"用来回收这部分漂移（+19）。(6) 同义率被语料硬度而非工程努力所界——余下未同义者多为真正非单证书可表达（过程/跨证书/语义内容），属诚实残差，与项目历史 ~24–27% 的天花板一致。

### 9.2 召回与可 lint 性的守恒划分（G1）

第一层质量信号是 G1 守恒（§8.3 定理 1）：关键词召回的规则总量，在下游任何分类步骤中都不应增减。当前快照下守恒严格成立：

$$
\underbrace{2077}_{\text{召回}} \;=\; \underbrace{476}_{\text{噪声}} + \underbrace{1601}_{\text{真规则}}, \qquad \underbrace{1601}_{\text{真规则}} \;=\; \underbrace{464}_{\text{可 lint}} + \underbrace{1137}_{\text{不可 lint}}.
$$

两式逐项相等，即 G1 残差 $\mathcal{L}_{\mathrm{recall}} = 0$、守恒顶两层闭合（数据见 §9.1a，可一句 SQL 复算）。可 lint 的 464 条按标准源分为 CABF 313 条与 RFC 5280 151 条；这 464 条即下游代码生成 $\phi_G$ 的定义域。

### 9.3 lint 覆盖：以 zlint 自带 citation 为 ground-truth

要回答"现有工具覆盖了多少可 lint 规则"，关键在于用对判据。本文以"该可 lint 规则是否被某条同源 zlint lint 真正实现"为判据：对每条规则按其 source/section 检索候选 zlint lint，再逐字段（subject / obligation / predicate / constraint）比对，给出 full（完整实现）/ partial（部分实现）/ none（无实现）三档裁定——这比仅看"规则所在 section 是否被某条 zlint 引用"更严格（后者会把同节内的不同需求误计为覆盖）。464 条可 lint 规则中，**完整覆盖 158 条、部分覆盖 38 条、未覆盖 268 条**（表 1）；以"非完整覆盖即需本系统自行生成"计，代码生成的定义域为 partial + none = **306 条**。

**表 1：zlint 既有实现对可 lint 规则的覆盖（464 条，按标准源）**

| 覆盖档 | CABF | RFC 5280 | 合计 |
|---|---:|---:|---:|
| full（完整覆盖） | 104 | 54 | **158** |
| partial（部分覆盖） | 34 | 4 | **38** |
| none（未覆盖） | 175 | 93 | **268** |
| 需生成（partial + none，codegen 定义域） | 209 | 97 | **306** |

partial 与 none 两档的成因经抽样归因：部分是本系统无可比 DSL 树（codegen 缺口或退化 IR，而 zlint 往往已实现，如 §4.1.2.5 → `e_utc_time_not_in_zulu`）；部分是同 section 内本属别的需求（section 共享 ≠ 需求覆盖）；少数是同需求而我方树抽错（如 §4.2.1.4"策略 OID 不得重复"↔ `e_ext_cert_policy_duplicate`，因我方把 uniqueness 误抽成 count 而判 partial）。故"位于某条 zlint 触及的 section"并不等于"该需求被实现"——这正是本节弃用宽松的"节号触及"判据、改用逐字段 full/partial/none 裁定的原因。覆盖缺口的结构性成因归类见附录 F，典型 lint↔规范对照案例见附录 G。

**两个方向勿混淆——覆盖度作为迭代目标（Gcov）。** 上表回答的是"zlint 覆盖了我方多少条规则"（完整 158、含部分 196，分母 464 可 lint）。而 §8.5 的覆盖残差 $\mathcal{L}_{\mathrm{cov}}$ 度量的是**反方向**——在**非硬编码**前提下，本系统端到端生成的 lint 复现了 zlint 自身多少**广度**：分母取 zlint 在该标准族的 lint 实测总数（项目内置 zlint 源码：RFC 5280=131、CABF BR=170，合计 301，含 CRL），分子为"本系统生成同义可证 lint 且对应某条 zlint citation 条款"者。这个反方向才是迭代要逼近闭合的目标。上文 §4.2.1.4"策略 OID 不得重复"的失配，根因正是 IR 把 uniqueness 误抽成 count——这类正是 $\rho_R$ 可自动修复、从而推动 $\mathcal{L}_{\mathrm{cov}}$ 下降的对象。

### 9.4 代码生成分层与证书级 oracle（主要结果）

"一条可 lint 规则能否被写成代码"分两个口径报告（表 2）。其一，**确定性可验证忠实性**：在全部 464 条可 lint 规则上，确定性归约器对其中 **254 条**产出 $\mathrm{Code}\equiv\mathrm{IR}$ 的 DSL 树（归约器 sound、所用原子经证书级 oracle 认证，构造性忠实，占可 lint 55%）；其余 464 条的去向为 CRL 可归约 17、渲染拒绝 25、not_reducible 159、原子未认证 9。其二，**代码生成产量**：在 306 条未覆盖（codegen 定义域）目标上，**190 条** DSL 树编译通过（确定性 162 + LLM 28）；再经同义双门得 **83 条**发射（详见 §9.5）。

**表 2：代码生成分层（当前定版快照，§9.1a）**

| 口径 | 数 |
|---|---:|
| 全 464 可 lint 中确定性归约得 $\mathrm{Code}\equiv\mathrm{IR}$ 树（oracle 认证） | **254** |
| 未覆盖 306 目标上编译通过的 DSL 树 | **190**（det 162 + LLM 28） |
| 经双门发射的同义 lint（详见 §9.5） | **83**（det 57 + LLM 26） |

254 这一档即证书级 oracle（§7.1）以与所用模型无关的方式验证 $\mathrm{Code}\equiv\mathrm{IR}$ 的集合，是本节的主要结果。这 254 条的忠实性不依赖任何 LLM 投票，而由"每个原子均通过受控证书 fixture 认证 + 归约器对 IR 逐原子忠实"经结构归纳给出（其为执行级验证而非定理，见 §7.1）；更换生成器或判官模型都不改变这一验证子集。相较之下，单票 LLM 判别器会接受一个明显更大、却未经此验证的超集（其可靠性问题见 §9.5 的校准），二者之差正是单票判据的风险所在。这一固定、与模型无关的 $\mathrm{Code}\equiv\mathrm{IR}$ 参照系也是后文得以把残余误差定位到抽取阶段（§9.5–§9.6）的前提：当代码对 IR 的忠实性被独立确定后，凡仍出错者必出在 IR 本身。

### 9.5 同义性作为发射判据（手裁校准）

oracle 验证的是 $\mathrm{Code}\equiv\mathrm{IR}$（代码忠实于 IR），但系统的最终价值在于 $\mathrm{Code}\equiv\mathrm{Spec}$（代码忠实于原文），这还要求 $\mathrm{IR}\equiv\mathrm{Spec}$。$\mathrm{IR}\equiv\mathrm{Spec}$ 由同义判定把关，且与 §9.3 用作覆盖判据的 zlint 既有实现、§9.4 以真实证书执行为真值的 oracle 一起，构成本评测三道彼此独立、皆非"系统自评"的外部信号。为抑制判官单票噪声（同一输入两跑约 11% 翻转），$\mathrm{IR}\equiv\mathrm{Spec}$ 的判定改取**去噪 5 票多数**。经 $\mathrm{Code}\equiv\mathrm{IR}$（证书级 oracle）∧ $\mathrm{IR}\equiv\mathrm{Spec}$（去噪 5 票）双门后，本快照发射 **83 条**同义 lint（确定性路 57 + LLM 路 26），发射集在构造上即 100% 同义。未经此发射筛选时，最难的"未覆盖 ∧ 可渲染"子集上的原始同义率约 **24–27%**（与项目历史天花板一致，§9.7）——下文说明为何这个低值正确、且并非框架上界。

须正确解读这个约 27% 的原始率，以免误读为系统四分之三的代码错误。其一，选择偏差：该子集（未被 zlint 覆盖 ∧ 可渲染）本就富集连 zlint 都未实现的困难规则，并非 464 条可 lint 规则的平均水平。其二，瓶颈在抽取：该比例反映的是 $\mathrm{Spec}\to\mathrm{IR}$ 抽取质量而非 $\mathrm{IR}\to\mathrm{Code}$ 生成质量（详见下文），且更换更强抽取器（gpt-5.4）并未抬高该率（§9.7 第 16 轮），说明天花板由抽取任务难度（IR 欠表达）而非模型规模所界，故它是未筛选产出在困难子集上的质量、而非框架上界——更强抽取或子字段内容原子是直接且尚未穷尽的改进杠杆（§10.4）。其三，不以未筛选产出交付：经发射判据筛选后，交付集在构造上即 100% 同义（见本节末）。

这一步也暴露了 LLM 同义判官的单票不可靠：同一输入两跑约 11% 翻转（18/166），且初判常含假阴性——既有渲染端模板缺口导致的错误摘要，也有判官对表格残片、指代、版本编码的系统性误判（如 "cA MUST be set TRUE" ↔ `IsCA()` 实为同义却被判否）。这正是本快照改取去噪 5 票多数、并由确定性 oracle 与去噪判官双向校准的原因（§7.1）。此处同义性按二元判定处理（表达 / 未表达，无中间档），判官三档中的 partial 一律归入"未表达"。

未同义样本中真正不同义的缺陷几乎全部源于上游抽取。逐条核实表明：归约器忠实地把错误 IR 映成错误树（归约器本身 sound，对退化原子一律返回 honest None），病根全部在抽取端。这与 §9.6 的 R24081 同源：oracle 仍可验证 $\mathrm{Code}\equiv\mathrm{IR}$，但 $\mathrm{IR}\neq\mathrm{Spec}$。故唯一出路是改抽取并重抽，而非在归约器上打补丁。

**方法学结论：同义性应作为发射判据，而非事后指标。** 系统的价值在于忠实翻译，一条不同义的 lint 即是一件错误产物。因此正确目标不是把同义率从 50% 提到 60%，而是只发射经双重验证的 lint：$\mathrm{Code}\equiv\mathrm{IR}$ 由 §7.1 的证书级 oracle 执行级验证、$\mathrm{IR}\equiv\mathrm{Spec}$ 由同义判定把关。此处须澄清该判定的**操作对象**：判官并不读取 IR 的 JSON，也不直接读 Go 源码（后者会令判官把"读不懂 zcrypto 习惯写法"误计为"不同义"），而是对生成树 $t$ 施加确定性渲染 $\sigma_{\mathrm{mech}}(t)$（无 LLM 的逐原子自然语言模板，忠实描述 $t$ 即代码所检之物），再判 $\sigma_{\mathrm{mech}}(t)$ 是否 EXPRESSES 原文。由于 $t$ 是 IR 的忠实归约、且 $\mathrm{Code}\equiv\mathrm{IR}$ 已被 oracle 钉死，"$\sigma_{\mathrm{mech}}(t)\equiv\mathrm{Spec}$"这一道判定**同时即是** $\mathrm{IR}\equiv\mathrm{Spec}$ 与 $\mathrm{Code}\equiv\mathrm{Spec}$——在已证 $\mathrm{Code}\equiv\mathrm{IR}$ 之下二者重合，故"先验 $\mathrm{Code}\equiv\mathrm{IR}$、再判 $\mathrm{Code}\equiv\mathrm{Spec}$"与本文的双腿表述等价。这也正解释了同义率为何偏低却正确：判官比对的是**代码的实际行为**而非 IR 摘要自身，当抽取只粗略捕获规则（IR 欠表达）时 $\mathrm{Code}\equiv\mathrm{IR}$ 仍成立、但 $\sigma_{\mathrm{mech}}(t)$ 说得比原文少，判官据此正确判不同义——瓶颈因而被精确定位到上游 IR 丰度，而非代码生成的忠实性。二者皆过才发射，其余诚实拒发为残差。如此发射集在构造上即 100% 同义（当前定版快照发射 83 条，§9.1a）；"收敛"的定义也随之改变——不再是同义率趋近某阈值，而是迭代修复上游抽取、把残差逐批转为同义，发射集随之增长且始终保持 100% 同义。这里须区分两类残差：一类为可归约但暂未修复（重抽即可消除），与真正不可归约的残差（受双轴纪律所限，如 PKI 外部 primitive 的 Unicode NFC / IDN→ACE、逐字节 hex 字面、语料内单形态规则）截然不同；后者构成本框架以受限词汇换取可验证性的诚实边界。

### 9.6 确定性忠实性筛查的交叉验证

作为与 oracle、判官皆独立的第三重确定性检查，本文对生成产出运行 §7.1 的实体级筛查 $\mathrm{Faithful}_{\mathrm{nec}}$。其代表案例 R24081 经审计确认根因是上游 IR 主语错抽（authorityCertIssuer / authorityCertSerialNumber 本属 AKI 字段，却被抽成 AIA 扩展）：oracle 仍可验证 $\mathrm{Code}\equiv\mathrm{IR}$（代码忠实于那条错误 IR），但筛查标记出"AIA 在原文中从未出现"，从而暴露 $\mathrm{IR}\neq\mathrm{Spec}$。据此所做的上游修复（为字段 schema 补齐缺失的 AKI 子字段）使其重抽后主语正确归位，并因"共现"语义无对应原子而诚实转为残差。这印证了"筛查—定位—上游修复"的闭环，也再次说明本框架的瓶颈与修复着力点都在抽取端，而非代码生成或验证端。

### 9.7 SAIV 迭代收敛与诚实性证据

SAIV 的价值在于其残差随迭代单调收敛：每轮由首要算子 $\rho_R$（§8.7）经确定性 g4-sanity 闸门自动修复一批 IR 并重测下游，残差非递增（§8.8）。本轮工作历经一次干净的全量重抽（锚点修复）、受控原子构建（§6）、以及三项方法学硬化（去噪 5 票同义判官、可 lint 性高精度负向门、best-of-N 采样），其**当前定版快照即 §9.1a**——召回 2077、可 lint 464、确定性归约 $\mathrm{Code}\equiv\mathrm{IR}$ 254、编译通过 190、同义发射 83，可一句 SQL/脚本复算。该快照之数已取代早前迭代轨迹中标记"测量中 / 待重测"的占位。

迭代过程留下两项可核验的诚实性证据。其一，**$\rho_R$ 在 not_reducible 残差上的产量很低、且大量判 NO_FIX**——这本身是一项诚实发现：该残差大多真正超出当前 DSL 表达力（条件式、跨字段编码、子字段内容），$\rho_R$ 正确地拒修而非臆造修复。其二，一次针对可 lint 标签的反向审计发现分类器 $\phi_C$ 的"结构救援"分支把一批本不可 lint 者（$\mathrm{check\_scope}$ 非单制品、主语未定、或算法委派类）误升为可 lint；将其降级（这正是 §9.1a 高精度负向门把可 lint 由 538 收紧至 464 的一部分）后，**确定性归约 $\mathrm{Code}\equiv\mathrm{IR}$ 的数并不随之下降**——证明"已验证覆盖"从未因误分类而虚高，被误判者全部落在 not_reducible 桶。

这两点共同印证全文的核心定位：本框架的瓶颈与修复着力点都在抽取端（§9.5–§9.6），而 not_reducible 是诚实暴露的**原子覆盖**缺口（缺保留 IP / CN-取自-SAN / NFC 归一化 / RDN 次序等原子，zlint 多已实现）、而非隐藏的可 lint 性短缺。

## 10. 讨论与有效性威胁

### 10.1 关键发现

**把忠实性判定本身确定化，是核心方法学发现。** 验证生成代码是否忠实于规范，传统做法或依赖人工（不可规模化）、或依赖另一个 LLM 投票（不可复现）；本文将这一判定确定化——证书级 oracle 以真实证书的执行结果取代投票，给出与所用模型无关的 $\mathrm{Code}\equiv\mathrm{IR}$ 执行级验证（§9.4）。同一思路贯穿全链路：受限 DSL 在语言层排除字段/OID 编造，$\sigma_{\mathrm{mech}}$ 以结构归纳消除 LLM 摘要的极性失真。由此提炼出一条不限于 PKI 的设计原则：验证链路上每个算子都应尽可能确定化，确定性的着力点可从生成端迁移到验证端。

**同义性应作为发射判据，而非事后指标。** 未覆盖子集的真实同义率约 24–27%（§9.5）不应被读作"四分之三代码是错的"：几乎所有不同义都源于上游 IR 抽取（主语错抽、子字段当成整个扩展）而非代码生成，归约器忠实地把错误 IR 映成错误树。故正确姿态不是把同义率略微调高，而是只发射经 $\mathrm{Code}\equiv\mathrm{IR}$ 与 $\mathrm{IR}\equiv\mathrm{Spec}$ 双重验证的 lint，使发射集在构造上即 100% 同义，残差由上游重抽逐批转化；"收敛"因此被重新定义为发射集在保持 100% 同义下持续增长。

### 10.2 跨 PKI 的适用性

本框架的核心机制并不特定于 PKI。Layer 1 的 RFC 2119 关键词集可经配置替换为其他生态的道义关键词（如 ISO 的 shall/should/may）。因此方法适用于同时满足三条件的规范源：**(1)** 以可识别的形式化道义关键词表达强制/推荐；**(2)** 约束目标是结构化、可机器解析的产物（证书、协议消息、配置文件）；**(3)** 具备支持知识图谱与作用域继承的层级化章节结构。这使本框架的方法学价值超出 PKI 单一领域。

### 10.3 对规范作者与工具维护者的建议

对**规范作者**，三条起草原则可显著降低提取歧义：单句单义务（一句至多一个 MUST/SHALL）、以 ASN.1 路径而非代词精确引用字段、用固定模式规范化跨文档引用（使每个引用都能映射为知识图谱上一条类型化边）。对 **lint 维护者**，建议把 `description` 直接写成显式给出字段路径/断言类型/取值/严重级别并引用规范条款的代码摘要——本研究发现大量 lint 描述既非规范引用、也非实现忠实摘要，致使覆盖分析必须先做一步代码摘要才能对齐，徒增开销与裁决噪声。

### 10.4 局限性与有效性威胁

**方法局限与结论范围。** 同义判定端点 $\phi_V$ 仍由 LLM 实现，更稳健的路径应将其与形式化验证或测试用例结合；原子集 $|\mathcal{A}|=68$ 对 ASN.1 字节级编码、宿主框架未暴露字段、多分支严重度等仍有缺口，需经离线 $\rho_A$ 单调扩展；跨文档引用与动态约束（"有效期不得超过 N 天"）支持有限。故本文结论严格受限于所用输入表示（结构化 IR）、受限代码空间（$\mathcal{T}_{\mathcal{V}}$）与验证流程，更适合可在单文档上下文闭合的静态约束，不应外推为"所有 PKI 规范均可完全自动化"或对所有标准族/语境稳定泛化。

**组件必要性未经消融。** 本文给出的是一个端到端可工作的系统，但未对各组件做受控消融，故"必要性"主张须分层界定。(i) 知识图谱与确定性检索：本文不主张其相对普通 RAG 的优越性——检索质量只通过下游 IR 忠实性间接显现、而后者由抽取器主导（§9.5），干净消融高度受混淆；采用确定性子图检索的初衷是可溯源与可复现，属工程取舍而非经实验验证的贡献。(ii) 受限 DSL：其相对"直接生成 Go"的必要性是架构性论证（命题 1 加 190 条离线编译零幻觉），而非实验结论。(iii) SAIV：框架与 g4-sanity 闸门已被证实可运行，但"有无 SAIV"的规模效果消融未在本文报告。

**现代 LLM 基线的缺位。** 让前沿模型直接生成 Go lint 效果如何，是当前最重要的实证缺口；本文未做此对比。但证书级 oracle 是生成器无关的——它对任意来源（含直接生成、含不同前沿模型）的 lint 都能以同一执行级判据验证 $\mathrm{Code}\equiv\mathrm{IR}$，故"在同一 254/464 目标集上评测直接生成基线的通过率"是定义明确的未来工作，而非方法学障碍；其结论将直接检验"生成不是瓶颈、抽取才是"这一观察。

**覆盖规模与泛化的边界。** 254 这一数字受 oracle 的**可认证性**所限，而非可 lint 规则的上界：只有能用证书工厂造出"满足/违反"区分对的原子才可认证，需跨证书上下文、密码学事实（如模数素性）或字节级编码的原子无法认证（本节末三条边界）。故 254 是*可被 oracle 执行验证*的子集规模，与可 lint 总量（464）是不同口径，二者之差并非"生成失败"而是"暂不可被该 oracle 验证"。至于跨体系泛化——Mozilla / Microsoft 根程序、ETSI EN 319、国密 GM/T——本文仅给出机制层面的适用性论证（§10.2），**未**在这些体系上做实证；其道义关键词集、字段 schema 与原子覆盖均需重新适配，故不应将 RFC 5280/CABF BR 上的结论外推为对所有标准族稳定泛化。

**端到端正确性口径与分类校验。** 须区分两条腿：$\mathrm{Code}\equiv\mathrm{IR}$ 由证书级 oracle 在可认证子集上确定性、与模型无关地自动验证，而 $\mathrm{IR}\equiv\mathrm{Spec}$ 当前由逐条人工同义裁定把关、尚未自动化，故端到端 $\mathrm{Code}\equiv\mathrm{Spec}$ 仅对经双重门的发射集成立（详见 §9.5）。本文不声称已自动求解 $\mathrm{Spec}\to\mathrm{IR}$，反而把"端到端自动化"的未决核心精确定位到这一上游阶段。此外，464 条的可 lint 性标签并非以逐条人工真值校验，而是以外部工具实现存在性作单向假阴性探测（若 zlint/pkilint/certlint/x509lint 任一已将某规则实现为静态检查则其必可 lint），并对其中已生成代码的子集做独立同义裁定（如 §9.5 的发射 83 条）；本文未对全部 464 条做穷尽审计，是一处诚实的开放点。

**有效性威胁。** 内部有效性的最大威胁是上游 IR 误差传播——抽错的边界/字段/约束会沿 $\phi_C/\phi_G/\phi_V$ 传播并伪装成生成端问题；§9.5–§9.6 表明当前几乎所有缺陷都源于此，$\rho_R$（首要算子）为之提供可证伪的修复窗口，$\phi_V$ 以置信度阈值过滤并主要作诊断信号。外部有效性：实证仅覆盖 RFC 5280 与 CABF BR，未含国密 GM/T 等体系；生成代码面向 zlint，跨框架迁移非即插即用；已验证规则相对完整规范仍属子集。构念有效性：编译通过只衡量可接受性而非语义忠实，对齐得分权重为经验值；为防"自己覆盖自己"的循环虚高，生成 lint 以 `cicasgen_*` 前缀与 zlint 原生代码两端互拒，保证"已覆盖"只计第三方实现；证书级 oracle 的验证受三条边界约束——仅覆盖可认证子集（约 254/464）、为受控 fixture 上的经验测试而非定理、且与 lint 端共享 `util.*` OID 表（盲于 OID 身份层错误），其外产出诚实归入"未验证"。

## 11. 结论

### 11.1 研究总结

本研究面向 PKI"规范-到-合规检查代码"的端到端自动化，给出一个贯通"规则提取 → 中间表示 → 可 lint 性判定 → 代码生成 → 验证"的统一框架，以结构化 IR 与五条件可 lint 性判定为前后两半的统一接缝。前半链路以确定性知识图谱检索 + 受 schema 约束的 LLM 语义解析保证提取可审计、可复现；后半链路在语言设计层面把代码空间限制为有限闭合的 DSL 树空间 $\mathcal{T}_{\mathcal{V}}$（命题 1 关闭字段/OID 编造类幻觉），并以**证书级语义 oracle** 对生成 lint 经真实证书执行*验证* $\mathrm{Code}\equiv\mathrm{IR}$（执行级验证，边界见 §7.1/§10.4）。阶段归因式迭代验证（SAIV）则将召回完整性、代码-规范同义性与双判定源一致性作为可计算残差，在**无人工标注真值**下提供沿管道反向定位与定向修复的收敛性保证。各环节的形式化与实证见 §4–§9。

### 11.2 主要结论

实证支持三点经验结论与一项方法学论断。其一，Web PKI 规范源与现有静态 lint 工具之间存在显著覆盖缺口：464 条可 lint 规则中 zlint 完整覆盖 158 条（另部分覆盖 38 条），余 306 条缺乏完整实现，构成自动生成的直接目标。其二，可靠的规则提取依赖受约束的提取而非端到端直接提示——将 LLM 限定为受 schema 约束的解析器，并以确定性检索与确定性可 lint 性判定包裹之。其三，Web PKI 规范规则中仅一小部分（1601 条真规则中约 29%、即 464 条）可被还原为单制品静态 lint 检查，这一比例本身即是对"哪些规范可被静态强制"这一长期模糊问题的量化回答。其四是一项诚实的负向发现：当生成端被 oracle 钉死为与模型无关的 $\mathrm{Code}\equiv\mathrm{IR}$ 之后，残余的不忠实全部落在 $\mathrm{Spec}\to\mathrm{IR}$ 抽取而非 $\mathrm{IR}\to\mathrm{Code}$ 生成，故就当前数据而言，生成不是难点、抽取才是。在方法学层面，本文提炼并以实证支持一项一般性原则——验证链路上每个算子都应尽可能确定化，其最有力的实例即证书级 oracle 把忠实性判定确定化为可执行、与模型无关的 $\mathrm{Code}\equiv\mathrm{IR}$ 验证——并以"可归约子集闭合 + 不可归约边界披露"双指标取代单一收敛阈值，为基于受限词汇的规范-到-代码生成提供可复现的诚实边界声明范式。

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

$\sigma_{\mathrm{mech}}$（§8.9）由原子-短语字典 $\mathcal{M} : \mathcal{A} \to \mathcal{L}_{\mathrm{NL}}$ 与三组合子归约规则构成。代表性条目：

| 原子 | $\mathcal{M}(a)$ 短语模板 |
|---|---|
| `ExtPresent(O)` | "the {O} extension is present" |
| `ExtCritical(O)` | "the {O} extension is present and marked critical" |
| `FieldEq(F, v)` | "{F} equals {v}" |
| `FieldEncodedAs(F, T)` | "{F} is encoded as ASN.1 {T}" |
| `KeyUsageHas(B)` | "the KeyUsage bit {B} is asserted" |
| `ListAllMatch(F, T)` | "every entry of {F} satisfies ({σ_mech(T)})" |
| `SubtreeIPListAnyHasOctetCountAndNotAllZero(F, n)` | "the NameConstraints IP subtree {F} contains a non-zero entry of {n} octets" |

组合子归约：$\sigma_{\mathrm{mech}}(\neg t) =$ "NOT ($\sigma_{\mathrm{mech}}(t)$)"；$\sigma_{\mathrm{mech}}(t_1 \wedge t_2) =$ "($\sigma_{\mathrm{mech}}(t_1)$) AND ($\sigma_{\mathrm{mech}}(t_2)$)"；$\vee$ 同理；原子基例 $\sigma_{\mathrm{mech}}(a) = \mathcal{M}(a)$。对条件二元组 $(p,q)$：当 $p = \neg(p')$ 时输出 "WHEN NOT ($\sigma_{\mathrm{mech}}(p')$), THEN $\sigma_{\mathrm{mech}}(q)$"（消除双重否定的 NEG-PRE 模板），否则输出 "WHEN ($\sigma_{\mathrm{mech}}(p)$), THEN $\sigma_{\mathrm{mech}}(q)$"，$p=\perp$ 时输出 $\sigma_{\mathrm{mech}}(q)$ 单句。

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
