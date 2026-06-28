"""
使用示例 - 提取模块完整流程
演示如何使用新的提取架构
"""
from app.services.extraction import ExtractionOrchestrator


def example_basic_extraction():
    """基本提取示例"""
    # 示例文档
    document_text = """
    4.2.1.3 Key Usage

    The keyUsage extension MUST be present in all CA certificates. The extension
    MUST be marked as critical.

    For CA certificates, the keyCertSign bit MUST be set. The cRLSign bit SHOULD
    be set if the CA will issue CRLs.

    See RFC 5280 Section 4.2.1.3 for the complete definition of the keyUsage
    extension format.
    """

    document_id = "CABF_BR_v1.8.0"

    # 初始化编排器（不使用 LLM 进行简单测试）
    orchestrator = ExtractionOrchestrator(
        llm_client=None,
        kg_client=None,
        enable_llm=False,
        enable_semantic_conflict=False,
    )

    # 执行提取
    def progress_callback(message: str, progress: float):
        print(f"[{progress*100:.0f}%] {message}")

    result = orchestrator.extract(
        document_text=document_text,
        document_id=document_id,
        progress_callback=progress_callback,
    )

    # 打印结果
    print("\n" + "=" * 80)
    print("提取结果摘要")
    print("=" * 80)
    print(f"文档ID: {result['document_id']}")
    print(f"提取规则数: {result['statistics']['total_rules']}")
    print(f"分块数: {result['statistics']['total_chunks']}")

    print("\n规则列表:")
    for i, rule in enumerate(result['rules'], 1):
        print(f"\n[规则 {i}]")
        print(f"  规范表述: {rule['canonical_text']}")
        print(f"  原始文本: {rule['original_text']}")
        print(f"  置信度: {rule['confidence']:.2f}")
        if rule['references']:
            print(f"  引用: {[ref['text'] for ref in rule['references']]}")


def example_with_llm():
    """使用 LLM 的完整示例"""
    from openai import OpenAI  # 或其他 LLM 客户端

    # 初始化 LLM 客户端
    llm_client = OpenAI(api_key="your-api-key")

    # 初始化编排器（完整功能）
    orchestrator = ExtractionOrchestrator(
        llm_client=llm_client,
        kg_client=None,  # 如果有 KG，传入 KG 客户端
        enable_llm=True,
        enable_semantic_conflict=True,
    )

    # 复杂文档示例
    complex_document = """
    7.1.2.3 Subject Alternative Name Extension

    Certificate Field: extensions:subjectAltName
    Required/Optional: Required

    The certificate MUST include at least one dNSName entry in the subjectAltName
    extension. Each entry MUST contain only fully-qualified domain names.

    If the certificate is for a wildcard domain (e.g., *.example.com), the
    wildcard character (*) MUST appear only in the leftmost label position.

    IP addresses MAY be included as iPAddress entries, but MUST NOT be used as
    the primary identifier.

    For end-entity certificates issued after 2023-09-15, the maximum validity
    period is 398 days.

    Conflict Note: This differs from RFC 5280 Section 4.2.1.6, which allows
    longer validity periods.
    """

    result = orchestrator.extract(
        document_text=complex_document,
        document_id="CABF_BR_v2.0.0",
        progress_callback=lambda msg, prog: print(f"[{prog*100:.0f}%] {msg}"),
    )

    # 检查冲突
    if result['conflicts']:
        print("\n检测到的冲突:")
        for conflict in result['conflicts']:
            print(f"  - {conflict['rule1']} vs {conflict['rule2']}")
            print(f"    类型: {conflict['type']}")
            print(f"    原因: {conflict['reason']}")


def example_custom_pipeline():
    """自定义流程示例"""
    from app.services.extraction import (
        StructuredChunker,
        ExtractorDispatcher,
        ExtractionVerifier,
        IRNormalizer,
    )

    # 步骤1: 分块
    chunker = StructuredChunker()
    chunks = chunker.chunk_document("your document text", "doc_id")

    # 步骤2: 提取
    dispatcher = ExtractorDispatcher(llm_client=None, enable_llm=False)
    results = dispatcher.extract_from_chunks(chunks)

    # 步骤3: 验证
    verifier = ExtractionVerifier()
    verified_results = []
    for result, chunk in zip(results, chunks):
        is_valid, reason = verifier.verify(result, chunk)
        if is_valid:
            verified_results.append(result)

    # 步骤4: 归一化
    normalizer = IRNormalizer()
    normalized_irs = [normalizer.normalize(r.ir) for r in verified_results]

    print(f"提取并验证了 {len(normalized_irs)} 条规则")


def example_query_results():
    """查询和使用结果示例"""
    # 假设已经运行了提取流程
    orchestrator = ExtractionOrchestrator()
    result = orchestrator.extract("document text", "doc_id")

    # 查询特定字段的规则
    keyusage_rules = [
        rule for rule in result['rules']
        if 'keyusage' in rule['raw_ir']['subject'].lower()
    ]

    print(f"找到 {len(keyusage_rules)} 条关于 KeyUsage 的规则")

    # 查询所有 MUST 规则
    must_rules = [
        rule for rule in result['rules']
        if rule['raw_ir']['obligation'] == 'MUST'
    ]

    print(f"找到 {len(must_rules)} 条 MUST 规则")

    # 查询有冲突的规则
    conflicted_rules = [
        rule for rule in result['rules']
        if rule['conflicts']
    ]

    print(f"找到 {len(conflicted_rules)} 条有冲突的规则")

    # 导出为 JSON
    import json
    with open('extraction_result.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)

    print("结果已导出到 extraction_result.json")


if __name__ == "__main__":
    print("运行基本提取示例...")
    example_basic_extraction()

    # 取消注释以运行其他示例
    # example_with_llm()
    # example_custom_pipeline()
    # example_query_results()
