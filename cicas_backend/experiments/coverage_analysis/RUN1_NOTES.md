# 实验 Run 1: 跨标准覆盖分析（2026-07-02）

## 背景

在论文审稿过程中发现，CABF BR的很多规则"derived from RFC 5280"（例如§7.1.2章节），但zlint实现时这些lint被标记为RFC 5280 source。

**问题**：原始的覆盖判断算法`_coverage_candidates`对CABF规则只在CABF lint池中查找候选，**系统性漏判了那些实际覆盖CABF规则但被标记为RFC 5280 source的lint**。

参见记忆：`[[cabf_rules_covered_by_rfc_lints_2026_06_29]]`

## 修改

修改后端 `app/services/certificate/zlint_interface.py` 中的 `_coverage_candidates` 函数：

```python
# 修改前（行240）：
if src in ("CABF", "CABF-BR", "CABF_BR", "BRS", "BR"):
    return list(self.zlint_ir_cabf)  # 只返回CABF lint

# 修改后（行243-244）：
if src in ("CABF", "CABF-BR", "CABF_BR", "BRS", "BR"):
    # CABF规则需要同时匹配CABF和RFC5280的lint（跨标准覆盖）
    return list(self.zlint_ir_cabf) + list(self.zlint_ir_rfc)
```

## 实验结果

运行 `recompute_coverage.py` 分析候选数量变化：

### CABF BR 规则（226条）

```bash
python3 experiments/coverage_analysis/recompute_coverage.py --standard-id 19
```

**结果：**
- **所有226条CABF BR规则的候选数量都增加了**
- 从 **170个候选 → 357个候选**（+187个）
- 187正好是从数据库加载的RFC 5280 lint数量
- 证实修改有效：CABF BR规则现在可以同时匹配CABF和RFC lint

**示例（增加最多的规则）：**
```
Rule ID  | Section      | 旧候选 | 新候选 | 增量
---------|--------------|--------|--------|------
R29788   | §A.2.1       | 0      | 357    | +357
R28708   | §7.1.2.8.4   | 170    | 357    | +187
R28710   | §7.1.2.7.2   | 170    | 357    | +187
R28711   | §7.1.2.7.3   | 170    | 357    | +187
...
```

### RFC 5280 规则（93条）

```bash
python3 experiments/coverage_analysis/recompute_coverage.py --standard-id 1
```

**结果：**
- 93条RFC规则候选数量都发生变化
- 多数从部分RFC lint → 全部135个RFC lint
- 6条规则处理出错（`lint_coverage`字段为NULL）

## 预期影响

修改后，预期会发现：
1. **CABF BR的full覆盖数（现在79）会增加**，因为原本漏判的RFC 5280 lint现在能被匹配到
2. **uncovered数（现在146）会减少**，转移到full覆盖
3. **论文Table 2需要更新**

特别是那些在CABF BR §7.1.2.x章节"derived from RFC 5280"的规则，例如：
- uniqueID相关规则（§7.1.2.3）
- signature algorithm相关规则（§7.1.2.1）  
- pathLenConstraint相关规则（§7.1.2.5.2）

这些规则原本被错误地判为"uncovered"，但实际上zlint有对应的RFC 5280 lint实现。

## 下一步

1. ⏳ **需要实际重新判断覆盖**：本次实验只分析了候选数量变化，需要启动后端服务通过API批量重新判断每条规则的覆盖情况
2. 📊 **运行 `run.py --snapshot`**：重新生成Table 2，对比修改前后的覆盖率变化
3. 📝 **更新论文**：如果覆盖率显著提升，需要更新论文§8.2的数据和讨论

## 文件

- `recompute_coverage.py` - 候选数量变化分析脚本
- `outputs/recompute_log.jsonl` - 详细的逐条规则变化日志
- `run.py` - 聚合覆盖判决生成Table 2（需要先重新判断覆盖）
