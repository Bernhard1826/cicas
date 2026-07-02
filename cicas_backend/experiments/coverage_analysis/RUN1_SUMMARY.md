# Run 1 实验总结

## 完成的工作

### 1. 后端代码修改

**文件**: `app/services/certificate/zlint_interface.py`

**修改位置**: Line 232-244, `_coverage_candidates` 函数

**修改内容**:
```python
# 修改前：
if src in ("CABF", "CABF-BR", "CABF_BR", "BRS", "BR"):
    return list(self.zlint_ir_cabf)

# 修改后：
if src in ("CABF", "CABF-BR", "CABF_BR", "BRS", "BR"):
    # CABF规则需要同时匹配CABF和RFC5280的lint（跨标准覆盖）
    return list(self.zlint_ir_cabf) + list(self.zlint_ir_rfc)
```

**原因**: CABF BR很多规则"derived from RFC 5280"，但zlint实现时标记为RFC 5280 source，导致原算法漏判。

### 2. 实验脚本

在 `experiments/coverage_analysis/` 目录下创建：

1. **`recompute_coverage.py`** - 分析候选数量变化
   - 从数据库加载zlint IR
   - 模拟修改后的`_coverage_candidates`逻辑
   - 统计每条规则的候选数量变化

2. **`generate_comparison.py`** - 生成修改前后对比报告
   - 读取baseline覆盖统计
   - 汇总候选变化
   - 输出对比表格

3. **`RUN1_NOTES.md`** - 实验说明文档
   - 背景和问题
   - 修改内容
   - 实验结果
   - 预期影响

### 3. 实验结果

**CABF BR (226条规则)**:
- ✅ **所有226条规则的候选数量都增加了**
- 170 → 357 (+187个RFC lint)
- 证实修改有效

**RFC 5280 (93条规则)**:
- 93条规则候选数量变化
- 平均 9 → 135

**Baseline覆盖情况**:
- CABF BR: 79 covered / 147 uncovered (35.0%)
- RFC 5280: 50 covered / 43 uncovered (53.8%)
- 合计: 129 covered / 190 uncovered (40.4%)

## 未完成的工作

### ⚠️ 关键缺失：实际重新判断覆盖

本次实验只分析了候选数量变化，**尚未实际重新判断每条规则的覆盖情况**。

原因：
1. 后端覆盖判断依赖 `lint_ir_summaries.json` 文件（不存在）
2. 虽然从数据库`zlint_lint_dsl`表加载了zlint IR，但完整的覆盖判断需要：
   - LLM字段级比对（`_judge_coverage`）
   - 一致性守卫（`_consistent_verdict`）
   - 批量处理和结果聚合

### 下一步操作

#### 方案A：通过后端API重新判断（推荐）

1. **启动后端服务**:
   ```bash
   cd cicas_backend
   ./start.sh
   ```

2. **调用批量覆盖判断API**:
   ```python
   # 示例：批量判断CABF规则
   POST /api/coverage/batch
   {
     "standard_id": 19,  # CABF BR
     "limit": 1000
   }
   ```

3. **等待判断完成后，运行聚合脚本**:
   ```bash
   python experiments/coverage_analysis/run.py --snapshot
   ```

4. **对比结果**:
   - 查看 `outputs/coverage_table.md`
   - 对比修改前后的covered/uncovered数量

#### 方案B：生成 lint_ir_summaries.json（备选）

如果后端API不可用，可以：

1. 从数据库导出zlint IR到JSON
2. 扩充必要字段（citation、section等）
3. 放置到 `experiments/results/lint_ir_summaries.json`
4. 运行独立的覆盖判断脚本

## 预期结果

修改后，预期：

1. **CABF BR的full覆盖数会增加**（当前79）
   - 特别是§7.1.2.x "derived from RFC 5280"的规则
   - 例如：uniqueID、signature algorithm、pathLenConstraint相关规则

2. **uncovered数会减少**（当前147）
   - 转移到covered的数量 = 新发现的覆盖

3. **总覆盖率会提升**（当前40.4%）

4. **论文Table 2需要更新**

## 文件清单

### 新增文件
```
experiments/coverage_analysis/
├── recompute_coverage.py          # 候选变化分析脚本
├── generate_comparison.py         # 对比报告生成器
├── RUN1_NOTES.md                 # 实验说明
├── outputs/
│   ├── recompute_log.jsonl       # 逐条规则变化日志
│   └── run1_comparison.md        # 修改前后对比
```

### 修改文件
```
app/services/certificate/zlint_interface.py  # _coverage_candidates函数
experiments/coverage_analysis/README.md       # 添加Run 1说明
```

## Git 提交建议

```bash
git add app/services/certificate/zlint_interface.py
git add experiments/coverage_analysis/

git commit -m "实验Run1: 修复CABF规则跨标准覆盖漏判

- 修改_coverage_candidates让CABF规则同时匹配CABF和RFC lint
- 所有226条CABF规则候选数从170→357(+187个RFC lint)
- 创建实验脚本分析候选变化
- 等待重新判断覆盖以量化实际覆盖率提升

Refs: [[cabf_rules_covered_by_rfc_lints_2026_06_29]]"
```

## 关键发现

✅ **修改是有效的**：候选数量确实增加了，说明CABF规则现在可以匹配到更多RFC lint

⏳ **需要完成重新判断**：才能知道实际有多少CABF规则的覆盖判决从"none"或"partial"变为"full"

📊 **影响是可测量的**：可以对比修改前后的covered/uncovered数量，量化改进效果
