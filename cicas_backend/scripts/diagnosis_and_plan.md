"""
诊断报告：提升代码生成率和同义率

## 一、IR 抽取 Gap（主杠杆）

### 高优先级修复（需要重抽）
| predicate + constraint_type | 数量 | 根因 |
|----------------------------|------|------|
| allowed_values + enum | 22 | constraint.value 缺失 |
| in_range + numeric | 6 | min/max 缺失 |
| must_equal + numeric | 2 | 精确值缺失 |
| in_range + length | 2 | 长度范围缺失 |
| must_equal + length | 2 | 长度值缺失 |

### 中优先级修复
| predicate + constraint_type | 数量 | 根因 |
|----------------------------|------|------|
| must_include + cardinality | 19 | count 缺失 |
| must_not_include + cardinality | 4 | count 缺失 |

### 低优先级（presence 类型不需要 value）
| predicate + constraint_type | 数量 | 说明 |
|----------------------------|------|------|
| must_be_present + presence | 30 | 不需要 value |
| must_not_be_present + presence | 58 | 不需要 value |

## 二、原子扩展建议

### 2.1 可扩展的通用原子

1. **IsPositiveInteger** - 正整数检查
   - 用途：serialNumber MUST be positive, non-negative
   - 示例规则：R31123 "CAs MUST force the serialNumber to be a non-negative integer"

2. **FieldAsn1TagInSet** - 通用 ASN.1 标签检查
   - 用途：检查字段的 DER 编码标签
   - 扩展现有 `ValidityDateAsn1TagInSet`

3. **IPv6LengthCheck** - IPv6 地址长度检查
   - 用途：IPv6 octet string 长度验证
   - 已有 IPv4Conditional，可参照扩展

### 2.2 非通用原子（谨慎添加）

1. **PolicyQualifierTypeInSet** - 策略限定符类型检查
2. **AccessMethodTypeInSet** - 访问方法类型检查

## 三、行动计划

### Phase 1: 修复 IR 抽取（高 ROI）
- [ ] 运行 reextract_missing_constraint_values.py
- [ ] 重点处理 32 条高优先级规则
- [ ] 验证 constraint.value 填充

### Phase 2: 扩展原子
- [ ] 实现 IsPositiveInteger
- [ ] 实现 FieldAsn1TagInSet
- [ ] cert-oracle 认证新原子
- [ ] 更新 ATOM_CLASSES 和 GENERIC_ATOMS/NON_GENERIC_ATOMS

### Phase 3: 重新测试
- [ ] 跑 codegen 测试
- [ ] 跑同义率测试
- [ ] 更新论文数据
"""