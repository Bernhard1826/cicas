"""
条件集合数据结构
用于结构化表示规则中的条件（IF-THEN, WHEN, UNLESS等）
"""
from typing import List, Literal, Union, Optional, Any
from pydantic import BaseModel, Field


class FieldCondition(BaseModel):
    """字段条件 - 针对单个字段的约束"""
    type: Literal["field"] = "field"
    field: str = Field(..., description="证书字段路径，如 c.IsCA, c.Subject.CommonName")
    operator: Literal["==", "!=", ">", "<", ">=", "<=", "EXISTS", "NOT_EXISTS"]
    value: Union[str, int, bool, None] = None

    class Config:
        json_schema_extra = {
            "example": {
                "type": "field",
                "field": "c.IsCA",
                "operator": "==",
                "value": True
            }
        }


class SetCondition(BaseModel):
    """集合条件 - 检查字段值是否在集合中"""
    type: Literal["set"] = "set"
    field: str = Field(..., description="字段路径")
    operator: Literal["IN", "NOT_IN", "CONTAINS", "NOT_CONTAINS"]
    values: List[Union[str, int]] = Field(..., description="集合值列表")

    class Config:
        json_schema_extra = {
            "example": {
                "type": "set",
                "field": "c.ExtKeyUsage",
                "operator": "CONTAINS",
                "values": ["serverAuth", "clientAuth"]
            }
        }


class RangeCondition(BaseModel):
    """范围条件 - 数值范围约束"""
    type: Literal["range"] = "range"
    field: str = Field(..., description="字段路径")
    operator: Literal[">", "<", ">=", "<="]
    value: Union[int, float] = Field(..., description="边界值")
    unit: Optional[str] = Field(None, description="单位，如 days, bits")

    class Config:
        json_schema_extra = {
            "example": {
                "type": "range",
                "field": "validity_days",
                "operator": "<=",
                "value": 825,
                "unit": "days"
            }
        }


class LogicalCondition(BaseModel):
    """逻辑组合条件 - AND/OR组合"""
    type: Literal["and", "or"] = "and"
    operands: List[Union[FieldCondition, SetCondition, RangeCondition, 'LogicalCondition']] = Field(
        ...,
        description="子条件列表"
    )
    max_depth: int = Field(2, description="最大嵌套深度，防止过于复杂")

    class Config:
        json_schema_extra = {
            "example": {
                "type": "and",
                "operands": [
                    {"type": "field", "field": "c.IsCA", "operator": "==", "value": True},
                    {"type": "range", "field": "pathLen", "operator": ">=", "value": 2}
                ]
            }
        }


# 类型别名：所有条件类型的联合
Condition = Union[FieldCondition, SetCondition, RangeCondition, LogicalCondition]


class ConditionSet(BaseModel):
    """
    条件集合 - 规则的前提条件

    Examples:
        >>> # 简单条件：IF cA=TRUE
        >>> cond_set = ConditionSet(
        ...     conditions=[FieldCondition(field="c.IsCA", operator="==", value=True)],
        ...     logic="AND"
        ... )

        >>> # 复杂条件：IF (cA=TRUE AND pathLen>=2)
        >>> cond_set = ConditionSet(
        ...     conditions=[
        ...         FieldCondition(field="c.IsCA", operator="==", value=True),
        ...         RangeCondition(field="pathLen", operator=">=", value=2)
        ...     ],
        ...     logic="AND"
        ... )
    """
    conditions: List[Condition] = Field(default_factory=list, description="条件列表")
    logic: Literal["AND", "OR"] = Field("AND", description="条件间的逻辑关系")

    def is_empty(self) -> bool:
        """检查条件集是否为空"""
        return len(self.conditions) == 0

    def to_ir_json(self) -> dict:
        """
        转换为IR JSON格式（兼容现有数据库）

        Returns:
            dict: IR格式的JSON
        """
        return {
            "conditions": [c.dict() for c in self.conditions],
            "logic": self.logic
        }

    @classmethod
    def from_ir_json(cls, ir_json: dict) -> 'ConditionSet':
        """
        从IR JSON加载ConditionSet

        Args:
            ir_json: IR格式的JSON

        Returns:
            ConditionSet实例
        """
        conditions = []
        for cond_dict in ir_json.get("conditions", []):
            cond_type = cond_dict.get("type", "field")

            if cond_type == "field":
                conditions.append(FieldCondition(**cond_dict))
            elif cond_type == "set":
                conditions.append(SetCondition(**cond_dict))
            elif cond_type == "range":
                conditions.append(RangeCondition(**cond_dict))
            elif cond_type in ["and", "or"]:
                conditions.append(LogicalCondition(**cond_dict))

        return cls(
            conditions=conditions,
            logic=ir_json.get("logic", "AND")
        )

    def get_fields(self) -> List[str]:
        """
        获取条件集涉及的所有字段

        Returns:
            字段列表
        """
        fields = []
        for cond in self.conditions:
            if hasattr(cond, 'field'):
                fields.append(cond.field)
            elif isinstance(cond, LogicalCondition):
                # 递归处理嵌套条件
                for operand in cond.operands:
                    if hasattr(operand, 'field'):
                        fields.append(operand.field)
        return list(set(fields))  # 去重

    def __str__(self) -> str:
        """人类可读的字符串表示"""
        if self.is_empty():
            return "ConditionSet(empty)"

        cond_strs = []
        for cond in self.conditions:
            if isinstance(cond, FieldCondition):
                cond_strs.append(f"{cond.field} {cond.operator} {cond.value}")
            elif isinstance(cond, RangeCondition):
                unit = f" {cond.unit}" if cond.unit else ""
                cond_strs.append(f"{cond.field} {cond.operator} {cond.value}{unit}")
            elif isinstance(cond, SetCondition):
                cond_strs.append(f"{cond.field} {cond.operator} {cond.values}")

        return f"ConditionSet({f' {self.logic} '.join(cond_strs)})"


# 更新LogicalCondition以支持递归
LogicalCondition.model_rebuild()
