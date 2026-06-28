"""
规则提取进度追踪器
用于实时推送提取进度到前端
"""
import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import json


class ExtractionProgressTracker:
    """
    规则提取进度追踪器

    负责跟踪提取过程的每个阶段，并通过回调函数实时推送进度
    """

    def __init__(self, progress_callback: Optional[Callable] = None):
        """
        初始化进度追踪器

        Args:
            progress_callback: 进度更新回调函数，接收进度消息字典
        """
        self.progress_callback = progress_callback
        self.start_time = None
        self.current_phase = None

        # 统计数据
        self.stats = {
            'total_rules': 0,
            'processed_rules': 0,
            'simple_rules': 0,
            'medium_rules': 0,
            'complex_rules': 0,
            'regex_only': 0,
            'rag_enhanced': 0,
            'llm_full': 0,
            'errors': 0
        }

        # 当前正在处理的规则
        self.current_rule = None

    async def send_progress(self, message: Dict[str, Any]):
        """
        发送进度消息

        Args:
            message: 进度消息字典
        """
        if self.progress_callback:
            # 添加时间戳
            message['timestamp'] = datetime.now().isoformat()
            message['elapsed_time'] = self._get_elapsed_time()
            message['stats'] = self.stats.copy()

            try:
                if asyncio.iscoroutinefunction(self.progress_callback):
                    await self.progress_callback(message)
                else:
                    self.progress_callback(message)
            except Exception as e:
                print(f"Error sending progress: {e}")

    def _get_elapsed_time(self) -> float:
        """获取已用时间（秒）"""
        if self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0

    async def start_extraction(self, standard_id: int, standard_title: str, total_rules: int):
        """开始提取"""
        self.start_time = datetime.now()
        self.stats['total_rules'] = total_rules
        self.current_phase = 'initialization'

        await self.send_progress({
            'type': 'start',
            'phase': 'initialization',
            'standard_id': standard_id,
            'standard_title': standard_title,
            'total_rules': total_rules,
            'message': f'开始提取规则：{standard_title}',
            'progress_percent': 0
        })

    async def start_rule_processing(self, rule_index: int, rule_text: str, section: str):
        """开始处理单个规则"""
        self.current_rule = {
            'index': rule_index,
            'text': rule_text[:100] + '...' if len(rule_text) > 100 else rule_text,
            'section': section
        }

        progress_percent = int((rule_index / self.stats['total_rules']) * 100) if self.stats['total_rules'] > 0 else 0

        await self.send_progress({
            'type': 'rule_start',
            'phase': 'rule_processing',
            'rule_index': rule_index,
            'rule_section': section,
            'rule_text_preview': self.current_rule['text'],
            'message': f'处理规则 {rule_index}/{self.stats["total_rules"]} (章节: {section})',
            'progress_percent': progress_percent
        })

    async def regex_extraction(self, rule_index: int, result: Dict[str, Any]):
        """正则表达式提取阶段"""
        self.current_phase = 'regex_extraction'

        await self.send_progress({
            'type': 'phase',
            'phase': 'regex_extraction',
            'rule_index': rule_index,
            'message': f'[REGEX] 正则匹配提取字段',
            'result': {
                'affected_field': result.get('affected_field'),
                'operation': result.get('operation'),
            }
        })

    async def complexity_assessment(self, rule_index: int, assessment: Dict[str, Any]):
        """复杂度评估阶段"""
        self.current_phase = 'complexity_assessment'
        complexity = assessment.get('complexity', 'unknown')

        # 更新统计
        self.stats[f'{complexity}_rules'] += 1

        await self.send_progress({
            'type': 'phase',
            'phase': 'complexity_assessment',
            'rule_index': rule_index,
            'message': f'[CHART] 复杂度评估: {complexity.upper()}',
            'result': {
                'complexity': complexity,
                'reasons': assessment.get('reasons', []),
            }
        })

    async def rag_extraction(self, rule_index: int, similar_rules_count: int):
        """RAG增强提取阶段"""
        self.current_phase = 'rag_extraction'
        self.stats['rag_enhanced'] += 1

        await self.send_progress({
            'type': 'phase',
            'phase': 'rag_extraction',
            'rule_index': rule_index,
            'message': f'[RAG] RAG检索增强 (找到 {similar_rules_count} 个相似规则)',
            'result': {
                'similar_rules_count': similar_rules_count
            }
        })

    async def llm_extraction(self, rule_index: int, model_name: str):
        """LLM完整提取阶段"""
        self.current_phase = 'llm_extraction'
        self.stats['llm_full'] += 1

        await self.send_progress({
            'type': 'phase',
            'phase': 'llm_extraction',
            'rule_index': rule_index,
            'message': f'[LLM] 大模型提取 (模型: {model_name})',
            'result': {
                'model': model_name
            }
        })

    async def rule_completed(self, rule_index: int, final_result: Dict[str, Any]):
        """规则处理完成"""
        self.stats['processed_rules'] += 1

        # 确定使用的方法
        extraction_method = final_result.get('extraction_method', 'regex')
        if 'regex' in extraction_method:
            self.stats['regex_only'] += 1

        progress_percent = int((self.stats['processed_rules'] / self.stats['total_rules']) * 100) if self.stats['total_rules'] > 0 else 0

        await self.send_progress({
            'type': 'rule_complete',
            'phase': 'rule_completed',
            'rule_index': rule_index,
            'message': f'[OK] 规则 {rule_index} 处理完成',
            'progress_percent': progress_percent,
            'result': {
                'affected_field': final_result.get('affected_field'),
                'operation': final_result.get('operation'),
                'extraction_method': extraction_method,
            }
        })

    async def rule_error(self, rule_index: int, error: str):
        """规则处理出错"""
        self.stats['errors'] += 1
        self.stats['processed_rules'] += 1

        await self.send_progress({
            'type': 'error',
            'phase': 'error',
            'rule_index': rule_index,
            'message': f'[X] 规则 {rule_index} 处理失败: {error}',
            'error': error
        })

    async def saving_to_database(self, rules_count: int):
        """保存到数据库"""
        self.current_phase = 'saving'

        await self.send_progress({
            'type': 'phase',
            'phase': 'saving',
            'message': f'[SAVE] 保存 {rules_count} 条规则到数据库...',
            'progress_percent': 95
        })

    async def generating_embeddings(self, rules_count: int, batch_number: int, total_batches: int):
        """生成embeddings"""
        self.current_phase = 'generating_embeddings'

        progress_percent = 90 + int((batch_number / total_batches) * 5)

        await self.send_progress({
            'type': 'phase',
            'phase': 'generating_embeddings',
            'message': f'[EMB] 生成embeddings (批次 {batch_number}/{total_batches})',
            'progress_percent': progress_percent,
            'result': {
                'batch': batch_number,
                'total_batches': total_batches,
                'rules_count': rules_count
            }
        })

    async def complete(self, total_duration: float):
        """提取完成"""
        self.current_phase = 'completed'

        await self.send_progress({
            'type': 'complete',
            'phase': 'completed',
            'message': f'[DONE] 提取完成！共处理 {self.stats["processed_rules"]} 条规则',
            'progress_percent': 100,
            'summary': {
                'total_rules': self.stats['total_rules'],
                'processed_rules': self.stats['processed_rules'],
                'simple_rules': self.stats['simple_rules'],
                'medium_rules': self.stats['medium_rules'],
                'complex_rules': self.stats['complex_rules'],
                'regex_only': self.stats['regex_only'],
                'rag_enhanced': self.stats['rag_enhanced'],
                'llm_full': self.stats['llm_full'],
                'errors': self.stats['errors'],
                'duration_seconds': total_duration
            }
        })
