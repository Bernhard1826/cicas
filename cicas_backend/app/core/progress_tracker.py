"""
全局进度跟踪器
用于跟踪长时间运行的异步任务进度
"""
from typing import Dict, Optional
from datetime import datetime


class ProgressTracker:
    """全局进度跟踪器"""

    def __init__(self):
        self._tasks: Dict[str, Dict] = {}

    def start_task(self, task_id: str, total: int, description: str = ""):
        """开始跟踪任务"""
        self._tasks[task_id] = {
            'total': total,
            'current': 0,
            'description': description,
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'current_file': '',
            'found_in_db': 0,
            'missing_in_db': 0,
            'cancelled': False,  # 取消标志
        }

    def update_progress(self, task_id: str, current: int, current_file: str = '',
                        found_in_db: int = 0, missing_in_db: int = 0):
        """更新任务进度"""
        if task_id in self._tasks:
            self._tasks[task_id]['current'] = current
            self._tasks[task_id]['current_file'] = current_file
            self._tasks[task_id]['found_in_db'] = found_in_db
            self._tasks[task_id]['missing_in_db'] = missing_in_db

    def complete_task(self, task_id: str, result: Optional[Dict] = None):
        """标记任务完成"""
        if task_id in self._tasks:
            self._tasks[task_id]['status'] = 'completed'
            self._tasks[task_id]['end_time'] = datetime.now().isoformat()
            if result:
                self._tasks[task_id]['result'] = result

    def fail_task(self, task_id: str, error: str):
        """标记任务失败"""
        if task_id in self._tasks:
            self._tasks[task_id]['status'] = 'failed'
            self._tasks[task_id]['error'] = error
            self._tasks[task_id]['end_time'] = datetime.now().isoformat()

    def get_progress(self, task_id: str) -> Optional[Dict]:
        """获取任务进度"""
        return self._tasks.get(task_id)

    def cancel_task(self, task_id: str):
        """请求取消任务"""
        if task_id in self._tasks:
            self._tasks[task_id]['cancelled'] = True
            app_logger = None  # 避免循环导入
            return True
        return False

    def is_task_cancelled(self, task_id: str) -> bool:
        """检查任务是否被取消"""
        if task_id in self._tasks:
            return self._tasks[task_id].get('cancelled', False)
        return False

    def clear_task(self, task_id: str):
        """清除任务记录"""
        if task_id in self._tasks:
            del self._tasks[task_id]


# 全局单例
progress_tracker = ProgressTracker()
