#!/bin/bash
# 同时启动 FastAPI 后端和 Celery Worker

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 项目目录
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# 激活虚拟环境（如果存在）
if [ -d "env" ]; then
    source env/bin/activate
    echo -e "${GREEN}[INFO]${NC} 已激活虚拟环境"
fi

# 获取处理器数量（逻辑CPU数，已包含超线程）
PROCESSOR_COUNT=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
WORKER_COUNT=$PROCESSOR_COUNT

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   PKI Standards Management System${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}处理器数量: ${PROCESSOR_COUNT}${NC}"
echo -e "${YELLOW}Celery Worker数: ${WORKER_COUNT}${NC}"
echo ""

# 清理函数 - 当脚本退出时停止所有后台进程
cleanup() {
    echo ""
    echo -e "${YELLOW}[INFO]${NC} 正在停止所有服务..."

    # 停止所有 Celery worker 进程（包括子进程）
    pkill -f "celery.*app.celery_app.*worker" 2>/dev/null
    sleep 1
    pkill -9 -f "celery.*app.celery_app.*worker" 2>/dev/null
    echo -e "${GREEN}[INFO]${NC} Celery Worker 已停止"

    # 停止 FastAPI
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
        echo -e "${GREEN}[INFO]${NC} FastAPI 后端已停止"
    fi

    # 清理 sed 管道进程
    pkill -f "sed.*Celery\|sed.*FastAPI" 2>/dev/null

    # 清空 Redis 中的 Celery 队列
    echo -e "${YELLOW}[INFO]${NC} 清空 Celery 队列..."
    redis-cli FLUSHALL > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[INFO]${NC} Celery 队列已清空"
    fi

    # 清理数据库中卡住的任务状态
    echo -e "${YELLOW}[INFO]${NC} 清理卡住的任务状态..."
    if [ -d "env" ]; then
        python -c "
from app.core.database import SessionLocal
from app.models.models import CTScanTask

try:
    db = SessionLocal()
    stuck_tasks = db.query(CTScanTask).filter(
        CTScanTask.status.in_(['running', 'processing'])
    ).all()

    if stuck_tasks:
        for task in stuck_tasks:
            task.status = 'cancelled'
        db.commit()
        print(f'清理了 {len(stuck_tasks)} 个卡住的任务')

    db.close()
except Exception:
    pass
" 2>/dev/null
        echo -e "${GREEN}[INFO]${NC} 任务状态已清理"
    fi

    exit 0
}

# 捕获退出信号
trap cleanup SIGINT SIGTERM

# 启动 Celery Worker（监听所有队列）
echo -e "${GREEN}[INFO]${NC} 启动 Celery Worker..."
watchmedo auto-restart \
    --directory=./app --pattern='*.py' --recursive -- \
    celery -A app.celery_app worker \
    --loglevel=info \
    --concurrency=$WORKER_COUNT \
    --queues=celery,certificate_validation,ct_scan,tranco_crawl,ir_extraction \
    2>&1 | sed 's/^/[Celery] /' &
CELERY_PID=$!

# 等待Celery启动
sleep 2

# 检查Celery是否启动成功
if ! kill -0 $CELERY_PID 2>/dev/null; then
    echo -e "${RED}[ERROR]${NC} Celery Worker 启动失败！请检查Redis是否运行。"
    exit 1
fi
echo -e "${GREEN}[INFO]${NC} Celery Worker 已启动 (PID: $CELERY_PID)"

# 启动 FastAPI 后端
echo -e "${GREEN}[INFO]${NC} 启动 FastAPI 后端..."
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir app 2>&1 | sed 's/^/[FastAPI] /' &
BACKEND_PID=$!

# 等待后端启动
sleep 2

# 检查后端是否启动成功
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo -e "${RED}[ERROR]${NC} FastAPI 后端启动失败！"
    cleanup
    exit 1
fi
echo -e "${GREEN}[INFO]${NC} FastAPI 后端已启动 (PID: $BACKEND_PID)"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   所有服务已启动${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "API地址: http://localhost:8000"
echo -e "API文档: http://localhost:8000/docs"
echo ""
echo -e "${YELLOW}按 Ctrl+C 停止所有服务${NC}"
echo ""

# 等待任意子进程退出
wait
