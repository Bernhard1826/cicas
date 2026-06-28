"""
CPU 拓扑和并发配置模块
根据 CPU 核心数和任务类型动态计算最优的 worker 和线程数
"""

import os
import multiprocessing
from collections import defaultdict


def get_cpu_info():
    """
    获取 CPU 信息（精确解析处理器和核心拓扑）

    Returns:
        dict: CPU 信息
            - logical_cpus: 逻辑CPU数量（含超线程）
            - physical_cores: 物理核心总数
            - sockets: 物理处理器数量
            - cores_per_socket: 每个处理器的核心数
            - threads_per_core: 每个核心的线程数（超线程）
    """
    try:
        # 解析 /proc/cpuinfo
        physical_ids = set()
        core_ids_per_socket = defaultdict(set)
        logical_cpu_count = 0

        with open('/proc/cpuinfo', 'r') as f:
            current_physical_id = None
            current_core_id = None

            for line in f:
                line = line.strip()

                if line.startswith('processor'):
                    logical_cpu_count += 1
                elif line.startswith('physical id'):
                    current_physical_id = int(line.split(':')[1].strip())
                    physical_ids.add(current_physical_id)
                elif line.startswith('core id'):
                    current_core_id = int(line.split(':')[1].strip())
                    if current_physical_id is not None:
                        core_ids_per_socket[current_physical_id].add(current_core_id)

        # 计算拓扑信息
        sockets = len(physical_ids)

        if sockets > 0 and core_ids_per_socket:
            # 计算每个socket的核心数（取第一个socket的核心数）
            cores_per_socket = len(core_ids_per_socket[min(physical_ids)])
            physical_cores = sockets * cores_per_socket
            threads_per_core = logical_cpu_count // physical_cores if physical_cores > 0 else 1
        else:
            # 如果无法解析，使用默认值
            logical_cpu_count = os.cpu_count() or 4
            physical_cores = logical_cpu_count
            sockets = 1
            cores_per_socket = physical_cores
            threads_per_core = 1

        return {
            'logical_cpus': logical_cpu_count,
            'physical_cores': physical_cores,
            'sockets': sockets,
            'cores_per_socket': cores_per_socket,
            'threads_per_core': threads_per_core,
        }

    except Exception as e:
        # 降级到简单模式
        cpu_count = os.cpu_count() or 4
        return {
            'logical_cpus': cpu_count,
            'physical_cores': cpu_count,
            'sockets': 1,
            'cores_per_socket': cpu_count,
            'threads_per_core': 1,
        }


def calculate_workers_and_threads(task_type='io', io_multiplier=4):
    """
    根据任务类型和 CPU 拓扑计算最优的 worker 数和线程数

    架构设计：
    - workers 基于物理处理器（socket）数量，每个 socket 运行一个 worker
    - threads 基于每个 socket 的核心数，充分利用 NUMA 架构

    Args:
        task_type: 任务类型
            - 'io': I/O 密集型任务（如网络请求、文件读写、subprocess调用）
            - 'cpu': CPU 密集型任务（如加密、解密、计算）
            - 'mixed': 混合型任务
        io_multiplier: I/O 密集型任务的线程倍数（默认4倍）
            - 对于 subprocess 等完全释放 GIL 的操作，可以用 4-8 倍
            - 对于网络 I/O，建议 2-4 倍
            - 需要根据实际 I/O 等待时间调优

    Returns:
        tuple: (workers, threads)
            - workers: 推荐的 worker/进程数（基于 socket 数量）
            - threads: 每个 worker 内的线程数（基于每个 socket 的核心数）
    """
    cpu_info = get_cpu_info()
    sockets = cpu_info['sockets']
    cores_per_socket = cpu_info['cores_per_socket']

    if task_type == 'io':
        # I/O 密集型：线程数可以是每个 socket 核心数的 2-8 倍
        # zlint subprocess 调用会释放 GIL，所以更多线程是有益的
        # 倍数取决于 I/O 等待时间占比：
        #   等待时间 50%: 2倍
        #   等待时间 75%: 4倍
        #   等待时间 90%: 8倍或更多
        workers = sockets  # 每个物理处理器一个 worker
        threads = cores_per_socket * io_multiplier  # 每个 socket 的核心数 × 倍数

    elif task_type == 'cpu':
        # CPU 密集型：线程数应该等于每个 socket 的核心数
        # 避免线程竞争和上下文切换开销
        workers = sockets  # 每个物理处理器一个 worker
        threads = cores_per_socket  # 每个 socket 的核心数

    elif task_type == 'mixed':
        # 混合型：折中方案
        workers = sockets
        threads = cores_per_socket * 2

    else:
        # 默认使用 I/O 密集型配置
        workers = sockets
        threads = cores_per_socket * 2

    return workers, threads


def get_optimal_batch_size(total_items, worker_count):
    """
    根据总数据量和 worker 数量计算最优批次大小

    Args:
        total_items: 总数据量
        worker_count: worker 数量

    Returns:
        int: 批次大小
    """
    # 确保每个 worker 至少处理 10 批数据
    min_batches_per_worker = 10
    ideal_batch_count = worker_count * min_batches_per_worker

    # 计算批次大小
    batch_size = max(100, total_items // ideal_batch_count)

    # 批次大小范围：100 - 10000
    batch_size = min(10000, max(100, batch_size))

    return batch_size


def get_concurrency_config(task_type='io', total_items=None):
    """
    获取完整的并发配置

    Args:
        task_type: 任务类型 ('io', 'cpu', 'mixed')
        total_items: 总数据量（用于计算批次大小）

    Returns:
        dict: 并发配置
    """
    workers, threads = calculate_workers_and_threads(task_type)
    cpu_info = get_cpu_info()

    config = {
        'logical_cpus': cpu_info['logical_cpus'],
        'physical_cores': cpu_info['physical_cores'],
        'sockets': cpu_info['sockets'],
        'cores_per_socket': cpu_info['cores_per_socket'],
        'threads_per_core': cpu_info['threads_per_core'],
        'workers': workers,
        'threads_per_worker': threads,
        'total_threads': workers * threads,
        'task_type': task_type,
    }

    if total_items:
        config['batch_size'] = get_optimal_batch_size(total_items, workers)
        config['total_batches'] = (total_items + config['batch_size'] - 1) // config['batch_size']

    return config


if __name__ == '__main__':
    # 测试
    print("=== CPU 拓扑信息 ===")
    cpu_info = get_cpu_info()
    print(f"物理处理器数量 (Sockets): {cpu_info['sockets']}")
    print(f"每个处理器的核心数 (Cores per socket): {cpu_info['cores_per_socket']}")
    print(f"物理核心总数 (Physical cores): {cpu_info['physical_cores']}")
    print(f"每个核心的线程数 (Threads per core): {cpu_info['threads_per_core']}")
    print(f"逻辑CPU总数 (Logical CPUs): {cpu_info['logical_cpus']}")
    print()

    print("=== I/O 密集型任务配置 ===")
    workers, threads = calculate_workers_and_threads('io')
    print(f"Workers: {workers}, Threads per worker: {threads}")
    config = get_concurrency_config('io', total_items=50000)
    print(f"完整配置: {config}")
    print()

    print("=== CPU 密集型任务配置 ===")
    workers, threads = calculate_workers_and_threads('cpu')
    print(f"Workers: {workers}, Threads per worker: {threads}")
    config = get_concurrency_config('cpu', total_items=50000)
    print(f"完整配置: {config}")

