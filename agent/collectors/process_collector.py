import psutil

def collect_processes(limit=10):
    processes = []

    for proc in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_percent"]
    ):
        try:
            info = proc.info

            info["cpu_percent"] = f"{info['cpu_percent'] or 0:.1f}%"
            info["memory_percent"] = f"{info['memory_percent'] or 0:.2f}%"

            processes.append(info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    processes = sorted(
        processes,
        key=lambda p: float(p["cpu_percent"].rstrip("%")),
        reverse=True
    )

    # return processes[:limit]
    return processes
