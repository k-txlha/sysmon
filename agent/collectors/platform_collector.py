import platform

def collect_platform_metrics():
    return {
        "operating_system": platform.platform(),
        "operating_system_name": platform.system(),
        "operating_system_version": platform.version(),
        "machine_archihtecture": platform.machine(),
        "operating_system_release": platform.release()
    }