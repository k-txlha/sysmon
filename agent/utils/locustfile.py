import random
import string
from datetime import datetime
from locust import HttpUser, task, between

###############################################################
# Configuration
###############################################################

NUM_AGENTS = 100

HOSTNAMES = [
    f"WIN-{''.join(random.choices(string.ascii_uppercase + string.digits, k=7))}"
    for _ in range(NUM_AGENTS)
]

USERS = [
    "Administrator",
    "SYSTEM",
    "Talha",
    "John",
    "Guest",
    "svc_sql",
    "svc_backup",
    "finance",
    "hr",
    "itadmin",
]

DOMAINS = [
    "CORP",
    "WORKGROUP",
    "LAB",
    "DEV",
]

PROCESS_NAMES = [
    "chrome.exe",
    "explorer.exe",
    "powershell.exe",
    "cmd.exe",
    "svchost.exe",
    "winlogon.exe",
    "notepad.exe",
    "Code.exe",
    "Teams.exe",
    "MsMpEng.exe",
]

###############################################################
# Helpers
###############################################################


def random_mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


###############################################################
# SYSTEM METRICS
###############################################################


def collect_system_metrics():
    total = random.choice([8, 16, 32, 64])
    used_percent = round(random.uniform(10, 95), 2)
    available = total * (100 - used_percent) / 100
    free = available * random.uniform(0.6, 1)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "cpu_usage": round(random.uniform(1, 100), 2),
        "memory_usage": used_percent,
        "memory_info": {
            "total_memory": f"{total:.2f} GB",
            "available_memory": f"{available:.2f} GB",
            "free_memory": f"{free:.2f} GB",
        },
    }


###############################################################
# PROCESS LIST
###############################################################


def collect_processes():
    process_list = []
    count = random.randint(20, 70)

    for _ in range(count):
        cpu = round(random.uniform(0, 40), 1)
        mem = round(random.uniform(0, 15), 2)

        process_list.append(
            {
                "pid": random.randint(100, 25000),
                "name": random.choice(PROCESS_NAMES),
                "cpu_percent": f"{cpu:.1f}%",
                "memory_percent": f"{mem:.2f}%",
            }
        )

    process_list.sort(
        key=lambda x: float(x["cpu_percent"][:-1]),
        reverse=True,
    )
    return process_list


###############################################################
# NETWORK
###############################################################


def collect_network_metrics(agent):
    return {
        "hostname": agent,
        "ip-address": random_ip(),
        "mac-address": random_mac(),
    }


###############################################################
# WINDOWS SECURITY EVENTS
###############################################################

LOGON_TYPES = {
    "2": "Interactive (Console/Keyboard)",
    "3": "Network (e.g., Shared Folder)",
    "4": "Batch (Scheduled Task)",
    "5": "Service (Background Process)",
    "7": "Unlock (Workstation Unlocked)",
    "10": "RemoteInteractive (RDP)",
}


def collect_platform_metrics():
    records = []
    count = random.randint(5, 20)

    for _ in range(count):
        event_id = random.choices([4624, 4625], weights=[85, 15], k=1)[0]
        code = random.choice(list(LOGON_TYPES.keys()))

        records.append(
            {
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "event_id": event_id,
                "status": "SUCCESS" if event_id == 4624 else "FAILURE",
                "username": random.choice(USERS),
                "domain": random.choice(DOMAINS),
                "logon_type": LOGON_TYPES[code],
                "source_ip": random_ip(),
            }
        )

    return {
        "operating_system": "Windows-10-10.0.19045-SP0",
        "operating_system_name": "Windows",
        "operating_system_version": "10.0.19045",
        "machine_architecture": "AMD64",
        "operating_system_release": "10",
        "login_attempts": records,
    }


###############################################################
# PAYLOAD
###############################################################


def build_payload():
    hostname = random.choice(HOSTNAMES)

    return {
        "agent_id": hostname,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "metrics": {
            "system": collect_system_metrics(),
            "processes": collect_processes(),
            "network": collect_network_metrics(hostname),
            "platform": collect_platform_metrics(),
        },
    }


###############################################################
# LOCUST USER
###############################################################


class SIEMAgent(HttpUser):
    wait_time = between(3, 8)

    @task
    def send_telemetry(self):
        payload = build_payload()
        self.client.post(
            "/api/v1/telemetry",
            json=payload,
            name="Telemetry Upload",
        )
