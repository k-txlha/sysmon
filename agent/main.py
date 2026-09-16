import platform
import sys
import time

from collectors.common import SystemCollector
from utils.assembler import TelemetryAssembler
from utils.config import settings
from utils.logger import setup_logger
from utils.transport import get_buffer, ship_to_backend

# 1. Detect Operating System
OS_TYPE = platform.system().lower()  # returns 'linux', 'windows', or 'darwin'

if OS_TYPE == "windows":
    from collectors.windows import OSCollector
elif OS_TYPE == "linux":
    from collectors.linux import OSCollector
elif OS_TYPE == "darwin":
    from collectors.darwin import OSCollector
else:
    raise NotImplementedError(f"Unsupported OS: {OS_TYPE}")

logger = setup_logger("main")


class Agent:
    """
    Core EDR Telemetry Agent:
    - Binds cross-platform and OS-specific telemetry collectors
    - Assembles standardized EDR EventEnvelopes
    - Manages continuous collection, local disk buffering, and transmission loop
    """

    def __init__(self):
        self.common_collector = SystemCollector()  # psutil (CPU, RAM, Processes, Network)
        self.os_collector = OSCollector()          # OS-specific telemetry & logs
        self.assembler = TelemetryAssembler(
            common_collector=self.common_collector,
            os_collector=self.os_collector,
        )
        self.buffer = get_buffer()

    def collect_envelopes(self):
        """Assembles telemetry metrics, security logs, and health diagnostics into standard EventEnvelopes."""
        return self.assembler.assemble(
            queue_depth=self.buffer.get_depth(),
            dropped_events_total=self.buffer.get_dropped_count(),
            buffer_bytes=self.buffer.get_buffer_size_bytes(),
        )

    def run(self):
        """Main execution loop for continuous data collection and durable transmission."""
        logger.info(f"Initializing Sysmon EDR Agent on [{OS_TYPE.upper()}] environment...")
        logger.info(
            f"Agent loop scheduled to run every {settings.COLLECTION_INTERVAL} seconds. "
            f"Buffer: {settings.BUFFER_DB_PATH}"
        )
        print("-" * 60)

        try:
            while True:
                envelopes = self.collect_envelopes()
                if envelopes:
                    ship_to_backend(envelopes)

                # Use configuration value for sleep timer
                time.sleep(settings.COLLECTION_INTERVAL)

        except KeyboardInterrupt:
            logger.info("Agent gracefully stopped by user interaction.")
        finally:
            self.buffer.close()


def main():
    agent = Agent()
    agent.run()


if __name__ == "__main__":
    main()
