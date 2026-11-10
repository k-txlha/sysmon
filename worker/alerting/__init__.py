# worker/alerting — Sysmon Alert Dispatcher
# Exports the dispatcher that routes FiredAlert objects to configured channels.
from worker.alerting.dispatcher import AlertDispatcher

__all__ = ["AlertDispatcher"]
