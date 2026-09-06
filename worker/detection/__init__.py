# worker/detection — Sysmon Detection Engine
# Exports the main engine entry point for use in the worker consume loop.
from .engine import DetectionEngine

__all__ = ["DetectionEngine"]
