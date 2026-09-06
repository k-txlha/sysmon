"""
worker/detection/loader.py

Scans the `rules/` directory, parses every .yaml file into a validated
DetectionRule object, and returns only the enabled ones.

Rules are hot-reloaded on every call to load_rules() so the worker can
pick up new rules without a restart (the engine calls this once on startup;
a future enhancement could add inotify/polling for live reload).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

import yaml
from pydantic import ValidationError

from .models import DetectionRule
from utils.logger import setup_logger

logger = setup_logger("rule_loader")

# Default rules directory: worker/detection/rules/
RULES_DIR = Path(__file__).resolve().parent / "rules"


def load_rules(rules_dir: Path = RULES_DIR) -> List[DetectionRule]:
    """
    Load and validate all .yaml rule files from `rules_dir`.

    Returns only rules where `enabled: true`. Logs a warning and skips
    any file that fails validation so one bad rule never breaks the engine.
    """
    rules: List[DetectionRule] = []

    if not rules_dir.exists():
        logger.warning(f"Rules directory not found: {rules_dir}. No rules loaded.")
        return rules

    yaml_files = sorted(rules_dir.glob("*.yaml"))
    if not yaml_files:
        logger.warning(f"No .yaml rule files found in {rules_dir}.")
        return rules

    for rule_file in yaml_files:
        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)

            if not isinstance(raw, dict):
                logger.warning(f"Skipping {rule_file.name}: expected a YAML mapping, got {type(raw).__name__}.")
                continue

            rule = DetectionRule(**raw)

            if not rule.enabled:
                logger.debug(f"Rule '{rule.name}' is disabled — skipping.")
                continue

            rules.append(rule)
            logger.info(f"Loaded rule: [{rule.severity.value}] {rule.name}")

        except (yaml.YAMLError, ValidationError, TypeError) as exc:
            logger.error(f"Failed to load rule from '{rule_file.name}': {exc}")
            continue

    logger.info(f"Detection engine armed with {len(rules)} active rule(s).")
    return rules
