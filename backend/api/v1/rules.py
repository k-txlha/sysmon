"""
backend/api/v1/rules.py

REST API router for Detection Rules:
- List all detection rules with metadata, severity, condition type, and active status
- Get raw YAML and parsed specification for a rule
- Enable/disable rules dynamically at runtime
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from config.settings import settings
from utils.logger import setup_logger

router = APIRouter(prefix="/api/v1/rules", tags=["Rules"])
logger = setup_logger("rules_api")

# In-memory runtime override store for toggled rules
_RULE_STATUS_OVERRIDES: Dict[str, bool] = {}


class ToggleRuleRequest(BaseModel):
    enabled: Optional[bool] = Field(
        default=None,
        description="Explicitly set True/False. If None, toggles current state.",
    )


def _load_all_rules_from_disk() -> List[Dict[str, Any]]:
    rules_dir: Path = settings.RULES_DIR
    if not rules_dir.exists():
        logger.warning(f"Rules directory not found: {rules_dir}")
        return []

    rules = []
    for fpath in sorted(rules_dir.glob("*.yaml")):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
                data = yaml.safe_load(content)

            if not isinstance(data, dict):
                continue

            rule_name = data.get("name", fpath.stem)
            default_enabled = data.get("enabled", True)
            effective_enabled = _RULE_STATUS_OVERRIDES.get(rule_name, default_enabled)

            condition = data.get("condition", {})
            condition_type = condition.get("type", "unknown")

            rules.append(
                {
                    "name": rule_name,
                    "filename": fpath.name,
                    "description": data.get("description", ""),
                    "severity": data.get("severity", "MEDIUM"),
                    "enabled": effective_enabled,
                    "default_enabled": default_enabled,
                    "tags": data.get("tags", []),
                    "condition_type": condition_type,
                    "condition": condition,
                    "raw_yaml": content,
                }
            )
        except Exception as e:
            logger.error(f"Failed parsing rule file {fpath.name}: {e}")

    return rules


@router.get("", status_code=status.HTTP_200_OK)
async def list_rules():
    """List all available detection rules and their current operational status."""
    rules = _load_all_rules_from_disk()
    return {"items": rules, "total": len(rules)}


@router.get("/{name}", status_code=status.HTTP_200_OK)
async def get_rule_detail(name: str):
    """Retrieve full configuration and raw YAML for a specific detection rule."""
    rules = _load_all_rules_from_disk()
    for rule in rules:
        if rule["name"].lower() == name.lower():
            return rule

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Detection rule '{name}' not found.",
    )


@router.post("/{name}/toggle", status_code=status.HTTP_200_OK)
@router.put("/{name}/toggle", status_code=status.HTTP_200_OK)
async def toggle_rule(name: str, payload: ToggleRuleRequest = ToggleRuleRequest()):
    """Toggle a rule's enabled/disabled operational status."""
    rules = _load_all_rules_from_disk()
    target_rule = None
    for rule in rules:
        if rule["name"].lower() == name.lower():
            target_rule = rule
            break

    if not target_rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{name}' not found.",
        )

    current_state = target_rule["enabled"]
    new_state = payload.enabled if payload.enabled is not None else (not current_state)
    _RULE_STATUS_OVERRIDES[target_rule["name"]] = new_state

    logger.info(f"Rule '{target_rule['name']}' state changed: {current_state} -> {new_state}")

    return {
        "status": "success",
        "name": target_rule["name"],
        "enabled": new_state,
        "message": f"Rule '{target_rule['name']}' is now {'enabled' if new_state else 'disabled'}.",
    }
