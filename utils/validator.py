"""
utils/validator.py — Schema validation for all inputs and outputs.
Uses jsonschema for strict validation. Import this in every module
that processes external data to enforce contract boundaries.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

import jsonschema
from jsonschema import validate, ValidationError

from config import INPUT_SCHEMA_PATH, OUTPUT_SCHEMA_PATH

logger = logging.getLogger(__name__)


def _load_schema(path: Path) -> dict:
    """Load a JSON schema file from disk."""
    if not path.exists():
        raise FileNotFoundError(f"Schema file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Load schemas once at module import — not on every call
_INPUT_SCHEMA = _load_schema(INPUT_SCHEMA_PATH)
_OUTPUT_SCHEMA = _load_schema(OUTPUT_SCHEMA_PATH)


def validate_input(alert: dict) -> tuple[bool, str | None]:
    """
    Validate a normalized alert dict against the input JSON schema.

    Returns:
        (True, None) if valid.
        (False, error_message) if invalid.
    """
    try:
        validate(instance=alert, schema=_INPUT_SCHEMA)
        return True, None
    except ValidationError as e:
        msg = f"Input validation failed at '{'.'.join(str(p) for p in e.path)}': {e.message}"
        logger.warning(msg)
        return False, msg


def validate_output(result: dict) -> tuple[bool, str | None]:
    """
    Validate an ML reasoning result dict against the output JSON schema.

    Returns:
        (True, None) if valid.
        (False, error_message) if invalid.
    """
    try:
        validate(instance=result, schema=_OUTPUT_SCHEMA)
        return True, None
    except ValidationError as e:
        msg = f"Output validation failed at '{'.'.join(str(p) for p in e.path)}': {e.message}"
        logger.warning(msg)
        return False, msg


def validate_input_strict(alert: dict) -> None:
    """
    Validate input and raise ValueError on failure.
    Use in inference pipeline where invalid input must halt processing.
    """
    valid, error = validate_input(alert)
    if not valid:
        raise ValueError(f"Invalid alert input: {error}")


def validate_output_strict(result: dict) -> None:
    """
    Validate output and raise ValueError on failure.
    Use after model generation to ensure downstream compatibility.
    """
    valid, error = validate_output(result)
    if not valid:
        raise ValueError(f"Invalid ML output: {error}")


def sanitize_alert(alert: dict) -> dict:
    """
    Lightly sanitize common formatting issues before validation.
    - Strips whitespace from string fields.
    - Converts timestamp to proper ISO format if needed.
    Does NOT alter the schema structure.
    """
    sanitized = dict(alert)
    # Normalize timestamp to UTC Z format
    if "timestamp" in sanitized and sanitized["timestamp"]:
        try:
            ts = sanitized["timestamp"]
            if not ts.endswith("Z") and "+" not in ts:
                sanitized["timestamp"] = ts + "Z"
        except Exception:
            pass  # Let the schema validator report the error
    return sanitized
