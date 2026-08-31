"""Persistence: saved attack states and capture files (JSON, stdlib only).

State files let an offline analysis be resumed or shared:

    wps-attack save  capture.bin.json   (from a pixie run)
    wps-attack pixie capture.bin.json   (solve from file)

Capture JSON schema = ``Capture.to_dict()`` (see wps.py).
"""

from __future__ import annotations

import json
import os
from typing import Optional

from .wps import Capture

__all__ = ["save_capture", "load_capture", "save_result_json",
           "load_result_json"]


def save_capture(path: str, capture: Capture) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(capture.to_dict(), fh, indent=2)
    return path


def load_capture(path: str) -> Capture:
    with open(path, "r", encoding="utf-8") as fh:
        return Capture.from_dict(json.load(fh))


def save_result_json(path: str, payload: dict) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def load_result_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
