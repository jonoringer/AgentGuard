from __future__ import annotations

import json
from pathlib import Path

from .models import PolicyConfig


def load_policy(path: str | Path) -> PolicyConfig:
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")
    return PolicyConfig.model_validate(json.loads(policy_path.read_text(encoding="utf-8")))
