from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


_ROLE_RANK = {
    Role.VIEWER: 1,
    Role.OPERATOR: 2,
    Role.ADMIN: 3,
}


@dataclass
class AuthContext:
    api_key: str
    role: Role


class AuthManager:
    def __init__(self, api_keys: dict[str, Role]) -> None:
        self._api_keys = api_keys
        self._header = APIKeyHeader(name="x-api-key", auto_error=False)

    @property
    def enabled(self) -> bool:
        return bool(self._api_keys)

    def require_role(self, min_role: Role):
        async def _dependency(api_key: str | None = Security(self._header)) -> AuthContext:
            if not self.enabled:
                return AuthContext(api_key="anonymous", role=Role.ADMIN)

            if not api_key or api_key not in self._api_keys:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing or invalid API key",
                )

            role = self._api_keys[api_key]
            if _ROLE_RANK[role] < _ROLE_RANK[min_role]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient role for this endpoint",
                )

            return AuthContext(api_key=api_key, role=role)

        return _dependency


def load_auth_manager() -> AuthManager:
    raw = os.getenv("AGENTGUARD_API_KEYS", "").strip()
    parsed: dict[str, Role] = {}

    if raw:
        # Format: key1:admin,key2:operator,key3:viewer
        for chunk in raw.split(","):
            item = chunk.strip()
            if not item:
                continue
            if ":" not in item:
                continue
            key, role_text = item.split(":", 1)
            key = key.strip()
            role_text = role_text.strip().lower()
            if not key:
                continue
            if role_text not in {"viewer", "operator", "admin"}:
                continue
            parsed[key] = Role(role_text)

    return AuthManager(api_keys=parsed)
