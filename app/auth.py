from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

try:
    import jwt
except Exception:  # pragma: no cover - optional until deps installed
    jwt = None


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
    principal_id: str
    role: Role
    tenant_id: str | None
    source: str


@dataclass
class OIDCConfig:
    issuer: str
    audience: str
    jwks_url: str
    role_claim: str = "role"
    tenant_claim: str = "tenant_id"


class AuthManager:
    def __init__(self, api_keys: dict[str, tuple[Role, str | None]], oidc: OIDCConfig | None) -> None:
        self._api_keys = api_keys
        self._oidc = oidc
        self._api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)
        self._bearer = HTTPBearer(auto_error=False)
        self._jwks_client = jwt.PyJWKClient(oidc.jwks_url) if (oidc and jwt is not None) else None

    @property
    def enabled(self) -> bool:
        return bool(self._api_keys or self._oidc)

    def require_role(self, min_role: Role):
        async def _dependency(
            api_key: str | None = Security(self._api_key_header),
            bearer: HTTPAuthorizationCredentials | None = Security(self._bearer),
        ) -> AuthContext:
            context = self._authenticate(api_key=api_key, bearer=bearer)
            if _ROLE_RANK[context.role] < _ROLE_RANK[min_role]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient role for this endpoint",
                )
            return context

        return _dependency

    def _authenticate(
        self,
        api_key: str | None,
        bearer: HTTPAuthorizationCredentials | None,
    ) -> AuthContext:
        if not self.enabled:
            return AuthContext(principal_id="anonymous", role=Role.ADMIN, tenant_id="global", source="none")

        if api_key and api_key in self._api_keys:
            role, tenant_id = self._api_keys[api_key]
            return AuthContext(principal_id=api_key, role=role, tenant_id=tenant_id, source="api_key")

        if bearer and bearer.credentials and self._oidc and self._jwks_client:
            return self._authenticate_oidc(bearer.credentials)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication credentials",
        )

    def _authenticate_oidc(self, token: str) -> AuthContext:
        assert self._oidc is not None
        if jwt is None:
            raise HTTPException(status_code=500, detail="PyJWT dependency is required for OIDC auth")
        assert self._jwks_client is not None

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self._oidc.audience,
                issuer=self._oidc.issuer,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid OIDC token: {exc}",
            ) from exc

        role_raw = str(claims.get(self._oidc.role_claim, "viewer")).lower()
        if role_raw not in {"viewer", "operator", "admin"}:
            role_raw = "viewer"
        tenant_id = claims.get(self._oidc.tenant_claim)

        principal = str(claims.get("sub") or claims.get("email") or "oidc-user")
        return AuthContext(principal_id=principal, role=Role(role_raw), tenant_id=tenant_id, source="oidc")


def load_auth_manager() -> AuthManager:
    raw = os.getenv("AGENTGUARD_API_KEYS", "").strip()
    parsed: dict[str, tuple[Role, str | None]] = {}

    if raw:
        # Format: key1:admin:tenant-a,key2:operator,key3:viewer:tenant-b
        for chunk in raw.split(","):
            item = chunk.strip()
            if not item:
                continue
            parts = [x.strip() for x in item.split(":")]
            if len(parts) < 2:
                continue
            key = parts[0]
            role_text = parts[1].lower()
            tenant = parts[2] if len(parts) > 2 and parts[2] else None
            if role_text not in {"viewer", "operator", "admin"}:
                continue
            parsed[key] = (Role(role_text), tenant)

    oidc = None
    issuer = os.getenv("AGENTGUARD_OIDC_ISSUER", "").strip()
    audience = os.getenv("AGENTGUARD_OIDC_AUDIENCE", "").strip()
    jwks_url = os.getenv("AGENTGUARD_OIDC_JWKS_URL", "").strip()
    if issuer and audience and jwks_url:
        oidc = OIDCConfig(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            role_claim=os.getenv("AGENTGUARD_OIDC_ROLE_CLAIM", "role"),
            tenant_claim=os.getenv("AGENTGUARD_OIDC_TENANT_CLAIM", "tenant_id"),
        )

    return AuthManager(api_keys=parsed, oidc=oidc)
