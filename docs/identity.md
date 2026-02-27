# Identity and Access

## Auth options
1. API keys
2. OIDC JWT (issuer/audience/JWKS)
3. Trusted SSO header bridge (for identity proxy deployments)

## Role model
- `viewer`: audit + policy read
- `operator`: guard evaluation endpoints
- `admin`: policy governance + SCIM provisioning

## Tenant resolution precedence
1. Tenant from auth identity (API key mapping, OIDC claim, trusted SSO header)
2. Request tenant (admin without fixed tenant)
3. Fallback `global`

## SCIM provisioning and overrides
- Provision users via `/v1/scim/v2/Users`.
- For OIDC/trusted SSO users, SCIM access metadata can override role/tenant.
- SCIM extension used:
  - `urn:agentguard:access.role`
  - `urn:agentguard:access.tenant_id`
