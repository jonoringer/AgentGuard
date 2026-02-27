# Deployment Guide

## Environments
- Local dev: SQLite stores, optional API keys.
- Staging/prod: Postgres DSNs, OIDC or trusted SSO bridge, SIEM + telemetry exports.

## Production checklist
1. Use Postgres for audit/policy/SCIM stores.
2. Enable authentication (`OIDC` recommended).
3. Configure SIEM and telemetry export sinks.
4. Seed/approve policy versions before enabling agents.
5. Configure tenant-scoped API keys or SCIM identity mappings.

## Example environment
Use [`/.env.production.example`](/Users/jonoringer/Documents/New project/.env.production.example) as a baseline.

## Start service
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## Migrations and health
```bash
python scripts/migrate_stores.py
curl -s http://127.0.0.1:8080/health | jq
```
