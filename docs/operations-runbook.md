# Operations Runbook

## Health checks
```bash
curl -s http://127.0.0.1:8080/health | jq
```
Expect `status: ok` and all stores `ok`.

## Store initialization/migration
```bash
python scripts/migrate_stores.py
```

## Policy rollback
1. `GET /v1/policy/versions` for tenant.
2. Re-approve a previous version via `POST /v1/policy/{version}/approve`.

## Key rotation
- Rotate API keys in `AGENTGUARD_API_KEYS`.
- Rotate trusted SSO shared secret.
- Rotate OIDC credentials/claims mapping as needed.

## SIEM troubleshooting
1. Enable JSONL sink for local fallback.
2. Validate webhook/syslog endpoint reachability.
3. Compare `/v1/audit/logs` count with exported event count.

## Telemetry troubleshooting
1. If OTLP unavailable, set `AGENTGUARD_TELEMETRY_JSONL_PATH`.
2. Verify local telemetry lines are generated.
3. Re-enable OTLP endpoint after collector/network recovery.
