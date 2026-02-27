# AgentGuard

AgentGuard is a middleware security layer for autonomous AI agents. It inspects every requested tool action, applies policy rules, and writes a real-time audit trail.

## What this MVP includes

- Action interception API (`POST /v1/guard/evaluate`)
- Policy enforcement:
  - tool allow/deny lists per agent
  - resource prefix scoping
  - per-agent rate limiting
  - payload size limits
  - basic data exfiltration detection (sensitive regex + blocked domains)
- Audit APIs:
  - search logs (`GET /v1/audit/logs`)
  - stream live events via SSE (`GET /v1/audit/stream`)

## Architecture

1. Agent sends an intended action to AgentGuard.
2. Policy engine evaluates the action against configured rules.
3. AgentGuard returns allow/deny decision with reasons.
4. AgentGuard stores an immutable audit record and emits an event stream update.

## Run locally

```bash
cd agentguard
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

## Example policy decision

```bash
curl -s http://127.0.0.1:8080/v1/guard/evaluate \
  -X POST \
  -H 'content-type: application/json' \
  -d '{
    "agent_id":"build-bot",
    "tool":"exec_shell",
    "resource":"/workspace/repo",
    "payload":{"cmd":"rm -rf /"}
  }' | jq
```

Expected result: `decision = "deny"` because `build-bot` is explicitly blocked from `exec_shell`.

## Stream audit events

```bash
curl -N http://127.0.0.1:8080/v1/audit/stream
```

Then trigger evaluations in another terminal to watch real-time events.

## Configure policy

Default policy lives at `config/default_policy.json`.

Override policy path with:

```bash
export AGENTGUARD_POLICY=/absolute/path/to/policy.json
```

## Test

```bash
cd agentguard
python -m unittest discover -s tests -v
```
