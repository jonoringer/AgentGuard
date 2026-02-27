# AgentGuard

<p align="center">
  <img src="assets/agentguard-icon.svg" alt="AgentGuard icon" width="160" />
</p>

AgentGuard is a security control plane for autonomous AI agents. It sits between your agent runtime and its tool/MCP execution layer, evaluates every requested action against policy, returns a clear `allow` or `deny` decision with reasons, and records each decision in an auditable event trail. In practice, it acts like a firewall for agent actions: fast enough for real workflows, strict enough for high-risk environments. 🛡️

This tool is built for teams deploying agents in real systems, especially enterprise security teams, platform teams, and engineering orgs using tools like Claude Code, Cursor, or Codex with custom MCP servers. If your agents can read internal files, call APIs, run code, or touch production systems, AgentGuard helps you enforce consistent controls before those actions execute.

Teams use AgentGuard to reduce the blast radius of prompt injection, malicious tool outputs, compromised skills, and accidental overreach by highly capable agents. Instead of relying on trust alone, you get explicit policy enforcement, scoped permissions, rate controls, and investigation-ready logs that can feed security monitoring workflows. The result is safer agent autonomy without slowing delivery velocity. 🤖

## Why it exists

Modern agents can:

- Call local and remote tools
- Persist memory over long sessions
- Chain actions autonomously
- Access internal systems through MCP connectors

That increases the blast radius of prompt injection, malicious tool outputs, compromised skills, and unsafe agent behavior. AgentGuard reduces that risk by enforcing policy before execution.

## What AgentGuard does

AgentGuard currently provides:

- `POST /v1/guard/evaluate`: evaluate an intended agent action before tool execution
- Policy enforcement for:
  - tool allowlists/denylists (global + per-agent)
  - resource scoping via path/URL prefix rules
  - per-agent rate limits
  - payload size limits
  - exfiltration heuristics (blocked domains + sensitive regex detection)
- Audit and observability:
  - `GET /v1/audit/logs`: query recent decisions
  - `GET /v1/audit/stream`: subscribe to real-time decision events (SSE)

## How it works

1. Your agent runtime sends each proposed action to AgentGuard.
2. AgentGuard evaluates rules in the policy engine.
3. AgentGuard returns a decision and explanations.
4. Your runtime executes the tool only if the decision is `allow`.
5. AgentGuard stores an audit event for investigation and reporting.

## Project structure

```text
app/
  main.py      # FastAPI endpoints
  engine.py    # Policy enforcement engine
  models.py    # Request/response and policy data models
  policy.py    # Policy file loading
  audit.py     # In-memory audit store + SSE fanout
config/
  default_policy.json
tests/
  test_engine.py
  test_api.py
```

## Quickstart

### 1. Install and run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

### 2. Health check

```bash
curl -s http://127.0.0.1:8080/health
```

Expected response:

```json
{"status":"ok"}
```

## API usage

### Evaluate an action (deny example)

```bash
curl -s http://127.0.0.1:8080/v1/guard/evaluate \
  -X POST \
  -H 'content-type: application/json' \
  -d '{
    "agent_id":"build-bot",
    "tool":"exec_shell",
    "resource":"/workspace/repo",
    "payload":{"cmd":"cat ~/.ssh/id_rsa"}
  }' | jq
```

Typical response:

```json
{
  "decision": "deny",
  "reasons": [
    "Tool 'exec_shell' is explicitly denied"
  ],
  "rule_results": [
    {"rule":"tool_scope","passed":false,"message":"Tool 'exec_shell' is explicitly denied"}
  ],
  "audit_id": "..."
}
```

### Evaluate an action (allow example)

```bash
curl -s http://127.0.0.1:8080/v1/guard/evaluate \
  -X POST \
  -H 'content-type: application/json' \
  -d '{
    "agent_id":"build-bot",
    "tool":"read_file",
    "resource":"/workspace/repo/README.md",
    "payload":{"path":"/workspace/repo/README.md"}
  }' | jq
```

Typical response includes:

```json
{
  "decision": "allow",
  "reasons": ["Action allowed by current policy"],
  "audit_id": "..."
}
```

### Query audit logs

```bash
curl -s 'http://127.0.0.1:8080/v1/audit/logs?agent_id=build-bot&limit=20' | jq
```

### Stream real-time decisions

```bash
curl -N http://127.0.0.1:8080/v1/audit/stream
```

Keep this running in one terminal while submitting `evaluate` calls in another.

## Policy configuration

Default policy file: `config/default_policy.json`

You can override the policy file path:

```bash
export AGENTGUARD_POLICY=/absolute/path/to/policy.json
```

Key policy fields:

- `default_allow_tools`: tools allowed if no agent-specific allowlist is set
- `default_deny_tools`: tools always denied unless policy changed
- `agent_allow_tools`: per-agent allowlists
- `agent_deny_tools`: per-agent denylists
- `resource_prefix_allowlist`: allowed path/URL prefixes per agent
- `rate_limit_per_minute`: max evaluated actions per agent per minute
- `max_payload_bytes`: payload size guardrail
- `blocked_domains`: deny if payload references these destinations
- `sensitive_regex`: patterns for API keys, private keys, bearer tokens, etc.

Example policy fragment:

```json
{
  "agent_allow_tools": {
    "research-bot": ["http_get", "search_code"]
  },
  "agent_deny_tools": {
    "research-bot": ["exec_shell", "git_push"]
  },
  "resource_prefix_allowlist": {
    "research-bot": ["https://docs.mycompany.com"]
  }
}
```

## Integration pattern (recommended)

Put AgentGuard inline in your agent execution flow:

1. Agent proposes tool call.
2. Runtime sends the proposed call to `POST /v1/guard/evaluate`.
3. If `decision == allow`, execute the real tool.
4. If `decision == deny`, return a policy error to the agent and stop execution.
5. Send audit logs to your SIEM/SOC pipeline.

## Testing

```bash
python -m unittest discover -s tests -v
```

## Current limitations

- Audit storage is in-memory (non-persistent)
- Exfiltration detection is heuristic-based (not full DLP)
- No authn/authz layer on API endpoints yet

For production, add persistent storage, authentication, and policy change controls.
