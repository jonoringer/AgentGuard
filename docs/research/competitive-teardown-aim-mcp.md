# Competitive Teardown: AIM-MCP

## What it does well
- MCP-native security controls.
- Security-focused utilities around credential and prompt risk.
- Practical posture for agent-tool integrations.

## Gaps we must close for parity/advantage
- First-class MCP interception SDK/adapters.
- Policy and risk scoring tuned specifically for MCP action boundaries.
- Built-in controls for credential leakage and destination risk.

## Build requirements derived
1. Provide MCP middleware adapters for request/response interception.
2. Add risk scoring and confidence into enforcement decisions.
3. Add destination controls for outbound MCP/tool traffic.
4. Add incident-ready event stream and export pipeline.

## Acceptance criteria
- MCP integration requires minimal host-side code.
- Decision path supports hard deny and soft quarantine.
- Audit events include MCP context attributes.
