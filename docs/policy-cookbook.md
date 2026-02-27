# Policy Cookbook

## Strict dev-agent profile
```json
{
  "default_allow_tools": ["read_file", "list_files", "search_code"],
  "default_deny_tools": ["exec_shell", "git_push"],
  "rate_limit_per_minute": 20
}
```

## Retrieval hardening
```json
{
  "retrieval_guard_regex": [
    "(?i)ignore previous instructions",
    "(?i)reveal system prompt",
    "(?i)disable guardrails"
  ]
}
```

## Output hardening
```json
{
  "output_guard_regex": [
    "(?i)BEGIN (RSA|EC|OPENSSH) PRIVATE KEY",
    "(?i)password\\s*[:=]",
    "(?i)api[_-]?key\\s*[:=]"
  ]
}
```

## Multi-tenant baseline
```json
{
  "agent_allow_tools": {
    "tenant-a-build-bot": ["read_file", "list_files", "run_tests"]
  },
  "resource_prefix_allowlist": {
    "tenant-a-build-bot": ["/workspace/tenant-a"]
  }
}
```

## Deny-first mode
```json
{
  "default_allow_tools": [],
  "default_deny_tools": ["exec_shell", "git_push", "write_secret_store"]
}
```
