# API Reference

## Guard endpoints
- `POST /v1/guard/evaluate`
  - Role: `operator`
  - Purpose: Evaluate tool action intent.
- `POST /v1/guard/retrieval`
  - Role: `operator`
  - Purpose: Evaluate retrieved context/tool response.
- `POST /v1/guard/output`
  - Role: `operator`
  - Purpose: Evaluate generated output.

## Audit endpoints
- `GET /v1/audit/logs`
  - Role: `viewer`
  - Purpose: Query decision logs.
- `GET /v1/audit/stream`
  - Role: `viewer`
  - Purpose: Stream decision events (SSE).

## Policy governance
- `GET /v1/policy/current`
  - Role: `viewer`
- `GET /v1/policy/versions`
  - Role: `viewer`
- `POST /v1/policy/propose`
  - Role: `admin`
- `POST /v1/policy/{version}/approve`
  - Role: `admin`

## SCIM-style provisioning
- `POST /v1/scim/v2/Users`
  - Role: `admin`
- `GET /v1/scim/v2/Users/{user_name}`
  - Role: `admin`
- `GET /v1/scim/v2/Users`
  - Role: `admin`
- `DELETE /v1/scim/v2/Users/{user_name}`
  - Role: `admin`

## Health
- `GET /health`
  - Purpose: service + store readiness summary.
