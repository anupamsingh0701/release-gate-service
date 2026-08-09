# TDS GA7 Release Gate Policy Service

[![TDS GA7 Release Gate](https://github.com/anupamsingh0701/release-gate-service/actions/workflows/release-gate.yml/badge.svg?branch=main)](https://github.com/anupamsingh0701/release-gate-service/actions/workflows/release-gate.yml)

A **deterministic HTTP policy endpoint** (`POST /release-gate`) that decides whether a GitHub Actions CI run may promote a container image.

## Endpoint

```
POST /release-gate
```

Evaluates a JSON payload against all 11 policy rules and returns a `promote` or `block` decision with the applicable violation codes.

## Response Format

```json
{"decision": "promote | block", "violations": ["CODE", "..."]}
```

`promote` is returned **only** when `violations` is empty.

## Policy Rules

| Violation Code | Rule |
|---|---|
| `EXCESS_PERMISSION` | `workflow.permissions` must be exactly `{"contents":"read","packages":"write","id-token":"none"}` |
| `UNSAFE_PR_TRIGGER` | PR events must use `pull_request`, never `pull_request_target` |
| `TESTS_INCOMPLETE` | `testsPassed:true`, `matrixComplete:true`, `failFast:false` |
| `MUTABLE_ACTION` | `actions/*` owner: version tag or SHA; third-party: 40-char hex SHA |
| `SINGLE_STAGE_IMAGE` | `image.multiStage` must be `true` |
| `ROOT_RUNTIME` | `image.runsAsRoot` must be `false` |
| `SECRET_IN_LAYER` | `image.secretMode` must be `"none"` or `"buildkit"` |
| `CRITICAL_CVE` | `image.criticalVulnerabilities` must be `0` |
| `UNPINNED_IMAGE` | `image.digestPinned` must be `true` |
| `INVALID_PRODUCTION_REF` | Production: `event=="push"` and `ref=="refs/heads/main"` |
| `APPROVAL_REQUIRED` | Production: `workflow.environmentApproval` must be `true` |

## Example Request

```bash
curl -X POST https://release-gate-service.onrender.com/release-gate \
  -H "Content-Type: application/json" \
  -d '{
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/pull/42/merge",
    "workflow": {
      "trigger": "pull_request",
      "permissions": {"contents":"read","packages":"write","id-token":"none"},
      "testsPassed": true, "matrixComplete": true, "failFast": false,
      "actions": [{"owner":"actions","name":"checkout","ref":"v4"}]
    },
    "image": {
      "multiStage": true, "runsAsRoot": false, "secretMode": "none",
      "criticalVulnerabilities": 0, "digestPinned": true
    }
  }'
```

Expected response:
```json
{"decision": "promote", "violations": []}
```

## Running Locally

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Running Tests

```bash
pytest test_release_gate.py -v
```

## Deploying to Render

1. Fork/push this repo to GitHub.
2. On [Render](https://dashboard.render.com/), create a **New Web Service**.
3. Connect your GitHub repo.
4. Render auto-detects `render.yaml` — just click **Deploy**.
