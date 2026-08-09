# TDS GA7 Release Gate Policy Service

Deterministic policy evaluation endpoint (`POST /release-gate`) for gating container image promotions based on least-privilege CI permissions, complete matrix testing, action pinning, image hardening, production branch/ref validation, and environment approvals.

[![TDS GA7 Release Gate](https://github.com/anupamsingh0701/release-gate-service/actions/workflows/release-gate.yml/badge.svg?branch=main)](https://github.com/anupamsingh0701/release-gate-service/actions/workflows/release-gate.yml)

## Security Policy Rules Enforced

1. **Least-Privilege Permissions (`EXCESS_PERMISSION`)**:
   - `workflow.permissions` must be exactly `{"contents": "read", "packages": "write", "id-token": "none"}` with no additional scopes.

2. **PR Trigger Safety (`UNSAFE_PR_TRIGGER`)**:
   - Pull request events must use `pull_request`, never `pull_request_target`.

3. **Complete Testing Matrix (`TESTS_INCOMPLETE`)**:
   - `testsPassed` must be `true`, `matrixComplete` must be `true`, and `failFast` must be `false`.

4. **Action Pinning (`MUTABLE_ACTION`)**:
   - Actions owned by `actions` may use a version tag or commit SHA (no mutable branches).
   - Third-party actions must be pinned to a full 40-character lowercase hexadecimal commit SHA.

5. **Hardened Multi-Stage Docker Image**:
   - Multi-stage build (`SINGLE_STAGE_IMAGE` if `multiStage` is not `true`).
   - Non-root runtime (`ROOT_RUNTIME` if `runsAsRoot` is not `false`).
   - Safe build secrets (`SECRET_IN_LAYER` if `secretMode` is not `"none"` or `"buildkit"`).
   - Zero critical CVEs (`CRITICAL_CVE` if `criticalVulnerabilities` is not `0`).
   - Digest pinned (`UNPINNED_IMAGE` if `digestPinned` is not `true`).

6. **Production Release Gates**:
   - Push event on `refs/heads/main` (`INVALID_PRODUCTION_REF`).
   - Environment approval required (`APPROVAL_REQUIRED` if `environmentApproval` is not `true`).

## Response Schema

```json
{
  "decision": "promote | block",
  "violations": ["CODE", "..."]
}
```

## Running Tests

```bash
pip install -r requirements.txt
pytest test_release_gate.py -v
```
