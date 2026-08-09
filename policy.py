import re
from typing import Any, Dict, List, Tuple

def evaluate_release_gate(payload: Dict[str, Any]) -> Tuple[str, List[str]]:
    violations: List[str] = []
    
    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")
    workflow = payload.get("workflow") or {}
    image = payload.get("image") or {}
    
    # 1. Permissions Check (EXCESS_PERMISSION)
    # Permissions must be exactly least privilege for a release:
    # contents: read, packages: write, and id-token: none. No additional scopes may be present.
    permissions = workflow.get("permissions")
    if not isinstance(permissions, dict):
        violations.append("EXCESS_PERMISSION")
    else:
        expected_permissions = {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        }
        # Check exact keys and values
        if set(permissions.keys()) != set(expected_permissions.keys()):
            violations.append("EXCESS_PERMISSION")
        else:
            for k, expected_v in expected_permissions.items():
                if permissions.get(k) != expected_v:
                    violations.append("EXCESS_PERMISSION")
                    break

    # 2. PR Trigger Safety (UNSAFE_PR_TRIGGER)
    # A pull request must use pull_request, never pull_request_target.
    trigger = workflow.get("trigger")
    if trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    elif event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests, Matrix, FailFast (TESTS_INCOMPLETE)
    # Tests must pass, the whole matrix must finish, and failFast must be false.
    tests_passed = workflow.get("testsPassed")
    matrix_complete = workflow.get("matrixComplete")
    fail_fast = workflow.get("failFast")
    if tests_passed is not True or matrix_complete is not True or fail_fast is not False:
        violations.append("TESTS_INCOMPLETE")

    # 4. Action Pinning (MUTABLE_ACTION)
    # Actions owned by actions may use a version tag.
    # Every third-party action must be pinned to a full 40-character lowercase hexadecimal commit SHA.
    actions = workflow.get("actions")
    if not isinstance(actions, list):
        violations.append("MUTABLE_ACTION")
    else:
        for action in actions:
            if not isinstance(action, dict):
                violations.append("MUTABLE_ACTION")
                break
            owner = str(action.get("owner", "")).strip()
            act_ref = str(action.get("ref", "")).strip()
            
            if owner == "actions":
                # Actions owned by 'actions' may use a version tag or commit SHA.
                # Disallow mutable branches or empty refs.
                mutable_branches = {"main", "master", "latest", "head", "dev", "develop", "nightly", "edge"}
                is_40_hex = bool(re.fullmatch(r"^[0-9a-f]{40}$", act_ref))
                is_version_tag = bool(re.match(r"^v?\d+(\.\d+)*(-[a-zA-Z0-9_.-]+)?$", act_ref))
                
                if (not act_ref) or (act_ref.lower() in mutable_branches) or (not (is_version_tag or is_40_hex)):
                    violations.append("MUTABLE_ACTION")
                    break
            else:
                # Third-party action: must be a full 40-character lowercase hexadecimal commit SHA
                if not re.fullmatch(r"^[0-9a-f]{40}$", act_ref):
                    violations.append("MUTABLE_ACTION")
                    break

    # 5. Single Stage Image (SINGLE_STAGE_IMAGE)
    # The image must be multi-stage
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Non-root runtime (ROOT_RUNTIME)
    # run as non-root (runsAsRoot must be False)
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Build secrets in layer (SECRET_IN_LAYER)
    # use either no build secret or a BuildKit secret mount (secretMode in "none", "buildkit")
    secret_mode = image.get("secretMode")
    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. Critical Vulnerabilities (CRITICAL_CVE)
    # have zero critical vulnerabilities
    critical_cves = image.get("criticalVulnerabilities")
    if critical_cves != 0 or not isinstance(critical_cves, int) or isinstance(critical_cves, bool):
        violations.append("CRITICAL_CVE")

    # 9. Digest Pinned (UNPINNED_IMAGE)
    # and be referenced by digest
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10. Production Reference (INVALID_PRODUCTION_REF)
    # Production additionally requires a push on refs/heads/main
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

    # 11. Environment Approval (APPROVAL_REQUIRED)
    # Production additionally requires an environmentApproval: true field on workflow
    if target == "production":
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"
    return decision, violations
