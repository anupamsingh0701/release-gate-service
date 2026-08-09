import copy
import pytest
from fastapi.testclient import TestClient
from app import app
from policy import evaluate_release_gate

client = TestClient(app)

# Canonical safe preview payload
SAFE_PREVIEW_PAYLOAD = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/pull/101/merge",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        },
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {"owner": "docker", "name": "setup-buildx-action", "ref": "f95db51fddba0c2d1ec667646a06c2ce06a004ef"}
        ]
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True
    }
}

# Canonical safe production payload
SAFE_PRODUCTION_PAYLOAD = {
    "target": "production",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        "trigger": "push",
        "permissions": {
            "contents": "read",
            "packages": "write",
            "id-token": "none"
        },
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "environmentApproval": True,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4.1.0"},
            {"owner": "docker", "name": "setup-buildx-action", "ref": "f95db51fddba0c2d1ec667646a06c2ce06a004ef"}
        ]
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True
    }
}

def test_safe_preview_payload():
    decision, violations = evaluate_release_gate(SAFE_PREVIEW_PAYLOAD)
    assert decision == "promote"
    assert violations == []

    response = client.post("/release-gate", json=SAFE_PREVIEW_PAYLOAD)
    assert response.status_code == 200
    assert response.json() == {"decision": "promote", "violations": []}

def test_safe_production_payload():
    decision, violations = evaluate_release_gate(SAFE_PRODUCTION_PAYLOAD)
    assert decision == "promote"
    assert violations == []

    response = client.post("/release-gate", json=SAFE_PRODUCTION_PAYLOAD)
    assert response.status_code == 200
    assert response.json() == {"decision": "promote", "violations": []}

def test_excess_permission_extra_scope():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["permissions"]["security-events"] = "write"
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "EXCESS_PERMISSION" in violations

def test_excess_permission_wrong_level():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["permissions"]["contents"] = "write"
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "EXCESS_PERMISSION" in violations

def test_excess_permission_missing_key():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    del p["workflow"]["permissions"]["id-token"]
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "EXCESS_PERMISSION" in violations

def test_unsafe_pr_trigger_pull_request_target():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["trigger"] = "pull_request_target"
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "UNSAFE_PR_TRIGGER" in violations

def test_unsafe_pr_trigger_mismatch():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["trigger"] = "push"
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "UNSAFE_PR_TRIGGER" in violations

def test_tests_incomplete_failed():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["testsPassed"] = False
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "TESTS_INCOMPLETE" in violations

def test_tests_incomplete_matrix():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["matrixComplete"] = False
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "TESTS_INCOMPLETE" in violations

def test_tests_incomplete_fail_fast():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["failFast"] = True
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "TESTS_INCOMPLETE" in violations

def test_mutable_action_third_party_version_tag():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["actions"] = [
        {"owner": "docker", "name": "setup-buildx-action", "ref": "v3"}
    ]
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "MUTABLE_ACTION" in violations

def test_mutable_action_third_party_short_sha():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["actions"] = [
        {"owner": "docker", "name": "setup-buildx-action", "ref": "f95db51"}
    ]
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "MUTABLE_ACTION" in violations

def test_mutable_action_actions_owner_branch():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["workflow"]["actions"] = [
        {"owner": "actions", "name": "checkout", "ref": "main"}
    ]
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "MUTABLE_ACTION" in violations

def test_single_stage_image():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["image"]["multiStage"] = False
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "SINGLE_STAGE_IMAGE" in violations

def test_root_runtime():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["image"]["runsAsRoot"] = True
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "ROOT_RUNTIME" in violations

def test_secret_in_layer_arg():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["image"]["secretMode"] = "arg"
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "SECRET_IN_LAYER" in violations

def test_secret_in_layer_copy():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["image"]["secretMode"] = "copy"
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "SECRET_IN_LAYER" in violations

def test_critical_cve():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["image"]["criticalVulnerabilities"] = 2
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "CRITICAL_CVE" in violations

def test_unpinned_image():
    p = copy.deepcopy(SAFE_PREVIEW_PAYLOAD)
    p["image"]["digestPinned"] = False
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "UNPINNED_IMAGE" in violations

def test_invalid_production_ref_branch():
    p = copy.deepcopy(SAFE_PRODUCTION_PAYLOAD)
    p["ref"] = "refs/heads/feature-gate"
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "INVALID_PRODUCTION_REF" in violations

def test_invalid_production_ref_event():
    p = copy.deepcopy(SAFE_PRODUCTION_PAYLOAD)
    p["event"] = "pull_request"
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "INVALID_PRODUCTION_REF" in violations

def test_approval_required_missing():
    p = copy.deepcopy(SAFE_PRODUCTION_PAYLOAD)
    del p["workflow"]["environmentApproval"]
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "APPROVAL_REQUIRED" in violations

def test_approval_required_false():
    p = copy.deepcopy(SAFE_PRODUCTION_PAYLOAD)
    p["workflow"]["environmentApproval"] = False
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    assert "APPROVAL_REQUIRED" in violations

def test_multi_failure_combination():
    p = {
        "target": "production",
        "event": "pull_request",
        "ref": "refs/heads/dev",
        "workflow": {
            "trigger": "pull_request_target",
            "permissions": {"contents": "write", "packages": "write", "id-token": "write"},
            "testsPassed": False,
            "matrixComplete": False,
            "failFast": True,
            "environmentApproval": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "main"},
                {"owner": "custom", "name": "action", "ref": "v1"}
            ]
        },
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "copy",
            "criticalVulnerabilities": 5,
            "digestPinned": False
        }
    }
    decision, violations = evaluate_release_gate(p)
    assert decision == "block"
    expected_violations = {
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
        "INVALID_PRODUCTION_REF",
        "APPROVAL_REQUIRED"
    }
    assert set(violations) == expected_violations
