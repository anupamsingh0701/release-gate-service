import urllib.request
import json

url = "https://tds-ga7-release-gate.star-jitterbug.workers.dev/release-gate"

def send_probe(name, payload, expected_decision, expected_violations=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
    )
    try:
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            decision = res.get("decision")
            violations = set(res.get("violations", []))
            
            dec_match = (decision == expected_decision)
            viols_match = True
            if expected_violations is not None:
                viols_match = (violations == set(expected_violations))
            
            status = "PASS" if (dec_match and viols_match) else "FAIL"
            print(f"[{status}] {name}")
            print(f"       Decision: {decision} (expected: {expected_decision})")
            print(f"       Violations: {sorted(list(violations))} (expected: {sorted(expected_violations) if expected_violations else []})")
            if status == "FAIL":
                raise Exception(f"Test failed: {name}")
    except urllib.error.HTTPError as e:
        print(f"[ERROR] {name}: HTTP {e.code} - {e.read().decode('utf-8')}")
        raise

# Base safe preview
p_safe_preview = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/pull/101/merge",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True, "matrixComplete": True, "failFast": False,
        "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}]
    },
    "image": {
        "multiStage": True, "runsAsRoot": False, "secretMode": "none",
        "criticalVulnerabilities": 0, "digestPinned": True
    }
}

send_probe("1. Safe Preview", p_safe_preview, "promote", [])

# Base safe production
p_safe_prod = {
    "target": "production",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        "trigger": "push",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True, "matrixComplete": True, "failFast": False,
        "environmentApproval": True,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4.1.0"},
            {"owner": "docker", "name": "setup-buildx-action", "ref": "f95db51fddba0c2d1ec667646a06c2ce06a004ef"}
        ]
    },
    "image": {
        "multiStage": True, "runsAsRoot": False, "secretMode": "buildkit",
        "criticalVulnerabilities": 0, "digestPinned": True
    }
}

send_probe("2. Safe Production", p_safe_prod, "promote", [])

# 3. EXCESS_PERMISSION
p = json.loads(json.dumps(p_safe_preview))
p["workflow"]["permissions"]["admin"] = "write"
send_probe("3. Excess Permission", p, "block", ["EXCESS_PERMISSION"])

# 4. UNSAFE_PR_TRIGGER
p = json.loads(json.dumps(p_safe_preview))
p["workflow"]["trigger"] = "pull_request_target"
send_probe("4. Unsafe PR Trigger", p, "block", ["UNSAFE_PR_TRIGGER"])

# 5. TESTS_INCOMPLETE
p = json.loads(json.dumps(p_safe_preview))
p["workflow"]["failFast"] = True
send_probe("5. Tests Incomplete", p, "block", ["TESTS_INCOMPLETE"])

# 6. MUTABLE_ACTION
p = json.loads(json.dumps(p_safe_preview))
p["workflow"]["actions"] = [{"owner": "custom", "name": "act", "ref": "v1.0"}]
send_probe("6. Mutable Action", p, "block", ["MUTABLE_ACTION"])

# 7. SINGLE_STAGE_IMAGE
p = json.loads(json.dumps(p_safe_preview))
p["image"]["multiStage"] = False
send_probe("7. Single Stage Image", p, "block", ["SINGLE_STAGE_IMAGE"])

# 8. ROOT_RUNTIME
p = json.loads(json.dumps(p_safe_preview))
p["image"]["runsAsRoot"] = True
send_probe("8. Root Runtime", p, "block", ["ROOT_RUNTIME"])

# 9. SECRET_IN_LAYER
p = json.loads(json.dumps(p_safe_preview))
p["image"]["secretMode"] = "copy"
send_probe("9. Secret in Layer", p, "block", ["SECRET_IN_LAYER"])

# 10. CRITICAL_CVE
p = json.loads(json.dumps(p_safe_preview))
p["image"]["criticalVulnerabilities"] = 1
send_probe("10. Critical CVE", p, "block", ["CRITICAL_CVE"])

# 11. UNPINNED_IMAGE
p = json.loads(json.dumps(p_safe_preview))
p["image"]["digestPinned"] = False
send_probe("11. Unpinned Image", p, "block", ["UNPINNED_IMAGE"])

# 12. INVALID_PRODUCTION_REF
p = json.loads(json.dumps(p_safe_prod))
p["ref"] = "refs/heads/feature"
send_probe("12. Invalid Production Ref", p, "block", ["INVALID_PRODUCTION_REF"])

# 13. APPROVAL_REQUIRED
p = json.loads(json.dumps(p_safe_prod))
p["workflow"]["environmentApproval"] = False
send_probe("13. Approval Required", p, "block", ["APPROVAL_REQUIRED"])

print("\nALL 13 LIVE PROBE TESTS PASSED SUCCESSFULLY!")
