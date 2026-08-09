// Pure JS release gate policy evaluation
function evaluateReleaseGate(payload) {
  const violations = [];
  
  const target = payload?.target;
  const event = payload?.event;
  const ref = payload?.ref;
  const workflow = payload?.workflow || {};
  const image = payload?.image || {};
  
  // 1. Permissions (EXCESS_PERMISSION)
  const permissions = workflow.permissions;
  if (!permissions || typeof permissions !== 'object' || Array.isArray(permissions)) {
    violations.push("EXCESS_PERMISSION");
  } else {
    const expected = {
      "contents": "read",
      "packages": "write",
      "id-token": "none"
    };
    const keys = Object.keys(permissions);
    if (keys.length !== 3 || !keys.includes("contents") || !keys.includes("packages") || !keys.includes("id-token")) {
      violations.push("EXCESS_PERMISSION");
    } else {
      if (permissions["contents"] !== "read" || permissions["packages"] !== "write" || permissions["id-token"] !== "none") {
        violations.push("EXCESS_PERMISSION");
      }
    }
  }

  // 2. PR Trigger Safety (UNSAFE_PR_TRIGGER)
  const trigger = workflow.trigger;
  if (trigger === "pull_request_target") {
    violations.push("UNSAFE_PR_TRIGGER");
  } else if (event === "pull_request" && trigger !== "pull_request") {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // 3. Tests, Matrix, FailFast (TESTS_INCOMPLETE)
  if (workflow.testsPassed !== true || workflow.matrixComplete !== true || workflow.failFast !== false) {
    violations.push("TESTS_INCOMPLETE");
  }

  // 4. Action Pinning (MUTABLE_ACTION)
  const actions = workflow.actions;
  if (!Array.isArray(actions)) {
    violations.push("MUTABLE_ACTION");
  } else {
    for (const act of actions) {
      if (!act || typeof act !== 'object') {
        violations.push("MUTABLE_ACTION");
        break;
      }
      const owner = String(act.owner || "").trim();
      const actRef = String(act.ref || "").trim();

      if (owner === "actions") {
        const mutableBranches = ["main", "master", "latest", "head", "dev", "develop", "nightly", "edge"];
        const is40Hex = /^[0-9a-f]{40}$/.test(actRef);
        const isVersionTag = /^v?\d+(\.\d+)*(-[a-zA-Z0-9_.-]+)?$/.test(actRef);
        if (!actRef || mutableBranches.includes(actRef.toLowerCase()) || !(isVersionTag || is40Hex)) {
          violations.push("MUTABLE_ACTION");
          break;
        }
      } else {
        if (!/^[0-9a-f]{40}$/.test(actRef)) {
          violations.push("MUTABLE_ACTION");
          break;
        }
      }
    }
  }

  // 5. Single Stage Image (SINGLE_STAGE_IMAGE)
  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }

  // 6. Non-root runtime (ROOT_RUNTIME)
  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }

  // 7. Build secrets in layer (SECRET_IN_LAYER)
  if (!["none", "buildkit"].includes(image.secretMode)) {
    violations.push("SECRET_IN_LAYER");
  }

  // 8. Critical CVE (CRITICAL_CVE)
  if (image.criticalVulnerabilities !== 0 || typeof image.criticalVulnerabilities !== 'number') {
    violations.push("CRITICAL_CVE");
  }

  // 9. Digest Pinned (UNPINNED_IMAGE)
  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }

  // 10. Production Reference (INVALID_PRODUCTION_REF)
  if (target === "production") {
    if (event !== "push" || ref !== "refs/heads/main") {
      violations.push("INVALID_PRODUCTION_REF");
    }
  }

  // 11. Environment Approval (APPROVAL_REQUIRED)
  if (target === "production") {
    if (workflow.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  const decision = violations.length === 0 ? "promote" : "block";
  return { decision, violations };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Content-Type": "application/json"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method === "GET") {
      return new Response(JSON.stringify({ status: "ok", service: "TDS GA7 Release Gate Policy Service" }), {
        headers: corsHeaders
      });
    }

    if (request.method === "POST") {
      try {
        const body = await request.json();
        const result = evaluateReleaseGate(body);
        return new Response(JSON.stringify(result), { headers: corsHeaders });
      } catch (err) {
        return new Response(JSON.stringify({ decision: "block", violations: ["INVALID_PAYLOAD"] }), {
          status: 400,
          headers: corsHeaders
        });
      }
    }

    return new Response(JSON.stringify({ error: "Method Not Allowed" }), { status: 405, headers: corsHeaders });
  }
};
