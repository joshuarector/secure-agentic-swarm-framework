"""LangGraph implementation of the Supervisor hub-and-spoke swarm.

Implements the spec in graph_design.md: SwarmState, the Supervisor +
Pipeline/Cloud/Incident sub-agent nodes, conditional routing via
route_next, and the GatewayGuard entry-boundary check that enforces the
GitOps & Deployment Constraints from playbook.md before the graph is
ever compiled or invoked.

Node bodies here are mocks standing in for the real Jenkins/Jira/AWS
sub-agent implementations described in playbook.md.
"""

from __future__ import annotations

import re
import subprocess

from pydantic import BaseModel, Field
from langgraph.graph import StateGraph, END


# ---------------------------------------------------------------------------
# 1. Shared Graph State
# ---------------------------------------------------------------------------

class SwarmState(BaseModel):
    """Shared state threaded through the Supervisor hub-and-spoke graph."""

    current_target: str = Field(
        default="",
        description="Identifier of the active hop (Supervisor / Pipeline-Agent / Cloud-Agent / Incident-Agent).",
    )
    payload: dict = Field(
        default_factory=dict,
        description="Context envelope: request_id, original_request, routing_plan, current_step, per-agent outputs, halt_on_error.",
    )
    dynamic_routing_chain: list[str] = Field(
        default_factory=list,
        description="Ordered queue of remaining sub-agent hops seeded by the Supervisor.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Accumulated error messages.",
    )


# ---------------------------------------------------------------------------
# 2. Nodes (mock sub-agent bodies, real orchestration shape)
# ---------------------------------------------------------------------------

# Routing Matrix from playbook.md, reduced to the signals this mock cares about.
ROUTING_MATRIX = [
    (("build", "pipeline breach", "ci security gate"), ["Pipeline-Agent", "Cloud-Agent", "Incident-Agent"]),
    (("security hub finding", "cloud custodian", "aws finding"), ["Cloud-Agent", "Incident-Agent"]),
    (("check build", "is pipeline passing"), ["Pipeline-Agent"]),
    (("audit", "weekly review", "full sweep"), ["Cloud-Agent", "Pipeline-Agent", "Incident-Agent"]),
]


def classify_request(request_text: str) -> list[str] | None:
    text = request_text.lower()
    for keywords, plan in ROUTING_MATRIX:
        if any(kw in text for kw in keywords):
            return plan
    return None


def supervisor_node(state: SwarmState) -> SwarmState:
    """Classifies the request against the Routing Matrix and seeds the chain."""
    request = state.payload.get("original_request", "")
    routing_plan = classify_request(request)
    if routing_plan is None:
        return state.model_copy(update={
            "current_target": "Supervisor",
            "errors": [*state.errors, "unclassifiable_request"],
            "dynamic_routing_chain": [],
        })
    return state.model_copy(update={
        "current_target": "Supervisor",
        "dynamic_routing_chain": routing_plan,
        "payload": {**state.payload, "routing_plan": routing_plan, "current_step": 0},
    })


def pipeline_agent_node(state: SwarmState) -> SwarmState:
    """Mock Jenkins domain agent. Read-only per playbook.md tool scope."""
    build_ctx = state.payload.get("build_context", {})
    result = {
        "job_name": build_ctx.get("job_name", "unknown-job"),
        "build_number": build_ctx.get("build_number", 0),
        "status": build_ctx.get("status", "FAILURE"),
        "relevant_log_excerpt": build_ctx.get(
            "log_excerpt", "[mock] security gate step failed: dependency scan flagged critical CVE"
        ),
        "artifacts": [],
        "error": None,
    }
    return state.model_copy(update={
        "current_target": "Pipeline-Agent",
        "payload": {**state.payload, "pipeline_agent_output": result},
    })


def cloud_agent_node(state: SwarmState) -> SwarmState:
    """Mock AWS Security Hub / Cloud Custodian agent. Strictly read-only."""
    finding_ctx = state.payload.get("finding_context", {})
    severity = finding_ctx.get("severity", "CRITICAL")
    result = {
        "findings": [{
            "id": finding_ctx.get("finding_id", "mock-finding-001"),
            "title": finding_ctx.get("title", "S3 bucket policy allows public write"),
            "severity": severity,
            "resource_arn": finding_ctx.get("resource_arn", "arn:aws:s3:::mock-bucket"),
            "aws_account_id": finding_ctx.get("aws_account_id", "000000000000"),
            "status": "ACTIVE",
            "first_observed_at": "2026-07-10T00:00:00Z",
        }],
        "summary": {"CRITICAL": 1 if severity == "CRITICAL" else 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
        "correlated_build": state.payload.get("pipeline_agent_output", {}).get("build_number"),
        "error": None,
    }
    return state.model_copy(update={
        "current_target": "Cloud-Agent",
        "payload": {**state.payload, "cloud_agent_output": result},
    })


def incident_agent_node(state: SwarmState) -> SwarmState:
    """Mock Jira agent. Applies severity->priority mapping from playbook.md."""
    cloud_output = state.payload.get("cloud_agent_output", {})
    severity = "LOW"
    if cloud_output.get("findings"):
        severity = cloud_output["findings"][0]["severity"]
    priority_map = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}
    result = {
        "action_performed": "CREATE",
        "issue_key": "SEC-999",
        "issue_url": "https://mock.atlassian.net/browse/SEC-999",
        "transition_applied": None,
        "priority": priority_map.get(severity, "P4"),
        "error": None,
    }
    return state.model_copy(update={
        "current_target": "Incident-Agent",
        "payload": {**state.payload, "incident_agent_output": result},
    })


def pop_routing_chain(state: SwarmState) -> SwarmState:
    """Advances the chain after the routed node has executed."""
    if not state.dynamic_routing_chain:
        return state
    remaining = state.dynamic_routing_chain[1:]
    step = state.payload.get("current_step", 0) + 1
    return state.model_copy(update={
        "dynamic_routing_chain": remaining,
        "payload": {**state.payload, "current_step": step},
    })


# ---------------------------------------------------------------------------
# 3. Conditional Routing
# ---------------------------------------------------------------------------

NODE_MAP = {
    "Pipeline-Agent": "pipeline_agent_node",
    "Cloud-Agent": "cloud_agent_node",
    "Incident-Agent": "incident_agent_node",
}


def route_next(state: SwarmState) -> str:
    """Conditional edge function: decide the next node, or END."""
    halt_on_error = state.payload.get("halt_on_error", True)
    if state.errors and halt_on_error:
        return END
    if not state.dynamic_routing_chain:
        return END
    next_hop = state.dynamic_routing_chain[0]
    return NODE_MAP[next_hop]


# ---------------------------------------------------------------------------
# 4. GatewayGuard — GitOps entry-boundary middleware
# ---------------------------------------------------------------------------

class GatewayGuardError(RuntimeError):
    """Raised when a run fails the entry-boundary check."""


BOT_BRANCH_PATTERN = re.compile(r"^feat/bot-[a-z0-9\-]+$")
PROTECTED_BRANCHES = {"main"}


def _current_branch() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def gateway_guard(source_branch: str | None = None) -> str:
    """Entry-boundary check, invoked before StateGraph is ever compiled.

    Enforces playbook.md's GitOps & Deployment Constraints:
      1. No direct execution against `main`.
      2. Branch must match feat/bot-[feature-description].
    Blocks compilation immediately on violation — no node, and no graph
    at all, is constructed for a non-compliant branch.
    """
    branch = source_branch if source_branch is not None else _current_branch()

    if branch in PROTECTED_BRANCHES:
        raise GatewayGuardError(
            f"GatewayGuard: blocked compilation — '{branch}' is a protected branch. "
            "Runs that may alter code must use a feat/bot-* branch (playbook.md GitOps rule 1)."
        )
    if not BOT_BRANCH_PATTERN.match(branch):
        raise GatewayGuardError(
            f"GatewayGuard: blocked compilation — branch '{branch}' does not match "
            "required naming convention 'feat/bot-[feature-description]' (playbook.md GitOps rule 2)."
        )
    return branch


def build_graph(source_branch: str | None = None):
    """Runs GatewayGuard, then compiles the StateGraph. Raises before
    compiling anything if the branch check fails."""
    gateway_guard(source_branch)

    builder = StateGraph(SwarmState)

    builder.add_node("supervisor_node", supervisor_node)
    builder.add_node("pipeline_agent_node", pipeline_agent_node)
    builder.add_node("cloud_agent_node", cloud_agent_node)
    builder.add_node("incident_agent_node", incident_agent_node)
    builder.add_node("pop_routing_chain", pop_routing_chain)

    builder.set_entry_point("supervisor_node")
    # supervisor_node only seeds the chain — nothing has executed yet, so it
    # routes on the chain as-is, with no pop.
    builder.add_conditional_edges("supervisor_node", route_next)
    # Each sub-agent node has just executed its hop, so pop_routing_chain
    # consumes that hop before routing to the next one.
    builder.add_edge("pipeline_agent_node", "pop_routing_chain")
    builder.add_edge("cloud_agent_node", "pop_routing_chain")
    builder.add_edge("incident_agent_node", "pop_routing_chain")

    builder.add_conditional_edges("pop_routing_chain", route_next)

    return builder.compile()


# ---------------------------------------------------------------------------
# 5. Mock end-to-end test: critical pipeline vulnerability finding
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # This mock run assumes it's invoked from a compliant feat/bot-* branch.
    # Override here rather than reading the repo's actual branch, so the demo
    # doesn't depend on what branch this script happens to be run from.
    MOCK_BRANCH = "feat/bot-week13-swarm-demo"

    print(f"--- GatewayGuard check (branch='{MOCK_BRANCH}') ---")
    graph = build_graph(source_branch=MOCK_BRANCH)
    print("GatewayGuard: PASS — graph compiled.\n")

    initial_state = SwarmState(
        payload={
            "request_id": "req-mock-critical-001",
            "original_request": "build failed: CI security gate blocked deploy, pipeline breach detected",
            "build_context": {
                "job_name": "payments-service/main",
                "build_number": 4821,
                "status": "FAILURE",
                "log_excerpt": "[ERROR] dependency-check: CVE-2026-31337 CRITICAL in libfoo 2.3.1",
            },
            "finding_context": {
                "finding_id": "sechub-finding-77213",
                "title": "Vulnerable dependency reachable from internet-facing service",
                "severity": "CRITICAL",
                "resource_arn": "arn:aws:ecs:us-east-1:123456789012:service/payments-service",
                "aws_account_id": "123456789012",
            },
            "halt_on_error": True,
        }
    )

    print("--- Running swarm on a critical pipeline vulnerability finding ---")
    final_state_dict = graph.invoke(initial_state)
    final_state = SwarmState(**final_state_dict)

    print(f"current_target: {final_state.current_target}")
    print(f"errors: {final_state.errors}")
    print(f"dynamic_routing_chain (remaining): {final_state.dynamic_routing_chain}")
    print("payload:")
    for key in ("routing_plan", "pipeline_agent_output", "cloud_agent_output", "incident_agent_output"):
        print(f"  {key}: {final_state.payload.get(key)}")

    assert final_state.errors == [], "expected no errors in mock run"
    assert final_state.payload["incident_agent_output"]["priority"] == "P1", "CRITICAL finding must map to P1"
    assert final_state.payload["incident_agent_output"]["issue_key"], "expected a Jira issue to be filed"
    print("\nEnd-to-end assertion PASS: CRITICAL finding routed Pipeline -> Cloud -> Incident, filed as P1.")
