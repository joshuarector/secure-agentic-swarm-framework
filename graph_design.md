# LangGraph State Graph Specification — Security Operations Swarm
## Week 13 — formalizing the Month 3 Supervisor Hub-and-Spoke playbook

This document maps the existing Supervisor / Pipeline-Agent / Incident-Agent /
Cloud-Agent hub-and-spoke system (`playbook.md`) onto a formal LangGraph
`StateGraph`. It defines the shared state schema, node contracts, conditional
routing derived from the playbook's Routing Matrix, and the `GatewayGuard`
entry-boundary check that keeps the graph's own GitOps branch rules intact.

---

## 1. Shared Graph State

```python
from pydantic import BaseModel, Field


class SwarmState(BaseModel):
    """Shared state threaded through the Supervisor hub-and-spoke graph."""

    current_target: str = Field(
        default="",
        description=(
            "Identifier of the active hop, e.g. 'Pipeline-Agent', "
            "'Cloud-Agent', 'Incident-Agent', or 'Supervisor'."
        ),
    )
    payload: dict = Field(
        default_factory=dict,
        description=(
            "The context envelope from playbook.md: request_id, "
            "original_request, routing_plan, current_step, "
            "pipeline_agent_output, cloud_agent_output, incident_agent_output, "
            "supervisor_auth_token, halt_on_error."
        ),
    )
    dynamic_routing_chain: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered queue of remaining sub-agent hops, seeded by the "
            "Supervisor from the Routing Matrix (e.g. "
            "['Pipeline-Agent', 'Cloud-Agent', 'Incident-Agent'])."
        ),
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Accumulated error messages. A non-empty list with halt_on_error=True stops the chain.",
    )
```

`payload` intentionally stays a loose `dict` rather than a nested Pydantic
model per sub-agent, because the context envelope in `playbook.md` is already
a append-only JSON object accumulated across hops — nodes only ever add a key,
never restructure it.

---

## 2. Nodes

Nodes are pure functions, `SwarmState -> SwarmState`. Each node corresponds to
one playbook role and enforces that role's domain boundary and tool scope —
the graph is the mechanism, `playbook.md` remains the source of truth for
tool permissions.

```python
def supervisor_node(state: SwarmState) -> SwarmState:
    """Classifies the request against the Routing Matrix and seeds the chain.

    Runs once, on entry. Never calls Jenkins/Jira/AWS tools directly
    (playbook.md: Supervisor operational constraints).
    """
    request = state.payload["original_request"]
    routing_plan = classify_request(request)  # -> list[str], per Routing Matrix
    if routing_plan is None:
        return state.model_copy(update={
            "errors": [*state.errors, "unclassifiable_request"],
            "dynamic_routing_chain": [],
        })
    return state.model_copy(update={
        "current_target": "Supervisor",
        "dynamic_routing_chain": routing_plan,
        "payload": {**state.payload, "routing_plan": routing_plan, "current_step": 0},
    })


def pipeline_agent_node(state: SwarmState) -> SwarmState:
    """Jenkins domain only. Read-only unless supervisor_auth_token is present."""
    result = run_pipeline_agent(state.payload)  # calls mcp__mcp-jenkins__* per tool scope
    if result.get("error"):
        return state.model_copy(update={"errors": [*state.errors, result["error"]]})
    return state.model_copy(update={
        "current_target": "Pipeline-Agent",
        "payload": {**state.payload, "pipeline_agent_output": result},
    })


def cloud_agent_node(state: SwarmState) -> SwarmState:
    """AWS Security Hub / Cloud Custodian domain only. Strictly read-only."""
    result = run_cloud_agent(state.payload)  # calls mcp__mcp-aws__* per tool scope
    if result.get("error"):
        return state.model_copy(update={"errors": [*state.errors, result["error"]]})
    return state.model_copy(update={
        "current_target": "Cloud-Agent",
        "payload": {**state.payload, "cloud_agent_output": result},
    })


def incident_agent_node(state: SwarmState) -> SwarmState:
    """Jira domain only. Applies severity->priority mapping from playbook.md."""
    result = run_incident_agent(state.payload)  # calls mcp__mcp-atlassian__jira_* per tool scope
    if result.get("error"):
        return state.model_copy(update={"errors": [*state.errors, result["error"]]})
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
```

`run_pipeline_agent` / `run_cloud_agent` / `run_incident_agent` are the
existing sub-agent implementations from Month 3 — this spec only formalizes
their entry/exit shape, it doesn't change their internal tool scopes or
prohibitions.

---

## 3. Conditional Routing

`route_next` is the single conditional-edge function, registered after
`pop_routing_chain`. It encodes two playbook rules directly:

- **`halt_on_error`** — if `errors` is non-empty and the envelope's
  `halt_on_error` flag is true, route to `END` immediately regardless of
  remaining chain (playbook.md, Sequential Handoff Protocol, rule 3).
- **Empty chain** — once `dynamic_routing_chain` is exhausted, route to `END`
  (Supervisor synthesizes the final response outside the graph loop).

```python
from langgraph.graph import END

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
```

This reproduces the playbook's Routing Decision Tree as data (the
`routing_plan` list built by `supervisor_node`) rather than as branching code,
so the Routing Matrix stays the single place that encodes execution order.

---

## 4. GatewayGuard — Entry-Boundary Check

`GatewayGuard` is evaluated **before** the graph accepts any invocation — it
is not a graph node and does not appear in `dynamic_routing_chain`. Its job is
to keep the swarm's own GitOps & Deployment Constraints (`playbook.md` §
"GitOps & Deployment Constraints") intact whenever a graph run could result in
a code change (e.g. a Pipeline-Agent execute-mode call, or any run invoked
from an automation context that also patches this repo).

Enforced rules, taken directly from `playbook.md`:

1. Direct commits to `main` are prohibited.
2. Any code-touching run must be scoped to a branch matching
   `feat/bot-[feature-description]`.
3. The run must be able to reach PR ingress (`gh pr create`) rather than
   push straight to a protected branch.
4. Merge to `main` is human-only — the guard never authorizes a merge, only
   the branch the run is permitted to operate on.

```python
import re

class GatewayGuardError(RuntimeError):
    """Raised when a run fails the entry-boundary check."""


BOT_BRANCH_PATTERN = re.compile(r"^feat/bot-[a-z0-9\-]+$")
PROTECTED_BRANCHES = {"main"}


def gateway_guard(state: SwarmState, source_branch: str) -> SwarmState:
    """Entry-boundary check, invoked before graph.invoke()/graph.stream().

    Rejects any run whose source_branch violates the GitOps & Deployment
    Constraints in playbook.md, before payload/routing state is trusted
    downstream by any node.
    """
    if source_branch in PROTECTED_BRANCHES:
        raise GatewayGuardError(
            f"Rejected: direct execution against protected branch '{source_branch}'. "
            "Runs that may alter code must use a feat/bot-* branch (playbook.md GitOps rule 1)."
        )
    if not BOT_BRANCH_PATTERN.match(source_branch):
        raise GatewayGuardError(
            f"Rejected: source_branch '{source_branch}' does not match required "
            "naming convention 'feat/bot-[feature-description]' (playbook.md GitOps rule 2)."
        )
    return state
```

Wiring: the graph invoker calls `gateway_guard` immediately after
`SwarmState` is constructed and before `graph.invoke(...)` — a failed check
raises `GatewayGuardError` and no node ever executes.

```python
def run_swarm(initial_state: SwarmState, source_branch: str, graph):
    state = gateway_guard(initial_state, source_branch)
    return graph.invoke(state)
```

This check governs *branch context for the run*, not sub-agent tool scope —
Pipeline-Agent/Incident-Agent/Cloud-Agent tool permissions and prohibitions
from `playbook.md` remain enforced independently inside each node.

---

## 5. Graph Assembly

```python
from langgraph.graph import StateGraph

builder = StateGraph(SwarmState)

builder.add_node("supervisor_node", supervisor_node)
builder.add_node("pipeline_agent_node", pipeline_agent_node)
builder.add_node("cloud_agent_node", cloud_agent_node)
builder.add_node("incident_agent_node", incident_agent_node)
builder.add_node("pop_routing_chain", pop_routing_chain)

builder.set_entry_point("supervisor_node")
# supervisor_node only seeds the chain -- nothing has executed yet, so it
# routes on the chain as-is, with no pop first.
builder.add_conditional_edges("supervisor_node", route_next)
# Each sub-agent node has just executed its hop, so pop_routing_chain
# consumes that hop before routing to the next one.
builder.add_edge("pipeline_agent_node", "pop_routing_chain")
builder.add_edge("cloud_agent_node", "pop_routing_chain")
builder.add_edge("incident_agent_node", "pop_routing_chain")

builder.add_conditional_edges("pop_routing_chain", route_next)

graph = builder.compile()
```

Note the entry point is `supervisor_node`, not the guard — `gateway_guard`
runs outside `graph.invoke()` entirely, per § 4, so it can reject a run
without ever constructing a partial LangGraph execution trace.

---

## 6. Mapping Summary (playbook.md → this spec)

| playbook.md concept | LangGraph equivalent |
|---|---|
| Supervisor | `supervisor_node` (entry point) |
| Sub-agent (Pipeline/Incident/Cloud) | `pipeline_agent_node` / `incident_agent_node` / `cloud_agent_node` |
| Context envelope | `SwarmState.payload` |
| Routing Matrix / Decision Tree | `supervisor_node`'s `classify_request` + `dynamic_routing_chain` |
| `halt_on_error` | `route_next` short-circuit to `END` |
| Max chain depth: 3 | Enforced by `classify_request` — never emits a `routing_plan` longer than 3 |
| GitOps & Deployment Constraints | `gateway_guard` entry-boundary check |
