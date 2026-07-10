# Secure Multi-Agent Orchestration & AppSec Swarm Framework

An enterprise-grade, zero-trust AI agent orchestration runtime built to automate DevSecOps engineering workflows securely. This laboratory framework shifts AI integration away from fragile, linear chat sessions into a deterministic, multi-agent **Hub-and-Spoke Swarm Architecture** hardened against adversarial threats.

## 🏗️ Architectural Overview

This framework utilizes Anthropic's **Model Context Protocol (MCP)** specification to orchestrate a decentralized swarm of hyper-specialized security sub-agents led by an isolated Supervisor model.

### Core Security & Performance Pillars

1. **Least-Privilege Isolation:** The central `Supervisor` model manages state-routing logic and task sequencing but is entirely stripped of direct tool execution capabilities, neutralizing the blast radius of a primary prompt injection.
2. **Bidirectional LLM Firewall (`GatewayGuard`):** A deterministic execution middleware layer that inspects data at both boundaries:
   * **Ingress Filtering:** Blocks indirect prompt injections, shell smuggling patterns, and persona-hijack strings *before* token inference occurs.
   * **Egress Containment:** Recursively deep-scans sub-agent dictionary output trees to intercept accidental token leaks, exposed cryptographic private keys, or long-term cloud access credentials (`AKIA`/`ASIA` keys).
3. **Contract-Driven Memory Management (`ContextEnvelope`):** Enforces a strict schema validation and token-compression utility that programmatically prunes verbose tool outputs down to metadata dictionaries, eliminating model hallucinations and controlling token cost inflation.
4. **Supply-Chain Integrity:** Leverages deterministic Python dependencies via cryptographically pinned SHA-256 package hashes alongside automated pre-execution vulnerability auditing.

## 🚀 Adversarial Verification & Stability Matrix

The framework includes a comprehensive regression testbed (`run_simulation.py`) that executes a multi-stage simulation loop using simulated "Red Team" injection payloads. The application successfully validates full system containment:

* **Input Containment:** Gracefully traps instruction-overrides and persona-hijacks, logging a persistent `input_violations.json` audit trail on disk.
* **Output Containment:** Intercepts credential leak strings and prohibited tool invocations, appending telemetry data safely to the `ContextEnvelope.audit_log`.
* **State Stability:** Proves full resilience by preserving internal state and successfully executing standard control requests immediately following active containment events.

## 🛠️ Repository Manifest

* `playbook.md`: System blueprints, role-scoping manifests, and tool limitation constraints.
* `swarm_orchestrator.py`: Core application runtime, `ContextEnvelope` class, and `GatewayGuard` middleware.
* `run_simulation.py`: Adversarial simulation testbed validating the active Red vs. Blue containment loops.
* `requirements.txt`: Cryptographically hash-pinned third-party package dependencies.
