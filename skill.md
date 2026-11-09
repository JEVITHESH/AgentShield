# MASTER PROMPT: BUILD AGENTSHIELD – MCP AI AGENT SECURITY SDK

## ROLE

Act as a Senior Python SDK Architect, AI Security Engineer, MCP Developer, and Open-Source Software Maintainer.

Your task is to design and develop **AgentShield**, a professional, reusable, developer-friendly Python security SDK for protecting MCP-based autonomous AI agents.

Do not build this as a simple college demonstration. Build it as a properly structured, maintainable Python package that other developers can install and integrate into their projects.

## 1. PROJECT OBJECTIVE

AgentShield is a dynamic security and autonomy-control middleware between MCP clients and MCP servers.

Its purpose is to:
- Intercept MCP tool requests.
- Assess operation risk.
- Maintain behavioral trust.
- Control agent autonomy dynamically.
- Detect suspicious operations.
- Prevent unauthorized information flows.
- Track cumulative tool-chain risk.
- Require human approval for sensitive operations.
- Verify approved operations before execution.
- Maintain security audit logs.

## 2. CORE TECHNOLOGY STACK

Use:

- Python 3.11+
- MCP Python SDK
- Pydantic
- NumPy
- SciPy
- SQLite
- Pytest
- Cryptography
- Ruff
- Python packaging standards (pyproject.toml)

Optional:
- Gemini API for System 2 analysis.
- FastAPI for optional dashboard/API.
- Docker for isolated testing.

Do not make external AI API access mandatory.

## 3. CORE ARCHITECTURE

Develop the following independent modules:

A. MCP Middleware
- Intercept MCP tool requests.
- Validate tool names and arguments.
- Apply security policies.
- Control execution.
- Support MCP client/server integration.

B. Dynamic Risk Assessment Engine

Implement eight risk factors:

1. Tool Criticality
2. Data Sensitivity
3. User Intent Risk
4. Prompt Injection Risk
5. Behavioral Risk
6. Historical Risk
7. Chain Dependency
8. Operation Risk

Normalize risk values between 0 and 1.

Implement configurable risk weights.

C. Tier-Stratified Bayesian Trust

- Maintain trust independently for each operation criticality tier.
- Use Beta distributions.
- Maintain positive and negative evidence.
- Implement asymmetric trust updates.
- Prevent low-tier trust farming.
- Implement configurable trust decay.

D. Information Flow Control

Implement security labels:

- Public
- Internal
- Confidential
- Credential

Use security lattice comparisons and sink clearance policies.

E. Cumulative Tool-Chain Risk

- Track previous operations.
- Maintain session-level risk.
- Identify suspicious operation sequences.
- Implement bounded, monotonic cumulative risk.

F. Dual-Process Decision Core

System 1:
- Fast risk prediction.
- Low-latency decision support.
- Monotonic risk constraints.

System 2:
- Detailed security analysis.
- Handle uncertain or suspicious requests.
- Support optional LLM-based analysis.
- Support human escalation.

System 2 must not override deterministic security restrictions.

G. Dynamic Autonomy Controller

Implement five levels:

L4: Autonomous
L3: Monitored
L2: Restricted
L1: Human Approval
L0: Block

Higher risk must never increase autonomy.
Higher trust may increase autonomy only within policy limits.

H. Execution Integrity

- Generate approval-bound operation digests.
- Bind approvals to normalized operation parameters, tool definitions and session security labels.
- Recheck approval integrity immediately before execution.
- Detect post-approval operation changes.
- Verify execution outcomes.

I. Security Audit Logger

Record:
- Request ID
- Agent identity
- Tool name
- Risk score
- Trust score
- Autonomy level
- Security decision
- Approval status
- Execution result
- Timestamp

Maintain tamper-evident audit records.

## 4. DEVELOPER EXPERIENCE

The SDK must be simple to integrate.

Target installation:

pip install agentshield

Provide a clean public Python API.

Example of intended API:

from agentshield import AgentShield

shield = AgentShield()

result = shield.protect_tool(
    tool_name="read_file",
    arguments={"path": "sample.txt"}
)

This is a design target. Implement and test the API before documenting it as available.

Support:
- Simple initialization.
- Configurable security policies.
- MCP middleware integration.
- Custom risk rules.
- Human approval callbacks.
- Audit log retrieval.
- Clear error handling.

## 5. PACKAGE STRUCTURE

Create a professional modular package:

agentshield/
    __init__.py
    core/
        engine.py
        config.py
        exceptions.py
    mcp/
        client.py
        middleware.py
        interceptor.py
    risk/
        engine.py
        factors.py
    trust/
        bayesian.py
        tiers.py
    security/
        information_flow.py
        chain_risk.py
        injection.py
        integrity.py
    decision/
        system1.py
        system2.py
        autonomy.py
    approval/
        manager.py
    verification/
        outcome.py
    audit/
        logger.py
    policies/
        defaults.py

tests/
examples/
docs/
pyproject.toml
README.md
LICENSE
CHANGELOG.md

Adjust the structure when technically justified, without unnecessarily complicating the package.

## 6. DEVELOPMENT RULES

- Build actual working source code, not pseudocode.
- Do not generate placeholder implementations for core security functions.
- Never silently allow a tool call when security validation fails.
- Default to deny for unknown or unregistered tools.
- Validate every tool request before execution.
- Keep policy enforcement outside the LLM.
- Do not trust LLM-generated security decisions without deterministic validation.
- Never execute destructive operations automatically in the test environment.
- Use mock tools and temporary test files.
- Do not expose API keys or credentials.
- Add type hints and docstrings.
- Follow clean-code principles.
- Use asynchronous execution where appropriate.
- Handle exceptions safely.
- Make configuration explicit and documented.
- Keep dependencies minimal.

## 7. TESTING REQUIREMENTS

Create automated tests for:

1. Normal file access.
2. Unauthorized tool access.
3. High-risk operations.
4. Prompt injection indicators.
5. Bayesian trust updates.
6. Trust farming attempts.
7. Confidential data leakage.
8. Cumulative chain risk.
9. Autonomy-level decisions.
10. Human approval.
11. Operation hash mismatch.
12. Execution verification.
13. Audit log integrity.
14. MCP client/server integration.

Use simulated attacks in isolated environments.

## 8. DOCUMENTATION

Create:

- Installation guide.
- Quick-start guide.
- Architecture documentation.
- API reference.
- MCP integration tutorial.
- Security policy configuration guide.
- Examples.
- Troubleshooting guide.
- Developer contribution guide.

## 9. PACKAGE RELEASE

Prepare the package for:

- GitHub open-source repository.
- PyPI distribution.
- Semantic versioning.
- Automated testing.
- Package build validation.
- Dependency and security checks.

Do not publish to PyPI without explicit human approval.

## 10. DEVELOPMENT WORKFLOW

Follow this sequence:

Phase 1: Inspect environment and establish package architecture.

Phase 2: Create the Python package foundation.

Phase 3: Implement MCP middleware.

Phase 4: Implement risk assessment.

Phase 5: Implement Bayesian trust management.

Phase 6: Implement autonomy control.

Phase 7: Implement information flow and cumulative chain risk.

Phase 8: Implement System 1 and System 2.

Phase 9: Implement approval, integrity and verification.

Phase 10: Implement audit logging.

Phase 11: Complete automated testing.

Phase 12: Create documentation and release preparation.

At the end of every phase:

1. Explain what was developed.
2. List files created or modified.
3. Run relevant tests.
4. Report actual test results.
5. Identify unresolved issues.
6. Explain the next phase.
7. Wait for my approval before proceeding to the next phase.

## 11. FINAL EXPECTATION

Deliver a working, modular, secure Python SDK that developers can integrate into their MCP-based AI agent applications.

Prioritize correctness, security, maintainability, testability, and ease of use over unnecessary features.

IMPORTANT: Start with Phase 1 only. Inspect the development environment, propose the architecture, and report your plan. Do not implement all phases in one response. Never claim a feature is implemented unless its source code and tests exist and pass.