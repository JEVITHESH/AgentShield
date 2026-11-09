# AgentShield

**AgentShield** is a dynamic security and autonomy-control middleware SDK for protecting Model Context Protocol (MCP) based autonomous AI agents.

## Features

- **MCP Middleware & Interception**: Intercepts MCP tool calls, validates inputs, and enforces security boundaries.
- **Dynamic 8-Factor Risk Assessment**: Evaluates tool criticality, data sensitivity, user intent, injection indicators, behavior, history, chain dependency, and operation risk.
- **Tier-Stratified Bayesian Trust**: Prevents trust farming using Beta distribution modeling across independent criticality tiers.
- **Information Flow Control**: Lattice-based taint tracking (`Public < Internal < Confidential < Credential`).
- **Cumulative Tool-Chain Risk**: Tracks cross-tool operation sequences to detect chained exfiltration attacks.
- **Dual-Process Decision Core**: Low-latency System 1 deterministic enforcement paired with System 2 deep analysis.
- **Dynamic Autonomy Controller**: Granular 5-level autonomy (`L0: Block` to `L4: Autonomous`).
- **Execution Integrity & Cryptographic Signatures**: Approval-bound HMAC digests preventing post-approval parameter tampering.
- **Tamper-Evident Audit Logging**: Hash-chained SQLite audit records.

## Installation

```bash
pip install agentshield
```

## Quick Start

```python
from agentshield import AgentShield, ShieldConfig

shield = AgentShield(config=ShieldConfig())

# Check and protect tool execution
result = shield.protect_tool(
    tool_name="read_file",
    arguments={"path": "sample.txt"}
)

if result.allowed:
    print(f"Tool execution allowed under autonomy level: {result.autonomy_level}")
else:
    print(f"Blocked or approval required: {result.reason}")
```

## License

MIT License.
