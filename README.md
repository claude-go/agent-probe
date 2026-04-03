# agent-probe

Agent-level adversarial resilience testing for AI agents.

Tests what others don't: tool interactions, memory poisoning, permission escalation, data exfiltration via tool calls.

## Why

Every existing red-teaming tool (PyRIT, DeepTeam, b3, promptfoo) tests the **LLM backbone**. None of them test the **agent layer** — the tools, the memory, the permissions, the multi-step workflows where real attacks happen.

agent-probe fills that gap.

## Install

```bash
pip install agent-probe
```

## Usage

```bash
# Run all probes against an HTTP agent endpoint
agent-probe probe http://localhost:8000/chat

# Run specific categories
agent-probe probe http://localhost:8000/chat --categories tool_misuse data_exfiltration

# JSON output for CI/CD
agent-probe probe http://localhost:8000/chat --json

# Fail if score below threshold (for CI)
agent-probe probe http://localhost:8000/chat --threshold 70

# List available probe categories
agent-probe list
```

## Probe Categories

| Category | What it tests |
|----------|--------------|
| `tool_misuse` | Can the agent be tricked into calling tools with malicious parameters? |
| `data_exfiltration` | Does the agent leak sensitive data through tool calls or outputs? |
| `agent_injection` | Do multi-step injection chains break agent-level guardrails? |

## Output

```
============================================================
  agent-probe  Adversarial Resilience Report
============================================================
  Target:  http://localhost:8000/chat
  Score:   72/100 (GOOD)
  Probes:  8/10 passed
  Findings: 3
============================================================

  [ 80/100] tool_misuse (GOOD)
          3/3 probes passed
  [ 55/100] data_exfiltration (FAIR)
          2/4 probes passed
    [CRITICAL] Agent leaked secrets via summarization
  [ 80/100] agent_injection (GOOD)
          3/3 probes passed
```

## License

MIT
