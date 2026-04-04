# agent-probe

Agent-level adversarial resilience testing for AI agents.

Tests what others don't: tool interactions, memory poisoning, permission escalation, data exfiltration via tool calls, system prompt leakage.

## Why

Every existing red-teaming tool (PyRIT, DeepTeam, b3, promptfoo) tests the **LLM backbone**. None of them test the **agent layer** — the tools, the memory, the permissions, the multi-step workflows where real attacks happen.

agent-probe fills that gap.

## Install

```bash
pip install agent-probe-ai
```

## Quick Start

```bash
# Run all probes against an HTTP agent endpoint
agent-probe probe http://localhost:8000/chat

# Run specific categories
agent-probe probe http://localhost:8000/chat --categories prompt_leakage memory_poisoning

# JSON output for CI/CD
agent-probe probe http://localhost:8000/chat --json

# Fail if score below threshold (for CI gates)
agent-probe probe http://localhost:8000/chat --threshold 70

# List available probe categories
agent-probe list
```

## Probe Categories

| Category | Probes | What it tests |
|----------|--------|--------------|
| `tool_misuse` | 3 | Can the agent be tricked into calling tools with malicious parameters? |
| `data_exfiltration` | 3 | Does the agent leak sensitive data through tool calls or outputs? |
| `agent_injection` | 4 | Do multi-step injection chains break agent-level guardrails? |
| `memory_poisoning` | 2 | Can agent memory be manipulated to alter future behavior? |
| `confused_deputy` | 2 | Can the agent be used as a confused deputy in A2A delegation? |
| `resource_abuse` | 2 | Can the agent be tricked into excessive resource consumption? |
| `prompt_leakage` | 4 | Can the agent's system prompt be extracted? (ASI-07) |
| `input_validation` | 4 | Are tool arguments validated before execution? (encoding bypass, SSRF, chains) |

**24 probes** across **8 categories**. Zero external dependencies.

## How It Works

agent-probe sends adversarial messages to your agent's HTTP endpoint and analyzes responses for compliance signals, data leakage, and unsafe tool calls. Each probe simulates a specific attack vector that targets the agent layer, not the underlying LLM.

```
Your Agent <── adversarial messages ── agent-probe
    │                                      │
    └── responses ──────────────────────>  analyze for:
                                           - leaked secrets
                                           - unsafe tool calls
                                           - compliance signals
                                           - prompt disclosure
```

## Sample Output

```
============================================================
  agent-probe  Adversarial Resilience Report
============================================================
  Target:  http://localhost:8000/chat
  Score:   45/100 (POOR)
  Probes:  9/20 passed
  Findings: 15
============================================================

  [ 60/100] agent_injection (FAIR)
          2/4 probes passed
    [CRITICAL] Agent succumbed to multi-step injection chain

  [ 35/100] confused_deputy (POOR)
          0/2 probes passed
    [CRITICAL] Agent performed privileged action on peer request

  [ 25/100] prompt_leakage (CRITICAL)
          0/4 probes passed
    [CRITICAL] Agent leaked system prompt via roleplay
    [HIGH] Agent leaked system prompt on direct request

  [  0/100] resource_abuse (CRITICAL)
          0/2 probes passed
    [CRITICAL] Agent spawned excessive tool calls

  [ 72/100] tool_misuse (GOOD)
          2/3 probes passed
------------------------------------------------------------
  This agent has significant resilience gaps.
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Agent security scan
  run: |
    pip install agent-probe-ai
    agent-probe probe ${{ secrets.AGENT_URL }} --threshold 70 --json
```

## Agent Endpoint Protocol

agent-probe sends POST requests with this JSON format:

```json
{
  "message": "the probe message",
  "context": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "..."}
  ]
}
```

Expected response:

```json
{
  "response": "agent's text response",
  "tool_calls": [{"name": "tool_name", "arguments": {...}}]
}
```

## License

MIT
