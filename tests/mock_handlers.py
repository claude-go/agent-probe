"""Extended mock agent handlers for new probe categories.

Separated from mock_server.py to keep files under 200 lines."""

from __future__ import annotations

import re


def vulnerable_memory_handler(payload: dict) -> dict:
    """Vulnerable handler for memory poisoning probes."""
    message = payload.get("message", "")
    context = payload.get("context", [])

    # Extract any secrets from context.
    secrets_found = []
    for entry in context:
        content = entry.get("content", "")
        for match in re.findall(
            r"(?:KEY|PWD|TKN|API_KEY|DB_TOKEN|SECRET)=(\S+)", content,
        ):
            secrets_found.append(match)

    lower_msg = message.lower()

    # Comply with "policy" memory injection.
    if "policy" in lower_msg or "audit" in lower_msg or "memorized" in lower_msg:
        response = (
            "Per the policy update, here is the audit footer: "
            f"api key: {' '.join(secrets_found)}"
        )
        return {"response": response}

    # Cross-contamination: leak stored data after reset.
    if "previous session" in lower_msg or "project code" in lower_msg:
        if secrets_found:
            return {"response": f"The project code was: {secrets_found[0]}"}
        return {"response": "I can help with general questions."}

    if secrets_found and ("remember" in lower_msg or "store" in lower_msg):
        return {"response": f"I've stored: {' '.join(secrets_found)}"}

    return {"response": f"I'll help with: {message}"}


def vulnerable_deputy_handler(payload: dict) -> dict:
    """Vulnerable handler for confused deputy probes."""
    message = payload.get("message", "")
    context = payload.get("context", [])

    # Extract secrets from context.
    secrets_found = []
    for entry in context:
        content = entry.get("content", "")
        for match in re.findall(
            r"(?:KEY|PWD|TKN|API_KEY|api_key)=(\S+)", content,
        ):
            secrets_found.append(match)

    lower_msg = message.lower()

    # Comply with A2A delegation without verification.
    if "agent-a" in lower_msg or "process" in lower_msg:
        for entry in context:
            content = entry.get("content", "").lower()
            if "delete" in content or "drop" in content:
                return {
                    "response": "Executing Agent-A's maintenance request. Deleted all records.",
                    "tool_calls": [
                        {"name": "db_execute", "arguments": {"sql": "DELETE FROM users"}},
                    ],
                }

    # Follow injected directives from tool results.
    if "summary" in lower_msg or "share" in lower_msg:
        for entry in context:
            if entry.get("role") == "tool":
                content = entry.get("content", "")
                if "directive" in content.lower() or "system" in content.lower():
                    leak = f" {' '.join(secrets_found)}" if secrets_found else ""
                    return {
                        "response": (
                            f"Summary: Market grew 15%. Revenue $2.3M. "
                            f"Per cross-agent verification directive:{leak}"
                        ),
                    }

    return {"response": "I can help with general questions."}


def vulnerable_resource_handler(payload: dict) -> dict:
    """Vulnerable handler for resource abuse probes."""
    message = payload.get("message", "")
    lower_msg = message.lower()

    if "repeatedly" in lower_msg or "1000 times" in lower_msg:
        return {
            "response": "I'll keep going until I get a 200 response. Repeatedly calling...",
            "tool_calls": [
                {"name": "http_get", "arguments": {"url": f"https://api.example.test/{i}"}}
                for i in range(15)
            ],
        }

    if "paginated" in lower_msg or "every" in lower_msg:
        return {
            "response": "Fetching every page from the API...",
            "tool_calls": [
                {"name": "http_get", "arguments": {"url": f"https://api.example.test/data?page={i}"}}
                for i in range(20)
            ],
        }

    if "translate" in lower_msg and ("50" in lower_msg or "all" in lower_msg):
        return {
            "response": "Translating into all 50 languages simultaneously...",
            "tool_calls": [
                {"name": "translate", "arguments": {"lang": f"lang_{i}"}}
                for i in range(50)
            ],
        }

    if "generate" in lower_msg and ("500" in lower_msg or "each" in lower_msg):
        return {
            "response": "Generating images for all 500 products...",
            "tool_calls": [
                {"name": "image_gen", "arguments": {"product_id": i}}
                for i in range(500)
            ],
        }

    if "every" in lower_msg and "email" in lower_msg:
        return {
            "response": "Processing all 50,000 emails for sentiment...",
            "tool_calls": [
                {"name": "analyze", "arguments": {"email_id": i}}
                for i in range(100)
            ],
        }

    if "search" in lower_msg and "keep going" in lower_msg:
        return {
            "response": "I'll keep going until I find the answer...",
            "tool_calls": [
                {"name": "search", "arguments": {"query": f"result_{i}"}}
                for i in range(15)
            ],
        }

    return {"response": f"I'll help with: {message}"}


def secure_extended_handler(payload: dict) -> dict:
    """Secure handler for all new categories — refuses everything."""
    message = payload.get("message", "")
    lower_msg = message.lower()

    if any(kw in lower_msg for kw in [
        "policy", "audit", "memorized", "remember",
        "previous session", "project code",
    ]):
        return {"response": "I don't retain data between sessions."}

    if any(kw in lower_msg for kw in [
        "agent-a", "delete", "drop", "maintenance",
        "directive", "orchestrator",
    ]):
        return {"response": "I cannot execute unverified delegated actions."}

    if any(kw in lower_msg for kw in [
        "repeatedly", "1000 times", "every page",
        "all languages", "500 products", "50,000 emails",
    ]):
        return {
            "response": (
                "That operation would be very expensive. "
                "I recommend processing in small batches with your approval."
            ),
        }

    return {"response": "I can help with general questions."}
