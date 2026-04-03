"""Example: Test a LangChain agent with agent-probe.

Requirements:
    pip install agent-probe langchain langchain-openai

This example shows how to wrap a LangChain AgentExecutor
as a FunctionTarget for adversarial testing.
"""

from agent_probe.engine import run_probes
from agent_probe.reporter import format_text_report
from agent_probe.sarif import format_sarif
from agent_probe.targets.function import FunctionTarget

# --- Uncomment and adapt to your LangChain setup ---

# from langchain.agents import AgentExecutor, create_openai_tools_agent
# from langchain_openai import ChatOpenAI
# from langchain_core.prompts import ChatPromptTemplate
#
# llm = ChatOpenAI(model="gpt-4o-mini")
# prompt = ChatPromptTemplate.from_messages([
#     ("system", "You are a helpful assistant."),
#     ("human", "{input}"),
#     ("placeholder", "{agent_scratchpad}"),
# ])
# agent = create_openai_tools_agent(llm, tools=[], prompt=prompt)
# executor = AgentExecutor(agent=agent, tools=[])
#
# target = FunctionTarget(
#     lambda msg: executor.invoke({"input": msg})["output"],
#     name="langchain-gpt4o-mini",
# )
#
# results = run_probes(target)
# print(format_text_report(results))
#
# # SARIF output for CI/CD
# with open("langchain-report.sarif", "w") as f:
#     f.write(format_sarif(results))


def main() -> None:
    """Demo with a mock LangChain-like function."""

    def mock_langchain_agent(message: str) -> str:
        """Simulates a LangChain agent response."""
        lower = message.lower()
        if "system prompt" in lower or "instructions" in lower:
            return "I cannot share my system prompt."
        if "rm -rf" in lower or "drop table" in lower:
            return "I cannot execute destructive commands."
        return f"I can help with that: {message}"

    target = FunctionTarget(
        mock_langchain_agent,
        name="mock-langchain",
    )
    results = run_probes(target)
    print(format_text_report(results))

    # Generate SARIF for GitHub Security tab
    print("\n--- SARIF output ---")
    print(format_sarif(results))


if __name__ == "__main__":
    main()
