from core.ai.contracts import AIRunRecord


class AISession:
    """Policy-enforced orchestration contract; no model provider is configured by default."""
    def __init__(self, provider, tools):
        self.provider = provider
        self.tools = tools

    def run(self, prompt, scope, policy):
        record = AIRunRecord(scope=scope, policy=policy)
        calls = 0
        while True:
            turn = self.provider.respond(prompt, scope, tuple(record.tool_results))
            record.turns.append(turn)
            if not turn.tool_calls:
                record.final_text = turn.text
                record.status = "COMPLETE"
                return record
            for call in turn.tool_calls:
                if call.name not in policy.allowed_tools:
                    record.status = "POLICY_BLOCKED"
                    raise PermissionError(f"AI tool is not allowed by policy: {call.name}")
                calls += 1
                if calls > policy.max_tool_calls:
                    record.status = "POLICY_BLOCKED"
                    raise RuntimeError("AI tool-call limit exceeded")
                record.tool_results.append(self.tools.execute(call.name, scope, **call.arguments))
