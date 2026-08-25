from core.ai.contracts import EvaluationResult


def evaluate(case, run):
    used = tuple(result.tool for result in run.tool_results)
    references = {citation.reference for result in run.tool_results for citation in result.citations}
    expected = set(case.expected_citations)
    recall = len(expected & references) / len(expected) if expected else 1.0
    errors = []
    if not set(case.expected_tools).issubset(used): errors.append("missing expected tools")
    if recall < 1.0: errors.append("missing expected citations")
    return EvaluationResult(case.name, not errors, recall, used, tuple(errors))
