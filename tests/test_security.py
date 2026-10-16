import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sentinel_core as core


def test_safe_calculator_returns_correct_result():
    assert core.safe_calculate("(125 * 8) + 40") == 1040


def test_safe_calculator_rejects_code_execution():
    with pytest.raises((ValueError, TypeError, SyntaxError)):
        core.safe_calculate("__import__('os').system('echo hacked')")


def test_verifier_accepts_valid_calculation():
    result = {"status": "success", "result": 2500}
    assert core.verify_tool_result(result, "calculate") is True


def test_verifier_rejects_nan():
    result = {"status": "success", "result": float("nan")}
    assert core.verify_tool_result(result, "calculate") is False


def test_verifier_rejects_incomplete_analysis():
    result = {"status": "success", "result": {"row_count": 4}}
    assert core.verify_tool_result(result, "analyze_data") is False


def test_unauthorized_tool_is_blocked():
    request = core.ToolRequest(
        tool_name=core.ToolName.DELETE_FILE,
        arguments={"path": "test.txt"},
    )
    result = core.execute_tool(request)
    assert result["status"] == "blocked"


def test_plan_rejects_unapproved_dataset():
    with pytest.raises(Exception):
        core.SecureAgentPlan.model_validate({
            "goal": "Analyze a private dataset",
            "steps": [{
                "step_id": 1,
                "tool_name": "analyze_data",
                "arguments": {"dataset_ref": "private_database"},
            }],
        })


def test_plan_rejects_unauthorized_tool():
    with pytest.raises(Exception):
        core.SecureAgentPlan.model_validate({
            "goal": "Delete a file",
            "steps": [{
                "step_id": 1,
                "tool_name": "delete_file",
                "arguments": {"path": "test.txt"},
            }],
        })


def test_secure_plan_records_execution_events():
    core.EXECUTION_EVENTS.clear()

    plan = core.SecureAgentPlan.model_validate({
        "goal": "Calculate a simple result",
        "steps": [{
            "step_id": 1,
            "tool_name": "calculate",
            "arguments": {"expression": "2 + 2"},
        }],
    })

    results = core.execute_secure_plan(plan, [])

    assert len(results) == 1
    assert results[0]["result"]["result"] == 4
    assert len(core.EXECUTION_EVENTS) == 1
    assert core.EXECUTION_EVENTS[0]["status"] == "SUCCESS"
