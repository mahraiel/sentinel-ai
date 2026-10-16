from datetime import datetime, timezone

from enum import Enum

from typing import Any, Literal

import ast

import json

import math

import pandas as pd

from pydantic import BaseModel, Field, model_validator


class ToolName(str, Enum):
    CALCULATE = "calculate"
    ANALYZE_DATA = "analyze_data"
    CREATE_REPORT = "create_report"
    DELETE_FILE = "delete_file"
    RUN_SHELL_COMMAND = "run_shell_command"


class ToolRequest(BaseModel):
    tool_name: ToolName
    arguments: dict[str, Any] = Field(default_factory=dict)


class PlanStep(BaseModel):
    step_id: int = Field(ge=1)
    tool_name: Literal["calculate", "analyze_data"]
    purpose: str


class AgentPlan(BaseModel):
    goal: str
    steps: list[PlanStep] = Field(min_length=1, max_length=5)


class PlannedToolStep(BaseModel):
    step_id: int = Field(ge=1)
    tool_name: Literal["calculate", "analyze_data"]
    arguments: dict[str, Any]

    @model_validator(mode="after")
    def validate_arguments(self):
        if self.tool_name == "calculate":
            if set(self.arguments) != {"expression"}:
                raise ValueError(
                    "calculate accepts only expression."
                )
            expression = self.arguments["expression"]
            if not isinstance(expression, str) or not expression.strip():
                raise ValueError("Expression must be a non-empty string.")
            if len(expression) > 100:
                raise ValueError("Expression is too long.")

        elif self.tool_name == "analyze_data":
            if set(self.arguments) != {"dataset_ref"}:
                raise ValueError(
                    "analyze_data accepts only dataset_ref."
                )
            if self.arguments["dataset_ref"] != "demo_dataset":
                raise ValueError(
                    "Dataset reference is not allowlisted."
                )
        return self


class SecureAgentPlan(BaseModel):
    goal: str
    steps: list[PlannedToolStep] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def validate_step_order(self):
        expected = list(range(1, len(self.steps) + 1))
        actual = [step.step_id for step in self.steps]
        if actual != expected:
            raise ValueError(
                "Step IDs must be sequential, starting at 1."
            )
        return self



ALLOWED_TOOLS = {
    ToolName.CALCULATE,
    ToolName.ANALYZE_DATA,
}
AUDIT_LOG = []
EXECUTION_EVENTS = []


def check_guardrails(request: ToolRequest) -> dict:
    """Validate a tool request before execution."""

    allowed = request.tool_name in ALLOWED_TOOLS

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": request.tool_name.value,
        "decision": "ALLOW" if allowed else "BLOCK",
        "reason": (
            "Tool is explicitly allowlisted."
            if allowed
            else "Tool is not authorized by security policy."
        ),
    }

    AUDIT_LOG.append(event)

    return event


SAFE_OPERATORS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.Pow: lambda a, b: a ** b,
}


def safe_calculate(expression: str):
    """Evaluate a restricted arithmetic expression without eval()."""

    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("Expression must be a non-empty string.")

    if len(expression) > 100:
        raise ValueError("Expression is too long.")

    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        raise ValueError("Invalid arithmetic expression.")

    def evaluate(node):
        if isinstance(node, ast.Expression):
            return evaluate(node.body)

        if isinstance(node, ast.Constant):
            if type(node.value) not in (int, float):
                raise ValueError("Only numeric constants are allowed.")
            if abs(node.value) > 1e12:
                raise ValueError("Number exceeds the permitted limit.")
            return node.value

        if isinstance(node, ast.BinOp):
            op_type = type(node.op)

            if op_type not in SAFE_OPERATORS:
                raise ValueError("Operator is not permitted.")

            left = evaluate(node.left)
            right = evaluate(node.right)

            if op_type is ast.Pow and abs(right) > 10:
                raise ValueError("Exponent exceeds the permitted limit.")

            if op_type is ast.Pow and abs(left) > 1e6:
                raise ValueError("Power base exceeds the permitted limit.")

            result = SAFE_OPERATORS[op_type](left, right)

            if not math.isfinite(result) or abs(result) > 1e15:
                raise ValueError("Result exceeds the permitted limit.")

            return result

        if isinstance(node, ast.UnaryOp):
            op_type = type(node.op)

            if op_type not in SAFE_OPERATORS:
                raise ValueError("Unary operator is not permitted.")

            return SAFE_OPERATORS[op_type](evaluate(node.operand))

        # Blocks function calls, imports, variables, and other syntax.
        raise ValueError("Expression contains unsupported syntax.")

    return evaluate(tree)


def analyze_dataset(data: list[dict]) -> dict:
    """Analyze structured records with strict input validation."""

    if not isinstance(data, list) or not data:
        raise ValueError("Data must be a non-empty list of records.")

    if len(data) > 10_000:
        raise ValueError("Dataset exceeds the 10,000-row limit.")

    if not all(isinstance(row, dict) for row in data):
        raise ValueError("Every row must be a dictionary.")

    df = pd.DataFrame(data)

    if df.empty or len(df.columns) == 0:
        raise ValueError("Dataset must contain at least one column.")

    if len(df.columns) > 50:
        raise ValueError("Dataset exceeds the 50-column limit.")

    # Summarize numeric columns only.
    numeric_df = df.select_dtypes(include="number")

    numeric_summary = {}

    for column in numeric_df.columns:
        values = numeric_df[column].dropna()

        if not all(math.isfinite(float(value)) for value in values):
            raise ValueError(
                f"Column '{column}' contains non-finite numeric values."
            )

        numeric_summary[column] = {
            "count": int(values.count()),
            "mean": float(values.mean()) if len(values) else None,
            "min": float(values.min()) if len(values) else None,
            "max": float(values.max()) if len(values) else None,
        }

    return {
        "row_count": int(len(df)),
        "column_count": int(len(df.columns)),
        "columns": [str(column) for column in df.columns],
        "missing_values": {
            str(column): int(count)
            for column, count in df.isna().sum().items()
        },
        "numeric_summary": numeric_summary,
    }


def execute_tool(request: ToolRequest) -> dict:
    security_event = check_guardrails(request)

    if security_event["decision"] != "ALLOW":
        return {
            "status": "blocked",
            "tool": request.tool_name.value,
            "reason": security_event["reason"],
        }

    try:
        if request.tool_name == ToolName.ANALYZE_DATA:
            if set(request.arguments) != {"data"}:
                raise ValueError("Expected only the 'data' argument.")

            result = analyze_dataset(request.arguments["data"])

            return {
                "status": "success",
                "tool": request.tool_name.value,
                "result": result,
            }

        # Reuse the previous executor for other authorized tools.
        # Its own guardrails check is intentionally avoided here.
        if request.tool_name == ToolName.CALCULATE:
            if set(request.arguments) != {"expression"}:
                raise ValueError("Expected only the 'expression' argument.")

            result = safe_calculate(request.arguments["expression"])

            return {
                "status": "success",
                "tool": request.tool_name.value,
                "result": result,
            }

        return {
            "status": "not_implemented",
            "tool": request.tool_name.value,
            "reason": "Tool is authorized but not implemented yet.",
        }

    except (ValueError, TypeError, ZeroDivisionError, OverflowError) as exc:
        return {
            "status": "error",
            "tool": request.tool_name.value,
            "reason": str(exc),
        }


def normalize_planner_output(raw_plan: dict) -> dict:
    if not isinstance(raw_plan, dict):
        raise ValueError("Planner output must be a JSON object.")

    raw_steps = raw_plan.get("steps")
    if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= 5:
        raise ValueError("Plan must contain between 1 and 5 steps.")

    normalized_steps = []

    for index, step in enumerate(raw_steps, start=1):
        if not isinstance(step, dict):
            raise ValueError(f"Step {index} must be an object.")

        # Accept only these two known spellings; reject conflicting fields.
        if "tool" in step and "tool_name" in step:
            raise ValueError(f"Step {index} contains conflicting tool fields.")

        tool_name = step.get("tool_name", step.get("tool"))
        if tool_name not in {"calculate", "analyze_data"}:
            raise ValueError(f"Step {index} uses a forbidden tool.")

        normalized_steps.append({
            "step_id": step.get("step_id", index),
            "tool_name": tool_name,
            "arguments": step.get("arguments", {}),
        })

    normalized_plan = {
        "goal": raw_plan.get("goal", ""),
        "steps": normalized_steps,
    }

    # Validate the complete plan before returning it.
    SecureAgentPlan.model_validate(normalized_plan)
    return normalized_plan


def verify_tool_result(result: dict, tool_name: str) -> bool:
    """Validate both the response structure and tool-specific result."""

    if not isinstance(result, dict):
        return False

    if result.get("status") != "success" or "result" not in result:
        return False

    value = result["result"]

    if tool_name == "calculate":
        # Reject booleans, non-numeric values, NaN, and infinity.
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        )

    if tool_name == "analyze_data":
        if not isinstance(value, dict):
            return False

        required_keys = {
            "row_count",
            "column_count",
            "columns",
            "missing_values",
            "numeric_summary",
        }

        if not required_keys.issubset(value.keys()):
            return False

        if (
            not isinstance(value["row_count"], int)
            or isinstance(value["row_count"], bool)
            or value["row_count"] < 0
        ):
            return False

        if (
            not isinstance(value["column_count"], int)
            or isinstance(value["column_count"], bool)
            or value["column_count"] < 0
        ):
            return False

        if not isinstance(value["columns"], list):
            return False

        if value["column_count"] != len(value["columns"]):
            return False

        if not isinstance(value["missing_values"], dict):
            return False

        if not isinstance(value["numeric_summary"], dict):
            return False

        # Missing-value counts must be valid and within the dataset size.
        for count in value["missing_values"].values():
            if (
                not isinstance(count, int)
                or isinstance(count, bool)
                or not 0 <= count <= value["row_count"]
            ):
                return False

        # Numeric summaries must contain valid finite statistics.
        for stats in value["numeric_summary"].values():
            if not isinstance(stats, dict):
                return False

            if not {"count", "mean", "min", "max"}.issubset(stats.keys()):
                return False

            for key in ("mean", "min", "max"):
                number = stats[key]
                if (
                    not isinstance(number, (int, float))
                    or isinstance(number, bool)
                    or not math.isfinite(number)
                ):
                    return False

        return True

    return False


def execute_secure_plan(plan, dataset):
    plan_data = {
        "goal": getattr(plan, "goal", ""),
        "steps": [
            {
                "step_id": step.step_id,
                "tool_name": step.tool_name,
                "arguments": step.arguments,
            }
            for step in plan.steps
        ],
    }
    plan = SecureAgentPlan.model_validate(plan_data)
    results = []

    for step in plan.steps:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "step_id": step.step_id,
            "tool_name": step.tool_name,
        }

        try:
            if step.tool_name not in {"calculate", "analyze_data"}:
                raise PermissionError(
                    f"Blocked unauthorized tool: {step.tool_name}"
                )

            if step.tool_name == "calculate":
                result = execute_tool(
                    ToolRequest(
                        tool_name=ToolName.CALCULATE,
                        arguments={
                            "expression": step.arguments["expression"]
                        },
                    )
                )

            elif step.tool_name == "analyze_data":
                dataset_ref = step.arguments["dataset_ref"]
                if dataset_ref != "demo_dataset":
                    raise PermissionError(
                        "Dataset reference is not allowlisted."
                    )

                result = execute_tool(
                    ToolRequest(
                        tool_name=ToolName.ANALYZE_DATA,
                        arguments={"data": dataset},
                    )
                )

            if result.get("status") != "success":
                event["status"] = "FAILED"
                event["details"] = result.get("reason", "Tool execution failed.")
            else:
                event["status"] = "SUCCESS"
                event["details"] = "Tool executed successfully."

            results.append({
                "step_id": step.step_id,
                "tool_name": step.tool_name,
                "result": result,
            })

            EXECUTION_EVENTS.append(event)

            if event["status"] != "SUCCESS":
                break

        except Exception as exc:
            event["status"] = "ERROR"
            event["details"] = type(exc).__name__
            EXECUTION_EVENTS.append(event)
            raise

    return results

