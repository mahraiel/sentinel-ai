# SENTINEL AI
### Secure Multi-Step Tool-Using AI Agent

SENTINEL AI is an educational prototype exploring how to build safer
LLM-powered agents through structured planning, strict validation,
tool allowlisting, result verification, and execution auditing.

## Key Features

- **Gemini-based planning:** Generate structured plans from natural-language requests.
- **Schema validation:** Validate plans with Pydantic before execution.
- **Tool allowlisting:** Restrict execution to explicitly permitted tools.
- **Restricted arithmetic:** Evaluate supported mathematical expressions using AST-based validation.
- **Dataset analysis:** Inspect tabular data using pandas.
- **Result verification:** Check tool response structures and selected value constraints.
- **Execution auditing:** Record execution events and authorization decisions.
- **Security testing:** Test invalid arguments, unsupported operations, injection attempts, and numeric boundaries.

## Architecture

1. **Planning:** Gemini proposes a structured plan.
2. **Normalization and validation:** The proposed plan is checked against the expected schema.
3. **Authorization:** Guardrails restrict which tools can execute.
4. **Execution:** Approved tools perform calculations or analyze datasets.
5. **Result verification:** Tool outputs are checked before acceptance.
6. **Audit trail:** Execution events and authorization decisions are recorded.

LLM output is treated as untrusted input. Validation must happen before a
proposed action reaches the execution layer.

## Allowed Tools

- `calculate` — restricted arithmetic evaluation.
- `analyze_data` — tabular dataset analysis.

Shell-command execution and file deletion are not authorized by the current policy.

## Validation and Testing

The following checks have been run during development:

- **Result verification:** 8/8 targeted tests passed after hardening row-count
  and column-count validation.
- **Tool execution:** 3/3 targeted tests passed for valid calculation,
  unexpected arguments, and a function-call injection attempt.
- **Arithmetic safety:** Targeted tests covered normal arithmetic, unsupported
  syntax, division by zero, and expression/numeric boundaries.
- **Plan validation:** Tests confirmed rejection of unauthorized tools and
  unexpected arguments.
- **Prompt-injection testing:** A proposed unauthorized tool call was rejected
  during validation before execution.

These are targeted development tests, not an independent or comprehensive
security assessment. Results apply only to the tested cases and code version.

## Tech Stack

- Python
- Google Gemini API (`google-genai`)
- Pydantic
- pandas
- pytest
- Google Colab

## Running in Google Colab

1. Open the project notebook or upload the project files to Colab.
2. Install the dependencies required by the implementation.
3. Configure the Gemini API key using Colab Secrets.
4. Import `sentinel_core` and run the validation and test workflows.

Do not hard-code API keys or commit secrets to the repository.

A dependency file and a reproducible setup guide should be added as the
project's packaging is finalized.

## Limitations and Future Work

SENTINEL AI is a prototype, not a production-ready security boundary.
Further work includes:

- Expanding automated regression and adversarial testing.
- Improving error normalization and result-schema consistency.
- Adding persistent, tamper-resistant audit storage.
- Introducing stronger process isolation and resource limits.
- Creating reproducible dependency management and CI tests.
- Evaluating the system against a broader, documented threat model.

## Security Disclaimer

Passing the included tests does not guarantee that the system is secure
against all attacks. Do not use this prototype to execute untrusted
workloads or handle sensitive production data without additional controls.
