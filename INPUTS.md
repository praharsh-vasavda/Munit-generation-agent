# MUnit Generation Agent — Input Guide

This document defines what users should provide so the agent can generate **proper, runnable MUnit** tests (similar to Anypoint Studio Test Recorder quality).

## Required inputs

| Input | Why |
|--------|-----|
| **Mule project ZIP** (or full `src/main/mule` + `src/main/resources`) | Needs all flows, **global configs**, and **DataWeave** files — not a single XML file in isolation. |
| **Target flow name** | Select the implementation flow to test (not APIkit console/router-only flows). |
| **`pom.xml` in the project** | Validates MUnit dependencies and resolves Mule runtime / MUnit version. |

## Strongly recommended

| Input | Why |
|--------|-----|
| **Generation mode** | See below. Default: `deterministic`. |
| **Sample request / response** | Same data Studio captures when recording a test. Dramatically improves set-event and assertions. |

### Sample payload format (JSON)

```json
{
  "request": {
    "queryParams": { "country": "India" }
  },
  "response": {
    "states": [
      { "name": "Maharashtra", "state_code": "MH" }
    ]
  }
}
```

For GET APIs that only use query parameters, `request.queryParams` is enough.

## Generation modes

| Mode | Behavior | When to use |
|------|----------|-------------|
| **deterministic** (default) | Code builds `munit:set-event`, **every outbound connector mock** from `mock_plan`, capped assertions | Day-to-day unit tests without live HTTP/DB |
| **recorder** | One happy-path test, **one `munit-tools:that` expression** (Studio-like) | When you have sample request/response |
| **llm_suite** | Legacy: LLM writes full suite XML | Only if you need experimental multi-scenario drafts |
| **blueprint** (API `/api/blueprint/generate`) | Multi-pass: mock DWL files + assembled XML | Advanced / isolated experiments |

## Optional inputs

| Input | Why |
|--------|-----|
| Business / use-case document | Drives scenario list (empty payload, downstream failure, etc.) |
| Confluence page | Same as business doc |
| RAML / OAS | REST contract for paths, methods, schemas |
| **Mule runtime / MUnit version** overrides | When `pom.xml` is missing or you need a specific target |
| **Selected flows** (multi-select in UI) | Generate suites only for chosen flows |

## What the agent derives automatically (do not ask users for)

- Outbound connectors to mock (`http:request`, `db:*`, etc.)
- `doc:name` matching for each mock
- HTTP listener path, method, `queryParams` / `uriParams` from DataWeave
- Mock payload field names from downstream transforms
- Maven layout output under `output/src/test/munit` and `output/src/test/resources/`

## Output layout

After generation (deterministic / recorder):

```
output/
  src/test/munit/<suite-name>.xml
  src/test/resources/<flowName>Flowtest/
    set-event_payload_1.dwl
    set-event_attributes_1.dwl
    mock_<processor>_1_1.dwl
    assert_expression_payload_1.dwl
```

Copy these into your Mule app’s `src/test/munit` and `src/test/resources` before running MUnit in Studio or Maven.

## Quality checks performed

- **Semantic validation**: every outbound connector in `mock_plan` must have a matching `mock-when`
- Invalid `processor="foo::bar"` syntax is rejected
- Warnings if assertion count is very high (unlike Studio recorder)

## CLI example

```bash
python3 main.py generate \
  --xml-source local \
  --xml-path ./myapp.zip \
  --output-path ./output
```

Set generation mode via web UI (`generation_mode` form field) or extend CLI with the same parameter in your deployment.

## Tips for your team

1. Always upload the **full project ZIP**, not one flow file.
2. Provide **sample request/response** whenever possible → use **Recorder** mode.
3. Prefer **Deterministic** mode for CI-friendly tests (no live external calls).
4. Check job results for `generation_mode`, `semantic_validation`, and `model_used`:
   - `model_used: deterministic-builder` → code path (recommended)
   - `template_based: true` → LLM fallback template (review carefully)
