# MUnit Generation Agent

A Python and Flask application that analyzes a Mule application and generates
runnable MUnit tests for a selected flow. It traces local and dynamic flow calls,
identifies connectors that require mocks, collects missing sample data, and
packages the generated MUnit XML with its DataWeave resource files.

## What It Does

The application provides a guided workflow:

1. Select the Mule runtime and MUnit version.
2. Upload a Mule application ZIP.
3. Optionally upload a use-case document.
4. Review the project's `pom.xml` and MUnit compatibility.
5. Select one flow and trace its execution path.
6. Provide mock responses and flow input/output samples where required.
7. Generate and download the MUnit suite and DWL resources.

Only one target flow is generated at a time to keep analysis focused and avoid
large generation jobs.

## Main Features

- Scans a complete Mule project ZIP, including Mule XML, DataWeave, RAML/OAS,
  resources, and `pom.xml`
- Lists flows, subflows, APIkit flows, entry points, and unreachable flows
- Traces nested `flow-ref` calls from the selected flow
- Resolves dynamic flow references such as:
  - `#[vars.flowName]`
  - `#[payload.flowName]`
  - `#[attributes.queryParams.flowName]`
  - values assigned in `set-variable` or DataWeave objects
- Carries variable values through nested flow calls when resolving dynamic
  targets
- Detects missing flow XML that may come from a Maven/runtime dependency
- Allows a missing dependency flow to be resolved by:
  - uploading its JAR, ZIP, Mule XML, or `.mule` artifact; or
  - manually declaring which local flow it calls back into
- Adds required dynamic/runtime flow names under
  `<munit:enable-flow-sources>` inside each `<munit:test>`
- Detects outbound connectors and creates `munit-tools:mock-when` definitions
- Collects mocked flow-ref return payloads, variables, attributes, or errors
- Deduplicates equivalent mocks within a test
- Generates matching DWL resource names and references
- Generates happy-path, validation, branch, edge, and connector-failure tests
- Adds the actual `expectedErrorType` for propagated error scenarios
- Preserves payload assertions for errors consumed by `on-error-continue`
- Validates generated XML and checks that referenced generated resources exist
- Downloads the complete Maven test layout as a ZIP

## Requirements

- Python 3.8 or newer
- A Mule application ZIP containing Mule configuration XML
- A `pom.xml` is strongly recommended for runtime and MUnit validation
- An LLM API key is optional when using deterministic generation, but is needed
  for provider-backed generation

## Installation

```bash
git clone <repository-url>
cd munit-generation-agent-claude

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

On Windows:

```powershell
py -m venv .venv
.venv\Scripts\activate
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root:

```dotenv
# Configure at least one provider for LLM-backed generation.
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
OPENROUTER_API_KEY=
GROQ_API_KEY=

# Examples:
# PRIMARY_LLM=openai/gpt-4o-mini
# PRIMARY_LLM=anthropic/claude-sonnet-4-20250514
# PRIMARY_LLM=openrouter/openai/gpt-4o-mini
PRIMARY_LLM=openrouter/openai/gpt-4o-mini

MAX_PROMPT_TOKENS=6000
LLM_TIMEOUT=60
OUTPUT_PATH=/tmp/munit-generation-agent-output

# Optional integrations
GITHUB_TOKEN=
CONFLUENCE_TOKEN=
CONFLUENCE_EMAIL=
```

Supported provider prefixes are `openai`, `anthropic`, `openrouter`, and
`groq`. If a provider call is unavailable, applicable generation paths can use
the deterministic/template fallback.

## Run the Web Application

The app's default `app.py` entry point uses port `5000`:

```bash
python3 app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

To run on another port:

```bash
python3 -m flask --app app run --debug --host 127.0.0.1 --port 5001
```

Then open [http://127.0.0.1:5001](http://127.0.0.1:5001).

## Input

### Mule Application

Upload the complete project ZIP rather than a single flow XML. A typical input
contains:

```text
my-mule-app/
├── pom.xml
└── src/
    └── main/
        ├── mule/
        │   └── application.xml
        └── resources/
            ├── api/
            └── dw/
```

The scanner also examines nested archives and Maven metadata. Environment-
specific property files are not used to infer dynamic flow targets.

### Optional Use-Case Document

The web UI accepts a Confluence export, Word document, PDF, or supported text
document. The document is used to improve scenario descriptions and test data;
it is not required to discover Mule flows.

### Additional Test Data

Before generation, the app may request:

- request payload
- query parameters
- URI parameters
- headers
- expected response and status code
- connector mock payloads or attributes
- mocked flow-ref payload, variables, attributes, or error type

These values can be entered directly in the UI.

## Flow Tracing and Runtime Dependencies

For a local chain:

```text
Flow A -> Flow B -> Flow C
```

the analyzer follows static and resolvable dynamic flow references and collects
the connectors across the complete chain.

If `Flow C` is referenced but its XML is absent, the trace stops explicitly:

```text
Flow A -> Flow B -> Flow C -> STOP
```

The app identifies `Flow C` as a possible runtime dependency and offers:

1. **Upload dependency artifact**: provide a JAR, ZIP, XML, or `.mule` file so
   its flows can be scanned.
2. **Declare manually**: select the local flow called by the external flow and
   optionally describe the routing condition.

A manually selected callback is appended after the missing flow:

```text
Flow A -> Flow B -> Flow C (external) -> Flow D
```

The external or dynamic flow source is enabled inside each generated test:

```xml
<munit:test name="flow-a-valid-test" description="Valid request">
    <munit:enable-flow-sources>
        <munit:enable-flow-source value="Flow C"/>
    </munit:enable-flow-sources>
    <munit:behavior>
        <!-- mocks -->
    </munit:behavior>
    <munit:execution>
        <!-- input and flow execution -->
    </munit:execution>
    <munit:validation>
        <!-- assertions -->
    </munit:validation>
</munit:test>
```

## Generated Output

The download contains a Maven-compatible test structure:

```text
output/
└── src/
    └── test/
        ├── munit/
        │   └── <flow>-test-suite.xml
        └── resources/
            └── <flow>Flowtest/
                ├── set_event_payload_valid.dwl
                ├── set_event_attributes_valid.dwl
                ├── mock_<connector>_valid.dwl
                ├── mock_<external-flow>_variables.dwl
                └── assert_expression_payload_valid.dwl
```

Every generated resource reference is checked against the files written to the
output folder. Mocked flow-ref variables use one stable resource file per
external flow, preventing duplicate files with equivalent content.

## Error Scenarios

For an error that escapes the tested flow, the generated test declares its
actual Mule error type:

```xml
<munit:test
    name="weather-experience-flow-get-open-meteo-forecast-failure-test"
    description="GET Open-Meteo Forecast failure path"
    expectedErrorType="HTTP:CONNECTIVITY">
```

This is not limited to HTTP errors. The builder can use discovered or supplied
types such as `HTTP:TIMEOUT`, `DB:CONNECTIVITY`,
`APP:VALIDATION_ERROR`, and `VALIDATION:IS_TRUE`.

If an `on-error-continue` handler consumes the error and returns a response, the
test validates that response instead of declaring `expectedErrorType`.

## CLI

The legacy CLI remains available:

```bash
python3 main.py generate \
  --xml-source local \
  --xml-path ./my-mule-app.zip \
  --output-path ./generated-tests
```

Configuration commands:

```bash
python3 main.py config --show
python3 main.py config --validate
python3 main.py config --create-env
```

The web workflow is recommended for flow selection, dependency resolution, and
interactive sample-data collection.

## API Overview

Primary web endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /` | Web interface |
| `POST /api/enhanced/analyze-flows` | Upload and analyze a Mule project |
| `POST /api/enhanced/resolve-selected-flow` | Trace one selected flow and resolve dependency artifacts/manual links |
| `POST /api/enhanced/generate` | Generate the selected flow's MUnit suite |
| `GET /api/job-status/<job_id>` | Read asynchronous job status |
| `GET /api/job-result/<job_id>` | Read generation results |
| `GET /api/download/<job_id>` | Download generated XML and resources |
| `GET /api/munit-versions/<runtime_version>` | List compatible MUnit versions |
| `POST /api/check-pom` | Validate MUnit dependencies in a POM |
| `GET /health` | Health check |

## Architecture

```text
Browser UI
    |
    v
Flask API (app.py)
    |
    +-- Project extraction and POM validation
    +-- XMLAnalyzer
    |     +-- flow graph
    |     +-- connector/error-handler discovery
    |     +-- DynamicFlowResolver
    |
    +-- DocumentParser
    +-- DeterministicMUnitBuilder
    +-- MUnitSemanticValidator
    +-- LLMRouter
    +-- MUnitWriter
    |
    v
MUnit XML + DWL resources + downloadable ZIP
```

Important modules:

| Module | Responsibility |
|---|---|
| `app.py` | Flask UI/API orchestration, uploads, cached analysis, jobs, and downloads |
| `core/xml_analyzer.py` | Mule flow, processor, branch, error-handler, and connector analysis |
| `core/dynamic_flow_resolver.py` | Static inference for dynamic `flow-ref` expressions |
| `core/deterministic_munit_builder.py` | MUnit scenarios, mocks, input events, resources, and assertions |
| `core/munit_semantic_validator.py` | Semantic checks for generated MUnit |
| `core/doc_parser.py` | Optional use-case document parsing |
| `core/version_config.py` | Mule runtime and MUnit compatibility data |
| `llm/llm_router.py` | Provider calls and template fallback |
| `munitWriter/munit_writer.py` | Output formatting and file writing |
| `rulesets/` | MUnit structure, mock, assertion, recorder, and scenario rules |

## Tests

Install the development test dependency:

```bash
python3 -m pip install pytest
```

Run the test suite:

```bash
python3 -m pytest
```

The tests cover flow analysis, dynamic flow resolution, endpoint behavior,
recorder/deterministic generation, resource packaging, dependency callbacks,
mock deduplication, and error-handler semantics.

## Limitations

- A dynamic flow target cannot be inferred when its value exists only in an
  environment-specific property or external runtime state.
- Dependency flow internals cannot be traced unless their Mule XML is uploaded
  or their callback relationship is declared manually.
- Generated tests should still be run against the target project's exact Mule
  runtime, connector versions, secure properties, and Maven configuration.
- The included Flask server is intended for local development. Use an
  appropriate production WSGI server and authentication controls for shared
  deployments.

## Troubleshooting

**A flow is shown as unreachable**

Confirm that its caller is present in the ZIP. For a dynamic call, check that
the target is assigned in Mule XML or DataWeave before the `flow-ref`. If the
caller belongs to a dependency, upload that artifact or declare the callback in
Step 5.

**MUnit reports `flow <name> not found`**

Regenerate after resolving the dynamic/runtime dependency. Confirm that the
flow appears in `<munit:enable-flow-sources>` inside the relevant
`<munit:test>`.

**A referenced DWL file is missing**

Download the complete generated ZIP rather than only the XML preview. Resource
files are stored under `src/test/resources/<flow>Flowtest/`.

**No provider-backed LLM is available**

Check `PRIMARY_LLM`, its matching API key, and `/api/config`. Deterministic
generation can still be used for supported analysis and generation paths.

**Port 5000 is already in use**

Run Flask on another port:

```bash
python3 -m flask --app app run --host 127.0.0.1 --port 5001
```
