"""
REPLACEMENT — core/prompt_builder.py

Key improvements over the original:
  1. Increased max_tokens default 6000 → 12000 (complex flows need more)
  2. Cleaner system instructions — role, version context, output format
  3. Explicit forbidden-patterns block (readUrl, file(), hardcoded payloads)
  4. Correct MunitTools::getResourceAsString() guidance
  5. Precise mock/spy/none decision rules keyed to connector type
  6. Assertion strategy: assert-that, assert-equals, verify-call, assert-payload
  7. MUnit 2.x vs 3.x syntax differences clearly stated
  8. Multi-scenario structure (happy path + error scenarios)
  9. Flow-context XML placed first (biggest reduction in wasted tokens)
 10. Sample payload section injects directly before asking for test cases
"""

from typing import Dict, List, Optional
from rich.console import Console
from .compliance_policy import CompliancePolicy


MUNIT_2X_NAMESPACE = """xmlns:munit="http://www.mulesoft.org/schema/mule/munit"
    xmlns:munit-tools="http://www.mulesoft.org/schema/mule/munit-tools"
    xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
    xsi:schemaLocation="
        http://www.mulesoft.org/schema/mule/munit
            http://www.mulesoft.org/schema/mule/munit/current/mule-munit.xsd
        http://www.mulesoft.org/schema/mule/munit-tools
            http://www.mulesoft.org/schema/mule/munit-tools/current/mule-munit-tools.xsd
    \""""

MUNIT_3X_NAMESPACE = MUNIT_2X_NAMESPACE   # same namespaces; syntax differences are within elements


class PromptBuilder:
    """Builds optimized prompts for LLM MUnit generation."""

    # connector type → decision
    MOCK_DECISIONS = {
        # must-mock (returns data used downstream)
        "mock": {
            "http:request", "wsc:consume",
            "db:select", "db:insert", "db:update", "db:delete", "db:stored-procedure",
            "salesforce:query", "salesforce:create", "salesforce:update",
            "salesforce:delete", "salesforce:upsert", "salesforce:retrieve",
            "sap:synchronous-remote-function-call", "sap:send",
            "sftp:read", "ftp:read", "file:read",
            "jms:publish-consume", "vm:publish-consume",
            "objectstore:retrieve", "objectstore:contains",
            "servicenow:invoke", "workday:invoke",
            "redis:get",
        },
        # spy (fire-and-forget side effects)
        "spy": {
            "anypoint-mq:publish", "kafka:publish", "amqp:publish",
            "jms:publish", "vm:publish",
            "email:send",
            "sftp:write", "ftp:write", "file:write",
            "objectstore:store", "objectstore:remove",
            "rabbitmq:publish",
        },
        # no mock needed
        "none": {
            "ee:transform", "set-payload", "set-variable", "remove-variable",
            "choice", "foreach", "parallel-foreach", "scatter-gather",
            "try", "raise-error", "flow-ref", "async",
            "validation:is-not-null", "validation:is-not-empty",
            "logger",
        },
    }

    def __init__(self, max_tokens: int = 12000):
        self.console = Console()
        self.max_tokens = max_tokens

    # ──────────────────────────────────────────────────────────────────────
    # Public entry point
    # ──────────────────────────────────────────────────────────────────────

    def build_prompt(
        self,
        flow_summary: Dict,
        scenarios: List[Dict],
        ruleset: Dict,
        flow_context: Dict = None,
        document_context: Optional[Dict] = None,
        dwl_content: Optional[Dict] = None,
        sample_payload: Optional[str] = None,
        munit_version: Optional[str] = None,
    ) -> str:
        """
        Build a focused, token-efficient prompt for MUnit generation.

        Ordering (most → least important at start of context):
          1. Flow XML (what the LLM is generating tests FOR)
          2. Sample payload (ground truth for set-event values)
          3. System instructions (role + rules)
          4. Scenarios from use-case document (if any)
          5. Ruleset hints
        """
        version_major = self._munit_major(munit_version)
        parts = []

        # ── A. Flow XML first — cheapest, highest value ───────────────────
        if flow_context:
            parts.append(self._build_flow_xml_section(flow_context, flow_summary))

        # ── B. Sample payload (user-supplied ground truth) ────────────────
        if sample_payload and sample_payload.strip():
            parts.append(self._build_sample_payload_section(sample_payload))

        # ── C. DWL files (only when no sample payload) ────────────────────
        if dwl_content and not (sample_payload and sample_payload.strip()):
            parts.append(self._build_dwl_section(dwl_content))

        # ── D. System prompt / task definition ───────────────────────────
        parts.append(self._build_system_prompt(version_major, flow_context))

        # ── E. Mock/spy/assert rules ──────────────────────────────────────
        parts.append(self._build_mock_rules(version_major))
        parts.append(self._build_assertion_rules(version_major))
        parts.append(self._build_forbidden_patterns())

        # ── F. Scenarios from use-case document ──────────────────────────
        if scenarios:
            parts.append(self._build_scenarios_section(scenarios))

        # ── G. Ruleset hints ──────────────────────────────────────────────
        if ruleset:
            parts.append(self._build_ruleset_section(ruleset))

        # ── H. Final generation request ───────────────────────────────────
        parts.append(self._build_generation_request(flow_context, version_major))

        return "\n\n".join(p for p in parts if p and p.strip())

    # ──────────────────────────────────────────────────────────────────────
    # Section builders
    # ──────────────────────────────────────────────────────────────────────

    def _build_system_prompt(self, version_major: int, flow_context: Optional[Dict]) -> str:
        flow_name = (flow_context or {}).get("name", "the provided flow")
        trigger = (flow_context or {}).get("trigger_type", "unknown trigger")
        return f"""## ROLE
You are an expert MuleSoft developer generating production-quality MUnit {version_major}.x test suites.

## TASK
Generate a complete MUnit test suite XML file for the flow: **{flow_name}**
Trigger type: {trigger}

## OUTPUT RULES
- Return ONLY valid XML — no markdown fences, no preamble, no commentary.
- The root element must be `<mule>` with all required MUnit namespaces.
- Every test must be a `<munit:test>` element with a descriptive `name` attribute.
- Always include: at least one happy-path test AND at least one error-scenario test.
- If the flow uses an HTTP listener, include tests for different HTTP status codes.
- Use `doc:name` on every element to describe its purpose.
"""

    def _build_flow_xml_section(self, flow_context: Dict, flow_summary: Dict) -> str:
        xml = flow_context.get("raw_xml") or flow_context.get("xml_content", "")
        # Include referenced sub-flows/flows
        dep_xmls = []
        for dep_name in flow_context.get("referenced_flows", []):
            dep_detail = (flow_summary.get("flow_registry") or {}).get(dep_name, {})
            if dep_detail.get("raw_xml"):
                dep_xmls.append(f"<!-- Referenced flow: {dep_name} -->\n{dep_detail['raw_xml']}")
        for sub_name in flow_context.get("dw_lookup_refs", []):
            sub_detail = (flow_summary.get("sub_flow_registry") or {}).get(sub_name, {})
            if sub_detail.get("raw_xml"):
                dep_xmls.append(f"<!-- Sub-flow via DW lookup: {sub_name} -->\n{sub_detail['raw_xml']}")

        all_xml = xml
        if dep_xmls:
            all_xml += "\n\n" + "\n\n".join(dep_xmls)

        return f"""## MULE APPLICATION CODE
```xml
{all_xml}
```"""

    def _build_sample_payload_section(self, sample: str) -> str:
        return f"""## SAMPLE REQUEST / RESPONSE PAYLOAD
Use these exact field names and values for `<munit-tools:set-event>` payload
and for mock return values:
```
{sample.strip()}
```"""

    def _build_dwl_section(self, dwl_content: Dict) -> str:
        if not dwl_content:
            return ""
        parts = ["## DATAWEAVE SCRIPTS (for mock payload derivation)"]
        for path, content in list(dwl_content.items())[:5]:   # cap at 5
            if content and len(content) < 3000:
                parts.append(f"### {path}\n```\n{content.strip()}\n```")
        return "\n".join(parts)

    def _build_mock_rules(self, version_major: int) -> str:
        if version_major >= 3:
            mock_syntax = """<munit-tools:mock-when processor="connector:operation" doc:name="Mock connector">
    <munit-tools:with-attributes>
        <munit-tools:with-attribute attributeName="config-ref" whereValue="#['configName']"/>
    </munit-tools:with-attributes>
    <munit-tools:then-return>
        <munit-tools:payload value="#[output application/json --- { field: 'value' }]"
                              mediaType="application/json"/>
        <munit-tools:attributes value="#[{ statusCode: 200 }]"/>
    </munit-tools:then-return>
</munit-tools:mock-when>"""
        else:
            mock_syntax = """<munit-tools:mock-when processor="connector:operation" doc:name="Mock connector">
    <munit-tools:with-attributes>
        <munit-tools:with-attribute attributeName="config-ref" whereValue="#['configName']"/>
    </munit-tools:with-attributes>
    <munit-tools:then-return>
        <munit-tools:payload value="#[output application/json --- { field: 'value' }]"
                              mediaType="application/json"/>
    </munit-tools:then-return>
</munit-tools:mock-when>"""

        spy_syntax = """<munit-tools:spy processor="connector:publish" doc:name="Spy on publish">
    <munit-tools:with-attributes>
        <munit-tools:with-attribute attributeName="config-ref" whereValue="#['configName']"/>
    </munit-tools:with-attributes>
    <munit-tools:after-call>
        <munit-tools:verify-call processor="connector:publish" times="1"/>
    </munit-tools:after-call>
</munit-tools:spy>"""

        return f"""## MOCK / SPY RULES

### Decision table
| Category | Examples | Action |
|----------|----------|--------|
| MOCK (returns data) | http:request, db:select, salesforce:query, sftp:read, objectstore:retrieve | Use mock-when |
| SPY (fire-and-forget) | anypoint-mq:publish, jms:publish, email:send, file:write | Use spy |
| NONE (pure transform) | ee:transform, set-payload, choice, foreach, flow-ref | No mock needed |

### MOCK syntax example
```xml
{mock_syntax}
```

### SPY syntax example
```xml
{spy_syntax}
```

### Critical rules
- `processor` attribute must be `"namespace:operation"` (e.g., `"http:request"`, `"db:select"`).
- Mock ALL http:request calls — never let them reach a real endpoint.
- Mock EVERY db: operation — tests must be database-independent.
- For mocks that return a file payload, use:
  `#[MunitTools::getResourceAsString('mock_payloads/my-response.json')]`
  NOT `readUrl()`, NOT `file()`, NOT hardcoded JSON strings longer than 2 lines.
- Payload value expression must be a valid DataWeave 2.0 expression.
"""

    def _build_assertion_rules(self, version_major: int) -> str:
        assert_that = """<munit-tools:assert-that
    expression="#[payload.status]"
    is="#[MunitTools::equalTo('success')]"
    message="Expected status to be success"
    doc:name="Assert status"/>"""

        assert_equals = """<munit-tools:assert-equals
    actual="#[payload.id]"
    expected="#['123']"
    message="Expected id to be 123"
    doc:name="Assert id"/>"""

        verify_call = """<munit-tools:verify-call
    processor="anypoint-mq:publish"
    times="1"
    doc:name="Verify publish called once"/>"""

        return f"""## ASSERTION RULES

### assert-that (recommended for most cases)
```xml
{assert_that}
```

### assert-equals (simple equality)
```xml
{assert_equals}
```

### verify-call (confirm a spy was triggered)
```xml
{verify_call}
```

### Rules
- ALWAYS assert the HTTP status code for HTTP listener flows.
- ALWAYS assert at least one payload field.
- For error scenarios: set `expectedErrorType="APP:CONNECTIVITY"` (or the actual error type)
  on the `<munit:test>` element AND assert the error message with assert-that.
- `MunitTools::equalTo()`, `MunitTools::containsString()`, `MunitTools::nullValue()` are the
  most common matchers. Never use raw `==` inside assert-that expressions.
- Use `#[vars.myVariable]` to assert variables set during the flow.
"""

    def _build_forbidden_patterns(self) -> str:
        return """## FORBIDDEN PATTERNS — never generate these
- `readUrl(...)` — use `MunitTools::getResourceAsString(...)` instead
- `file:read` inside a test — use resource files via MunitTools
- `#[payload]` as a mock return value without an explicit DW expression
- `@Before` / `@After` Java annotations — this is XML, not JUnit
- `<munit:before-suite>` calling the flow under test
- `<munit-tools:set-event>` with `mediaType` set to anything other than the
  actual content type the flow expects
- Mocking `flow-ref` — mock the individual connectors INSIDE the referenced
  flow instead
- `<munit-tools:spy>` on a processor that returns data (use mock-when instead)
"""

    def _build_scenarios_section(self, scenarios: List[Dict]) -> str:
        if not scenarios:
            return ""
        lines = ["## BUSINESS SCENARIOS (from use-case document)"]
        lines.append("Create test cases for each scenario below:\n")
        for i, s in enumerate(scenarios[:10], 1):    # cap at 10
            name = s.get("name") or s.get("title") or f"Scenario {i}"
            desc = s.get("description") or s.get("steps") or ""
            if isinstance(desc, list):
                desc = "; ".join(str(x) for x in desc)
            lines.append(f"{i}. **{name}**: {str(desc)[:300]}")
        return "\n".join(lines)

    def _build_ruleset_section(self, ruleset: Dict) -> str:
        if not ruleset:
            return ""
        lines = ["## ADDITIONAL GENERATION HINTS"]
        for key, val in list(ruleset.items())[:10]:
            lines.append(f"- {key}: {val}")
        return "\n".join(lines)

    def _build_generation_request(
        self, flow_context: Optional[Dict], version_major: int
    ) -> str:
        flow_name = (flow_context or {}).get("name", "the flow above")
        ns = MUNIT_2X_NAMESPACE if version_major < 3 else MUNIT_3X_NAMESPACE

        return f"""## GENERATE THE MUNIT TEST SUITE

Generate the complete MUnit test suite for **{flow_name}**.

The output file must start with:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<mule {ns}>
```

Requirements:
1. At least one **happy-path** test (`<munit:test name="{flow_name}-happy-path-test">`)
2. At least one **error-scenario** test (`<munit:test name="{flow_name}-error-test" expectedErrorType="...">`)
3. All external connectors mocked or spied per the rules above.
4. All set-event payloads use realistic values from the sample payload or DWL analysis.
5. Every test contains a `<munit:behavior>`, `<munit:execution>`, and `<munit:validation>` section.
6. Close the `</mule>` root element at the end.

Generate the XML now:"""

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _munit_major(version: Optional[str]) -> int:
        """Return integer major version number; default to 2."""
        if not version:
            return 2
        try:
            return int(str(version).split(".")[0])
        except (ValueError, IndexError):
            return 2
