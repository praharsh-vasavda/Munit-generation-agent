"""
Prompt builder for creating efficient LLM prompts for MUnit generation.

Enhanced version with:
- 5-step analytical process for flow analysis
- Explicit mock derivation rules
- set-event derivation rules per trigger type
- Forbidden MUnit elements list
- DWL content support for accurate mock payloads
"""

from typing import Dict, List, Optional
from rich.console import Console


class PromptBuilder:
    """Builds optimized prompts for LLM MUnit generation."""

    def __init__(self, max_tokens: int = 6000):
        """
        Initialize prompt builder.
        
        Args:
            max_tokens: Maximum tokens allowed in prompt
        """
        self.console = Console()
        self.max_tokens = max_tokens
        # No tiktoken dependency - use simple character-based token counting

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
        Build optimized prompt for MUnit generation.

        Args:
            flow_summary: XML analysis results
            scenarios: Extracted scenarios
            ruleset: Merged ruleset dictionary
            flow_context: Target flow context (optional)
            document_context: Business use case context (optional)
            dwl_content: DataWeave file contents keyed by path (optional)
            sample_payload: User-supplied sample request/response JSON or text.
                When provided this is inserted immediately after the flow XML
                as the authoritative source for set-event payload and mock
                return values, replacing inferred values from DWL analysis.

        Returns:
            Optimized prompt string

        Raises:
            Exception: If prompt cannot be built within token limit
        """
        try:
            # Build initial prompt
            prompt_parts = []
            
            # Add system instructions with 5-step analysis process
            system_instructions = self._build_system_instructions(ruleset, flow_context, munit_version=munit_version)
            prompt_parts.append(system_instructions)
            
            # Add analysis steps (critical for accurate mock/payload derivation)
            analysis_steps = self._build_analysis_steps()
            prompt_parts.append(analysis_steps)
            
            # Add mock derivation rules
            mock_derivation = self._build_mock_derivation_rules()
            prompt_parts.append(mock_derivation)
            
            # Add set-event derivation rules
            set_event_rules = self._build_set_event_rules()
            prompt_parts.append(set_event_rules)
            
            # Add assertion derivation rules
            assertion_rules = self._build_assertion_derivation_rules()
            prompt_parts.append(assertion_rules)
            
            # Add flow summary
            flow_section = self._build_flow_section(flow_summary, flow_context)
            prompt_parts.append(flow_section)

            # ── SAMPLE PAYLOAD (highest priority after flow XML) ───────────
            # When the user provides a real sample request/response, this
            # overrides DWL-inferred field names for set-event and mock payloads.
            if sample_payload and sample_payload.strip():
                prompt_parts.append(self._build_sample_payload_section(sample_payload))
            
            # Add DWL content if available (critical for mock payload derivation)
            # Only include DWL when no sample payload was supplied — the real
            # payload is always more accurate than static DWL analysis.
            if dwl_content and not (sample_payload and sample_payload.strip()):
                dwl_section = self._build_dwl_section(dwl_content)
                if dwl_section:
                    prompt_parts.append(dwl_section)
            
            # Add scenarios
            scenarios_section = self._build_scenarios_section(scenarios)
            prompt_parts.append(scenarios_section)

            # Add business/use-case context
            document_section = self._build_document_context_section(document_context, flow_context)
            if document_section:
                prompt_parts.append(document_section)

            # Add ruleset with assertion rules and mock scope
            ruleset_section = self._build_ruleset_section(ruleset, flow_context, munit_version=munit_version)
            prompt_parts.append(ruleset_section)
            
            # Combine and check tokens
            full_prompt = "\n\n".join(prompt_parts)
            token_count = self._count_tokens(full_prompt)
            
            if token_count > self.max_tokens:
                self.console.print(f"[yellow]Prompt too long ({token_count} tokens), optimizing...[/yellow]")
                full_prompt = self._optimize_prompt(full_prompt, token_count)
            
            final_token_count = self._count_tokens(full_prompt)
            self.console.print(f"[green]Final prompt: {final_token_count} tokens[/green]")
            
            return full_prompt

        except Exception as e:
            raise Exception(f"Failed to build prompt: {str(e)}")

    def _build_system_instructions(self, ruleset: Dict, flow_context: Dict = None, munit_version: Optional[str] = None) -> str:
        """Build system instructions section with enhanced guidance."""
        resolved_munit_version = (munit_version or "3.6.0").strip()

        # Derive a unique suite name from the source file or target flow
        suite_name = "test-suite"
        if flow_context:
            source_file = flow_context.get("source_file", "")
            target_flow = flow_context.get("target_flow", "")
            if source_file and source_file != "unknown.xml":
                base = source_file.rsplit(".", 1)[0]
                base = base.replace("_", "-").lower()
                base = "".join(c for c in base if c.isalnum() or c == "-").strip("-")
                suite_name = f"{base}-test-suite"
            elif target_flow:
                clean = target_flow.replace("_", "-").lower()
                clean = "".join(c for c in clean if c.isalnum() or c == "-").strip("-")
                suite_name = f"{clean}-test-suite"

        instructions = [
            f"You are an expert MuleSoft developer generating MUnit {resolved_munit_version} test suites (Java 17 compatible).",
            "You understand how MUnit's test recorder works and you simulate that behavior.",
            "",
            "## YOUR TASK",
            "1. Analyze the flow XML to understand the data path",
            "2. Trace which fields flow through each processor",
            "3. Generate MUnit tests that simulate recorded tests",
            f"Output ONLY valid MUnit {resolved_munit_version} XML. No explanations, no markdown, no code fences.",
            "",
            "## CRITICAL MUNIT CONCEPTS",
            "",
            "### What gets MOCKED (external systems that would make real calls):",
            "- http:request (outbound HTTP calls)",
            "- db:select, db:insert, db:update, db:delete (database)",
            "- salesforce:query, salesforce:create, etc. (Salesforce)",
            "- s3:*, azure:*, etc. (cloud storage)",
            "",
            "DEFAULT TEST STYLE: unit-safe isolation.",
            "Never let generated MUnit make a live outbound call to HTTP, database, Salesforce, MQ, Kafka, file, SFTP, email, or any other external system.",
            "If the selected flow contains outbound connectors, those connectors must be mocked or verified. Live integration calls are forbidden in generated output.",
            "",
            "### What NEVER gets mocked (let them execute):",
            "- ee:transform / transform:message — THIS IS YOUR BUSINESS LOGIC, never mock it!",
            "- set-variable, set-payload — core Mule operations",
            "- flow-ref — let sub-flows execute to test the full chain",
            "- logger — no side effects",
            "- choice, scatter-gather, foreach — routing logic must execute",
            "",
            "### What gets SIMULATED with set-event (triggers):",
            "- http:listener — set-event provides the HTTP request",
            "- anypoint-mq:subscriber — set-event provides the message",
            "- scheduler — set-event provides scheduledTime",
            "- sftp:listener — set-event provides file content",
            "",
            f"## FORBIDDEN ELEMENTS — these do NOT exist in MUnit {resolved_munit_version}:",
            "- munit-tools:assert-equals (use assert-that with equalTo())",
            "- munit-tools:assert (does not exist)",
            "- munit-tools:assert-error-type (does not exist)",
            "- munit-tools:assert-not-null (use assert-that with notNullValue())",
            "",
            "## VALID ASSERTIONS — use ONLY these:",
            "```xml",
            "<!-- For value checks -->",
            "<munit-tools:assert-that expression='#[payload.status]' is='#[MunitTools::equalTo(\"SUCCESS\")]'/>",
            "",
            "<!-- For not null -->",
            "<munit-tools:assert-that expression='#[payload.id]' is='#[MunitTools::notNullValue()]'/>",
            "",
            "<!-- For collections -->",
            "<munit-tools:assert-that expression='#[payload.items]' is='#[MunitTools::hasSize(2)]'/>",
            "",
            "<!-- For void connectors (MQ, email) — verify it was called -->",
            "<munit-tools:verify-call processor='anypoint-mq:publish' times='1'/>",
            "```",
            "",
            f"## munit:config name MUST be: \"{suite_name}\"",
            "",
            "## COMPLETE TEST STRUCTURE EXAMPLE",
            "```xml",
            "<munit:test name='test-{flow-name}-happy-path' description='Valid request returns success'>",
            "    <munit:behavior>",
            "        <!-- 1. FIRST: Simulate the trigger -->",
            "        <munit:set-event doc:name='Set Input'>",
            "            <munit:payload value='#[{derived from first transform}]' mediaType='application/json'/>",
            "            <munit:attributes value='#[{method: \"POST\", requestPath: \"/api\"}]'/>",
            "        </munit:set-event>",
            "        ",
            "        <!-- 2. Mock ONLY external connectors, match by doc:name -->",
            "        <munit-tools:mock-when processor='http:request'>",
            "            <munit-tools:with-attributes>",
            "                <munit-tools:with-attribute attributeName='doc:name' whereValue='Call Backend'/>",
            "            </munit-tools:with-attributes>",
            "            <munit-tools:then-return>",
            "                <munit-tools:payload value='#[{fields downstream DWL needs}]' mediaType='application/json'/>",
            "                <munit-tools:attributes value='#[{statusCode: 200}]'/>",
            "            </munit-tools:then-return>",
            "        </munit-tools:mock-when>",
            "    </munit:behavior>",
            "    ",
            "    <munit:execution>",
            "        <!-- Call the flow under test -->",
            "        <flow-ref name='{target-flow-name}'/>",
            "    </munit:execution>",
            "    ",
            "    <munit:validation>",
            "        <!-- Assert specific fields from final output -->",
            "        <munit-tools:assert-that expression='#[payload.status]' is='#[MunitTools::equalTo(\"SUCCESS\")]'/>",
            "        <munit-tools:assert-that expression='#[payload.data.id]' is='#[MunitTools::notNullValue()]'/>",
            "    </munit:validation>",
            "</munit:test>",
            "```",
            "",
            "## OUTPUT FORMAT",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<mule xmlns:munit=\"http://www.mulesoft.org/schema/mule/munit\"",
            "      xmlns:munit-tools=\"http://www.mulesoft.org/schema/mule/munit-tools\"",
            "      xmlns=\"http://www.mulesoft.org/schema/mule/core\"",
            "      xmlns:doc=\"http://www.mulesoft.org/schema/mule/documentation\"",
            "      xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"",
            "      xsi:schemaLocation=\"http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd",
            "                          http://www.mulesoft.org/schema/mule/munit http://www.mulesoft.org/schema/mule/munit/current/mule-munit.xsd",
            "                          http://www.mulesoft.org/schema/mule/munit-tools http://www.mulesoft.org/schema/mule/munit-tools/current/mule-munit-tools.xsd\">",  # always /current/ — version in URL is not how MuleSoft schemas work
            "",
            f"    <munit:config name=\"{suite_name}\"/>",
            "",
            "    <!-- Generate tests here -->",
            "",
            "</mule>"
        ]
        
        return "\n".join(instructions)

    def _build_analysis_steps(self) -> str:
        """Build expert-level flow analysis that simulates MUnit recording."""
        return """## STEP 1 — TRACE THE DATA FLOW (simulate what MUnit recorder captures)

Think like MuleSoft's test recorder. For each flow, trace the EXACT data path:

### 1.1 IDENTIFY THE TRIGGER (this becomes munit:set-event)
Find the FIRST element in the flow:
- <http:listener> → set-event needs: payload + attributes.method + attributes.requestPath + attributes.headers
- <anypoint-mq:subscriber> → set-event needs: payload + attributes.messageId + attributes.destination
- <scheduler> → set-event needs: null payload + attributes.scheduledTime
- <sftp:listener> → set-event needs: file content as payload + attributes.fileName + attributes.directory

CRITICAL: The trigger is NEVER mocked. It's simulated with munit:set-event.

### 1.2 TRACE EACH PROCESSOR IN ORDER
List every processor with its doc:name. For each one, note:
- What it READS from (payload, vars, attributes)
- What it WRITES to (payload, vars)
- Whether it's EXTERNAL (needs mock) or INTERNAL (let it execute)

Example trace for a flow:
```
1. http:listener doc:name="Receive Request" → TRIGGER (set-event)
2. transform:message doc:name="Build Request" → INTERNAL (executes, reads payload.customerId, writes payload)
3. http:request doc:name="Call Backend API" → EXTERNAL (mock this, returns to payload)
4. transform:message doc:name="Map Response" → INTERNAL (executes, reads payload.data.id, payload.data.name)
5. logger doc:name="Log Result" → INTERNAL (no-op, ignore)
```

### 1.3 FOR EACH EXTERNAL CONNECTOR, FIND WHAT CONSUMES ITS OUTPUT
This is the KEY to correct mocks. Find the NEXT transform after the connector:

BAD (generic): mock returns `{"status": "success"}`
GOOD (derived): mock returns `{"data": {"id": "MOCK-ID-001", "name": "Test Record"}}` 
               because downstream transform reads `payload.data.id` and `payload.data.name`

### 1.4 FIND THE FINAL OUTPUT
The last set-payload or transform:message determines what your assertions check.
If it outputs `{"customerId": vars.customerId, "status": "PROCESSED"}`, 
then assert: `payload.customerId` and `payload.status`"""

    def _build_mock_derivation_rules(self) -> str:
        """Build expert mock derivation with concrete examples."""
        return """## STEP 2 — BUILD MOCKS BY READING DOWNSTREAM DATAWEAVE

### 2.1 THE GOLDEN RULE
The mock payload MUST contain the EXACT fields that the NEXT transform reads.
If the transform after http:request reads `payload.response.items[0].productId`, 
your mock MUST return `{"response": {"items": [{"productId": "MOCK-PROD-001"}]}}`

### 2.2 HOW TO FIND REQUIRED FIELDS
Look at the DataWeave AFTER the connector. Find all `payload.xxx` references:

Example DataWeave:
```
%dw 2.0
output application/json
---
{
    clientId: payload.customer.id,
    clientName: payload.customer.fullName,
    email: payload.customer.contactEmail
}
```

The mock for the connector BEFORE this transform MUST return:
```json
{"customer": {"id": "MOCK-CUSTOMER-001", "fullName": "Test Customer", "contactEmail": "test@example.com"}}
```

### 2.3 MOCK-WHEN STRUCTURE (match by doc:name, NOT config-ref)

CORRECT:
```xml
<munit-tools:mock-when doc:name="Mock Backend API" processor="http:request">
    <munit-tools:with-attributes>
        <munit-tools:with-attribute attributeName="doc:name" whereValue="Call Backend API"/>
    </munit-tools:with-attributes>
    <munit-tools:then-return>
        <munit-tools:payload value='#[{"customer": {"id": "MOCK-001", "fullName": "Test"}}]' mediaType="application/json"/>
        <munit-tools:attributes value='#[{statusCode: 200, headers: {"content-type": "application/json"}}]'/>
    </munit-tools:then-return>
</munit-tools:mock-when>
```

WRONG (matches all http:request, triggers wrong connector):
```xml
<munit-tools:mock-when processor="http:request">
    <munit-tools:then-return>
        <munit-tools:payload value='#[{"status": "success"}]'/>  <!-- Generic garbage -->
    </munit-tools:then-return>
</munit-tools:mock-when>
```

### 2.4 CONNECTOR-SPECIFIC MOCK PATTERNS

**http:request** — ALWAYS include attributes with statusCode:
```xml
<munit-tools:then-return>
    <munit-tools:payload value='#[{derived fields here}]' mediaType="application/json"/>
    <munit-tools:attributes value='#[{statusCode: 200, headers: {"content-type": "application/json"}}]'/>
</munit-tools:then-return>
```

**db:select** — Returns array, even for single row:
```xml
<munit-tools:payload value='#[[{"id": 1, "name": "Record"}]]' mediaType="application/java"/>
```

**salesforce:query** — Returns records array:
```xml
<munit-tools:payload value='#[[{"Id": "001xx000003ABCD", "Name": "Account"}]]' mediaType="application/java"/>
```

**anypoint-mq:publish / kafka:producer / email:send** — VOID connectors, use verify-call NOT mock:
```xml
<!-- In validation section, NOT behavior -->
<munit-tools:verify-call processor="anypoint-mq:publish" times="1">
    <munit-tools:with-attributes>
        <munit-tools:with-attribute attributeName="doc:name" whereValue="Publish to Queue"/>
    </munit-tools:with-attributes>
</munit-tools:verify-call>
```"""

    def _build_set_event_rules(self) -> str:
        """Build expert set-event rules that simulate the trigger correctly."""
        return """## STEP 3 — SET-EVENT SIMULATES THE TRIGGER (not a mock!)

### 3.1 CRITICAL UNDERSTANDING
munit:set-event REPLACES the trigger (http:listener, mq:subscriber, etc.)
It does NOT mock it. The trigger never executes in MUnit tests.
set-event provides: payload + attributes that the trigger WOULD have provided.

### 3.2 FIND REQUIRED INPUT FIELDS
Look at the FIRST transform:message in the flow. What does it read from payload?

Example flow starts with:
```xml
<http:listener doc:name="Receive Order" config-ref="HTTP_Config" path="/orders" method="POST"/>
<transform:message doc:name="Validate Order">
    <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
        ---
        {
            orderId: payload.order.id,
            items: payload.order.lineItems,
            customerId: payload.customer.customerId
        }]]></ee:set-payload>
    </ee:message>
</transform:message>
```

The set-event MUST provide:
- payload.order.id
- payload.order.lineItems (array)
- payload.customer.customerId
- attributes for HTTP (method, requestPath, headers)

### 3.3 SET-EVENT STRUCTURE BY TRIGGER TYPE

**HTTP Listener:**
```xml
<munit:set-event doc:name="Set HTTP Request">
    <munit:payload value='#[{
        "order": {
            "id": "ORD-TEST-001",
            "lineItems": [{"sku": "SKU-001", "qty": 2}]
        },
        "customer": {"customerId": "CUST-001"}
    }]' mediaType="application/json"/>
    <munit:attributes value='#[{
        method: "POST",
        requestPath: "/orders",
        headers: {"content-type": "application/json", "x-correlation-id": "test-123"},
        queryParams: {},
        uriParams: {}
    }]'/>
</munit:set-event>
```

**Anypoint MQ Subscriber:**
```xml
<munit:set-event doc:name="Set MQ Message">
    <munit:payload value='#[{derived from first transform}]' mediaType="application/json"/>
    <munit:attributes value='#[{
        messageId: "MSG-TEST-001",
        destination: {name: "my-queue", type: "QUEUE"},
        properties: {}
    }]'/>
</munit:set-event>
```

**Scheduler:**
```xml
<munit:set-event doc:name="Set Scheduler Trigger">
    <munit:payload value='#[null]'/>
    <munit:attributes value='#[{scheduledTime: now()}]'/>
</munit:set-event>
```

**SFTP Listener:**
```xml
<munit:set-event doc:name="Set SFTP File">
    <munit:payload value='#["col1,col2\\nval1,val2"]' mediaType="text/csv"/>
    <munit:attributes value='#[{
        fileName: "test-file.csv",
        directory: "/inbound",
        size: 24,
        timestamp: now()
    }]'/>
</munit:set-event>
```

### 3.4 SET-EVENT MUST BE FIRST IN BEHAVIOR
```xml
<munit:behavior>
    <!-- 1. FIRST: set-event (simulates trigger) -->
    <munit:set-event doc:name="Set Input">...</munit:set-event>
    
    <!-- 2. THEN: mocks for external connectors -->
    <munit-tools:mock-when processor="http:request">...</munit-tools:mock-when>
    <munit-tools:mock-when processor="db:select">...</munit-tools:mock-when>
</munit:behavior>
```

### 3.5 SCENARIO-SPECIFIC SET-EVENT

**Happy Path:** All required fields with valid values
**Empty Payload:** `<munit:payload value='#[null]'/>` (tests null handling)
**Invalid Input:** Remove one required field to trigger validation error
**Missing Field:** Set field to null: `"customerId": null`
**Error Path:** Valid input, but mock returns error (set-event is same as happy path)"""

    def _build_assertion_derivation_rules(self) -> str:
        """Build rules for deriving assertions from flow output."""
        return """## STEP 4 — DERIVE ASSERTIONS FROM FINAL OUTPUT

### 4.1 FIND THE FINAL TRANSFORM
The last transform:message or set-payload determines what you assert.

Example final transform:
```xml
<transform:message doc:name="Build Response">
    <ee:set-payload><![CDATA[%dw 2.0
    ---
    {
        status: "SUCCESS",
        orderId: vars.orderId,
        processedItems: sizeOf(vars.items),
        timestamp: now()
    }]]></ee:set-payload>
</transform:message>
```

### 4.2 DERIVE ASSERTIONS FROM OUTPUT FIELDS
For the above transform, assert:
```xml
<munit-tools:assert-that expression='#[payload.status]' is='#[MunitTools::equalTo("SUCCESS")]' message="Status should be SUCCESS"/>
<munit-tools:assert-that expression='#[payload.orderId]' is='#[MunitTools::notNullValue()]' message="Order ID should not be null"/>
<munit-tools:assert-that expression='#[payload.processedItems]' is='#[MunitTools::greaterThan(0)]' message="Should have processed items"/>
```

### 4.3 ERROR SCENARIO ASSERTIONS
For error tests, add expectedErrorType and assert error fields:
```xml
<munit:test name="test-flow-validation-error" expectedErrorType="VALIDATION:INVALID_INPUT">
    <!-- ... behavior with invalid input ... -->
    <munit:validation>
        <munit-tools:assert-that expression='#[error.description]' is='#[MunitTools::containsString("required field")]'/>
    </munit:validation>
</munit:test>
```

### 4.4 AVOID GENERIC ASSERTIONS
BAD: `<munit-tools:assert-that expression='#[payload]' is='#[MunitTools::notNullValue()]'/>`
GOOD: Assert SPECIFIC fields that the flow outputs"""

    def _build_sample_payload_section(self, sample_payload: str) -> str:
        """
        Build the sample payload section.

        This is the MUnit-recorder equivalent: real request/response data that
        the user captured from a live run. It is the HIGHEST-PRIORITY source
        for set-event payload values and mock return values.

        The instructions tell the LLM to:
          1. Use the sample request body directly as the munit:set-event payload.
          2. Use the sample response body as the mock return payload for the
             first outbound connector, then derive mocks for downstream ones
             from the DataWeave transforms.
          3. Derive assertions from the actual response fields shown here
             rather than guessing from DWL.
        """
        truncated = sample_payload.strip()
        if len(truncated) > 3000:
            truncated = truncated[:3000] + "\n...[truncated — use the fields shown above]"

        return f"""## SAMPLE REQUEST / RESPONSE DATA (USE THIS FIRST — highest priority)

The user has provided real payload data captured from a live run of this flow.
This is equivalent to what MUnit Test Recorder captures. Use it as follows:

### Rules:
1. **set-event payload**: Copy the REQUEST section below directly as the
   munit:set-event `<munit:payload>` value. Do NOT invent fields.
2. **Mock return values**: Use the RESPONSE section below as the mock payload
   returned by the first outbound connector. For downstream connectors derive
   from DataWeave as usual.
3. **Assertions**: Assert the specific field names and values visible in the
   RESPONSE section, not generic notNullValue() checks.
4. **Error scenarios**: Keep the same REQUEST payload but change the mock to
   return an error (using `<munit-tools:error typeId="..."/>`).

### Sample Data:
{truncated}"""

    def _build_dwl_section(self, dwl_content: Dict) -> str:
        """Build DataWeave files section for mock payload derivation."""
        if not dwl_content:
            return ""
        
        section = [
            "## DATAWEAVE FILES — CRITICAL FOR MOCK DERIVATION",
            "",
            "Use these to find what fields each transform reads/writes.",
            "Your mocks MUST return the fields that the NEXT transform expects.",
            ""
        ]
        
        for path, content in list(dwl_content.items())[:5]:  # Limit to 5 DWL files
            truncated = self._truncate_block(content, 1500)
            section.append(f"### {path}")
            section.append(truncated)
            section.append("")
        
        if len(dwl_content) > 5:
            section.append(f"... and {len(dwl_content) - 5} more DWL files")
        
        return "\n".join(section)

    def _build_flow_section(self, flow_summary: Dict, flow_context: Dict = None) -> str:
        """Build flow information section."""
        active_targets = flow_summary.get('test_targets', flow_summary['flows'])
        if flow_context:
            active_targets = [flow_context.get("target_flow", active_targets[0] if active_targets else "main-flow")]

        section = [
            "MULE APPLICATION ANALYSIS:",
            "",
            f"Job Type: {flow_summary['job_type']}",
            f"Main Flows: {', '.join(flow_summary['flows'])}",
            f"Sub-flows: {', '.join(flow_summary['sub_flows'])}",
            f"Test Targets: {', '.join(active_targets)}",
            f"Connectors Used: {', '.join(flow_summary['connectors'])}",
            f"Transformers: {', '.join(flow_summary['transformers'])}",
            f"Error Handlers: {', '.join(flow_summary['error_handlers'])}",
        ]

        if flow_context:
            section.extend([
                "Target Flow Context:",
                f"  - Target Flow: {flow_context.get('target_flow', 'main-flow')}",
                f"  - Target Type: {flow_context.get('target_type', 'flow')}",
                f"  - Source File: {flow_context.get('source_file', 'unknown.xml')}",
                f"  - Parent Flows: {', '.join(flow_context.get('parent_flows', [])) or 'none'}",
                f"  - Child Flows: {', '.join(flow_context.get('child_flows', [])) or 'none'}",
                f"  - Related Flows: {', '.join(flow_context.get('related_flows', [])) or 'none'}",
                f"  - Target Connectors: {', '.join(flow_context.get('connectors', [])) or 'none'}",
                f"  - Target Error Handlers: {', '.join(flow_context.get('error_handlers', [])) or 'none'}",
            ])
            trigger = flow_context.get("trigger", {})
            if trigger:
                section.append(f"  - Trigger Processor: {trigger.get('summary', trigger.get('type', 'unknown'))}")
            final_processor = flow_context.get("final_processor", {})
            if final_processor:
                section.append(f"  - Final Processor: {final_processor.get('summary', final_processor.get('type', 'unknown'))}")
            payload_refs = flow_context.get("payload_references", []) or []
            if payload_refs:
                section.append(f"  - Data References: {', '.join(payload_refs[:12])}")
            dwl_files = flow_context.get("dwl_files", []) or []
            if dwl_files:
                section.append(f"  - DWL Resources: {', '.join(dwl_files[:8])}")
            processor_chain = flow_context.get("processor_chain", []) or []
            if processor_chain:
                section.append("Ordered Processor Chain:")
                for processor in processor_chain[:20]:
                    section.append(f"  {processor.get('index', 0)}. {processor.get('summary', processor.get('type', 'processor'))}")
            mock_plan = flow_context.get("mock_plan", []) or []
            if mock_plan:
                section.append("Deterministic Mock/Verify Plan:")
                for item in mock_plan[:16]:
                    downstream_refs = ", ".join(item.get("downstream_payload_references", [])[:8]) or "none detected"
                    return_attrs = item.get("return_attributes")
                    section.append(
                        "  - "
                        f"{item.get('action', 'mock-when')} {item.get('processor', 'processor')} "
                        f"where {item.get('match_attribute', 'doc:name')}='{item.get('match_value', '')}' "
                        f"returns {item.get('result_shape', 'object')} as {item.get('media_type', 'application/json')}; "
                        f"downstream reads: {downstream_refs}"
                    )
                    if return_attrs:
                        section.append(f"    return attributes: {return_attrs}")
            xml_snippet = (flow_context.get("xml_snippet") or "").strip()
            if xml_snippet:
                section.append("Target Flow XML Snippet:")
                section.append(self._truncate_block(xml_snippet, 2200))
            related_details = flow_context.get("related_flow_details", []) or []
            child_details = [
                detail for detail in related_details
                if detail.get("name") and detail.get("name") != flow_context.get("target_flow")
            ]
            if child_details:
                section.append("Referenced Child Flow XML Snippets:")
                for detail in child_details[:4]:
                    snippet = (detail.get("xml_snippet") or "").strip()
                    if not snippet:
                        continue
                    section.append(f"### {detail.get('type', 'flow')} {detail.get('name')} in {detail.get('source_file', 'unknown.xml')}")
                    section.append(self._truncate_block(snippet, 1600))

        source_files = flow_summary.get("source_files", [])
        if source_files:
            section.append(f"Source Files: {', '.join(source_files[:10])}")
            if len(source_files) > 10:
                section.append(f"Additional Source Files Count: {len(source_files) - 10}")

        if flow_summary['http_endpoints']:
            section.append("HTTP Endpoints:")
            for endpoint in flow_summary['http_endpoints']:
                section.append(f"  - {endpoint['method']} {endpoint['path']} (config: {endpoint['config_ref']})")

        flow_details = flow_summary.get("flow_details", [])
        if flow_details:
            section.append("Flow Details:")
            filtered_details = flow_details
            if flow_context:
                related = set(flow_context.get("related_flows", []))
                filtered_details = [detail for detail in flow_details if detail.get("name") in related]

            for detail in filtered_details[:12]:
                source_file = detail.get("source_file", "unknown.xml")
                referenced_flows = ", ".join(detail.get("referenced_flows", [])) or "none"
                connectors = ", ".join(detail.get("connectors", [])) or "none"
                handlers = ", ".join(detail.get("error_handlers", [])) or "none"
                section.append(
                    f"  - {detail['type']} {detail['name']} in {source_file}: "
                    f"references [{referenced_flows}], connectors [{connectors}], error handlers [{handlers}]"
                )
            if len(filtered_details) > 12:
                section.append(f"  - Additional flow details omitted: {len(filtered_details) - 12}")
        
        return "\n".join(section)

    def _build_scenarios_section(self, scenarios: List[Dict]) -> str:
        """Build scenarios section."""
        section = [
            "BUSINESS SCENARIOS TO TEST:",
            ""
        ]
        
        for i, scenario in enumerate(scenarios, 1):
            section.append(f"{i}. {scenario['description']}")
            section.append(f"   Type: {scenario['type']}")
            section.append("")
        
        return "\n".join(section)

    def _build_document_context_section(self, document_context: Optional[Dict], flow_context: Dict = None) -> str:
        """Build business use-case context section."""
        if not document_context:
            return ""

        section = [
            "BUSINESS USE CASE CONTEXT:",
            ""
        ]

        business_rules = document_context.get("business_rules", []) or []
        inputs_outputs = document_context.get("inputs_outputs", []) or []
        raw_excerpt = (document_context.get("raw_content_excerpt") or "").strip()

        if business_rules:
            section.append("Business Rules:")
            for rule in business_rules[:8]:
                section.append(f"- {rule}")
            section.append("")

        if inputs_outputs:
            section.append("Important Input/Output Expectations:")
            for pair in inputs_outputs[:8]:
                section.append(f"- {pair.get('type', 'detail')}: {pair.get('description', '')}")
            section.append("")

        if raw_excerpt:
            section.append("Use Case Excerpt:")
            section.append(self._truncate_block(raw_excerpt, 2500))
            section.append("")

        section.extend([
            "Coverage Expectations:",
            "- Generate tests that maximize branch and error-path coverage for this target flow.",
            "- Prefer concrete business assertions derived from the use case over generic not-null checks.",
            "- Cover the target flow's success path, validation failures, downstream failures, and explicit error handlers where applicable."
        ])

        return "\n".join(section)

    def _build_ruleset_section(self, ruleset: Dict, flow_context: Dict = None, munit_version: Optional[str] = None) -> str:
        """Build ruleset section with FULL rules from YAML files."""
        resolved_munit_version = (munit_version or "3.6.0").strip()
        # Derive a concrete test naming example
        base_name = "flow-name"
        if flow_context:
            source_file = flow_context.get("source_file", "")
            target_flow = flow_context.get("target_flow", "")
            if source_file and source_file != "unknown.xml":
                base_name = source_file.rsplit(".", 1)[0].replace("_", "-").lower()
                base_name = "".join(c for c in base_name if c.isalnum() or c == "-").strip("-")
            elif target_flow:
                base_name = target_flow.replace("_", "-").lower()
                base_name = "".join(c for c in base_name if c.isalnum() or c == "-").strip("-")

        naming_convention = ruleset.get('munit_structure', {}).get(
            'test_naming_convention', 'test-{flow-name}-{scenario}'
        ).replace("{flow-name}", base_name)

        section = [
            "## MUNIT GENERATION RULES (from ruleset files)",
            "",
            f"### Test Naming: {naming_convention}",
            ""
        ]
        relevant_connectors = set((flow_context or {}).get("connectors", []) or [])
        relevant_scenario_types = {
            scenario.get("type")
            for scenario in ((flow_context or {}).get("scenarios", []) or [])
            if scenario.get("type")
        }
        target_trigger = ((flow_context or {}).get("trigger", {}) or {}).get("type", "")
        
        # ─────────────────────────────────────────
        # INCLUDE FULL MOCK RULES FROM YAML
        # ─────────────────────────────────────────
        mock_rules = ruleset.get('mock_rules', {})
        mock_strategies = mock_rules.get('mock_strategies', {})
        
        section.extend([
            "### MOCK RULES (from mock_rules.yaml)",
            "",
            "**Payload Derivation Rule:**",
            "Mock payload is NEVER hardcoded. It is ALWAYS derived from the DataWeave",
            "transform that immediately follows the connector in the flow.",
            "",
            "**Algorithm:**",
            "1. Find the connector in the flow XML",
            "2. Find the NEXT transform:message or set-variable after it",
            "3. Extract every field that transform READS from payload (e.g. payload.id)",
            "4. Build a mock object containing exactly those fields",
            "",
            "**Connector-Specific Mock Patterns:**",
        ])
        
        # Add detailed mock strategy for each connector
        for connector, strategy in mock_strategies.items():
            if relevant_connectors and connector not in relevant_connectors:
                continue
            mock_type = strategy.get('mock_type', 'unknown')
            matching = strategy.get('matching_attributes', {})
            
            if mock_type == 'munit:set-event':
                # Source connectors - use set-event
                section.append(f"")
                section.append(f"**{connector}** → SOURCE CONNECTOR (use set-event, not mock)")
                section.append(f"  - Set payload derived from first downstream transform")
                attrs = strategy.get('attributes_to_set', {})
                if attrs:
                    section.append(f"  - Required attributes: {attrs}")
            elif strategy.get('return_type') == 'void':
                # Void connectors - use verify-call
                section.append(f"")
                section.append(f"**{connector}** → VOID CONNECTOR (use verify-call in validation)")
                section.append(f"  ```xml")
                section.append(f"  <munit-tools:verify-call processor='{connector}' times='1'>")
                section.append(f"      <munit-tools:with-attributes>")
                section.append(f"          <munit-tools:with-attribute attributeName='doc:name' whereValue='...'/>")
                section.append(f"      </munit-tools:with-attributes>")
                section.append(f"  </munit-tools:verify-call>")
                section.append(f"  ```")
            else:
                # Regular connectors - use mock-when
                payload_source = strategy.get('payload_source', 'derive')
                result_format = strategy.get('result_format', 'object')
                media_type = strategy.get('media_type', 'application/json')
                
                section.append(f"")
                section.append(f"**{connector}** → mock-when with doc:name matching")
                section.append(f"  - Payload source: {payload_source}")
                section.append(f"  - Result format: {result_format} {'(wrap in [])' if result_format == 'array' else ''}")
                section.append(f"  - Media type: {media_type}")
                
                # Show fixed payloads for insert/update operations
                if strategy.get('fixed_payload'):
                    section.append(f"  - Fixed payload: {strategy.get('fixed_payload')}")
                
                # Show error scenario overrides
                error_override = strategy.get('error_scenario_overrides') or strategy.get('error_scenario_payload')
                if error_override:
                    section.append(f"  - Error scenario: {error_override}")
                
                # Show required attributes (e.g., statusCode for http:request)
                attrs = strategy.get('attributes_to_return', {})
                if attrs:
                    section.append(f"  - Must return attributes: {attrs}")
        
        # ─────────────────────────────────────────
        # INCLUDE WHAT TO MOCK VS NOT MOCK FROM munit_structure.yaml
        # ─────────────────────────────────────────
        munit_structure = ruleset.get('munit_structure', {})
        behavior_section = munit_structure.get('behavior_section', {})
        
        mock_applies = behavior_section.get('mock_when_applies_to', [])
        mock_not_applies = behavior_section.get('mock_when_does_NOT_apply_to', [])
        
        if mock_applies or mock_not_applies:
            section.extend([
                "",
                "### MOCK SCOPE (from munit_structure.yaml)",
                "",
                "**mock-when APPLIES TO (external connectors):**"
            ])
            for item in mock_applies:
                section.append(f"  - {item}")
            
            section.extend([
                "",
                "**mock-when does NOT apply to (NEVER MOCK THESE):**"
            ])
            for item in mock_not_applies:
                section.append(f"  - {item}")
        
        # ─────────────────────────────────────────
        # INCLUDE SET-EVENT TEMPLATES FROM munit_structure.yaml
        # ─────────────────────────────────────────
        set_event_struct = munit_structure.get('set_event_structure', {})
        if set_event_struct:
            section.extend([
                "",
                "### SET-EVENT TEMPLATES (from munit_structure.yaml)",
            ])
            
            # HTTP template
            if set_event_struct.get('full_template'):
                section.append("")
                section.append("**HTTP Listener set-event:**")
                section.append("```xml")
                section.append(set_event_struct.get('full_template', '').strip())
                section.append("```")
            
            # Scheduler template
            if set_event_struct.get('scheduler_template'):
                section.append("")
                section.append("**Scheduler set-event:**")
                section.append("```xml")
                section.append(set_event_struct.get('scheduler_template', '').strip())
                section.append("```")
            
            # MQ template
            if set_event_struct.get('mq_template'):
                section.append("")
                section.append("**MQ Subscriber set-event:**")
                section.append("```xml")
                section.append(set_event_struct.get('mq_template', '').strip())
                section.append("```")
        
        # ─────────────────────────────────────────
        # INCLUDE ASSERTION RULES FROM assertion_rules.yaml
        # ─────────────────────────────────────────
        assertion_rules_data = ruleset.get('assertion_rules', {})
        assertion_types = assertion_rules_data.get('assertion_types', {})
        
        if assertion_types:
            section.extend([
                "",
                "### ASSERTION RULES (from assertion_rules.yaml)",
            ])
            
            for scenario_type, assertions in assertion_types.items():
                if relevant_scenario_types and scenario_type not in relevant_scenario_types and scenario_type != "happy_path":
                    continue
                required = assertions.get('required_assertions', [])
                section.append(f"")
                section.append(f"**{scenario_type}:**")
                for assertion in required[:3]:  # Limit to 3 per type
                    expr = assertion.get('expression', assertion.get('expression_template', ''))
                    matcher = assertion.get('matcher', assertion.get('matcher_template', ''))
                    desc = assertion.get('message', assertion.get('description', ''))
                    section.append(f"  - {assertion.get('type', 'check')}: expression={expr}, matcher={matcher}")
        
        # ─────────────────────────────────────────
        # INCLUDE SCENARIO DERIVATION FROM scenario_rules.yaml
        # ─────────────────────────────────────────
        scenario_rules = ruleset.get('scenario_rules', {})
        input_derivation = scenario_rules.get('scenario_derivation_rules', {}).get('input_derivation_by_trigger', {})
        
        if input_derivation:
            section.extend([
                "",
                "### INPUT DERIVATION BY TRIGGER (from scenario_rules.yaml)",
            ])
            for trigger, rules in input_derivation.items():
                if target_trigger and trigger not in target_trigger:
                    continue
                section.append(f"")
                section.append(f"**{trigger}:**")
                payload_fields = rules.get('payload_fields', 'derive from first transform')
                section.append(f"  - Derive payload from: {payload_fields}")
                if rules.get('example'):
                    section.append(f"  - Example: {rules.get('example')}")

        # Add detailed connector guidance for target flow
        target_connectors = (flow_context or {}).get("connectors", [])
        if target_connectors:
            section.extend(["", "### TARGET FLOW CONNECTOR GUIDANCE:"])
            for connector in target_connectors:
                strategy = mock_strategies.get(connector, {})
                if strategy:
                    section.append(
                        f"- {connector}: mock_type={strategy.get('mock_type', 'unknown')}, "
                        f"match by={strategy.get('matching_attributes', {}).get('primary', 'doc:name')}, "
                        f"payload_source={strategy.get('payload_source', 'derive')}"
                    )

        # Add strict output instructions with checklist
        section.extend([
            "",
            "### FINAL CHECKLIST — VERIFY BEFORE GENERATING",
            "",
            "Before writing XML, confirm:",
            "[ ] I identified the trigger type (http:listener, scheduler, mq:subscriber, etc.)",
            "[ ] I traced every processor and know what each reads/writes",
            "[ ] I found all external connectors that need mocks",
            "[ ] For each mock, I found the downstream DWL and derived exact field names",
            "[ ] I built set-event payload from what the FIRST transform expects",
            "[ ] I built assertions from what the LAST transform outputs",
            "[ ] I am NOT mocking: ee:transform, transform:message, set-variable, flow-ref, logger, choice",
            "[ ] I am using doc:name matching for all mocks",
            "[ ] I included attributes with statusCode for http:request mocks",
            "",
            "### STRICT OUTPUT RULES",
            f"- Return ONLY valid MUnit {resolved_munit_version} XML. No markdown, no explanations, no code fences.",
            "- One munit:test per scenario.",
            "- Test naming: test-{flow-name}-{scenario-type}",
            "- set-event FIRST in behavior, then mock-when elements",
            "- flow-ref in execution calls the target flow",
            "- Let child flow-ref processors execute; do not mock child flows unless they are true external utility boundaries.",
            "- Use the Deterministic Mock/Verify Plan when present; it is derived from the ordered XML and is more reliable than guessing.",
            "- Assert SPECIFIC fields in validation, not generic payload checks",
            "",
            "### FORBIDDEN (will cause test failures):",
            "- munit-tools:assert-equals → use assert-that with equalTo()",
            "- munit-tools:assert → does not exist",
            "- munit-tools:assert-error-type → does not exist",
            "- Mocking ee:transform / transform:message → defeats test purpose",
            "- Mocking flow-ref to sub-flows → breaks the logic chain",
            "- Generic mocks without doc:name matching → may mock wrong connector",
            "- Payloads like {\"status\": \"success\"} → must derive from actual DWL"
        ])
        
        return "\n".join(section)

    def _truncate_block(self, text: str, max_chars: int) -> str:
        """Trim verbose text blocks while preserving readability."""
        cleaned = text.strip()
        if len(cleaned) <= max_chars:
            return cleaned
        return cleaned[:max_chars].rstrip() + "\n...[truncated]"

    def _count_tokens(self, text: str) -> int:
        """Count tokens in text using simple character-based estimation."""
        # Simple estimation: 1 token ~ 4 characters on average
        # This is a rough approximation but works well enough for our purposes
        return len(text) // 4

    def _optimize_prompt(self, prompt: str, current_tokens: int) -> str:
        """
        Optimize prompt to fit within token limit.
        
        Args:
            prompt: Current prompt
            current_tokens: Current token count
            
        Returns:
            Optimized prompt
        """
        # Split prompt into sections
        sections = prompt.split("\n\n")
        
        # Try to truncate use case text first (usually in scenarios section)
        for i, section in enumerate(sections):
            if "BUSINESS SCENARIOS" in section:
                # Keep only first few scenarios
                lines = section.split('\n')
                new_lines = []
                scenario_count = 0
                for line in lines:
                    if line.strip().startswith(('1.', '2.', '3.', '4.', '5.')):
                        scenario_count += 1
                        if scenario_count <= 3:  # Keep only first 3 scenarios
                            new_lines.append(line)
                    elif not line.strip().startswith(('6.', '7.', '8.', '9.', '10.')):
                        new_lines.append(line)
                
                sections[i] = '\n'.join(new_lines)
                break
        
        # Rebuild and check
        optimized_prompt = "\n\n".join(sections)
        optimized_tokens = self._count_tokens(optimized_prompt)
        
        if optimized_tokens > self.max_tokens:
            # If still too long, simplify flow summary
            for i, section in enumerate(sections):
                if "MULE APPLICATION ANALYSIS" in section:
                    # Keep only essential info
                    lines = section.split('\n')
                    essential_lines = [lines[0]]  # Header
                    for line in lines[1:]:
                        if any(keyword in line for keyword in ['Job Type:', 'Main Flows:', 'Connectors Used:']):
                            essential_lines.append(line)
                    sections[i] = '\n'.join(essential_lines)
                    break
        
        optimized_prompt = "\n\n".join(sections)
        final_tokens = self._count_tokens(optimized_prompt)
        
        if final_tokens > self.max_tokens:
            # Last resort: truncate ruleset (never truncate this in real implementation)
            self.console.print(f"[red]Warning: Still over token limit, may need manual optimization[/red]")
            return optimized_prompt
        
        self.console.print(f"[green]Optimized prompt: {final_tokens} tokens (was {current_tokens})[/green]")
        return optimized_prompt

    def validate_prompt_structure(self, prompt: str) -> bool:
        """
        Validate prompt has required sections.
        
        Args:
            prompt: Prompt to validate
            
        Returns:
            True if prompt structure is valid
        """
        required_sections = [
            "MULE APPLICATION ANALYSIS",
            "BUSINESS SCENARIOS",
            "MUNIT GENERATION RULES"
        ]
        
        prompt_upper = prompt.upper()
        return all(section in prompt_upper for section in required_sections)
