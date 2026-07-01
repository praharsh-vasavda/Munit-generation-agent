"""
tests/test_dynamic_flow_resolver.py
────────────────────────────────────
Covers all 9 dynamic flow-ref patterns:
  1. Literal flow-ref           #['OrderFlow']
  2. Variable flow-ref          #[vars.targetFlow]
  3. Choice branch + variable   choice → set-variable → flow-ref
  4. DW inline if/else          #[if (cond) 'FlowA' else 'FlowB']
  5. String concat              #['process-' ++ vars.type ++ '-flow']
  6. Map dispatch               #[{order: 'OrderFlow', invoice: 'InvoiceFlow'}[vars.type]]
  7. DW lookup() literal        lookup("ProcessFlow", payload)
  8. DW lookup() with variable  lookup(vars.targetFlow, payload)
  9. DW lookup() with concat    lookup("process-" ++ vars.type ++ "-flow", payload)
"""

import json
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

# Allow running from project root without installing
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.dynamic_flow_resolver import DynamicFlowResolver, resolve_dynamic_refs
from core.deterministic_munit_builder import DeterministicMUnitBuilder
from core.xml_analyzer import XMLAnalyzer

ALL_FLOWS = {
    "OrderFlow",
    "InvoiceFlow",
    "ProcessFlow",
    "process-order-flow",
    "process-invoice-flow",
    "process-return-flow",
    "FlowA",
    "FlowB",
    "SubFlowX",
    "CreditFlow",
}


def _xml(snippet: str) -> ET.Element:
    """Wrap snippet in a <flow> root and parse it."""
    return ET.fromstring(f"""
    <mule xmlns="http://www.mulesoft.org/schema/mule/core"
          xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
      <flow name="test-flow">
        {snippet}
      </flow>
    </mule>""").find(".//{http://www.mulesoft.org/schema/mule/core}flow") \
    or ET.fromstring(f"<flow>{snippet}</flow>")


# ── Case 1: Literal string ────────────────────────────────────────────────────

def test_literal_flow_ref():
    el = _xml('<flow-ref name="#[\'OrderFlow\']"/>')
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    assert "OrderFlow" in result.dynamic_refs, f"Got: {result.dynamic_refs}"


# ── Case 2: Variable reference ────────────────────────────────────────────────

def test_variable_flow_ref():
    el = _xml("""
        <set-variable variableName="targetFlow" value="InvoiceFlow"/>
        <flow-ref name="#[vars.targetFlow]"/>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    assert "InvoiceFlow" in result.all_refs, f"Got: {result.all_refs}"


# ── Case 3: Choice branch sets variable, then flow-ref uses it ───────────────

def test_choice_branch_variable():
    """
    Real-world pattern:
      <choice>
        <when expression="#[vars.type == 'order']">
          <set-variable variableName="flowName" value="OrderFlow"/>
        </when>
        <otherwise>
          <set-variable variableName="flowName" value="InvoiceFlow"/>
        </otherwise>
      </choice>
      <flow-ref name="#[vars.flowName]"/>
    """
    el = _xml("""
        <choice>
          <when expression="#[vars.type == 'order']">
            <set-variable variableName="flowName" value="OrderFlow"/>
          </when>
          <otherwise>
            <set-variable variableName="flowName" value="InvoiceFlow"/>
          </otherwise>
        </choice>
        <flow-ref name="#[vars.flowName]"/>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    assert "OrderFlow" in result.all_refs, f"OrderFlow missing: {result.all_refs}"
    assert "InvoiceFlow" in result.all_refs, f"InvoiceFlow missing: {result.all_refs}"


# ── Case 4: DW inline if/else ────────────────────────────────────────────────

def test_dw_inline_if_else():
    el = _xml("""
        <flow-ref name="#[if (vars.type == 'order') 'FlowA' else 'FlowB']"/>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    assert "FlowA" in result.dynamic_refs, f"FlowA missing: {result.dynamic_refs}"
    assert "FlowB" in result.dynamic_refs, f"FlowB missing: {result.dynamic_refs}"


# ── Case 5: String concatenation ─────────────────────────────────────────────

def test_string_concat():
    """
    <flow-ref name="#['process-' ++ vars.type ++ '-flow']"/>
    With vars.type possibly being 'order', 'invoice', 'return' —
    should match: process-order-flow, process-invoice-flow, process-return-flow
    """
    el = _xml("""
        <set-variable variableName="type" value="order"/>
        <flow-ref name="#['process-' ++ vars.type ++ '-flow']"/>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    # Should find process-order-flow via variable substitution
    assert "process-order-flow" in result.all_refs, f"Got: {result.all_refs}"


def test_string_concat_prefix_only():
    """Even without knowing vars.type, prefix matching gives candidates."""
    el = _xml("""
        <flow-ref name="#['process-' ++ vars.type ++ '-flow']"/>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    # All three process-*-flow names should be found by prefix/suffix pattern
    found = result.all_refs
    assert any(f.startswith("process-") for f in found), f"No process-* flows found: {found}"


# ── Case 6: Map / dict dispatch ───────────────────────────────────────────────

def test_map_dispatch():
    """
    <flow-ref name="#[{order: 'OrderFlow', invoice: 'InvoiceFlow'}[vars.type]]"/>
    """
    el = _xml("""
        <flow-ref name="#[{order: 'OrderFlow', invoice: 'InvoiceFlow'}[vars.type]]"/>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    assert "OrderFlow" in result.dynamic_refs, f"OrderFlow missing: {result.dynamic_refs}"
    assert "InvoiceFlow" in result.dynamic_refs, f"InvoiceFlow missing: {result.dynamic_refs}"


# ── Case 7: DW lookup() literal ───────────────────────────────────────────────

def test_dw_lookup_literal():
    el = _xml("""
        <ee:transform xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
          <ee:message>
            <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
lookup("ProcessFlow", payload)]]></ee:set-payload>
          </ee:message>
        </ee:transform>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    assert "ProcessFlow" in result.dw_lookup_refs, f"Got: {result.dw_lookup_refs}"


# ── Case 8: DW lookup() with variable ────────────────────────────────────────

def test_dw_lookup_variable():
    el = _xml("""
        <set-variable variableName="targetFlow" value="CreditFlow"/>
        <ee:transform xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
          <ee:message>
            <ee:set-payload><![CDATA[lookup(vars.targetFlow, payload)]]></ee:set-payload>
          </ee:message>
        </ee:transform>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    # CreditFlow should be in the results (resolved via variable lookup)
    assert "CreditFlow" in result.all_refs, f"Got: {result.all_refs}"


# ── Case 9: DW lookup() with concat ──────────────────────────────────────────

def test_dw_lookup_concat():
    el = _xml("""
        <set-variable variableName="type" value="order"/>
        <ee:transform xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
          <ee:message>
            <ee:set-payload><![CDATA[lookup("process-" ++ vars.type ++ "-flow", payload)]]></ee:set-payload>
          </ee:message>
        </ee:transform>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    assert "process-order-flow" in result.all_refs, f"Got: {result.all_refs}"


# ── Unresolvable — should appear in unresolved ────────────────────────────────

def test_truly_dynamic_marked_unresolved():
    """A fully runtime-computed expression produces no false candidates."""
    el = _xml("""
        <flow-ref name="#[vars.computedAtRuntime]"/>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    # No variable assignment for 'computedAtRuntime' → should be unresolved
    # (no false positives)
    assert len(result.dynamic_refs) == 0, f"Unexpected candidates: {result.dynamic_refs}"
    assert len(result.unresolved) > 0, "Should have been marked unresolved"


# ── var_value_map populated correctly ─────────────────────────────────────────

def test_var_value_map():
    el = _xml("""
        <choice>
          <when expression="#[vars.condition == 'A']">
            <set-variable variableName="flowName" value="FlowA"/>
          </when>
          <otherwise>
            <set-variable variableName="flowName" value="FlowB"/>
          </otherwise>
        </choice>
        <flow-ref name="#[vars.flowName]"/>
    """)
    result = resolve_dynamic_refs(el, ALL_FLOWS)
    vmap = result.var_value_map
    assert "flowName" in vmap, f"var_value_map: {vmap}"
    assert "FlowA" in vmap["flowName"], f"FlowA not in map values: {vmap}"
    assert "FlowB" in vmap["flowName"], f"FlowB not in map values: {vmap}"


def test_weather_style_nested_dynamic_flow_chain():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core"
          xmlns:http="http://www.mulesoft.org/schema/mule/http"
          xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
          xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
      <flow name="weather-experience-flow">
        <http:listener doc:name="Weather listener" path="/weather"/>
        <flow-ref doc:name="Validate request" name="validate-request-flow"/>
      </flow>
      <sub-flow name="validate-request-flow">
        <choice doc:name="Validate inputs">
          <when expression="#[isEmpty(attributes.queryParams.latitude)]">
            <raise-error doc:name="Missing latitude" type="VALIDATION:MISSING_LATITUDE"/>
          </when>
          <when expression="#[isEmpty(attributes.queryParams.longitude)]">
            <raise-error doc:name="Missing longitude" type="VALIDATION:MISSING_LONGITUDE"/>
          </when>
          <otherwise>
            <flow-ref doc:name="Validation success" name="weather-api-validation-success-Flow"/>
          </otherwise>
        </choice>
      </sub-flow>
      <sub-flow name="weather-api-validation-success-Flow">
        <ee:transform doc:name="Set next flow">
          <ee:variables>
            <ee:set-variable variableName="flowName"><![CDATA[%dw 2.0
output application/java
---
"weather-process-flow"]]></ee:set-variable>
          </ee:variables>
        </ee:transform>
        <flow-ref doc:name="Call next flow" name="#[vars.flowName]"/>
      </sub-flow>
      <sub-flow name="weather-process-flow">
        <set-variable variableName="flowName" value="openmeteo-system-flow"/>
        <flow-ref doc:name="Call system flow" name="#[vars.flowName]"/>
      </sub-flow>
      <sub-flow name="openmeteo-system-flow">
        <http:request doc:name="OpenMeteo API"/>
      </sub-flow>
    </mule>"""

    result = XMLAnalyzer().analyze_mule_project(xml)
    graph = result["flow_graph"]
    context = result["flow_contexts"]["weather-experience-flow"]

    assert "validate-request-flow" in graph["weather-experience-flow"]["children"]
    assert "weather-api-validation-success-Flow" in graph["validate-request-flow"]["children"]
    assert "weather-process-flow" in graph["weather-api-validation-success-Flow"]["children"]
    assert "openmeteo-system-flow" in graph["weather-process-flow"]["children"]
    assert "openmeteo-system-flow" in context["execution_flows"]
    assert "http:request" in context["connectors"]
    assert context["munit_enable_flow_sources"] == [
        "weather-process-flow",
        "openmeteo-system-flow",
    ]

    suite_xml, metadata = DeterministicMUnitBuilder().build_suite(
        context,
        generation_mode="recorder",
    )
    assert '<munit:enable-flow-sources>' in suite_xml
    assert '<munit:enable-flow-source value="weather-process-flow"/>' in suite_xml
    assert '<munit:enable-flow-source value="openmeteo-system-flow"/>' in suite_xml
    test_start = suite_xml.index("<munit:test ")
    enable_start = suite_xml.index("<munit:enable-flow-sources>")
    execution_start = suite_xml.index("<munit:execution>")
    test_end = suite_xml.index("</munit:test>")
    assert test_start < enable_start < execution_start < test_end
    assert "<munit:enable-flow-sources>" not in suite_xml[:test_start]
    assert metadata["enabled_flow_sources"] == [
        "weather-process-flow",
        "openmeteo-system-flow",
    ]


def test_dynamic_flow_ref_from_dataweave_payload_object_field():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core"
          xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
      <flow name="main-flow">
        <ee:transform doc:name="Build route payload">
          <ee:message>
            <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  "flowName": "flowA",
  "name": "ravi",
  "status": "success"
}]]></ee:set-payload>
          </ee:message>
        </ee:transform>
        <flow-ref doc:name="Call payload route" name="#[payload.flowName]"/>
      </flow>
      <flow name="flowA">
        <logger message="flow A"/>
      </flow>
    </mule>"""

    result = XMLAnalyzer().analyze_mule_project(xml)
    graph = result["flow_graph"]
    context = result["flow_contexts"]["main-flow"]

    assert "flowA" in graph["main-flow"]["children"]
    assert "flowA" in context["execution_flows"]
    assert context["munit_enable_flow_sources"] == ["flowA"]


def test_dynamic_flow_ref_from_dataweave_variable_object_field():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core"
          xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
      <flow name="main-flow">
        <ee:transform doc:name="Build route variable">
          <ee:variables>
            <ee:set-variable variableName="route"><![CDATA[%dw 2.0
output application/java
---
{
  flowName: "flowA",
  name: "ravi",
  status: "success"
}]]></ee:set-variable>
          </ee:variables>
        </ee:transform>
        <flow-ref doc:name="Call variable route" name="#[vars.route.flowName]"/>
      </flow>
      <flow name="flowA">
        <logger message="flow A"/>
      </flow>
    </mule>"""

    result = XMLAnalyzer().analyze_mule_project(xml)
    graph = result["flow_graph"]
    context = result["flow_contexts"]["main-flow"]

    assert "flowA" in graph["main-flow"]["children"]
    assert "flowA" in context["execution_flows"]
    assert context["munit_enable_flow_sources"] == ["flowA"]


def test_dynamic_flow_ref_from_dataweave_equals_assignment():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core"
          xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
      <flow name="main-flow">
        <ee:transform>
          <ee:variables>
            <ee:set-variable variableName="flowName"><![CDATA[%dw 2.0
output application/java
var flowName = "flowA"
---
flowName
]]></ee:set-variable>
          </ee:variables>
        </ee:transform>
        <flow-ref doc:name="Call assigned route" name="#[vars.flowName]"/>
      </flow>
      <flow name="flowA">
        <logger message="flow A"/>
      </flow>
    </mule>"""

    result = XMLAnalyzer().analyze_mule_project(xml)
    context = result["flow_contexts"]["main-flow"]
    suite_xml, metadata = DeterministicMUnitBuilder().build_suite(
        context,
        generation_mode="recorder",
    )

    assert "flowA" in result["flow_graph"]["main-flow"]["children"]
    assert context["execution_flows"] == ["main-flow", "flowA"]
    assert context["munit_enable_flow_sources"] == ["flowA"]
    assert metadata["enabled_flow_sources"] == ["flowA"]
    assert '<munit:enable-flow-source value="flowA"/>' in suite_xml


def test_dynamic_flow_ref_from_cdata_literal_set_variable():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core"
          xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
      <flow name="main-flow">
        <ee:transform>
          <ee:variables>
            <ee:set-variable variableName="flowName"><![CDATA['flowA']]></ee:set-variable>
          </ee:variables>
        </ee:transform>
        <flow-ref doc:name="Call literal route" name="#[vars.flowName]"/>
      </flow>
      <flow name="flowA">
        <logger message="flow A"/>
      </flow>
    </mule>"""

    result = XMLAnalyzer().analyze_mule_project(xml)
    context = result["flow_contexts"]["main-flow"]
    suite_xml, metadata = DeterministicMUnitBuilder().build_suite(
        context,
        generation_mode="recorder",
    )

    assert result["flow_graph"]["main-flow"]["children"] == ["flowA"]
    assert context["execution_flows"] == ["main-flow", "flowA"]
    assert context["munit_enable_flow_sources"] == ["flowA"]
    assert metadata["enabled_flow_sources"] == ["flowA"]
    assert '<munit:enable-flow-source value="flowA"/>' in suite_xml


def test_dynamic_flow_ref_from_nested_variable_object_arbitrary_field():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core"
          xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
      <flow name="main-flow">
        <ee:transform doc:name="Build params">
          <ee:variables>
            <ee:set-variable variableName="params"><![CDATA[{
              invokeFlow: "system-flow",
              name: "ravi",
              status: "success"
            }]]></ee:set-variable>
          </ee:variables>
        </ee:transform>
        <flow-ref doc:name="Call process" name="process-flow"/>
      </flow>
      <flow name="process-flow">
        <flow-ref doc:name="Call dynamic system" name="#[vars.params.invokeFlow]"/>
      </flow>
      <flow name="system-flow">
        <logger message="system"/>
      </flow>
    </mule>"""

    result = XMLAnalyzer().analyze_mule_project(xml)
    graph = result["flow_graph"]
    context = result["flow_contexts"]["main-flow"]
    dynamic_ref = graph["process-flow"]["processor_chain"][0]

    assert "process-flow" in graph["main-flow"]["children"]
    assert "system-flow" in graph["process-flow"]["children"]
    assert dynamic_ref["dynamic_flow_candidates"] == ["system-flow"]
    assert dynamic_ref["dynamic_unresolved"] is False
    assert context["execution_flows"] == ["main-flow", "process-flow", "system-flow"]
    assert context["munit_enable_flow_sources"] == ["system-flow"]


def test_dynamic_flow_ref_from_dataweave_attributes_object_field():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core"
          xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
      <flow name="main-flow">
        <ee:transform doc:name="Build route attributes">
          <ee:message>
            <ee:set-attributes><![CDATA[%dw 2.0
output application/java
---
{
  "flowName": "flowA",
  "name": "ravi",
  "status": "success"
}]]></ee:set-attributes>
          </ee:message>
        </ee:transform>
        <flow-ref doc:name="Call attributes route" name="#[attributes.flowName]"/>
      </flow>
      <flow name="flowA">
        <logger message="flow A"/>
      </flow>
    </mule>"""

    result = XMLAnalyzer().analyze_mule_project(xml)
    graph = result["flow_graph"]
    context = result["flow_contexts"]["main-flow"]

    assert "flowA" in graph["main-flow"]["children"]
    assert "flowA" in context["execution_flows"]
    assert context["munit_enable_flow_sources"] == ["flowA"]


def test_runtime_input_dynamic_flow_ref_asks_then_accepts_user_target():
    from app import WebMUnitGenerator

    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core">
      <flow name="main-flow">
        <flow-ref doc:name="Call query-param route" name="#[attributes.queryParams.flowName]"/>
      </flow>
      <flow name="flowA">
        <logger message="flow A"/>
      </flow>
    </mule>"""

    generator = WebMUnitGenerator()
    summary = generator.xml_analyzer.analyze_mule_project(xml)
    summary = generator.apply_selected_flows(summary, ["main-flow"])
    context = summary["flow_contexts"]["main-flow"]

    assert context["execution_flows"] == ["main-flow"]
    assert context["unresolved_flow_refs"]
    assert "runtime request attributes" in context["unresolved_flow_refs"][0]["reason"]

    updated = generator._apply_user_dynamic_flow_targets(
        summary,
        {"flow_test_data": '{"dynamicFlowTargets":"flowA"}'},
    )
    updated_context = updated["flow_contexts"]["main-flow"]
    suite_xml, metadata = DeterministicMUnitBuilder().build_suite(
        updated_context,
        generation_mode="recorder",
    )

    assert "flowA" in updated["flow_graph"]["main-flow"]["children"]
    assert "flowA" in updated_context["execution_flows"]
    assert updated_context["unresolved_flow_refs"] == []
    assert metadata["enabled_flow_sources"] == ["flowA"]
    assert '<munit:enable-flow-source value="flowA"/>' in suite_xml


def test_missing_dependency_flow_can_be_mocked_and_linked_to_local_child():
    from app import WebMUnitGenerator

    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core">
      <flow name="flowA">
        <set-variable variableName="flowName" value="flowC"/>
        <flow-ref doc:name="Call dependency flow" name="flowB"/>
      </flow>
      <flow name="flowC">
        <logger message="local child"/>
      </flow>
    </mule>"""

    generator = WebMUnitGenerator()
    summary = generator.xml_analyzer.analyze_mule_project(xml)
    summary = generator.apply_selected_flows(summary, ["flowA"])
    context = summary["flow_contexts"]["flowA"]

    assert summary["flow_graph"]["flowB"]["external_dependency"] is True
    assert "flowB" in context["execution_flows"]
    assert "flowB" in context["external_flow_names"]
    assert "flowB" in context["munit_enable_flow_sources"]
    assert any(
        item.get("processor") == "flow-ref" and item.get("external_flow") == "flowB"
        for item in context["mock_plan"]
    )

    linked = generator._apply_external_flow_links(
        summary,
        {
            "flow_test_data": json.dumps({
                "externalFlowLinks": [
                    {"externalFlow": "flowB", "linkedLocalFlows": ["flowC"]}
                ]
            })
        },
    )
    linked_context = linked["flow_contexts"]["flowA"]
    suite_xml, metadata = DeterministicMUnitBuilder().build_suite(
        linked_context,
        generation_mode="recorder",
    )

    assert "flowC" in linked["flow_graph"]["flowB"]["children"]
    assert "flowB" in linked["flow_graph"]["flowC"]["parents"]
    assert "flowC" in linked_context["execution_flows"]
    assert metadata["enabled_flow_sources"] == ["flowB", "flowC"]
    assert '<munit:enable-flow-source value="flowB"/>' in suite_xml
    assert '<munit:enable-flow-source value="flowC"/>' in suite_xml


def test_manual_external_callback_is_appended_after_external_stop():
    from app import WebMUnitGenerator

    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core">
      <flow name="flowA">
        <flow-ref name="flowB"/>
      </flow>
      <sub-flow name="flowB">
        <flow-ref name="flowC"/>
      </sub-flow>
      <sub-flow name="flowD">
        <logger message="local callback"/>
      </sub-flow>
    </mule>"""

    generator = WebMUnitGenerator()
    summary = generator.xml_analyzer.analyze_mule_project(xml)
    summary = generator.apply_selected_flows(summary, ["flowA"])
    linked = generator._apply_external_flow_links(
        summary,
        {
            "flow_test_data": json.dumps({
                "externalFlowLinks": [{
                    "externalFlow": "flowC",
                    "linkedLocalFlows": ["flowD"],
                    "condition": "flowD when vars.route == 'D'",
                }]
            })
        },
    )
    trace = generator.build_selected_flow_trace_payload(linked, ["flowA"])

    assert linked["flow_contexts"]["flowA"]["execution_flows"] == [
        "flowA",
        "flowB",
        "flowC",
        "flowD",
    ]
    assert trace["traces"][0]["flow"] == "flowA"
    assert trace["traces"][0]["execution_flows"] == [
        "flowA",
        "flowB",
        "flowC",
        "flowD",
    ]


def test_flow_selection_keeps_only_one_generation_target():
    from app import WebMUnitGenerator

    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <mule xmlns="http://www.mulesoft.org/schema/mule/core">
      <flow name="flowA"><logger message="a"/></flow>
      <flow name="flowB"><logger message="b"/></flow>
    </mule>"""

    generator = WebMUnitGenerator()
    summary = generator.xml_analyzer.analyze_mule_project(xml)
    selected = generator.apply_selected_flows(summary, ["flowA", "flowB"])
    trace = generator.build_selected_flow_trace_payload(selected, ["flowA", "flowB"])

    assert selected["selected_flows"] == ["flowA"]
    assert selected["test_targets"] == ["flowA"]
    assert [item["flow"] for item in trace["traces"]] == ["flowA"]


def test_duplicate_external_flow_ref_mock_is_rendered_once():
    flow_context = {
        "target_flow": "flowA",
        "target_type": "flow",
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "flow-ref",
                "doc_name": "Call external flow",
                "match_attribute": "doc:name",
                "match_value": "Call external flow",
                "external_dependency": True,
                "external_flow": "flowB",
                "media_type": "application/json",
                "result_shape": "object",
            },
            {
                "action": "mock-when",
                "processor": "flow-ref",
                "doc_name": "Call external flow",
                "match_attribute": "doc:name",
                "match_value": "Call external flow",
                "external_dependency": True,
                "external_flow": "flowB",
                "media_type": "application/json",
                "result_shape": "object",
            },
        ],
        "set_event_plan": {},
        "required_inputs": {},
        "unresolved_flow_refs": [],
    }

    suite_xml, metadata = DeterministicMUnitBuilder().build_suite(
        flow_context,
        generation_mode="recorder",
        sample_payload='{"statusCode": 200}',
    )

    test_blocks = re.findall(r"<munit:test\b.*?</munit:test>", suite_xml, flags=re.DOTALL)
    assert test_blocks
    assert all(block.count('processor="flow-ref"') == 1 for block in test_blocks)
    assert all(block.count('whereValue="Call external flow"') == 1 for block in test_blocks)
    assert not any(
        re.search(r"mock_call-external-flow_.+_2(?:_attributes)?\.dwl$", name)
        for name in metadata["resource_files"]
    )


def test_external_flow_ref_mock_can_return_payload_variables_and_attributes():
    from app import WebMUnitGenerator

    flow_context = {
        "target_flow": "flowA",
        "target_type": "flow",
        "mock_plan": [{
            "action": "mock-when",
            "processor": "flow-ref",
            "doc_name": "Request to Flow D",
            "match_attribute": "doc:name",
            "match_value": "Request to Flow D",
            "external_dependency": True,
            "external_flow": "Flow C",
            "media_type": "application/json",
            "result_shape": "object",
        }],
        "set_event_plan": {},
        "required_inputs": {},
        "unresolved_flow_refs": [],
    }
    builder = DeterministicMUnitBuilder(
        output_dir=tempfile.mkdtemp(prefix="external-flow-return-test-")
    )
    sample_key = builder._connector_sample_key("flowA", flow_context["mock_plan"][0])
    posted_samples = {
        "sample_card": {
            "id": sample_key,
            "flow": "flowA",
            "processor": "flow-ref",
            "external_dependency": True,
            "external_flow": "Flow C",
            "output": '{"status":"success"}',
            "returnTypes": ["payload"],
            "variables": '{"clientId":"CLIENT-001","validated":true}',
            "returnAttributes": '{"statusCode":202}',
        }
    }
    parsed_samples = WebMUnitGenerator()._build_connector_samples_dict({
        "connector_samples": json.dumps(posted_samples)
    })

    suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        sample_payload='{"statusCode": 200}',
        connector_samples=parsed_samples["flowA"],
    )
    written_paths = builder.write_maven_layout(suite_xml, metadata)

    ET.fromstring(suite_xml)
    first_test = re.findall(r"<munit:test\b.*?</munit:test>", suite_xml, flags=re.DOTALL)[0]
    assert "<munit-tools:payload " in first_test
    assert "<munit-tools:variables>" in first_test
    assert 'munit-tools:variable key="clientId"' in first_test
    assert 'munit-tools:variable key="validated"' in first_test
    assert "<munit-tools:attributes " in first_test
    variable_resource_names = [
        name for name in metadata["resource_files"]
        if name.endswith("_variables.dwl")
    ]
    assert variable_resource_names == ["mock_flow-c_variables.dwl"]
    assert any(name.endswith("_attributes.dwl") for name in metadata["resource_files"])
    variable_paths = [
        Path(path)
        for key, path in written_paths.items()
        if key.endswith("_variables.dwl")
    ]
    assert variable_paths
    assert all(path.is_file() for path in variable_paths)
    variable_references = re.findall(
        r"getResourceAsString\('([^']+_variables\.dwl)'\)",
        suite_xml,
    )
    assert variable_references
    assert len(set(variable_references)) == 1
    assert variable_references[0].endswith("/mock_flow-c_variables.dwl")
    for reference in variable_references:
        assert (
            builder.output_dir / "src" / "test" / "resources" / reference
        ).is_file()


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        ("Case 1: Literal",             test_literal_flow_ref),
        ("Case 2: Variable ref",        test_variable_flow_ref),
        ("Case 3: Choice branch",       test_choice_branch_variable),
        ("Case 4: DW if/else",          test_dw_inline_if_else),
        ("Case 5: Concat + var",        test_string_concat),
        ("Case 5b: Concat prefix only", test_string_concat_prefix_only),
        ("Case 6: Map dispatch",        test_map_dispatch),
        ("Case 7: lookup() literal",    test_dw_lookup_literal),
        ("Case 8: lookup() + var",      test_dw_lookup_variable),
        ("Case 9: lookup() + concat",   test_dw_lookup_concat),
        ("Unresolvable → unresolved",   test_truly_dynamic_marked_unresolved),
        ("var_value_map populated",     test_var_value_map),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✅  {name}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌  {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  💥  {name}: {type(e).__name__}: {e}")
            failed += 1

    print(f"\n  {passed}/{passed+failed} tests passed")
    sys.exit(0 if failed == 0 else 1)
