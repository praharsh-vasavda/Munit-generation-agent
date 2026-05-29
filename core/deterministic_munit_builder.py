"""
Deterministic MUnit XML builder.

Builds Behavior / Execution / Validation from XMLAnalyzer output (mock_plan,
set_event_plan) so outbound connectors are always mocked and set-event matches
what the flow actually reads — without relying on the LLM for structure.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


MUNIT_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:munit="http://www.mulesoft.org/schema/mule/munit"
      xmlns:munit-tools="http://www.mulesoft.org/schema/mule/munit-tools"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xsi:schemaLocation="
        http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
        http://www.mulesoft.org/schema/mule/munit http://www.mulesoft.org/schema/mule/munit/current/mule-munit.xsd
        http://www.mulesoft.org/schema/mule/munit-tools http://www.mulesoft.org/schema/mule/munit-tools/current/mule-munit-tools.xsd">

    <munit:config name="{suite_name}"/>

{tests}

</mule>
"""


class DeterministicMUnitBuilder:
    """Assemble MUnit suites from flow_context analysis artifacts."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)

    def build_suite(
        self,
        flow_context: Dict[str, Any],
        *,
        generation_mode: str = "deterministic",
        sample_payload: Optional[str] = None,
        scenarios: Optional[List[Dict]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Build a full MUnit suite XML string and sidecar resource files.

        generation_mode:
          - recorder: one happy-path test, minimal assertions (Studio-like)
          - deterministic: happy path + optional scenarios from rules, enforced mocks
          - llm_suite: not handled here (caller uses LLM)
        """
        target_flow = flow_context.get("target_flow", "main-flow")
        suite_name = self._suite_name(target_flow, flow_context)
        resource_folder = self._resource_folder_name(target_flow)

        if generation_mode == "recorder":
            scenario_list = [{"name": "happy_path", "type": "happy_path", "description": "Recorded happy path"}]
        else:
            scenario_list = scenarios or [{"name": "happy_path", "type": "happy_path", "description": "Happy path"}]
            # Cap non-recorder modes to avoid assert explosion unless user supplied scenarios
            if not scenarios and generation_mode == "deterministic":
                scenario_list = scenario_list[:1]

        resource_files: Dict[str, str] = {}
        tests_xml: List[str] = []

        for index, scenario in enumerate(scenario_list, start=1):
            test_xml, files = self._build_test(
                flow_context,
                scenario,
                resource_folder,
                index,
                sample_payload=sample_payload if scenario.get("type") == "happy_path" else None,
                recorder_style=(generation_mode == "recorder"),
            )
            tests_xml.append(test_xml)
            resource_files.update(files)

        suite_xml = MUNIT_XML_TEMPLATE.format(
            suite_name=suite_name,
            tests="\n".join(tests_xml),
        )

        metadata = {
            "generation_mode": generation_mode,
            "builder": "deterministic",
            "target_flow": target_flow,
            "suite_name": suite_name,
            "resource_folder": resource_folder,
            "resource_files": resource_files,
            "test_count": len(scenario_list),
            "mock_plan_count": len(flow_context.get("mock_plan", []) or []),
        }
        return suite_xml, metadata

    def write_maven_layout(
        self,
        suite_xml: str,
        metadata: Dict[str, Any],
    ) -> Dict[str, str]:
        """Write suite + DWL resources under standard Maven test paths."""
        target_flow = metadata.get("target_flow", "main-flow")
        suite_name = metadata.get("suite_name", self._suite_name(target_flow, {}))
        paths: Dict[str, str] = {}

        munit_dir = self.output_dir / "src" / "test" / "munit"
        munit_dir.mkdir(parents=True, exist_ok=True)
        suite_path = munit_dir / f"{suite_name}.xml"
        suite_path.write_text(suite_xml, encoding="utf-8")
        paths["suite_file"] = str(suite_path)

        resource_folder = metadata.get("resource_folder", self._resource_folder_name(target_flow))
        for rel_name, content in (metadata.get("resource_files") or {}).items():
            resource_path = self.output_dir / "src" / "test" / "resources" / resource_folder / rel_name
            resource_path.parent.mkdir(parents=True, exist_ok=True)
            resource_path.write_text(content, encoding="utf-8")
            paths[rel_name] = str(resource_path)

        paths["suite_file_maven"] = str(suite_path)
        return paths

    def _build_test(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        *,
        sample_payload: Optional[str],
        recorder_style: bool,
    ) -> Tuple[str, Dict[str, str]]:
        target_flow = flow_context.get("target_flow", "main-flow")
        scenario_slug = self._slugify(scenario.get("type") or scenario.get("name") or f"scenario-{index}")
        test_name = f"{self._slugify(target_flow)}-{scenario_slug}-test"
        description = scenario.get("description", f"{scenario_slug} for {target_flow}")

        behavior_parts: List[str] = []
        resource_files: Dict[str, str] = {}

        set_event_xml, set_files = self._build_set_event(
            flow_context,
            scenario,
            resource_folder,
            index,
            sample_payload=sample_payload,
        )
        behavior_parts.append(set_event_xml)
        resource_files.update(set_files)

        mock_parts, mock_files = self._build_mocks(
            flow_context,
            scenario,
            resource_folder,
            index,
        )
        behavior_parts.extend(mock_parts)
        resource_files.update(mock_files)

        validation_xml, assert_files = self._build_validation(
            flow_context,
            scenario,
            resource_folder,
            index,
            recorder_style=recorder_style,
            sample_payload=sample_payload,
        )
        resource_files.update(assert_files)

        expected_error = ""
        if scenario.get("type") in {"downstream_failure", "error_scenario", "downstream_api_failure"}:
            expected_error = ' expectedErrorType="HTTP:CONNECTIVITY"'

        test_xml = f"""    <munit:test name="{test_name}" description="{self._xml_escape(description)}"{expected_error}>
        <munit:behavior>
{chr(10).join(behavior_parts)}
        </munit:behavior>
        <munit:execution>
            <flow-ref doc:name="Execute {self._xml_escape(target_flow)}" name="{self._xml_escape(target_flow)}"/>
        </munit:execution>
        <munit:validation>
{validation_xml}
        </munit:validation>
    </munit:test>"""

        return test_xml, resource_files

    def _build_set_event(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        *,
        sample_payload: Optional[str],
    ) -> Tuple[str, Dict[str, str]]:
        plan = dict(flow_context.get("set_event_plan") or {})
        files: Dict[str, str] = {}

        if sample_payload and scenario.get("type") == "happy_path":
            payload_file = f"set-event_payload_{index}.dwl"
            attrs_file = f"set-event_attributes_{index}.dwl"
            payload_dwl, attrs_dwl = self._split_sample_payload(sample_payload, plan)
            files[payload_file] = payload_dwl
            files[attrs_file] = attrs_dwl
            return (
                f"""            <munit:set-event doc:name="Set Input">
                <munit:payload value="#[MunitTools::getResourceAsString('{resource_folder}/{payload_file}')]" mediaType="application/json" encoding="UTF-8"/>
                <munit:attributes value="#[MunitTools::getResourceAsString('{resource_folder}/{attrs_file}')]"/>
            </munit:set-event>""",
                files,
            )

        if scenario.get("type") == "empty_payload":
            plan = dict(plan)
            plan["payload_expression"] = '""'
            plan["payload_media_type"] = "application/java"

        payload_file = f"set-event_payload_{index}.dwl"
        attrs_file = f"set-event_attributes_{index}.dwl"
        files[payload_file] = self._plan_to_payload_dwl(plan)
        files[attrs_file] = self._plan_to_attributes_dwl(plan)
        payload_media_type = plan.get("payload_media_type", "application/json")

        return (
            f"""            <munit:set-event doc:name="Set Input">
                <munit:payload value="#[MunitTools::getResourceAsString('{resource_folder}/{payload_file}')]" mediaType="{payload_media_type}" encoding="UTF-8"/>
                <munit:attributes value="#[MunitTools::getResourceAsString('{resource_folder}/{attrs_file}')]"/>
            </munit:set-event>""",
            files,
        )

    def _build_mocks(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
    ) -> Tuple[List[str], Dict[str, str]]:
        parts: List[str] = []
        files: Dict[str, str] = {}
        mock_plan = flow_context.get("mock_plan", []) or []
        scenario_type = scenario.get("type", "happy_path")

        if scenario_type in {"empty_payload", "invalid_input", "validation_error"}:
            return parts, files

        for mock_index, item in enumerate(mock_plan, start=1):
            if item.get("action") != "mock-when":
                continue

            processor = item.get("processor", "http:request")
            doc_name = item.get("doc_name") or item.get("match_value") or processor
            match_attr = item.get("match_attribute", "doc:name")
            match_value = item.get("match_value") or doc_name

            mock_file = f"mock_{self._slugify(doc_name)}_{index}_{mock_index}.dwl"
            mock_body = self._build_mock_payload_dwl(item, scenario_type, flow_context)
            files[mock_file] = mock_body

            if scenario_type in {"downstream_failure", "downstream_api_failure", "error_scenario"}:
                error_type = self._error_type_for_processor(processor)
                parts.append(
                    f"""            <munit-tools:mock-when doc:name="Mock {self._xml_escape(doc_name)} failure" processor="{processor}">
                <munit-tools:with-attributes>
                    <munit-tools:with-attribute attributeName="{match_attr}" whereValue="{self._xml_escape(match_value)}"/>
                </munit-tools:with-attributes>
                <munit-tools:then-return>
                    <munit-tools:error typeId="{error_type}"/>
                </munit-tools:then-return>
            </munit-tools:mock-when>"""
                )
            else:
                attrs = item.get("return_attributes") or {"statusCode": 200}
                attrs_file = f"mock_{self._slugify(doc_name)}_{index}_{mock_index}_attributes.dwl"
                files[attrs_file] = self._build_mock_resource_content(attrs)
                parts.append(
                    f"""            <munit-tools:mock-when doc:name="Mock {self._xml_escape(doc_name)}" processor="{processor}">
                <munit-tools:with-attributes>
                    <munit-tools:with-attribute attributeName="{match_attr}" whereValue="{self._xml_escape(match_value)}"/>
                </munit-tools:with-attributes>
                <munit-tools:then-return>
                    <munit-tools:payload value="#[MunitTools::getResourceAsString('{resource_folder}/{mock_file}')]" mediaType="{item.get('media_type', 'application/json')}"/>
                    <munit-tools:attributes value="#[MunitTools::getResourceAsString('{resource_folder}/{attrs_file}')]" mediaType="application/java"/>
                </munit-tools:then-return>
            </munit-tools:mock-when>"""
                )
        return parts, files

    def _build_validation(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        *,
        recorder_style: bool,
        sample_payload: Optional[str],
    ) -> Tuple[str, Dict[str, str]]:
        files: Dict[str, str] = {}
        scenario_type = scenario.get("type", "happy_path")
        output_fields = flow_context.get("output_fields", []) or []

        if scenario_type in {"downstream_failure", "downstream_api_failure", "error_scenario"}:
            return (
                """            <munit-tools:assert-that
                doc:name="Assert error type present"
                expression="#[error.errorType.identifier]"
                is="#[MunitTools::notNullValue()]"
                message="Error should be thrown"/>""",
                files,
            )

        if scenario_type in {"empty_payload", "invalid_input", "validation_error"}:
            return (
                """            <munit-tools:assert-that
                doc:name="Assert validation error"
                expression="#[error]"
                is="#[MunitTools::notNullValue()]"
                message="Validation should fail"/>""",
                files,
            )

        assert_file = f"assert_expression_payload_{index}.dwl"
        assert_dwl = self._build_assert_dwl(flow_context, sample_payload, recorder_style)
        files[assert_file] = assert_dwl

        module_name = resource_folder
        if recorder_style or len(output_fields) <= 2:
            return (
                f"""            <munit-tools:assert doc:name="Assert payload" message="The payload does not match">
                <munit-tools:that><![CDATA[#[%dw 2.0
import {module_name}::assert_expression_payload_{index}
---
{module_name}::assert_expression_payload_{index}::main({{payload: payload, attributes: attributes, vars: vars}})]]]></munit-tools:that>
            </munit-tools:assert>""",
                files,
            )

        # Deterministic mode: at most 3 field checks + optional notNull on payload
        lines = [
            """            <munit-tools:assert-that
                doc:name="Assert payload not null"
                expression="#[payload]"
                is="#[MunitTools::notNullValue()]"
                message="Payload must not be null"/>"""
        ]
        for field in output_fields[:3]:
            lines.append(
                f"""            <munit-tools:assert-that
                doc:name="Assert {self._xml_escape(field)} present"
                expression="#[payload.{field}]"
                is="#[MunitTools::notNullValue()]"
                message="Field {self._xml_escape(field)} must be present"/>"""
            )
        return "\n".join(lines), files

    def _build_mock_payload_dwl(
        self,
        mock_item: Dict[str, Any],
        scenario_type: str,
        flow_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Build the content of a mock payload DWL file.

        Mock connector files are raw resource files, not executable DWL
        scripts. Keep them free of %dw/output/--- headers so MUnit reads the
        mock content exactly as Studio-style resources.
        """
        refs = mock_item.get("downstream_payload_references", []) or []
        shape = mock_item.get("result_shape", "object")
        literals = dict(mock_item.get("hardcoded_literals", {}) or {})
        if flow_context:
            literals.update((flow_context.get("set_event_plan") or {}).get("hardcoded_literals", {}))

        if any(ref.startswith("payload.data") for ref in refs):
            country = literals.get("filter_country") or literals.get("country") or "India"
            payload_obj = {
                "data": [
                    {
                        "name": country,
                        "states": [{"name": "Test State", "state_code": "TS"}],
                    }
                ]
            }
        else:
            payload_obj = self._refs_to_mock_object(refs, hardcoded_literals=literals)

        if shape == "array":
            # db:select, salesforce:query etc return arrays
            return self._build_mock_resource_content([payload_obj])

        # http:request, vm:publish-consume etc return objects
        return self._build_mock_resource_content(payload_obj)

    def _build_assert_dwl(
        self,
        flow_context: Dict[str, Any],
        sample_payload: Optional[str],
        recorder_style: bool,
    ) -> str:
        expected = self._expected_output_from_sample(sample_payload)
        if expected:
            return (
                "%dw 2.0\nimport * from dw::test::Asserts\n"
                "fun main(vars: Object) = do {\n"
                "  var payload = vars.payload\n"
                "  ---\n"
                f"  payload must equalTo({json.dumps(expected)})\n"
                "}"
            )

        fields = flow_context.get("output_fields", []) or ["payload"]
        checks = ["payload must notNullValue()"]
        for field in fields[:3]:
            checks.append(f"payload.{field} must notNullValue()")
        body = "\n".join(checks)
        return (
            f"%dw 2.0\nimport * from dw::test::Asserts\n"
            f"fun main(vars: Object) = do {{\n"
            f"  var payload = vars.payload\n"
            f"  ---\n"
            f"  {body}\n"
            f"}}"
        )

    def _split_sample_payload(self, sample_payload: str, plan: Dict[str, Any]) -> Tuple[str, str]:
        """Split user sample into payload + attributes DWL files."""
        text = sample_payload.strip()
        request_obj: Any = {}
        response_obj: Any = {}

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                request_obj = parsed.get("request", parsed.get("input", {}))
                response_obj = parsed.get("response", parsed.get("output", parsed))
                if not request_obj and "queryParams" in parsed:
                    request_obj = parsed
        except json.JSONDecodeError:
            request_obj = {}
            response_obj = {"status": "SUCCESS"}

        if not request_obj:
            request_obj = {}

        payload_dwl = "%dw 2.0\noutput application/json\n---\n" + json.dumps(request_obj, indent=2) + "\n"

        attrs = plan.get("attributes_template") or {
            "method": "GET",
            "requestPath": "/",
            "queryParams": request_obj.get("queryParams", {}),
            "headers": {"content-type": "application/json"},
        }
        if isinstance(request_obj, dict) and request_obj.get("queryParams"):
            attrs["queryParams"] = request_obj["queryParams"]

        attrs_dwl = self._build_attributes_dwl(attrs)

        self._last_sample_response = response_obj
        return payload_dwl, attrs_dwl

    def _expected_output_from_sample(self, sample_payload: Optional[str]) -> Optional[Dict]:
        if not sample_payload:
            return getattr(self, "_last_sample_response", None) if isinstance(
                getattr(self, "_last_sample_response", None), dict
            ) else None
        try:
            parsed = json.loads(sample_payload.strip())
            if isinstance(parsed, dict) and "response" in parsed:
                resp = parsed["response"]
                return resp if isinstance(resp, dict) else None
        except json.JSONDecodeError:
            pass
        return None

    def _refs_to_mock_object(
        self,
        refs: List[str],
        hardcoded_literals: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Build a mock payload object from downstream payload references.

        Handles both dotted notation (payload.id) and array-index notation
        (payload[0].id, payload[0].address.city) by normalising the ref first.
        """
        hardcoded_literals = hardcoded_literals or {}
        root: Dict[str, Any] = {}

        for ref in refs:
            # Normalise payload[0].field.sub → payload.field.sub
            normalised = re.sub(r"\[\d+\]", "", ref)
            if not normalised.startswith("payload."):
                continue
            path = normalised[len("payload."):]
            segments = [segment for segment in path.split(".") if segment]
            if not segments:
                continue
            self._assign_path(root, segments, hardcoded_literals)

        if not root:
            # Minimal safe fallback — avoid noisy nested "data" objects
            root = {"id": "MOCK-001", "status": "ACTIVE", "name": "Test Record"}

        return root

    def _assign_path(self, root: Dict[str, Any], segments: List[str], hardcoded_literals: Dict[str, str]) -> None:
        cursor = root
        for idx, segment in enumerate(segments):
            is_last = idx == len(segments) - 1
            value = hardcoded_literals.get(segment) or self._mock_value_for_field(segment)
            if is_last:
                cursor[segment] = value
            else:
                if segment not in cursor or not isinstance(cursor[segment], dict):
                    cursor[segment] = {}
                cursor = cursor[segment]

    def _mock_value_for_field(self, field: str) -> Any:
        lowered = field.lower()
        if lowered in {"country", "name"}:
            return "India" if lowered == "country" else "Test Record"
        if lowered.endswith("id") or lowered == "id":
            return "MOCK-001"
        if lowered == "email":
            return "test@example.com"
        if lowered == "status":
            return "ACTIVE"
        if lowered in {"states", "items", "records", "results"}:
            return [{"name": "Sample", "state_code": "XX"}]
        return "MOCK-VALUE"

    def _error_type_for_processor(self, processor: str) -> str:
        if processor.startswith("db:"):
            return "DB:CONNECTIVITY"
        if processor.startswith("salesforce:"):
            return "SALESFORCE:CONNECTIVITY"
        return "HTTP:CONNECTIVITY"

    def _plan_to_payload_dwl(self, plan: Dict[str, Any]) -> str:
        """
        Build set-event payload DWL file content.

        The analyzer supplies a shaped JSON payload when the flow reads
        payload fields. When the flow has no request body, use Mule's standard
        empty binary expression instead of JSON null.
        """
        media_type = plan.get("payload_media_type", "application/json")

        # GET flow or explicitly empty payload.
        if plan.get("payload_expression") == '""' or plan.get("payload_expression") is None:
            return '"" as Binary {base: "64"}\n'

        try:
            body = json.loads(plan.get("payload_expression", "{}"))
        except (json.JSONDecodeError, TypeError):
            body = {}
        return f"%dw 2.0\noutput {media_type}\n---\n{json.dumps(body, indent=2)}\n"

    def _plan_to_attributes_dwl(self, plan: Dict[str, Any]) -> str:
        """
        Build set-event attributes DWL file content.

        This IS a real DWL script, so it keeps the %dw 2.0 / output / --- header.
        The object body is emitted as JSON-compatible DataWeave with double-quoted
        keys and string values so generated files match Mule project conventions.
        """
        attrs = plan.get("attributes_template") or {}
        return self._build_attributes_dwl(attrs)

    def _build_mock_resource_content(self, value: Any) -> str:
        """Build raw mock connector resource content with no DWL header."""
        return json.dumps(value, indent=2) + "\n"

    def _build_attributes_dwl(self, value: Any) -> str:
        """Build a DWL script for Mule attributes using double-quoted keys."""
        return "%dw 2.0\noutput application/java\n---\n" + json.dumps(value, indent=2) + "\n"

    def _dwl_object_literal(self, value: Any) -> str:
        if isinstance(value, dict):
            parts = []
            for key, item in value.items():
                if isinstance(item, str):
                    parts.append(f"{key}: '{item}'")
                elif isinstance(item, dict):
                    parts.append(f"{key}: {self._dwl_inline_map(item)}")
                else:
                    parts.append(f"{key}: {item}")
            return "{" + ", ".join(parts) + "}"
        return json.dumps(value)

    def _dwl_inline_map(self, value: Dict[str, Any]) -> str:
        parts = []
        for key, item in value.items():
            safe_key = key if re.match(r"^[A-Za-z_]\w*$", key) else f"'{key}'"
            if isinstance(item, str):
                parts.append(f"{safe_key}: '{item}'")
            elif isinstance(item, dict):
                parts.append(f"{safe_key}: {self._dwl_inline_map(item)}")
            else:
                parts.append(f"{safe_key}: {item}")
        return "{" + ", ".join(parts) + "}"

    def _suite_name(self, target_flow: str, flow_context: Dict[str, Any]) -> str:
        source = flow_context.get("source_file", "")
        if source and source not in {"unknown.xml", "input.xml"}:
            base = Path(source).stem.replace("_", "-").lower()
            base = self._slugify(base)
            if base:
                return f"{base}-test-suite"
        flow_slug = self._slugify(target_flow.replace("Flow", "").replace("flow", ""))
        if flow_slug:
            return f"{flow_slug}-test-suite"
        return f"{self._slugify(target_flow)}-test-suite"

    def _resource_folder_name(self, target_flow: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9]", "", target_flow or "flow")
        if clean.lower().endswith("flow"):
            clean = clean[:-4]
        if not clean:
            clean = "flow"
        return f"{clean}Flowtest"

    def _slugify(self, value: str) -> str:
        normalized = (value or "flow").replace("_", "-").replace(" ", "-").lower()
        normalized = re.sub(r"[^a-z0-9-]+", "-", normalized)
        normalized = re.sub(r"-{2,}", "-", normalized)
        return normalized.strip("-") or "flow"

    def _xml_escape(self, value: str) -> str:
        return (
            (value or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )


def _pre_outbound_script_text(processor_chain: List[Dict], inline_dwl: List[Dict]) -> str:
    """Only DWL that runs before the first outbound connector (listener input)."""
    outbound_types = {
        "http:request",
        "db:select",
        "db:insert",
        "db:update",
        "db:delete",
        "salesforce:query",
        "salesforce:create",
        "vm:publish",
        "email:send",
        "kafka:publish",
    }
    scripts: List[str] = []
    for proc in processor_chain or []:
        ptype = (proc.get("type") or "").lower()
        if ptype in outbound_types:
            break
        excerpt = (proc.get("dwl_excerpt") or "").strip()
        if excerpt and excerpt not in scripts:
            scripts.append(excerpt)
    if scripts:
        return "\n".join(scripts)
    # Fallback when chain excerpts are missing
    return "\n".join(item.get("script", "") for item in (inline_dwl or [])[:1])


def build_set_event_plan(processor_chain: List[Dict], inline_dwl: List[Dict], trigger: Dict) -> Dict[str, Any]:
    """Derive set-event plan from trigger + early transforms (used by XMLAnalyzer)."""
    trigger_type = (trigger or {}).get("type", "")
    plan: Dict[str, Any] = {
        "payload_expression": "{}",
        "payload_media_type": "application/json",
        "attributes_expression": "{method: 'GET', requestPath: '/', queryParams: {}, headers: {}}",
        "attributes_template": {
            "method": "GET",
            "requestPath": "/",
            "queryParams": {},
            "headers": {"content-type": "application/json"},
        },
        "hardcoded_literals": {},
    }

    scripts = _pre_outbound_script_text(processor_chain, inline_dwl)
    query_params = {}
    for match in re.findall(r"attributes\.queryParams\.(\w+)", scripts):
        query_params[match] = _mock_value_for_field_static(match)

    country_literal = re.search(r'item\.name\s*==\s*"([^"]+)"', scripts)
    if country_literal:
        plan["hardcoded_literals"]["filter_country"] = country_literal.group(1)
        query_params.setdefault("country", country_literal.group(1))

    if trigger_type == "http:listener":
        method = (trigger.get("method") or trigger.get("allowedMethods") or "GET").split(",")[0].strip()
        path = trigger.get("path") or trigger.get("requestPath") or "/"
        plan["attributes_template"] = {
            "method": method,
            "requestPath": path,
            "queryParams": query_params,
            "headers": {"content-type": "application/json"},
            "uriParams": {},
        }
        if method.upper() == "GET" and not re.search(r"\bpayload\.", scripts[:500]):
            plan["payload_expression"] = '""'
            plan["payload_media_type"] = "application/java"
        else:
            body = {}
            for match in re.findall(r"\bpayload\.(\w+)", scripts):
                body[match] = _mock_value_for_field_static(match)
            if body:
                plan["payload_expression"] = json.dumps(body)
        plan["attributes_expression"] = _attributes_to_dwl_expression(plan["attributes_template"])

    return plan


def extract_output_fields(inline_dwl: List[Dict], final_processor: Dict) -> List[str]:
    """Top-level output field names from the last transform script."""
    scripts = []
    if final_processor and final_processor.get("dwl_excerpt"):
        scripts.append(final_processor["dwl_excerpt"])
    for item in inline_dwl or []:
        scripts.append(item.get("script", ""))
    if not scripts:
        return []

    last_script = scripts[-1]
    fields = re.findall(r"^\s*(\w+)\s*:", last_script, re.MULTILINE)
    ordered: List[str] = []
    for field in fields:
        if field not in ordered and field not in {"output", "ns", "import"}:
            ordered.append(field)
    return ordered[:6]


def _mock_value_for_field_static(field: str) -> Any:
    lowered = field.lower()
    if lowered == "country":
        return "India"
    if lowered.endswith("id"):
        return "MOCK-001"
    if lowered == "email":
        return "test@example.com"
    return "MOCK-VALUE"


def _attributes_to_dwl_expression(attrs: Dict[str, Any]) -> str:
    parts = []
    for key, value in attrs.items():
        if isinstance(value, dict):
            inner = ", ".join(
                f"{k}: '{v}'" if isinstance(v, str) else f"{k}: {v}" for k, v in value.items()
            )
            parts.append(f"{key}: {{{inner}}}")
        else:
            parts.append(f"{key}: '{value}'")
    return "{" + ", ".join(parts) + "}"
