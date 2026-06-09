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
        connector_samples: Optional[Dict[str, Dict[str, str]]] = None,
        scenarios: Optional[List[Dict]] = None,
        target_munit_version: Optional[str] = None,
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

        scenario_list = self._build_scenario_plan(
            flow_context,
            scenarios=scenarios,
            generation_mode=generation_mode,
        )

        resource_files: Dict[str, str] = {}
        tests_xml: List[str] = []

        for index, scenario in enumerate(scenario_list, start=1):
            test_xml, files = self._build_test(
                flow_context,
                scenario,
                resource_folder,
                index,
                sample_payload=sample_payload if scenario.get("type") == "happy_path" else None,
                connector_samples=connector_samples or {},
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
            "scenario_plan": scenario_list,
            "target_munit_version": target_munit_version,
            "preflight_validation": self._validate_generated_suite(suite_xml, resource_files, flow_context),
        }
        return suite_xml, metadata

    def _build_scenario_plan(
        self,
        flow_context: Dict[str, Any],
        *,
        scenarios: Optional[List[Dict]],
        generation_mode: str,
    ) -> List[Dict[str, Any]]:
        """Create a focused scenario model before rendering MUnit XML."""
        supplied = [dict(item) for item in (scenarios or []) if item]
        if supplied:
            planned = supplied
        else:
            planned = [
                {
                    "name": "happy_path",
                    "type": "happy_path",
                    "description": "Happy path",
                    "assertion_strategy": "payload_equals_expected",
                }
            ]

        mock_plan = [
            item for item in (flow_context.get("mock_plan", []) or [])
            if item.get("action") == "mock-when"
        ]
        has_validation = self._flow_has_processor(flow_context, "validation:")
        has_error_handler = bool(flow_context.get("error_handlers"))
        branch_points = flow_context.get("branch_points", []) or []

        # Recorder is now backend-driven Studio-like generation, but it should
        # still create useful failure/branch coverage when the flow analysis
        # gives us enough structure to do so.
        if not supplied and generation_mode in {"recorder", "deterministic"}:
            if has_validation:
                planned.append({
                    "name": "validation_error",
                    "type": "validation_error",
                    "description": "Validation failure path",
                    "assertion_strategy": "expected_error",
                    "expected_error_type": "VALIDATION:INVALID_BOOLEAN",
                })

            for branch_index, branch in enumerate(branch_points[:2], start=1):
                planned.append({
                    "name": f"branch_{branch_index}",
                    "type": "branch_path",
                    "description": branch.get("description") or f"Choice branch {branch_index}",
                    "branch_condition": branch.get("condition", ""),
                    "assertion_strategy": "payload_equals_expected",
                })

            for item in mock_plan[:2]:
                shape = item.get("result_shape", "object")
                if shape not in {"array", "object", "affectedRows"}:
                    continue
                planned.append({
                    "name": f"{self._slugify(item.get('doc_name') or item.get('processor'))}_empty_result",
                    "type": "empty_downstream_response",
                    "description": f"{item.get('doc_name') or item.get('processor')} empty/no-result response path",
                    "empty_processor": item.get("processor", ""),
                    "empty_match_value": item.get("match_value") or item.get("doc_name"),
                    "empty_result_shape": shape,
                    "assertion_strategy": "payload_equals_expected",
                })

            for item in mock_plan[:3]:
                processor = item.get("processor", "")
                planned.append({
                    "name": f"{self._slugify(item.get('doc_name') or processor)}_failure",
                    "type": "downstream_failure",
                    "description": f"{item.get('doc_name') or processor} failure path",
                    "failed_processor": processor,
                    "failed_match_value": item.get("match_value") or item.get("doc_name"),
                    "expected_error_type": self._error_type_for_processor(processor),
                    "assertion_strategy": "error_handler_response" if has_error_handler else "expected_error",
                })

        return self._dedupe_scenarios(planned)

    def _dedupe_scenarios(self, scenarios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for scenario in scenarios:
            key = (
                scenario.get("type"),
                scenario.get("name"),
                scenario.get("failed_processor"),
                scenario.get("failed_match_value"),
                scenario.get("branch_condition"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(scenario)
        return deduped

    def _flow_has_processor(self, flow_context: Dict[str, Any], prefix: str) -> bool:
        for processor in flow_context.get("processor_chain", []) or []:
            if (processor.get("type") or "").startswith(prefix):
                return True
        for processor in flow_context.get("processors", []) or []:
            if str(processor).startswith(prefix):
                return True
        return False

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
        connector_samples: Dict[str, Dict[str, str]],
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
            connector_samples=connector_samples,
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
            connector_samples=connector_samples,
        )
        verify_xml = self._build_verify_calls(flow_context, scenario)
        if verify_xml:
            validation_xml = f"{validation_xml}\n{verify_xml}" if validation_xml else verify_xml
        resource_files.update(assert_files)

        expected_error = ""
        if self._scenario_expects_thrown_error(scenario):
            expected_error = f' expectedErrorType="{self._xml_escape(self._expected_error_type(scenario))}"'

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
        plan = self._apply_scenario_to_set_event_plan(plan, scenario)
        files: Dict[str, str] = {}

        if sample_payload and scenario.get("type") == "happy_path":
            payload_file = f"set-event_payload_{index}.dwl"
            attrs_file = f"set-event_attributes_{index}.dwl"
            payload_dwl, attrs_dwl = self._split_sample_payload(sample_payload, plan)
            files[payload_file] = payload_dwl
            files[attrs_file] = attrs_dwl
            payload_media_type = self._infer_resource_media_type(payload_dwl, plan.get("payload_media_type"))
            attributes_media_type = self._infer_attributes_media_type(attrs_dwl)
            return (
                f"""            <munit:set-event doc:name="Set Input">
                <munit:payload value="#[MunitTools::getResourceAsString('{resource_folder}/{payload_file}')]" mediaType="{payload_media_type}" encoding="UTF-8"/>
                <munit:attributes value="#[read(MunitTools::getResourceAsString('{resource_folder}/{attrs_file}'), 'application/json')]" mediaType="{attributes_media_type}"/>
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
        payload_media_type = self._infer_resource_media_type(
            files[payload_file],
            plan.get("payload_media_type"),
        )
        attributes_media_type = self._infer_attributes_media_type(files[attrs_file])

        return (
            f"""            <munit:set-event doc:name="Set Input">
                <munit:payload value="#[MunitTools::getResourceAsString('{resource_folder}/{payload_file}')]" mediaType="{payload_media_type}" encoding="UTF-8"/>
                <munit:attributes value="#[read(MunitTools::getResourceAsString('{resource_folder}/{attrs_file}'), 'application/json')]" mediaType="{attributes_media_type}"/>
            </munit:set-event>""",
            files,
        )

    def _build_mocks(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        *,
        connector_samples: Dict[str, Dict[str, str]],
    ) -> Tuple[List[str], Dict[str, str]]:
        parts: List[str] = []
        files: Dict[str, str] = {}
        mock_plan = flow_context.get("mock_plan", []) or []
        scenario_type = scenario.get("type", "happy_path")

        if scenario_type in {"empty_payload", "invalid_input", "validation_error"}:
            return parts, files

        for mock_index, item in enumerate(mock_plan, start=1):
            if item.get("action") == "verify-call":
                continue

            if item.get("action") != "mock-when":
                continue

            processor = item.get("processor", "http:request")
            doc_name = item.get("doc_name") or item.get("match_value") or processor
            match_attr = item.get("match_attribute", "doc:name")
            match_value = item.get("match_value") or doc_name

            mock_file = f"mock_{self._slugify(doc_name)}_{index}_{mock_index}.dwl"
            sample = connector_samples.get(self._connector_sample_key(flow_context.get("target_flow", ""), item), {})
            mock_body = self._build_mock_payload_dwl(item, scenario_type, flow_context, sample=sample, scenario=scenario)
            files[mock_file] = mock_body
            mock_media_type = self._infer_resource_media_type(
                mock_body,
                sample.get("media_type") or item.get("media_type"),
            )

            if scenario_type in {"downstream_failure", "downstream_api_failure", "error_scenario"} and self._is_failed_mock_for_scenario(item, scenario):
                error_type = self._expected_error_type(scenario) or self._error_type_for_processor(processor)
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
                continue

            attrs = item.get("return_attributes") or {"statusCode": 200}
            attrs_file = f"mock_{self._slugify(doc_name)}_{index}_{mock_index}_attributes.dwl"
            files[attrs_file] = self._build_mock_resource_content(attrs)
            attributes_media_type = self._infer_attributes_media_type(files[attrs_file])
            parts.append(
                f"""            <munit-tools:mock-when doc:name="Mock {self._xml_escape(doc_name)}" processor="{processor}">
                <munit-tools:with-attributes>
                    <munit-tools:with-attribute attributeName="{match_attr}" whereValue="{self._xml_escape(match_value)}"/>
                </munit-tools:with-attributes>
                <munit-tools:then-return>
                    <munit-tools:payload value="#[MunitTools::getResourceAsString('{resource_folder}/{mock_file}')]" mediaType="{mock_media_type}"/>
                    <munit-tools:attributes value="#[read(MunitTools::getResourceAsString('{resource_folder}/{attrs_file}'), 'application/json')]" mediaType="{attributes_media_type}"/>
                </munit-tools:then-return>
            </munit-tools:mock-when>"""
            )
        return parts, files

    def _build_verify_calls(self, flow_context: Dict[str, Any], scenario: Dict[str, Any]) -> str:
        """Generate validation-time verify-call blocks for side-effect connectors."""
        if scenario.get("type") in {"downstream_failure", "downstream_api_failure", "error_scenario", "validation_error", "invalid_input", "empty_payload"}:
            return ""
        parts = []
        for item in flow_context.get("mock_plan", []) or []:
            if item.get("action") != "verify-call":
                continue
            processor = item.get("processor", "")
            doc_name = item.get("doc_name") or item.get("match_value") or processor
            match_attr = item.get("match_attribute", "doc:name")
            match_value = item.get("match_value") or doc_name
            parts.append(
                f"""            <munit-tools:verify-call doc:name="Verify {self._xml_escape(doc_name)}" processor="{processor}" times="1">
                <munit-tools:with-attributes>
                    <munit-tools:with-attribute attributeName="{match_attr}" whereValue="{self._xml_escape(match_value)}"/>
                </munit-tools:with-attributes>
            </munit-tools:verify-call>"""
            )
        return "\n".join(parts)

    def _build_validation(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        *,
        recorder_style: bool,
        sample_payload: Optional[str],
        connector_samples: Dict[str, Dict[str, str]],
    ) -> Tuple[str, Dict[str, str]]:
        files: Dict[str, str] = {}
        scenario_type = scenario.get("type", "happy_path")
        output_fields = flow_context.get("output_fields", []) or []

        if scenario_type in {"downstream_failure", "downstream_api_failure", "error_scenario"}:
            if scenario.get("assertion_strategy") == "error_handler_response":
                assert_file = f"assert_expression_payload_{index}.dwl"
                files[assert_file] = self._build_assert_module_content(
                    self._expected_error_handler_response(flow_context, scenario)
                )
                module_name = assert_file.rsplit(".", 1)[0]
                return (
                    f"""            <munit-tools:assert doc:name="Assert error response" message="The handled error response does not match expected response">
                <munit-tools:that><![CDATA[#[%dw 2.0
import {resource_folder}::{module_name}
---
{resource_folder}::{module_name}::main({{payload: payload, attributes: attributes, vars: vars}})]]]></munit-tools:that>
            </munit-tools:assert>""",
                    files,
                )
            return (
                """            <munit-tools:assert-that
                doc:name="Assert error type present"
                expression="#[error.errorType.identifier]"
                is="#[MunitTools::notNullValue()]"
                message="Error should be thrown"/>""",
                files,
            )

        if scenario_type in {"empty_payload", "invalid_input", "validation_error"}:
            expected_type = self._expected_error_type(scenario)
            return (
                f"""            <munit-tools:assert-that
                doc:name="Assert validation error"
                expression="#[error.errorType.identifier]"
                is="#[MunitTools::equalTo('{self._xml_escape(expected_type.split(':')[-1])}')]"
                message="Validation should fail"/>""",
                files,
            )

        assert_file = f"assert_expression_payload_{index}.dwl"
        assert_dwl = self._build_assert_dwl(
            flow_context,
            sample_payload,
            recorder_style,
            connector_samples=connector_samples,
            scenario=scenario,
        )
        files[assert_file] = assert_dwl

        if recorder_style or len(output_fields) <= 2:
            module_name = assert_file.rsplit(".", 1)[0]
            return (
                f"""            <munit-tools:assert doc:name="Assert payload" message="The payload does not match expected response">
                <munit-tools:that><![CDATA[#[%dw 2.0
import {resource_folder}::{module_name}
---
{resource_folder}::{module_name}::main({{payload: payload, attributes: attributes, vars: vars}})]]]></munit-tools:that>
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
        sample: Optional[Dict[str, str]] = None,
        scenario: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Build the content of a mock payload DWL file.

        Mock connector files are raw resource files, not executable DWL
        scripts. Keep them free of %dw/output/--- headers so MUnit reads the
        mock content exactly as Studio-style resources.
        """
        scenario = scenario or {}
        if scenario.get("type") == "empty_downstream_response" and self._is_empty_result_mock_for_scenario(mock_item, scenario):
            return self._build_mock_resource_content(
                self._empty_result_for_shape(scenario.get("empty_result_shape") or mock_item.get("result_shape", "object"))
            )

        sample_response = self._parse_connector_sample_response(sample)
        if sample_response is not None:
            return self._build_mock_resource_content(sample_response)

        refs = mock_item.get("downstream_payload_references", []) or []
        shape = mock_item.get("result_shape", "object")
        downstream_script = mock_item.get("downstream_dwl_excerpt", "")
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
            if not refs and downstream_script:
                payload_obj = self._script_to_mock_object(downstream_script, hardcoded_literals=literals)

        if shape == "array":
            # db:select, salesforce:query etc return arrays
            return self._build_mock_resource_content([payload_obj])

        # http:request, vm:publish-consume etc return objects
        return self._build_mock_resource_content(payload_obj)

    def _parse_connector_sample_response(self, sample: Optional[Dict[str, str]]) -> Optional[Any]:
        """Return user-provided connector response content when available."""
        if not sample:
            return None
        response_text = (sample.get("response") or "").strip()
        if not response_text:
            return None
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            return response_text

    def _connector_sample_key(self, flow_name: str, mock_item: Dict[str, Any]) -> str:
        raw = "|".join([
            flow_name or "",
            mock_item.get("processor", ""),
            mock_item.get("match_value") or mock_item.get("doc_name") or "",
        ])
        return re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw).strip("_")

    def _build_assert_dwl(
        self,
        flow_context: Dict[str, Any],
        sample_payload: Optional[str],
        recorder_style: bool,
        *,
        connector_samples: Optional[Dict[str, Dict[str, str]]] = None,
        scenario: Optional[Dict[str, Any]] = None,
    ) -> str:
        scenario = scenario or {}
        expected = None
        if scenario.get("type") == "empty_downstream_response":
            expected = self._expected_empty_downstream_output(flow_context, scenario)
        if expected is None:
            expected = self._expected_output_from_sample(sample_payload)
        if expected is None:
            expected = self._expected_output_from_flow(flow_context, connector_samples or {})
        return self._build_assert_module_content(expected)

    def _build_assert_module_content(self, expected: Any) -> str:
        """Build assertion module content for assert_expression_payload resources."""
        expected_literal = json.dumps(expected, indent=2)
        return (
            "%dw 2.0\n"
            "import * from dw::test::Asserts\n"
            "fun main(vars: Object) = do {\n"
            "  var payload = vars.payload\n"
            "  ---\n"
            f"  payload must equalTo({expected_literal})\n"
            "}\n"
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

        payload_obj = self._sample_request_payload(request_obj)
        payload_dwl = self._build_raw_resource_content(payload_obj)

        attrs = json.loads(json.dumps(plan.get("attributes_template") or {
            "method": "GET",
            "requestPath": "/",
            "queryParams": {},
            "headers": {"content-type": "application/json"},
            "uriParams": {},
        }))
        self._merge_sample_request_attributes(attrs, request_obj)

        attrs_dwl = self._build_raw_resource_content(attrs)

        self._last_sample_response = response_obj
        return payload_dwl, attrs_dwl

    def _sample_request_payload(self, request_obj: Any) -> Any:
        """Return the request body portion from a recorder-style sample."""
        if not isinstance(request_obj, dict):
            return request_obj
        for key in ("payload", "body"):
            if key in request_obj:
                return request_obj[key]
        attribute_keys = {
            "attributes", "headers", "queryParams", "uriParams",
            "method", "requestPath", "path",
        }
        if request_obj and all(key in attribute_keys for key in request_obj):
            return {}
        return request_obj

    def _merge_sample_request_attributes(self, attrs: Dict[str, Any], request_obj: Any) -> None:
        """Merge request attributes from user samples into the set-event attributes."""
        if not isinstance(request_obj, dict):
            return

        nested_attrs = request_obj.get("attributes")
        if isinstance(nested_attrs, dict):
            for key, value in nested_attrs.items():
                if key in {"headers", "queryParams", "uriParams"} and isinstance(value, dict):
                    attrs.setdefault(key, {}).update(value)
                elif key in {"method", "requestPath", "path"}:
                    attrs["requestPath" if key == "path" else key] = value

        for key in ("headers", "queryParams", "uriParams"):
            value = request_obj.get(key)
            if isinstance(value, dict):
                attrs.setdefault(key, {}).update(value)

        if request_obj.get("method"):
            attrs["method"] = request_obj["method"]
        if request_obj.get("requestPath") or request_obj.get("path"):
            attrs["requestPath"] = request_obj.get("requestPath") or request_obj.get("path")

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

    def _expected_output_from_flow(
        self,
        flow_context: Dict[str, Any],
        connector_samples: Dict[str, Dict[str, str]],
    ) -> Any:
        """Build a concrete dummy final response from the analyzed output shape."""
        sample_context = self._build_connector_sample_context(connector_samples)
        if "__payload__" not in sample_context:
            sample_context.update(self._build_generated_mock_sample_context(flow_context))
        sample_context["vars"] = self._build_variable_context(flow_context, sample_context)
        final_script = self._final_transform_script(flow_context)
        if final_script:
            expected = self._expected_output_from_final_transform(final_script, sample_context)
            if expected:
                return expected

        passthrough = self._passthrough_connector_response(flow_context, connector_samples)
        if passthrough is not None:
            return passthrough

        fields = flow_context.get("output_fields", []) or []
        expected: Dict[str, Any] = {}
        for field in fields[:8]:
            expected[field] = self._mock_value_for_field(field)
        if expected:
            return expected
        return {"status": "SUCCESS", "message": "Mock response"}

    def _build_connector_sample_context(self, connector_samples: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
        """Merge connector sample responses into a context for final-transform evaluation."""
        context: Dict[str, Any] = {}
        for sample in connector_samples.values():
            parsed = self._parse_connector_sample_response(sample)
            if parsed is not None:
                context["__payload__"] = parsed
            if isinstance(parsed, dict):
                context.update(parsed)
            elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                context.update(parsed[0])
        return context

    def _build_generated_mock_sample_context(self, flow_context: Dict[str, Any]) -> Dict[str, Any]:
        """Use the generated happy-path mock payload as context for assertion derivation."""
        context: Dict[str, Any] = {}
        for item in flow_context.get("mock_plan", []) or []:
            if item.get("action") != "mock-when":
                continue
            raw_payload = self._build_mock_payload_dwl(
                item,
                "happy_path",
                flow_context,
                sample={},
                scenario={"type": "happy_path"},
            )
            try:
                parsed = json.loads(raw_payload)
            except json.JSONDecodeError:
                parsed = raw_payload.strip()

            context["__payload__"] = parsed
            if isinstance(parsed, dict):
                context.update(parsed)
            elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                context.update(parsed[0])
            break
        return context

    def _build_variable_context(
        self,
        flow_context: Dict[str, Any],
        sample_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Best-effort vars map from analyzed set-variable processors."""
        vars_context: Dict[str, Any] = {}
        for variable in flow_context.get("variable_writes", []) or []:
            name = variable.get("name")
            if not name:
                continue
            expression = variable.get("value") or variable.get("dwl_excerpt") or ""
            vars_context[name] = self._value_from_dwl_expression(expression, name, sample_context)
        return vars_context

    def _passthrough_connector_response(
        self,
        flow_context: Dict[str, Any],
        connector_samples: Dict[str, Dict[str, str]],
    ) -> Optional[Any]:
        """Use connector response as expected output when no final transform changes it."""
        if self._final_transform_script(flow_context):
            return None

        mock_plan = flow_context.get("mock_plan", []) or []
        for item in reversed(mock_plan):
            key = self._connector_sample_key(flow_context.get("target_flow", ""), item)
            parsed = self._parse_connector_sample_response(connector_samples.get(key))
            if parsed is not None:
                return parsed
        return None

    def _final_transform_script(self, flow_context: Dict[str, Any]) -> str:
        final_processor = flow_context.get("final_processor", {}) or {}
        script = (final_processor.get("dwl_excerpt") or "").strip()
        if script:
            return script
        inline_dwl = flow_context.get("inline_dwl", []) or []
        return (inline_dwl[-1].get("script", "") if inline_dwl else "").strip()

    def _expected_output_from_final_transform(
        self,
        script: str,
        sample_context: Dict[str, Any],
    ) -> Any:
        """Derive an expected response object from a simple final DataWeave object."""
        body = script.split("---", 1)[1] if "---" in script else script
        transform_shape = self._infer_dwl_result_shape(body)
        if transform_shape == "array":
            item_context = self._first_payload_item(sample_context)
            mapped = self._expected_object_from_dwl_body(body, {
                **sample_context,
                "__item__": item_context,
            })
            if mapped:
                return [mapped]
            return self._expected_array_from_dwl_body(body, sample_context, item_context)
        if transform_shape == "object":
            return self._expected_object_from_dwl_body(body, sample_context)
        return self._expected_object_from_dwl_body(body, sample_context)

    def _infer_dwl_result_shape(self, body: str) -> str:
        """Infer whether a DataWeave body returns an array, object, or scalar."""
        text = (body or "").strip()
        if re.search(r"\bpayload\s+(?:mapObject|groupBy|reduce)\b", text):
            return "object"
        if re.search(r"\bpayload\s+(?:map|filter|flatMap|pluck|distinctBy|orderBy)\b", text):
            return "array"
        if re.search(r"\bpayload\s*\[[^\]]+\]", text):
            return "array"
        if text.startswith("{"):
            return "object"
        if text.startswith("["):
            return "array"
        return "scalar"

    def _expected_array_from_dwl_body(
        self,
        body: str,
        sample_context: Dict[str, Any],
        item_context: Any,
    ) -> List[Any]:
        """Derive a representative array result for map/pluck/filter/order functions."""
        text = (body or "").strip()
        if re.search(r"\bpayload\s+(?:filter|distinctBy|orderBy)\b", text):
            return [item_context] if item_context else []

        expression = ""
        arrow_match = re.search(r"->\s*([^\n\r]+)", text)
        if arrow_match:
            expression = arrow_match.group(1).strip()
        else:
            pluck_match = re.search(r"\bpayload\s+pluck\s+([^\n\r]+)", text)
            if pluck_match:
                expression = pluck_match.group(1).strip()

        if expression:
            value = self._value_from_dwl_expression(expression, "item", {
                **sample_context,
                "__item__": item_context,
            })
            return [value]

        payload = sample_context.get("__payload__")
        if isinstance(payload, list):
            return payload
        return [item_context] if item_context else []

    def _expected_object_from_dwl_body(
        self,
        body: str,
        sample_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        expected: Dict[str, Any] = {}
        for match in re.finditer(r'^\s*"?([A-Za-z_][\w-]*)"?\s*:\s*(.+?)\s*,?\s*$', body, re.MULTILINE):
            key = match.group(1)
            expression = match.group(2).strip()
            if key in {"output", "ns", "import"}:
                continue
            expected[key] = self._value_from_dwl_expression(expression, key, sample_context)
        return expected

    def _value_from_dwl_expression(
        self,
        expression: str,
        output_field: str,
        sample_context: Dict[str, Any],
    ) -> Any:
        expression = expression.strip().rstrip(",")
        literal = self._parse_literal_expression(expression)
        if literal is not None:
            return literal

        filter_handled, filtered = self._value_from_filter_selector_expression(expression, sample_context)
        if filter_handled:
            return filtered

        payload_match = re.search(r"\bpayload\.([A-Za-z0-9_.\[\]-]+)", expression)
        if payload_match:
            resolved = self._resolve_path(sample_context, payload_match.group(1))
            if resolved is not None:
                return resolved
            return self._mock_value_for_field(payload_match.group(1).split(".")[-1])

        item_match = re.search(r"(?:\bitem|\$)\.([A-Za-z0-9_.\[\]-]+)", expression)
        if item_match:
            resolved = self._resolve_path(sample_context.get("__item__", {}), item_match.group(1))
            if resolved is not None:
                return resolved
            return self._mock_value_for_field(item_match.group(1).split(".")[-1])

        vars_match = re.search(r"\bvars\.([A-Za-z0-9_.\[\]-]+)", expression)
        if vars_match:
            resolved = self._resolve_path(sample_context.get("vars", {}), vars_match.group(1))
            if resolved is not None:
                return resolved
            return self._mock_value_for_field(vars_match.group(1).split(".")[-1])

        return self._mock_value_for_field(output_field)

    def _value_from_filter_selector_expression(
        self,
        expression: str,
        sample_context: Dict[str, Any],
    ) -> Tuple[bool, Any]:
        """
        Evaluate common DWL filter+selector shapes, e.g.
        (payload.data filter ((item) -> item.name == "India")).states[0].
        """
        match = re.search(
            r"\(?\s*payload\.([A-Za-z0-9_.\[\]-]+)\s+filter\s*\(.*?\bitem\.([A-Za-z0-9_.\[\]-]+)\s*==\s*(['\"])(.*?)\3.*?\)\s*\)?\.([A-Za-z0-9_.\[\]-]+)",
            expression,
            re.DOTALL,
        )
        if not match:
            return False, None

        source_path = match.group(1)
        filter_path = match.group(2)
        filter_value = match.group(4)
        selector_path = match.group(5)

        source = self._resolve_path(sample_context, source_path)
        if source is None:
            source = self._resolve_path(sample_context.get("__payload__", {}), source_path)
        if not isinstance(source, list):
            return True, None

        selected = []
        for item in source:
            value = self._resolve_path(item, filter_path) if isinstance(item, dict) else None
            if value == filter_value:
                selected.append(item)

        if not selected:
            return True, None

        # DWL selector over an array followed by [0], such as `.states[0]`,
        # returns the selected field from the first filtered item.
        selector_root = selector_path.split("[", 1)[0]
        first_value = self._resolve_path(selected[0], selector_root)
        if first_value is not None:
            return True, first_value

        resolved = self._resolve_path(selected[0], selector_path)
        return True, resolved

    def _parse_literal_expression(self, expression: str) -> Optional[Any]:
        if re.match(r"^['\"].*['\"]$", expression):
            return expression[1:-1]
        if expression in {"true", "false"}:
            return expression == "true"
        if expression == "null":
            return None
        try:
            if "." in expression:
                return float(expression)
            return int(expression)
        except ValueError:
            return None

    def _resolve_path(self, source: Any, path: str) -> Optional[Any]:
        cursor = source
        for segment in [part for part in re.split(r"\.", path) if part]:
            index_match = re.match(r"([A-Za-z0-9_-]+)(?:\[(\d+)\])?", segment)
            if not index_match:
                return None
            key, index = index_match.group(1), index_match.group(2)
            if isinstance(cursor, dict) and key in cursor:
                cursor = cursor[key]
            else:
                return None
            if index is not None:
                if isinstance(cursor, list) and len(cursor) > int(index):
                    cursor = cursor[int(index)]
                else:
                    return None
        return cursor

    def _first_payload_item(self, sample_context: Dict[str, Any]) -> Any:
        payload = sample_context.get("__payload__")
        if isinstance(payload, list) and payload:
            return payload[0]
        if isinstance(payload, dict):
            return payload
        return sample_context

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

    def _script_to_mock_object(
        self,
        script: str,
        hardcoded_literals: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Build a mock object from downstream DWL item/payload field usage."""
        hardcoded_literals = hardcoded_literals or {}
        root: Dict[str, Any] = {}
        fields = []
        for pattern in (
            r"\b(?:item|\$)\.([A-Za-z0-9_.\[\]-]+)",
            r"\bpayload\.([A-Za-z0-9_.\[\]-]+)",
        ):
            fields.extend(re.findall(pattern, script or ""))

        for field_path in fields:
            normalized = re.sub(r"\[\d+\]", "", field_path)
            segments = [segment for segment in normalized.split(".") if segment]
            if segments:
                self._assign_path(root, segments, hardcoded_literals)

        return root or {"id": "MOCK-001", "name": "Test Record", "status": "ACTIVE"}

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
        if processor.startswith("file:"):
            return "FILE:ILLEGAL_PATH"
        if processor.startswith("sftp:"):
            return "SFTP:CONNECTIVITY"
        if processor.startswith("jms:"):
            return "JMS:CONNECTIVITY"
        if processor.startswith("vm:"):
            return "VM:CONNECTIVITY"
        if processor.startswith("objectstore:"):
            return "OS:KEY_NOT_FOUND"
        return "HTTP:CONNECTIVITY"

    def _apply_scenario_to_set_event_plan(
        self,
        plan: Dict[str, Any],
        scenario: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Adjust input event for branch/validation scenarios from flow conditions."""
        if scenario.get("type") not in {"branch_path", "validation_error", "invalid_input", "empty_payload"}:
            return plan

        adjusted = dict(plan)
        attrs = json.loads(json.dumps(adjusted.get("attributes_template") or {}))
        payload_obj: Dict[str, Any] = {}
        try:
            parsed = json.loads(adjusted.get("payload_expression") or "{}")
            if isinstance(parsed, dict):
                payload_obj = parsed
        except (json.JSONDecodeError, TypeError):
            payload_obj = {}

        condition = scenario.get("branch_condition", "")
        for source, field, value in self._extract_condition_equalities(condition):
            if source == "attributes.queryParams":
                attrs.setdefault("queryParams", {})[field] = value
            elif source == "attributes.headers":
                attrs.setdefault("headers", {})[field] = value
            elif source == "attributes.uriParams":
                attrs.setdefault("uriParams", {})[field] = value
            elif source == "payload":
                payload_obj[field] = value

        if scenario.get("type") in {"validation_error", "invalid_input"}:
            if payload_obj:
                first_key = next(iter(payload_obj))
                payload_obj.pop(first_key, None)
            else:
                adjusted["payload_expression"] = '""'
                adjusted["payload_media_type"] = "application/java"

        adjusted["attributes_template"] = attrs
        if payload_obj:
            adjusted["payload_expression"] = json.dumps(payload_obj)
            adjusted["payload_media_type"] = "application/json"
        return adjusted

    def _extract_condition_equalities(self, condition: str) -> List[Tuple[str, str, Any]]:
        """Parse simple route conditions like attributes.queryParams.kind == 'a'."""
        results: List[Tuple[str, str, Any]] = []
        for match in re.finditer(
            r"\b(payload|attributes\.queryParams|attributes\.headers|attributes\.uriParams)\.([A-Za-z0-9_-]+)\s*==\s*(['\"])(.*?)\3",
            condition or "",
        ):
            results.append((match.group(1), match.group(2), match.group(4)))
        for match in re.finditer(
            r"\b(payload|attributes\.queryParams|attributes\.headers|attributes\.uriParams)\.([A-Za-z0-9_-]+)\s*==\s*(\d+(?:\.\d+)?)",
            condition or "",
        ):
            number = float(match.group(3)) if "." in match.group(3) else int(match.group(3))
            results.append((match.group(1), match.group(2), number))
        return results

    def _is_empty_result_mock_for_scenario(self, item: Dict[str, Any], scenario: Dict[str, Any]) -> bool:
        empty_processor = scenario.get("empty_processor")
        empty_match = scenario.get("empty_match_value")
        if empty_processor and item.get("processor") != empty_processor:
            return False
        if empty_match and empty_match not in {item.get("match_value"), item.get("doc_name")}:
            return False
        return True

    def _empty_result_for_shape(self, shape: str) -> Any:
        if shape == "array":
            return []
        if shape == "affectedRows":
            return {"affectedRows": 0}
        return {}

    def _expected_empty_downstream_output(self, flow_context: Dict[str, Any], scenario: Dict[str, Any]) -> Any:
        final_script = self._final_transform_script(flow_context)
        shape = scenario.get("empty_result_shape", "object")
        if final_script:
            body = final_script.split("---", 1)[1] if "---" in final_script else final_script
            transform_shape = self._infer_dwl_result_shape(body)
            if transform_shape == "array":
                return []
            if transform_shape == "object":
                return self._expected_object_from_dwl_body(body, {"__payload__": self._empty_result_for_shape(shape), "vars": {}})
        return self._empty_result_for_shape(shape)

    def _expected_error_type(self, scenario: Dict[str, Any]) -> str:
        explicit = scenario.get("expected_error_type")
        if explicit:
            return explicit
        failed_processor = scenario.get("failed_processor", "")
        if failed_processor:
            return self._error_type_for_processor(failed_processor)
        if scenario.get("type") in {"empty_payload", "invalid_input", "validation_error"}:
            return "VALIDATION:INVALID_BOOLEAN"
        return "HTTP:CONNECTIVITY"

    def _scenario_expects_thrown_error(self, scenario: Dict[str, Any]) -> bool:
        if scenario.get("assertion_strategy") == "error_handler_response":
            return False
        return scenario.get("type") in {
            "downstream_failure",
            "downstream_api_failure",
            "error_scenario",
            "empty_payload",
            "invalid_input",
            "validation_error",
        }

    def _is_failed_mock_for_scenario(self, item: Dict[str, Any], scenario: Dict[str, Any]) -> bool:
        failed_processor = scenario.get("failed_processor")
        failed_match = scenario.get("failed_match_value")
        if failed_processor and item.get("processor") != failed_processor:
            return False
        if failed_match and failed_match not in {item.get("match_value"), item.get("doc_name")}:
            return False
        return bool(failed_processor or scenario.get("type") in {"downstream_failure", "downstream_api_failure", "error_scenario"})

    def _expected_error_handler_response(self, flow_context: Dict[str, Any], scenario: Dict[str, Any]) -> Any:
        """Best-effort expected payload for on-error-continue handled failures."""
        for handler in flow_context.get("error_handler_details", []) or []:
            script = handler.get("dwl_excerpt", "")
            if script:
                expected = self._expected_output_from_final_transform(script, {})
                if expected:
                    return expected
        return {
            "status": "ERROR",
            "message": f"{scenario.get('failed_match_value') or scenario.get('failed_processor') or 'Downstream'} failed",
        }

    def _validate_generated_suite(
        self,
        suite_xml: str,
        resource_files: Dict[str, str],
        flow_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Preflight checks that catch common MUnit generation defects."""
        errors: List[str] = []
        warnings: List[str] = []
        try:
            ET.fromstring(suite_xml)
        except ET.ParseError as exc:
            errors.append(f"Generated MUnit XML is not well formed: {exc}")

        refs = re.findall(r"MunitTools::getResourceAsString\('([^']+)'\)", suite_xml or "")
        resource_names = set(resource_files.keys())
        for ref in refs:
            name = ref.rsplit("/", 1)[-1]
            if name not in resource_names:
                errors.append(f"Missing resource file for reference: {ref}")

        seen = set()
        for name, content in resource_files.items():
            if name in seen:
                errors.append(f"Duplicate resource file name: {name}")
            seen.add(name)
            if name.startswith("assert_expression_"):
                if "import * from dw::test::Asserts" not in content:
                    errors.append(f"Assertion resource missing dw::test::Asserts import: {name}")
                continue
            if re.search(r"(?im)^\s*%dw\b|^\s*output\s+application/|^\s*---\s*$", content or ""):
                errors.append(f"Non-assert resource contains a DataWeave header: {name}")

        inline_resource_patterns = [
            r"<munit-tools:payload\b[^>]*value=\"#\[\s*[\{\[]",
            r"<munit-tools:attributes\b[^>]*value=\"#\[\s*[\{\[]",
            r"<munit:payload\b[^>]*value=\"#\[\s*[\{\[]",
            r"<munit:attributes\b[^>]*value=\"#\[\s*[\{\[]",
        ]
        for pattern in inline_resource_patterns:
            if re.search(pattern, suite_xml or ""):
                errors.append("Inline payload/attributes content found; generated MUnit must read resource files.")

        mocked_processors = set(re.findall(r"<munit-tools:mock-when\b[^>]*processor=\"([^\"]+)\"", suite_xml or ""))
        live_processors = set(re.findall(r"<([A-Za-z0-9_-]+:[A-Za-z0-9_-]+)\b", suite_xml or ""))
        unmocked = sorted(
            processor for processor in live_processors
            if processor in {
                "http:request", "db:select", "db:insert", "db:update", "db:delete",
                "wsc:consume",
                "salesforce:query", "salesforce:create", "salesforce:update",
                "file:read", "sftp:read", "jms:publish-consume", "vm:publish-consume",
                "objectstore:retrieve",
            }
            and processor not in mocked_processors
        )
        if unmocked:
            errors.append(f"Live outbound connector calls remain unmocked: {', '.join(unmocked)}")

        for item in (flow_context or {}).get("mock_plan", []) or []:
            processor = item.get("processor")
            match_value = item.get("match_value") or item.get("doc_name")
            if item.get("action") == "mock-when":
                if processor and f'processor="{processor}"' not in suite_xml:
                    errors.append(f"Missing mock-when for outbound connector: {processor} {match_value or ''}".strip())
                if match_value and self._xml_escape(match_value) not in suite_xml:
                    errors.append(f"Missing mock attribute match for outbound connector: {match_value}")
            elif item.get("action") == "verify-call":
                if processor and f'processor="{processor}"' not in suite_xml:
                    warnings.append(f"Missing verify-call for outbound side-effect connector: {processor} {match_value or ''}".strip())

        return {"valid": not errors, "errors": errors, "warnings": warnings}

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
        return self._build_raw_resource_content(body)

    def _plan_to_attributes_dwl(self, plan: Dict[str, Any]) -> str:
        """
        Build set-event attributes DWL file content.

        The object body is emitted as raw JSON-compatible content with
        double-quoted keys and string values.
        """
        attrs = plan.get("attributes_template") or {}
        return self._build_raw_resource_content(attrs)

    def _build_mock_resource_content(self, value: Any) -> str:
        """Build raw mock connector resource content with no DWL header."""
        return self._build_raw_resource_content(value)

    def _build_raw_resource_content(self, value: Any) -> str:
        """Build raw resource content with double-quoted JSON-style values."""
        if isinstance(value, str):
            return value.rstrip() + "\n"
        return json.dumps(value, indent=2) + "\n"

    def _infer_resource_media_type(
        self,
        content: str,
        fallback: Optional[str] = None,
    ) -> str:
        """Infer the mediaType to put on MUnit payload XML for a resource file."""
        text = (content or "").strip()
        output_match = re.search(r"(?im)^\s*output\s+([A-Za-z0-9_./+-]+)", text)
        if output_match:
            return output_match.group(1)

        if 'as Binary {base: "64"}' in text or "as Binary {base: '64'}" in text:
            return "application/java"

        if text.startswith("{") or text.startswith("["):
            try:
                json.loads(text)
                return "application/json"
            except json.JSONDecodeError:
                pass

        if text.startswith("<"):
            return "application/xml"

        return fallback or "application/json"

    def _infer_attributes_media_type(self, content: str) -> str:
        """Infer mediaType for Mule attributes resources."""
        return "application/java"

    def _build_attributes_dwl(self, value: Any) -> str:
        """Build raw Mule attributes content using double-quoted keys."""
        return self._build_raw_resource_content(value)

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
        "wsc:consume",
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
        for key in ("value", "expression"):
            expression = (proc.get(key) or "").strip()
            if expression and expression not in scripts:
                scripts.append(expression)
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
    query_params = {
        field: _mock_value_for_attribute_static("queryParams", field)
        for field in _extract_attribute_fields_static(scripts, "queryParams")
    }
    header_params = {
        field: _mock_value_for_attribute_static("headers", field)
        for field in _extract_attribute_fields_static(scripts, "headers")
    }
    uri_params = {
        field: _mock_value_for_attribute_static("uriParams", field)
        for field in _extract_attribute_fields_static(scripts, "uriParams")
    }

    country_literal = re.search(r'item\.name\s*==\s*"([^"]+)"', scripts)
    if country_literal:
        plan["hardcoded_literals"]["filter_country"] = country_literal.group(1)
        query_params.setdefault("country", country_literal.group(1))

    if trigger_type == "http:listener":
        method = (trigger.get("method") or trigger.get("allowedMethods") or "GET").split(",")[0].strip()
        path = trigger.get("path") or trigger.get("requestPath") or "/"
        for field in re.findall(r"\{([A-Za-z0-9_-]+)\}", path):
            uri_params.setdefault(field, _mock_value_for_attribute_static("uriParams", field))
        headers = {"content-type": "application/json"}
        headers.update(header_params)
        plan["attributes_template"] = {
            "method": method,
            "requestPath": path,
            "queryParams": query_params,
            "headers": headers,
            "uriParams": uri_params,
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


def _extract_attribute_fields_static(text: str, attribute_group: str) -> List[str]:
    """Extract attributes.queryParams/header/uriParams field names from DWL text."""
    if not text:
        return []

    escaped_group = re.escape(attribute_group)
    patterns = [
        rf"\battributes\.{escaped_group}\.([A-Za-z_][A-Za-z0-9_-]*)",
        rf"\battributes\.{escaped_group}\[['\"]([^'\"]+)['\"]\]",
        rf"\battributes\.{escaped_group}\s*\[\s*['\"]([^'\"]+)['\"]\s*\]",
    ]
    ordered: List[str] = []
    for pattern in patterns:
        for match in re.findall(pattern, text):
            if match and match not in ordered:
                ordered.append(match)
    return ordered


def _mock_value_for_attribute_static(attribute_group: str, field: str) -> Any:
    lowered = (field or "").lower()
    if attribute_group == "headers":
        if lowered in {"authorization", "auth", "auth-token", "access-token"}:
            return "Bearer test-token"
        if lowered in {"client_id", "client-id", "x-client-id"}:
            return "test-client-id"
        if lowered in {"client_secret", "client-secret", "x-client-secret"}:
            return "test-client-secret"
        if "correlation" in lowered:
            return "test-correlation-id"
    return _mock_value_for_field_static(field)


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
