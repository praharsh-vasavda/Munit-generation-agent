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
from .compliance_policy import CompliancePolicy


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
        munit_plan = self._build_munit_plan(
            flow_context,
            scenario_list,
            generation_mode=generation_mode,
            sample_payload=sample_payload,
            connector_samples=connector_samples or {},
        )
        enabled_flow_sources = self._enabled_flow_sources(flow_context)

        resource_files: Dict[str, str] = {}
        tests_xml: List[str] = []
        used_test_names: set = set()

        for index, scenario in enumerate(scenario_list, start=1):
            test_xml, files = self._build_test(
                flow_context,
                scenario,
                resource_folder,
                index,
                used_test_names=used_test_names,
                sample_payload=sample_payload,
                connector_samples=connector_samples or {},
                recorder_style=(generation_mode == "recorder"),
                enabled_flow_sources=enabled_flow_sources,
            )
            tests_xml.append(test_xml)
            resource_files.update(files)

        suite_xml = MUNIT_XML_TEMPLATE.format(
            suite_name=suite_name,
            tests="\n".join(tests_xml),
        )
        suite_xml, resource_files = self._dedupe_reusable_resource_files(suite_xml, resource_files)

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
            "munit_plan": munit_plan,
            "enabled_flow_sources": enabled_flow_sources,
            "target_munit_version": target_munit_version,
            "compliance_policy": CompliancePolicy.metadata(),
            "preflight_validation": self._validate_generated_suite(suite_xml, resource_files, flow_context),
        }
        return suite_xml, metadata

    def _build_munit_plan(
        self,
        flow_context: Dict[str, Any],
        scenarios: List[Dict[str, Any]],
        *,
        generation_mode: str,
        sample_payload: Optional[str] = None,
        connector_samples: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Build the explicit Behavior / Execution / Validation plan used for rendering."""
        target_flow = flow_context.get("target_flow", "main-flow")
        set_event_plan = flow_context.get("set_event_plan") or {}
        required_inputs = flow_context.get("required_inputs") or {}
        mock_plan = self._dedupe_mock_plan(flow_context.get("mock_plan") or [])
        warnings = []

        behavior_mocks = []
        behavior_verifications = []
        behavior_spies = self._build_spy_plan(flow_context)
        for item in mock_plan:
            entry = {
                "processor": item.get("processor", ""),
                "flow": item.get("flow", ""),
                "doc_name": item.get("doc_name", ""),
                "match_attribute": item.get("match_attribute", "doc:name"),
                "match_value": item.get("match_value") or item.get("doc_name") or item.get("processor", ""),
                "result_shape": item.get("result_shape"),
                "media_type": item.get("media_type"),
            }
            if not entry["doc_name"]:
                warnings.append({
                    "type": "missing_doc_name",
                    "message": f"{entry['processor']} has no doc:name; mock matching will use {entry['match_attribute']}.",
                    "processor": entry["processor"],
                    "flow": entry["flow"],
                })
            if item.get("action") == "mock-when":
                behavior_mocks.append(entry)
            elif item.get("action") == "verify-call":
                behavior_verifications.append(entry)

        validation_plan = [
            self._validation_plan_for_scenario(
                flow_context,
                scenario,
                sample_payload=sample_payload,
                connector_samples=connector_samples or {},
            )
            for scenario in scenarios
        ]
        if not any(item.get("assertions") or item.get("verifications") for item in validation_plan):
            warnings.append({
                "type": "weak_validation",
                "message": "No implementation-driven validation could be derived; generated suite may need manual assertion review.",
            })

        warnings.extend(flow_context.get("flow_traversal_warnings") or [])
        warnings.extend(flow_context.get("unresolved_flow_refs") or [])
        clarification_requests = self._build_clarification_requests(
            flow_context,
            sample_payload=sample_payload,
            connector_samples=connector_samples or {},
        )

        attrs = set_event_plan.get("attributes_template") or {}
        return {
            "targetFlow": target_flow,
            "generationMode": generation_mode,
            "execution": {
                "callFlow": target_flow,
                "callOnlySelectedFlow": True,
                "setEventLocation": "execution",
                "setEventRequired": bool(set_event_plan),
                "payloadRequired": bool(required_inputs.get("payloadRequired")),
                "method": attrs.get("method"),
                "requestPath": attrs.get("requestPath"),
                "headers": sorted((attrs.get("headers") or {}).keys()),
                "queryParams": sorted((attrs.get("queryParams") or {}).keys()),
                "uriParams": sorted((attrs.get("uriParams") or {}).keys()),
            },
            "behavior": {
                "mockWhen": behavior_mocks,
                "spy": behavior_spies,
                "verifyLater": behavior_verifications,
                "source": "mock_plan_from_full_flow_traversal",
            },
            "validation": validation_plan,
            "traversal": {
                "flows": flow_context.get("execution_flows", []),
                "flowLevels": flow_context.get("flow_levels", {}),
                "connectors": flow_context.get("traversal_connectors", []),
                "enabledFlowSources": self._enabled_flow_sources(flow_context),
            },
            "warnings": warnings,
            "clarificationRequests": clarification_requests,
            "compliance": CompliancePolicy.metadata(),
        }

    def _enabled_flow_sources(self, flow_context: Dict[str, Any]) -> List[str]:
        """Return dynamically resolved flow names to expose through munit:enable-flow-sources."""
        candidates = flow_context.get("munit_enable_flow_sources") or []
        if not candidates:
            candidates = flow_context.get("dynamic_flow_sources") or []

        seen = set()
        result: List[str] = []
        target_flow = flow_context.get("target_flow")
        for name in candidates:
            flow_name = str(name or "").strip()
            if not flow_name or flow_name == target_flow or flow_name in seen:
                continue
            seen.add(flow_name)
            result.append(flow_name)
        return result

    def _render_enable_flow_sources(self, flow_names: List[str]) -> str:
        if not flow_names:
            return ""
        rows = "\n".join(
            f'            <munit:enable-flow-source value="{self._xml_escape(flow_name)}"/>'
            for flow_name in flow_names
        )
        return f"""        <munit:enable-flow-sources>
{rows}
        </munit:enable-flow-sources>
"""

    def _dedupe_mock_plan(self, mock_plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Keep one mock/verification for each effective MUnit matcher."""
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in mock_plan or []:
            processor = str(item.get("processor") or "").strip()
            action = str(item.get("action") or "").strip()
            match_attribute = str(item.get("match_attribute") or "doc:name").strip()
            match_value = str(
                item.get("match_value")
                or item.get("doc_name")
                or processor
            ).strip()
            key = (action, processor, match_attribute, match_value)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def _build_spy_plan(self, flow_context: Dict[str, Any]) -> List[Dict[str, str]]:
        """Plan optional spies for named DataWeave/transform processors."""
        spies: List[Dict[str, str]] = []
        seen = set()
        for processor in flow_context.get("processor_chain", []) or []:
            processor_type = processor.get("type") or ""
            doc_name = processor.get("doc_name") or ""
            if not doc_name:
                continue
            if processor_type not in {"ee:transform", "ee:set-payload", "set-payload", "transform"}:
                continue
            key = (processor_type, doc_name)
            if key in seen:
                continue
            seen.add(key)
            spies.append({
                "processor": processor_type,
                "doc_name": doc_name,
                "match_attribute": "doc:name",
                "match_value": doc_name,
                "phase": "after-call",
                "assertion": "payload not null",
                "reason": "DataWeave output can be observed without mocking the transform",
            })
        return spies[:4]

    def _build_clarification_requests(
        self,
        flow_context: Dict[str, Any],
        *,
        sample_payload: Optional[str],
        connector_samples: Dict[str, Dict[str, str]],
    ) -> List[Dict[str, Any]]:
        """Ask for user-safe examples when static analysis cannot know real data."""
        requests: List[Dict[str, Any]] = []
        requested_input_fields = self._missing_input_field_groups(flow_context)
        if not sample_payload and (flow_context.get("required_inputs") or {}).get("payloadRequired"):
            requests.append({
                "type": "sample_request_response",
                "flow": flow_context.get("target_flow", ""),
                "title": "Provide request and expected response sample",
                "sample_kind": "request_response",
                "reason": "This flow reads request data. Provide one synthetic request sample with payload, queryParams, uriParams, and headers as needed, plus the expected response if known.",
                "requested_fields": requested_input_fields,
                "security_note": "Provide synthetic or masked data only. Do not include secrets or production PII.",
            })

        for item in self._dedupe_mock_plan(flow_context.get("mock_plan", []) or []):
            if item.get("action") != "mock-when":
                continue
            key = self._connector_sample_key(flow_context.get("target_flow", ""), item)
            if key in connector_samples:
                continue
            if item.get("downstream_payload_references") or item.get("downstream_dwl_excerpt"):
                continue
            requests.append({
                "type": "connector_mock_response",
                "flow": flow_context.get("target_flow", ""),
                "connector_key": key,
                "processor": item.get("processor", ""),
                "doc_name": item.get("doc_name") or item.get("match_value") or item.get("processor", ""),
                "external_flow": item.get("external_flow", ""),
                "title": (
                    "Provide mock response for external dependency flow"
                    if item.get("external_dependency")
                    else "Provide mock response for external connector"
                ),
                "sample_kind": "connector_response",
                "reason": (
                    f"Flow `{item.get('external_flow')}` is called by this app, but its XML is not present in the uploaded ZIP. "
                    "Provide the synthetic response body that this dependency flow should return."
                    if item.get("external_dependency")
                    else "This external connector will be mocked. Provide the synthetic response body that this connector should return during the MUnit test."
                ),
                "security_note": "Provide a synthetic response sample. The agent must not call live systems.",
            })

        for unresolved in flow_context.get("unresolved_flow_refs", []) or []:
            unresolved_reason = unresolved.get("reason") or "Dynamic flow-ref target could not be resolved safely from code."
            requests.append({
                "type": "dynamic_flow_ref_resolution",
                "flow": unresolved.get("flow") or flow_context.get("target_flow", ""),
                "expression": unresolved.get("expression", ""),
                "title": "Provide dynamic flow-ref targets",
                "sample_kind": "dynamic_flow_targets",
                "reason": f"{unresolved_reason}. Provide possible target flow names and the condition/input that selects each target.",
                "placeholder": '[{"condition":"payload.type == \\"A\\"","targetFlow":"processAFlow"},{"condition":"otherwise","targetFlow":"processBFlow"}]',
                "security_note": "Provide possible target flow names only, not sensitive payload data.",
            })

        if not sample_payload and not any(item.get("type") == "sample_request_response" for item in requests):
            requests.append({
                "type": "sample_request_response",
                "flow": flow_context.get("target_flow", ""),
                "title": "Additional Sample Test Data",
                "sample_kind": "request_response",
                "reason": "Provide the flow input and expected output samples. Add query parameters, URI parameters, and headers when the flow requires them.",
                "requested_fields": requested_input_fields,
                "security_note": "Provide synthetic or masked data only. Do not include secrets or production PII.",
            })
        return requests[:8]

    def _synthetic_default_clarification_requests(self, flow_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Ask for one grouped request sample when static analysis used generic placeholders."""
        requested_fields = self._missing_input_field_groups(flow_context)
        if not any(requested_fields.values()):
            return []
        return [{
            "type": "sample_request_response",
            "flow": flow_context.get("target_flow", ""),
            "title": "Provide request sample",
            "sample_kind": "request_response",
            "reason": "Static analysis found request inputs but cannot infer reliable values. Provide one synthetic request sample with payload, queryParams, uriParams, and headers instead of field-by-field values.",
            "requested_fields": requested_fields,
            "security_note": "Provide synthetic or masked data only. Do not include secrets or production PII.",
        }]

    def _missing_input_field_groups(self, flow_context: Dict[str, Any]) -> Dict[str, List[str]]:
        """Group unknown request inputs by source so UI can ask for one sample."""
        set_event_plan = flow_context.get("set_event_plan") or {}
        attrs = set_event_plan.get("attributes_template") or {}
        groups: Dict[str, List[str]] = {
            "payload": [],
            "queryParams": [],
            "uriParams": [],
            "headers": [],
        }

        def add(location: str, field: str) -> None:
            if field and field not in groups.setdefault(location, []):
                groups[location].append(field)

        for location, values in (
            ("headers", attrs.get("headers") or {}),
            ("queryParams", attrs.get("queryParams") or {}),
            ("uriParams", attrs.get("uriParams") or {}),
        ):
            for field, value in values.items():
                if value == "MOCK-VALUE":
                    add(location, field)

        payload_expression = (set_event_plan.get("payload_expression") or "").strip()
        if "MOCK-VALUE" in payload_expression:
            try:
                parsed = json.loads(payload_expression)
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                for field, value in parsed.items():
                    if value == "MOCK-VALUE":
                        add("payload", field)
            else:
                add("payload", "payload")

        for variable in flow_context.get("variable_writes", []) or []:
            expression = " ".join([
                variable.get("value") or "",
                variable.get("dwl_excerpt") or "",
            ])
            for location, field in self._input_fields_from_expression(expression):
                add(location, field)

        return {key: sorted(values) for key, values in groups.items() if values}

    def _input_fields_from_expression(self, expression: str) -> List[Tuple[str, str]]:
        """Extract request input fields referenced by set-variable/DataWeave expressions."""
        text = expression or ""
        field_refs: List[Tuple[str, str]] = []

        def add(location: str, field: str) -> None:
            if field and (location, field) not in field_refs:
                field_refs.append((location, field))

        patterns = [
            ("payload", r"\bpayload\.([A-Za-z_][A-Za-z0-9_-]*)"),
            ("queryParams", r"\battributes\.queryParams(?:\.|\[['\"])([A-Za-z_][A-Za-z0-9_-]*)"),
            ("uriParams", r"\battributes\.uriParams(?:\.|\[['\"])([A-Za-z_][A-Za-z0-9_-]*)"),
            ("headers", r"\battributes\.headers(?:\.|\[['\"])([A-Za-z_][A-Za-z0-9_-]*)"),
        ]
        for location, pattern in patterns:
            for match in re.findall(pattern, text):
                add(location, match)
        return field_refs

    def _validation_plan_for_scenario(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        *,
        sample_payload: Optional[str] = None,
        connector_samples: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Describe why validation uses assert-that, assert-expression, or verify-call."""
        scenario_type = scenario.get("type", "happy_path")
        plan = {
            "scenario": scenario.get("name") or scenario_type,
            "type": scenario_type,
            "assertionStrategy": scenario.get("assertion_strategy", "payload_equals_expected"),
            "assertions": [],
            "verifications": [],
            "expectedErrorType": self._expected_error_type(scenario) if self._scenario_expects_thrown_error(scenario) else None,
        }

        if scenario_type in {"downstream_failure", "downstream_api_failure", "error_scenario"}:
            if scenario.get("assertion_strategy") == "error_handler_response":
                plan["assertions"].append({
                    "kind": "assert-expression",
                    "target": "payload",
                    "reason": "error handler transforms or sets an error response",
                })
            elif self._error_handler_has_only_verifiable_side_effects(flow_context):
                plan["verifications"].extend(self._error_handler_verification_plan(flow_context))
            else:
                plan["assertions"].append({
                    "kind": "assert-that",
                    "target": "error.errorType.identifier",
                    "reason": "failure path should surface an expected error type",
                })
            return plan

        if scenario_type in {"empty_payload", "invalid_input", "validation_error"}:
            if self._scenario_expects_thrown_error(scenario):
                return plan
            plan["assertions"].append({
                "kind": "assert-that",
                "target": "error.errorType.identifier",
                "reason": "invalid input should trigger validation error",
            })
            return plan

        final_processor = flow_context.get("final_processor") or {}
        output_fields = flow_context.get("output_fields") or []
        dynamic_fields = self._dynamic_output_fields(flow_context)
        if self._expected_output_from_sample(sample_payload) is not None:
            plan["assertions"].append({
                "kind": "assert-expression",
                "target": "payload",
                "reason": "user-provided sample response determines expected output",
            })
            return plan
        if final_processor.get("dwl_excerpt"):
            if dynamic_fields:
                for field in output_fields[:6]:
                    dynamic_reason = dynamic_fields.get(field)
                    plan["assertions"].append({
                        "kind": "assert-that",
                        "target": f"payload.{field}",
                        "matcher": (
                            "matchesRegex" if dynamic_reason == "uuid"
                            else "notNullValue" if dynamic_reason
                            else "equalTo"
                        ),
                        "reason": "dynamic runtime value" if dynamic_reason else "stable final DataWeave field",
                    })
            else:
                plan["assertions"].append({
                    "kind": "assert-expression",
                    "target": "payload",
                    "reason": "final DataWeave output determines response contract",
                })
        elif output_fields:
            for field in output_fields[:3]:
                plan["assertions"].append({
                    "kind": "assert-that",
                    "target": f"payload.{field}",
                    "reason": "derived output field should be present",
                })
        elif flow_context.get("mock_plan"):
            plan["assertions"].append({
                "kind": "assert-expression",
                "target": "payload",
                "reason": "flow response is derived from mocked downstream connector output",
            })
        plan["verifications"].extend([
            {
                "kind": "verify-call",
                "processor": item.get("processor", ""),
                "doc_name": item.get("doc_name") or item.get("match_value") or item.get("processor", ""),
                "reason": "side-effect connector execution is the observable behavior",
            }
            for item in (flow_context.get("mock_plan") or [])
            if item.get("action") == "verify-call"
        ])
        return plan

    def _dedupe_reusable_resource_files(
        self,
        suite_xml: str,
        resource_files: Dict[str, str],
    ) -> Tuple[str, Dict[str, str]]:
        """Reuse one generated DWL resource when another file has identical content."""
        canonical_by_content: Dict[Tuple[str, str], str] = {}
        deduped_files: Dict[str, str] = {}

        for name, content in resource_files.items():
            if not name.endswith(".dwl"):
                deduped_files[name] = content
                continue

            category = self._resource_dedupe_category(name)
            canonical = canonical_by_content.get((category, content))
            if canonical:
                suite_xml = self._replace_resource_reference(suite_xml, name, canonical)
                continue

            canonical_by_content[(category, content)] = name
            deduped_files[name] = content

        return suite_xml, deduped_files

    def _resource_dedupe_category(self, name: str) -> str:
        """Dedupe identical resources within the same semantic category."""
        if name.startswith("set-event_payload") or name.startswith("set_event_payload"):
            return "set-event-payload"
        if name.startswith("set-event_attributes") or name.startswith("set_event_attributes"):
            return "set-event-attributes"
        if name.startswith("mock_") and name.endswith("_variables.dwl"):
            # Keep variable resource names stable. The XML variable expressions
            # reference the exact scenario-specific file path.
            return f"mock-variables:{name}"
        if name.startswith("mock_") and name.endswith("_attributes.dwl"):
            return "mock-attributes"
        if name.startswith("mock_"):
            return "mock-payload"
        if name.startswith("assert_") or name.startswith("assert-expression"):
            return "assertion"
        return "other"

    def _replace_resource_reference(self, suite_xml: str, old_name: str, canonical_name: str) -> str:
        """Update resource-file and extensionless module references after dedupe."""
        suite_xml = suite_xml.replace(old_name, canonical_name)
        if old_name.endswith(".dwl") and canonical_name.endswith(".dwl"):
            old_module = old_name.rsplit(".", 1)[0]
            canonical_module = canonical_name.rsplit(".", 1)[0]
            suite_xml = suite_xml.replace(old_module, canonical_module)
        return suite_xml

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

            for branch_index, branch in enumerate(branch_points[:6], start=1):
                if branch.get("type") == "otherwise":
                    continue
                if branch.get("terminates_with_error"):
                    scenario_name = self._branch_error_scenario_name(branch, branch_index)
                    planned.append({
                        "name": scenario_name,
                        "type": "validation_error",
                        "description": branch.get("description") or f"Choice branch {branch_index} raises an error",
                        "branch_condition": branch.get("condition", ""),
                        "assertion_strategy": "expected_error",
                        "expected_error_type": branch.get("expected_error_type") or "VALIDATION:INVALID_BOOLEAN",
                        "terminates_with_error": True,
                    })
                    continue
                planned.append({
                    "name": f"branch_{branch_index}",
                    "type": "branch_path",
                    "description": branch.get("description") or f"Choice branch {branch_index}",
                    "branch_condition": branch.get("condition", ""),
                    "assertion_strategy": "payload_equals_expected",
                })

            for dynamic_ref in (flow_context.get("dynamic_flow_refs") or [])[:4]:
                for candidate_index, candidate in enumerate((dynamic_ref.get("candidates") or [])[:4], start=1):
                    target_flow = candidate.get("flow")
                    if not target_flow:
                        continue
                    planned.append({
                        "name": f"dynamic_{self._slugify(target_flow)}",
                        "type": "branch_path",
                        "description": (
                            f"Dynamic flow-ref {dynamic_ref.get('doc_name') or dynamic_ref.get('expression')} "
                            f"routes to {target_flow}"
                        ),
                        "branch_condition": candidate.get("condition", ""),
                        "dynamic_flow_ref": dynamic_ref.get("expression", ""),
                        "dynamic_target_flow": target_flow,
                        "assertion_strategy": "payload_equals_expected",
                    })

            for item in mock_plan[:2]:
                shape = item.get("result_shape", "object")
                if shape not in {"array", "object", "affectedRows"}:
                    continue
                if not self._should_plan_empty_downstream_scenario(item):
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
                expected_error_type = self._error_type_for_processor(processor)
                assertion_strategy = (
                    self._error_handler_assertion_strategy(flow_context, expected_error_type)
                    if has_error_handler
                    else "expected_error"
                )
                planned.append({
                    "name": f"{self._slugify(item.get('doc_name') or processor)}_failure",
                    "type": "downstream_failure",
                    "description": f"{item.get('doc_name') or processor} failure path",
                    "failed_processor": processor,
                    "failed_match_value": item.get("match_value") or item.get("doc_name"),
                    "expected_error_type": expected_error_type,
                    "assertion_strategy": assertion_strategy,
                    "verify_error_handler": has_error_handler,
                })

        return self._dedupe_scenarios(planned)

    def _branch_error_scenario_name(self, branch: Dict[str, Any], branch_index: int) -> str:
        """Name branch error tests from the actual validation/raise-error action."""
        candidates = [
            (branch.get("raise_error") or {}).get("doc_name"),
            (branch.get("validation_failure") or {}).get("doc_name"),
            branch.get("description"),
        ]
        for candidate in candidates:
            slug = self._slugify(candidate or "")
            if slug and slug not in {"flow", "when", "otherwise"} and not slug.startswith("when-branch"):
                return slug
        return f"branch-{branch_index}-raises-error"

    def _should_plan_empty_downstream_scenario(self, mock_item: Dict[str, Any]) -> bool:
        """Only generate empty-result scenarios when the downstream transform can plausibly handle them."""
        shape = mock_item.get("result_shape", "object")
        if shape in {"array", "affectedRows"}:
            return True
        if mock_item.get("processor") == "http:request" and mock_item.get("downstream_dwl_excerpt"):
            return False
        script = mock_item.get("downstream_dwl_excerpt") or ""
        if not script:
            return True
        risky_patterns = [
            r"\bpayload\.[A-Za-z_][A-Za-z0-9_-]*\.",
            r"\bpayload\.[A-Za-z_][A-Za-z0-9_-]*\s*\[",
        ]
        return not any(re.search(pattern, script) for pattern in risky_patterns)

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

    def _error_handler_assertion_strategy(
        self,
        flow_context: Dict[str, Any],
        expected_error_type: str = "",
    ) -> str:
        """Use payload assertions only when a matching continue handler consumes the error."""
        for handler in flow_context.get("error_handler_details", []) or []:
            handler_error_type = handler.get("error_type") or handler.get("match_type") or ""
            if (
                handler_error_type
                and expected_error_type
                and not self._handler_matches_error_type(handler_error_type, expected_error_type)
            ):
                continue
            handler_kind = str(handler.get("type") or "").lower()
            if "on-error-continue" in handler_kind and self._error_handler_has_response_logic(handler):
                return "error_handler_response"
        return "expected_error"

    def _error_handler_has_response_logic(self, handler: Dict[str, Any]) -> bool:
        if handler.get("dwl_excerpt") or handler.get("dwl_excerpts"):
            return True

        response_processors = {
            "ee:transform",
            "transform",
            "set-payload",
        }
        for processor in handler.get("processors", []) or []:
            processor_type = processor.get("type") or ""
            if processor_type in response_processors:
                return True
            if processor_type.endswith(":transform") or processor_type.endswith(":set-payload"):
                return True
            if processor.get("dwl_excerpt"):
                return True
        return False

    def _error_handler_has_only_verifiable_side_effects(self, flow_context: Dict[str, Any]) -> bool:
        """Return True when error handlers do work like logging but do not build a response."""
        handlers = flow_context.get("error_handler_details", []) or []
        if not handlers:
            return False
        has_verifiable = False
        for handler in handlers:
            if self._error_handler_has_response_logic(handler):
                return False
            if self._error_handler_verification_plan({"error_handler_details": [handler]}):
                has_verifiable = True
        return has_verifiable

    def _error_handler_verification_plan(self, flow_context: Dict[str, Any]) -> List[Dict[str, str]]:
        """Return processors in error handlers that should be validated with verify-call."""
        verifiable_processors = {
            "logger",
            "anypoint-mq:publish",
            "kafka:producer",
            "email:send",
            "sftp:write",
            "file:write",
            "jms:publish",
            "vm:publish",
            "objectstore:store",
            "objectstore:remove",
        }
        verifications: List[Dict[str, str]] = []
        seen = set()
        for handler in flow_context.get("error_handler_details", []) or []:
            for processor in handler.get("processors", []) or []:
                processor_type = processor.get("type") or ""
                if processor_type not in verifiable_processors:
                    continue
                doc_name = processor.get("doc_name") or processor_type
                key = (processor_type, doc_name)
                if key in seen:
                    continue
                seen.add(key)
                verifications.append({
                    "kind": "verify-call",
                    "processor": processor_type,
                    "doc_name": doc_name,
                    "reason": "error handler side effect is the observable behavior",
                })
        return verifications

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

        referenced_resources = self._extract_munit_resource_references(suite_xml)
        generated_prefix = f"{resource_folder}/"
        resource_contents = metadata.get("resource_files") or {}
        missing_resources: List[str] = []
        for reference in referenced_resources:
            if not reference.startswith(generated_prefix):
                continue
            referenced_path = self.output_dir / "src" / "test" / "resources" / reference
            relative_name = reference[len(generated_prefix):]
            if not referenced_path.is_file() and relative_name in resource_contents:
                referenced_path.parent.mkdir(parents=True, exist_ok=True)
                referenced_path.write_text(resource_contents[relative_name], encoding="utf-8")
            if not referenced_path.is_file():
                import logging
                logging.getLogger(__name__).warning(
                    "Generated MUnit references an unavailable resource: %s",
                    reference,
                )
                missing_resources.append(reference)
                continue
            paths.setdefault(reference, str(referenced_path))

        if missing_resources:
            paths["missing_resource_references"] = ", ".join(sorted(missing_resources))

        paths["suite_file_maven"] = str(suite_path)
        return paths

    def _build_test(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        *,
        used_test_names: Optional[set] = None,
        sample_payload: Optional[str],
        connector_samples: Dict[str, Dict[str, str]],
        recorder_style: bool,
        enabled_flow_sources: Optional[List[str]] = None,
    ) -> Tuple[str, Dict[str, str]]:
        target_flow = flow_context.get("target_flow", "main-flow")
        scenario_slug = self._slugify(scenario.get("name") or scenario.get("type") or f"scenario-{index}")
        resource_suffix = self._resource_suffix_for_scenario(scenario, index)
        test_name = self._unique_test_name(
            f"{self._slugify(target_flow)}-{scenario_slug}-test",
            used_test_names,
        )
        description = scenario.get("description", f"{scenario_slug} for {target_flow}")

        resource_files: Dict[str, str] = {}

        set_event_xml, set_files = self._build_set_event(
            flow_context,
            scenario,
            resource_folder,
            index,
            resource_suffix,
            sample_payload=sample_payload,
        )
        resource_files.update(set_files)

        mock_parts, mock_files = self._build_mocks(
            flow_context,
            scenario,
            resource_folder,
            index,
            resource_suffix,
            connector_samples=connector_samples,
        )
        resource_files.update(mock_files)
        spy_parts = self._build_spies(flow_context, scenario)

        validation_xml, assert_files = self._build_validation(
            flow_context,
            scenario,
            resource_folder,
            index,
            resource_suffix,
            recorder_style=recorder_style,
            sample_payload=sample_payload if not self._scenario_expects_thrown_error(scenario) else None,
            connector_samples=connector_samples,
        )
        verify_xml = self._build_verify_calls(flow_context, scenario)
        if verify_xml:
            validation_xml = f"{validation_xml}\n{verify_xml}" if validation_xml else verify_xml
        resource_files.update(assert_files)

        expected_error = ""
        if self._scenario_expects_thrown_error(scenario):
            expected_error = f' expectedErrorType="{self._xml_escape(self._expected_error_type(scenario))}"'

        behavior_body = "\n".join(mock_parts + spy_parts)
        behavior_xml = (
            f"""        <munit:behavior>
{behavior_body}
        </munit:behavior>
"""
            if behavior_body.strip()
            else ""
        )
        validation_xml = validation_xml.strip()
        validation_section = (
            f"""        <munit:validation>
{validation_xml}
        </munit:validation>
"""
            if validation_xml
            else ""
        )

        enable_flow_sources_xml = self._render_enable_flow_sources(enabled_flow_sources or [])
        test_xml = f"""    <munit:test name="{test_name}" description="{self._xml_escape(description)}"{expected_error}>
{enable_flow_sources_xml}{behavior_xml}        <munit:execution>
{set_event_xml}
            <flow-ref doc:name="Execute {self._xml_escape(target_flow)}" name="{self._xml_escape(target_flow)}"/>
        </munit:execution>
{validation_section}    </munit:test>"""

        return test_xml, resource_files

    def _build_spies(self, flow_context: Dict[str, Any], scenario: Dict[str, Any]) -> List[str]:
        """Render conservative spies for DataWeave processors on non-error scenarios."""
        if scenario.get("type") in {"downstream_failure", "downstream_api_failure", "error_scenario", "validation_error", "invalid_input", "empty_payload"}:
            return []
        if flow_context.get("mock_plan"):
            return []
        parts: List[str] = []
        for item in self._build_spy_plan(flow_context):
            processor = item.get("processor", "")
            match_attr = item.get("match_attribute", "doc:name")
            match_value = item.get("match_value") or item.get("doc_name") or processor
            doc_name = item.get("doc_name") or processor
            parts.append(
                f"""            <munit-tools:spy doc:name="Spy {self._xml_escape(doc_name)}" processor="{self._xml_escape(processor)}">
                <munit-tools:with-attributes>
                    <munit-tools:with-attribute attributeName="{self._xml_escape(match_attr)}" whereValue="{self._xml_escape(match_value)}"/>
                </munit-tools:with-attributes>
                <munit-tools:after-call>
                    <munit-tools:assert-that
                        doc:name="Assert {self._xml_escape(doc_name)} output"
                        expression="#[payload]"
                        is="#[MunitTools::notNullValue()]"
                        message="DataWeave output should be present"/>
                </munit-tools:after-call>
            </munit-tools:spy>"""
            )
        return parts

    def _build_set_event(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        resource_suffix: str,
        *,
        sample_payload: Optional[str],
    ) -> Tuple[str, Dict[str, str]]:
        plan = dict(flow_context.get("set_event_plan") or {})
        plan = self._apply_scenario_to_set_event_plan(plan, scenario)
        files: Dict[str, str] = {}

        if sample_payload:
            payload_file = f"set_event_payload_{resource_suffix}.dwl"
            attrs_file = f"set_event_attributes_{resource_suffix}.dwl"
            payload_dwl, attrs_dwl = self._split_sample_payload(sample_payload, plan, scenario=scenario)
            files[payload_file] = self._sanitize_set_event_payload_resource_content(payload_dwl)
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

        payload_file = f"set_event_payload_{resource_suffix}.dwl"
        attrs_file = f"set_event_attributes_{resource_suffix}.dwl"
        payload_dwl = self._plan_to_payload_dwl(plan)
        use_inline_empty_payload = (
            self._should_inline_empty_request_payload(plan, payload_dwl)
            and scenario.get("type") not in {"validation_error", "invalid_input", "empty_payload"}
        )
        if not use_inline_empty_payload:
            files[payload_file] = self._sanitize_set_event_payload_resource_content(payload_dwl)
        files[attrs_file] = self._plan_to_attributes_dwl(plan)
        payload_media_type = self._infer_resource_media_type(payload_dwl, plan.get("payload_media_type"))
        attributes_media_type = self._infer_attributes_media_type(files[attrs_file])
        payload_xml = (
            f"""                <munit:payload value="#['']" mediaType="{payload_media_type}"/>"""
            if use_inline_empty_payload
            else f"""                <munit:payload value="#[MunitTools::getResourceAsString('{resource_folder}/{payload_file}')]" mediaType="{payload_media_type}" encoding="UTF-8"/>"""
        )

        return (
            f"""            <munit:set-event doc:name="Set Input">
{payload_xml}
                <munit:attributes value="#[read(MunitTools::getResourceAsString('{resource_folder}/{attrs_file}'), 'application/json')]" mediaType="{attributes_media_type}"/>
            </munit:set-event>""",
            files,
        )

    def _should_inline_empty_request_payload(self, plan: Dict[str, Any], payload_dwl: str) -> bool:
        """Avoid creating empty payload sidecar files for request methods without bodies."""
        attrs = plan.get("attributes_template") or {}
        method = (attrs.get("method") or "").upper()
        if method not in {"GET", "DELETE", "HEAD", "OPTIONS"}:
            return False

        payload_expression = plan.get("payload_expression")
        if payload_expression not in {'""', None}:
            return False

        return payload_dwl.strip() in {'"" as Binary {base: "64"}', '""'}

    def _build_mocks(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        resource_suffix: str,
        *,
        connector_samples: Dict[str, Dict[str, str]],
    ) -> Tuple[List[str], Dict[str, str]]:
        parts: List[str] = []
        files: Dict[str, str] = {}
        mock_plan = self._dedupe_mock_plan(flow_context.get("mock_plan", []) or [])
        scenario_type = scenario.get("type", "happy_path")

        if scenario.get("terminates_with_error") or scenario_type in {"empty_payload", "invalid_input", "validation_error"}:
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

            if scenario_type in {"downstream_failure", "downstream_api_failure", "error_scenario"}:
                if not self._is_failed_mock_for_scenario(item, scenario):
                    continue
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
                break

            mock_file = f"mock_{self._slugify(doc_name)}_{resource_suffix}_{mock_index}.dwl"
            sample = connector_samples.get(self._connector_sample_key(flow_context.get("target_flow", ""), item), {})
            if processor == "flow-ref" or item.get("external_dependency"):
                then_return_xml, return_files = self._build_external_flow_ref_return(
                    item,
                    scenario,
                    scenario_type,
                    flow_context,
                    sample,
                    resource_folder,
                    resource_suffix,
                    mock_index,
                )
                files.update(return_files)
                parts.append(
                    f"""            <munit-tools:mock-when doc:name="Mock {self._xml_escape(doc_name)}" processor="{processor}">
                <munit-tools:with-attributes>
                    <munit-tools:with-attribute attributeName="{self._xml_escape(match_attr)}" whereValue="{self._xml_escape(match_value)}"/>
                </munit-tools:with-attributes>{then_return_xml}
            </munit-tools:mock-when>"""
                )
                continue

            mock_body = self._build_mock_payload_dwl(item, scenario_type, flow_context, sample=sample, scenario=scenario)
            files[mock_file] = mock_body
            mock_media_type = self._infer_resource_media_type(
                mock_body,
                sample.get("media_type") or item.get("media_type"),
            )
            attrs = item.get("return_attributes") or {"statusCode": 200}
            attrs_file = f"mock_{self._slugify(doc_name)}_{resource_suffix}_{mock_index}_attributes.dwl"
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

    def _build_external_flow_ref_return(
        self,
        item: Dict[str, Any],
        scenario: Dict[str, Any],
        scenario_type: str,
        flow_context: Dict[str, Any],
        sample: Dict[str, Any],
        resource_folder: str,
        resource_suffix: str,
        mock_index: int,
    ) -> Tuple[str, Dict[str, str]]:
        """Render the event components returned by a mocked external flow-ref."""
        files: Dict[str, str] = {}
        return_types = [
            str(value).strip()
            for value in (sample.get("return_types") or [])
            if str(value).strip()
        ]
        if not return_types:
            # Preserve behavior for old connector samples that only supplied output.
            return_types = ["payload", "attributes"]

        if "nothing" in return_types:
            return "", files

        if "error" in return_types:
            error_type = sample.get("error_type") or self._error_type_for_processor("flow-ref")
            return (
                f"""
                <munit-tools:then-return>
                    <munit-tools:error typeId="{self._xml_escape(str(error_type))}"/>
                </munit-tools:then-return>""",
                files,
            )

        children: List[str] = []
        doc_name = item.get("doc_name") or item.get("match_value") or "external-flow"
        resource_base = f"mock_{self._slugify(doc_name)}_{resource_suffix}_{mock_index}"

        if "payload" in return_types:
            payload_file = f"{resource_base}.dwl"
            payload_body = self._build_mock_payload_dwl(
                item,
                scenario_type,
                flow_context,
                sample=sample,
                scenario=scenario,
            )
            files[payload_file] = payload_body
            payload_media_type = self._infer_resource_media_type(
                payload_body,
                sample.get("media_type") or item.get("media_type"),
            )
            children.append(
                f"""                    <munit-tools:payload value="#[MunitTools::getResourceAsString('{resource_folder}/{payload_file}')]" mediaType="{payload_media_type}"/>"""
            )

        if "variables" in return_types:
            variables = self._parse_json_object(sample.get("variables"))
            if variables:
                # Returned variables belong to the mocked flow-ref, not to an
                # individual doc:name or generated scenario. Reuse one file
                # named from the actual external target flow in every test.
                external_flow_name = (
                    item.get("external_flow")
                    or item.get("match_value")
                    or doc_name
                )
                variables_file = (
                    f"mock_{self._slugify(str(external_flow_name))}_variables.dwl"
                )
                files[variables_file] = self._build_mock_resource_content(variables)
                variable_rows_list = []
                for key in variables:
                    variable_expression = (
                        f"#[read(MunitTools::getResourceAsString('{resource_folder}/{variables_file}'), "
                        f"'application/json')[{json.dumps(str(key))}]]"
                    )
                    variable_rows_list.append(
                        f"""                            <munit-tools:variable key="{self._xml_escape(str(key))}" value="{self._xml_escape(variable_expression)}"/>"""
                    )
                variable_rows = "\n".join(variable_rows_list)
                children.append(
                    f"""                    <munit-tools:variables>
{variable_rows}
                    </munit-tools:variables>"""
                )

        if "attributes" in return_types:
            attributes = self._parse_json_object(sample.get("return_attributes"))
            if not attributes:
                attributes = item.get("return_attributes") or {"statusCode": 200}
            attributes_file = f"{resource_base}_attributes.dwl"
            files[attributes_file] = self._build_mock_resource_content(attributes)
            attributes_media_type = self._infer_attributes_media_type(files[attributes_file])
            children.append(
                f"""                    <munit-tools:attributes value="#[read(MunitTools::getResourceAsString('{resource_folder}/{attributes_file}'), 'application/json')]" mediaType="{attributes_media_type}"/>"""
            )

        if not children:
            return "", files
        return (
            "\n                <munit-tools:then-return>\n"
            + "\n".join(children)
            + "\n                </munit-tools:then-return>",
            files,
        )

    @staticmethod
    def _parse_json_object(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        text = str(value or "").strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _build_verify_calls(self, flow_context: Dict[str, Any], scenario: Dict[str, Any]) -> str:
        """Generate validation-time verify-call blocks for side-effect connectors."""
        parts = []
        error_scenario = scenario.get("type") in {
            "downstream_failure",
            "downstream_api_failure",
            "error_scenario",
            "validation_error",
            "invalid_input",
            "empty_payload",
        }

        if not error_scenario:
            for item in self._dedupe_mock_plan(flow_context.get("mock_plan", []) or []):
                if item.get("action") != "verify-call":
                    continue
                parts.append(self._verify_call_xml(
                    item.get("processor", ""),
                    item.get("doc_name") or item.get("match_value") or item.get("processor", ""),
                    item.get("match_attribute", "doc:name"),
                    item.get("match_value") or item.get("doc_name") or item.get("processor", ""),
                ))

        if scenario.get("verify_error_handler"):
            parts.extend(self._build_error_handler_verify_calls(flow_context, scenario))
        return "\n".join(parts)

    def _build_error_handler_verify_calls(self, flow_context: Dict[str, Any], scenario: Optional[Dict[str, Any]] = None) -> List[str]:
        """Verify side-effect processors that are actually implemented in error handlers."""
        verifiable_processors = {
            "logger",
            "anypoint-mq:publish",
            "kafka:producer",
            "email:send",
            "sftp:write",
            "file:write",
            "jms:publish",
            "vm:publish",
            "objectstore:store",
            "objectstore:remove",
        }
        parts: List[str] = []
        seen = set()
        expected_error_type = self._expected_error_type(scenario or {})
        for handler in flow_context.get("error_handler_details", []) or []:
            handler_type = handler.get("error_type") or handler.get("match_type") or handler.get("type") or ""
            if handler.get("error_type") and expected_error_type and not self._handler_matches_error_type(handler_type, expected_error_type):
                continue
            for processor in handler.get("processors", []) or []:
                processor_type = processor.get("type") or ""
                if processor_type not in verifiable_processors:
                    continue
                doc_name = processor.get("doc_name") or processor_type
                key = (processor_type, doc_name)
                if key in seen:
                    continue
                seen.add(key)
                parts.append(self._verify_call_xml(processor_type, doc_name, "doc:name", doc_name))
        return parts

    def _handler_matches_error_type(self, handler_type: str, expected_error_type: str) -> bool:
        """Return True when an error-handler type declaration can catch expected_error_type."""
        if not handler_type or handler_type == "ANY":
            return not handler_type or expected_error_type == "ANY"
        expected = (expected_error_type or "").strip()
        for candidate in re.split(r"\s*,\s*", handler_type):
            candidate = candidate.strip()
            if candidate == expected:
                return True
            if candidate == "ANY":
                return True
            if ":" in candidate and ":" in expected:
                candidate_ns, candidate_id = candidate.split(":", 1)
                expected_ns, expected_id = expected.split(":", 1)
                if candidate_ns == expected_ns and candidate_id == expected_id:
                    return True
        return False

    def _verify_call_xml(self, processor: str, doc_name: str, match_attr: str, match_value: str) -> str:
        return f"""            <munit-tools:verify-call doc:name="Verify {self._xml_escape(doc_name)}" processor="{processor}" times="1">
                <munit-tools:with-attributes>
                    <munit-tools:with-attribute attributeName="{match_attr}" whereValue="{self._xml_escape(match_value)}"/>
                </munit-tools:with-attributes>
            </munit-tools:verify-call>"""

    def _build_validation(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        resource_folder: str,
        index: int,
        resource_suffix: str,
        *,
        recorder_style: bool,
        sample_payload: Optional[str],
        connector_samples: Dict[str, Dict[str, str]],
    ) -> Tuple[str, Dict[str, str]]:
        files: Dict[str, str] = {}
        validation_plan = self._validation_plan_for_scenario(
            flow_context,
            scenario,
            sample_payload=sample_payload,
            connector_samples=connector_samples,
        )
        assertions = validation_plan.get("assertions", []) or []

        if any(item.get("kind") == "assert-expression" for item in assertions):
            if scenario.get("type") in {"downstream_failure", "downstream_api_failure", "error_scenario"}:
                assert_file = f"assert_expression_payload_{resource_suffix}.dwl"
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

            assert_file = f"assert_expression_payload_{resource_suffix}.dwl"
            assert_dwl = self._build_assert_dwl(
                flow_context,
                sample_payload,
                recorder_style,
                connector_samples=connector_samples,
                scenario=scenario,
            )
            files[assert_file] = assert_dwl
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

        if assertions:
            expected = self._expected_output_for_validation(
                flow_context,
                scenario,
                sample_payload,
                connector_samples,
            )
            return "\n".join(
                self._assert_that_xml(assertion, scenario, expected)
                for assertion in assertions
                if assertion.get("kind") == "assert-that"
            ), files

        return "", files

    def _expected_output_for_validation(
        self,
        flow_context: Dict[str, Any],
        scenario: Dict[str, Any],
        sample_payload: Optional[str],
        connector_samples: Dict[str, Dict[str, str]],
    ) -> Any:
        if scenario.get("type") == "empty_downstream_response":
            return self._expected_empty_downstream_output(flow_context, scenario)
        expected = self._expected_output_from_sample(sample_payload)
        if expected is not None:
            return expected
        return self._expected_output_from_flow(flow_context, connector_samples or {})

    def _assert_that_xml(self, assertion: Dict[str, Any], scenario: Dict[str, Any], expected: Any) -> str:
        target = assertion.get("target") or "payload"
        matcher = assertion.get("matcher") or ""
        doc_name = self._assert_doc_name(assertion, scenario)
        message = assertion.get("reason") or "Validation failed"
        is_expr = self._assert_matcher_expression(target, matcher, scenario, expected)
        return f"""            <munit-tools:assert-that
                doc:name="{self._xml_escape(doc_name)}"
                expression="#[{self._xml_escape(target)}]"
                is="#[{is_expr}]"
                message="{self._xml_escape(message)}"/>"""

    def _assert_doc_name(self, assertion: Dict[str, Any], scenario: Dict[str, Any]) -> str:
        target = assertion.get("target") or "payload"
        if target == "error.errorType.identifier":
            return "Assert error type"
        if target.startswith("payload."):
            return f"Assert {target.split('.', 1)[1]}"
        if target.startswith("attributes."):
            return f"Assert {target.split('.', 1)[1]}"
        return f"Assert {scenario.get('name') or target}"

    def _assert_matcher_expression(
        self,
        target: str,
        matcher: str,
        scenario: Dict[str, Any],
        expected: Any,
    ) -> str:
        if matcher == "matchesRegex":
            return "MunitTools::matchesRegex('^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$')"
        if matcher == "notNullValue":
            return "MunitTools::notNullValue()"
        if target == "error.errorType.identifier":
            expected_type = self._expected_error_type(scenario).split(":")[-1]
            if scenario.get("type") in {"empty_payload", "invalid_input", "validation_error"}:
                return f"MunitTools::equalTo('{self._xml_escape(expected_type)}')"
            return "MunitTools::notNullValue()"

        expected_value = self._expected_value_for_target(target, expected)
        if expected_value is not None and not isinstance(expected_value, (dict, list)):
            return f"MunitTools::equalTo({self._dwl_literal(expected_value)})"
        return "MunitTools::notNullValue()"

    def _expected_value_for_target(self, target: str, expected: Any) -> Any:
        if target == "payload":
            return expected
        if target.startswith("payload.") and isinstance(expected, dict):
            return self._resolve_path(expected, target.split(".", 1)[1])
        return None

    def _dwl_literal(self, value: Any) -> str:
        if isinstance(value, str):
            return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
        if value is True:
            return "true"
        if value is False:
            return "false"
        if value is None:
            return "null"
        return json.dumps(value)

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
        dynamic_fields = self._dynamic_output_fields(flow_context)
        if isinstance(expected, dict):
            dynamic_fields.update(self._dynamic_fields_from_expected(expected))
        if dynamic_fields and isinstance(expected, dict):
            return self._build_hybrid_assert_module_content(expected, dynamic_fields)
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

    def _build_hybrid_assert_module_content(self, expected: Dict[str, Any], dynamic_fields: Dict[str, str]) -> str:
        """Build field-level assertions when some response fields are non-deterministic."""
        lines = [
            "%dw 2.0",
            "import * from dw::test::Asserts",
            "fun main(vars: Object) = do {",
            "  var payload = vars.payload",
            "  ---",
            "  [",
        ]
        checks: List[str] = []
        for field, value in expected.items():
            field_ref = f"payload.{field}"
            if field in dynamic_fields:
                reason = dynamic_fields[field]
                if reason == "uuid":
                    checks.append(
                        f"    ({field_ref} as String) must match(/^([0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}})$/)"
                    )
                else:
                    checks.append(f"    {field_ref} must notNullValue()")
                continue
            expected_literal = json.dumps(value)
            checks.append(f"    {field_ref} must equalTo({expected_literal})")

        if not checks:
            checks.append("    payload must notNullValue()")
        lines.append(",\n".join(checks))
        lines.extend([
            "  ]",
            "}\n",
        ])
        return "\n".join(lines)

    def _dynamic_output_fields(self, flow_context: Dict[str, Any]) -> Dict[str, str]:
        """Return output fields generated from runtime-unstable expressions."""
        script = self._final_transform_script(flow_context)
        if not script:
            return {}
        body = script.split("---", 1)[1] if "---" in script else script
        dynamic: Dict[str, str] = {}
        for field, expression in self._parse_dwl_object_fields(body):
            if field in {"output", "ns", "import"}:
                continue
            reason = self._dynamic_expression_reason(field, expression)
            if reason:
                dynamic[field] = reason
        return dynamic

    def _dynamic_fields_from_expected(self, expected: Dict[str, Any]) -> Dict[str, str]:
        """Treat runtime-shaped sample fields as flexible even without DWL context."""
        dynamic: Dict[str, str] = {}
        for field, value in expected.items():
            reason = self._dynamic_expression_reason(field, str(value))
            if reason:
                dynamic[field] = reason
        return dynamic

    def _dynamic_expression_reason(self, field: str, expression: str) -> str:
        """Classify expressions whose result should not be exact-equality asserted."""
        text = (expression or "").lower()
        field_lower = (field or "").lower()
        if re.search(r"\buuid\s*\(", text):
            return "uuid"
        if re.search(r"\b(?:now|currentdatetime|currentdate|currenttime)\s*\(", text):
            return "datetime"
        if re.search(r"\b(?:random|randomint|randomuuid)\s*\(", text):
            return "random"
        if any(token in text for token in ("correlationid", "event.id", "message.id")):
            return "runtime-id"
        if "${secure::" in text or "secure::" in text:
            return "secret"
        if re.search(r"\$\{[^}]+\}", text):
            return "property"
        if any(token in field_lower for token in ("uuid", "correlation", "timestamp", "datetime", "date", "token", "secret", "nonce", "otp")):
            return "dynamic-field"
        return ""

    def _split_sample_payload(
        self,
        sample_payload: str,
        plan: Dict[str, Any],
        *,
        scenario: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str]:
        """Split user sample into payload + attributes DWL files."""
        text = sample_payload.strip()
        request_obj: Any = {}
        response_obj: Any = {}

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                request_obj = (
                    parsed.get("request")
                    or parsed.get("input")
                    or parsed.get("requestPayload")
                    or parsed.get("inputPayload")
                    or {}
                )
                response_obj = (
                    parsed.get("response")
                    or parsed.get("output")
                    or parsed.get("expectedResponse")
                    or parsed.get("expected")
                    or parsed
                )
                if not request_obj and any(key in parsed for key in ("payload", "body", "attributes", "headers", "queryParams", "uriParams", "method", "requestPath", "path")):
                    request_obj = parsed
                elif not request_obj and not any(key in parsed for key in ("response", "output", "expectedResponse", "expected")):
                    request_obj = {"payload": parsed}
            elif isinstance(parsed, list):
                request_obj = {"payload": parsed}
                response_obj = {}
        except json.JSONDecodeError:
            request_obj = {"payload": text}
            response_obj = {"status": "SUCCESS"}

        if not request_obj:
            request_obj = {}

        if scenario and scenario.get("type") in {"branch_path", "validation_error", "invalid_input", "empty_payload"}:
            request_obj = self._apply_scenario_to_sample_request(request_obj, scenario)

        payload_obj = self._sample_request_payload(request_obj)
        payload_obj = self._unwrap_recorder_payload_if_needed(payload_obj)
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

    def _apply_scenario_to_sample_request(self, request_obj: Any, scenario: Dict[str, Any]) -> Any:
        """Apply branch/invalid scenario input mutations to a user recorder sample."""
        if not isinstance(request_obj, dict):
            return request_obj

        adjusted = json.loads(json.dumps(request_obj))
        payload_obj = self._sample_request_payload(adjusted)
        if isinstance(payload_obj, dict):
            payload_obj = json.loads(json.dumps(payload_obj))
        else:
            payload_obj = {}

        condition = scenario.get("branch_condition", "")
        for source, field, value in self._extract_condition_equalities(condition):
            if source == "attributes.queryParams":
                adjusted.setdefault("queryParams", {})[field] = value
            elif source == "attributes.headers":
                adjusted.setdefault("headers", {})[field] = value
            elif source == "attributes.uriParams":
                adjusted.setdefault("uriParams", {})[field] = value
            elif source == "payload":
                payload_obj[field] = value

        for field in self._payload_null_fields_for_condition(condition):
            payload_obj.pop(field, None)
        for field, value in self._payload_overrides_for_condition(condition).items():
            payload_obj[field] = value

        if scenario.get("type") == "empty_payload":
            payload_obj = ""
        elif scenario.get("type") in {"validation_error", "invalid_input"} and not scenario.get("terminates_with_error"):
            if payload_obj:
                first_key = next(iter(payload_obj))
                payload_obj.pop(first_key, None)
            else:
                payload_obj = {}

        adjusted["payload"] = payload_obj
        return adjusted

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

    def _unwrap_recorder_payload_if_needed(self, payload_obj: Any) -> Any:
        """Prevent the full recorder sample wrapper from being written as set-event payload."""
        if not isinstance(payload_obj, dict):
            return payload_obj
        if "request" in payload_obj or "input" in payload_obj:
            request_obj = payload_obj.get("request") or payload_obj.get("input") or {}
            return self._sample_request_payload(request_obj)
        if "payload" in payload_obj and any(
            key in payload_obj for key in ("response", "output", "expectedResponse", "expected")
        ):
            return payload_obj.get("payload")
        return payload_obj

    def _sanitize_set_event_payload_resource_content(self, content: str) -> str:
        """Last-resort guard: set-event payload resources must contain only request payload."""
        text = (content or "").strip()
        if not text:
            return content

        parsed: Any
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return content

        # Handle doubly encoded JSON strings defensively.
        if isinstance(parsed, str):
            try:
                parsed = json.loads(parsed)
            except json.JSONDecodeError:
                return content

        unwrapped = self._unwrap_recorder_payload_if_needed(parsed)
        if unwrapped is parsed:
            return content
        return self._build_raw_resource_content(unwrapped)

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
        for key, expression in self._parse_dwl_object_fields(body):
            if key in {"output", "ns", "import"}:
                continue
            expected[key] = self._value_from_dwl_expression(expression, key, sample_context)
        return expected

    def _parse_dwl_object_fields(self, body: str) -> List[Tuple[str, str]]:
        """Parse top-level fields from a DWL object body, preserving nested expressions."""
        object_body = self._unwrap_dwl_collection(body, "{", "}")
        if object_body is None:
            return []

        fields: List[Tuple[str, str]] = []
        for part in self._split_top_level(object_body, ","):
            if ":" not in part:
                continue
            key, expression = self._split_key_value(part)
            if not key:
                continue
            fields.append((key, expression.strip()))
        return fields

    def _split_key_value(self, text: str) -> Tuple[str, str]:
        """Split a DWL object field at the first top-level colon."""
        depth = 0
        quote = ""
        escape = False
        for index, char in enumerate(text):
            if quote:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == quote:
                    quote = ""
                continue
            if char in {"'", '"'}:
                quote = char
                continue
            if char in "{[(":
                depth += 1
            elif char in "}])" and depth > 0:
                depth -= 1
            elif char == ":" and depth == 0:
                key = text[:index].strip().strip("'\"")
                return key, text[index + 1:]
        return "", text

    def _unwrap_dwl_collection(self, text: str, open_char: str, close_char: str) -> Optional[str]:
        """Return content inside the first balanced top-level DWL collection."""
        candidate = (text or "").strip().rstrip(",")
        start = candidate.find(open_char)
        if start < 0:
            return None
        depth = 0
        quote = ""
        escape = False
        for index in range(start, len(candidate)):
            char = candidate[index]
            if quote:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == quote:
                    quote = ""
                continue
            if char in {"'", '"'}:
                quote = char
                continue
            if char == open_char:
                depth += 1
            elif char == close_char:
                depth -= 1
                if depth == 0:
                    return candidate[start + 1:index]
        return None

    def _split_top_level(self, text: str, delimiter: str) -> List[str]:
        """Split text by delimiter while ignoring nested braces, brackets, parens, and strings."""
        parts: List[str] = []
        start = 0
        depth = 0
        quote = ""
        escape = False
        for index, char in enumerate(text or ""):
            if quote:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == quote:
                    quote = ""
                continue
            if char in {"'", '"'}:
                quote = char
                continue
            if char in "{[(":
                depth += 1
            elif char in "}])" and depth > 0:
                depth -= 1
            elif char == delimiter and depth == 0:
                part = text[start:index].strip()
                if part:
                    parts.append(part)
                start = index + 1
        tail = (text or "")[start:].strip()
        if tail:
            parts.append(tail)
        return parts

    def _value_from_dwl_expression(
        self,
        expression: str,
        output_field: str,
        sample_context: Dict[str, Any],
    ) -> Any:
        expression = expression.strip().rstrip(",")
        if expression.startswith("(") and expression.endswith(")"):
            expression = expression[1:-1].strip()

        if expression.startswith("{"):
            return self._expected_object_from_dwl_body(expression, sample_context)

        if expression.startswith("["):
            array_body = self._unwrap_dwl_collection(expression, "[", "]")
            if array_body is not None:
                return [
                    self._value_from_dwl_expression(item, output_field, sample_context)
                    for item in self._split_top_level(array_body, ",")
                ]

        if_match = re.match(r"if\s*\((.*?)\)\s*(.*?)\s+else\s+(.*)$", expression, re.DOTALL)
        if if_match:
            return self._value_from_dwl_expression(if_match.group(2).strip(), output_field, sample_context)

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
        return _mock_value_for_field_static(field)

    def _expected_type_for_field(self, field: str) -> str:
        value = self._mock_value_for_field(field)
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        if isinstance(value, list):
            return "array"
        if isinstance(value, dict):
            return "object"
        return "string"

    def _error_type_for_processor(self, processor: str) -> str:
        if processor.startswith("db:"):
            return "DB:CONNECTIVITY"
        if processor.startswith("salesforce:"):
            return "SALESFORCE:CONNECTIVITY"
        if processor.startswith("sap:"):
            return "SAP:CONNECTIVITY"
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
        for field in self._payload_null_fields_for_condition(condition):
            payload_obj.pop(field, None)
        for field, value in self._payload_overrides_for_condition(condition).items():
            payload_obj[field] = value

        if scenario.get("type") in {"validation_error", "invalid_input"} and not scenario.get("terminates_with_error"):
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

    def _payload_null_fields_for_condition(self, condition: str) -> List[str]:
        """Return payload fields that should be absent to satisfy null checks."""
        return re.findall(r"\bpayload\.([A-Za-z_][A-Za-z0-9_-]*)\s*==\s*null", condition or "")

    def _payload_overrides_for_condition(self, condition: str) -> Dict[str, Any]:
        """Infer scenario request values from common validation branch conditions."""
        text = condition or ""
        overrides: Dict[str, Any] = {}
        numeric_ranges = re.findall(
            r"\bpayload\.([A-Za-z_][A-Za-z0-9_-]*)\s*([<>]=?)\s*(-?\d+(?:\.\d+)?)",
            text,
        )
        for field, operator, raw_value in numeric_ranges:
            value = float(raw_value) if "." in raw_value else int(raw_value)
            if operator in {">", ">="}:
                overrides[field] = value + 1
            elif operator in {"<", "<="} and field not in overrides:
                overrides[field] = value - 1
        return overrides

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

        refs = self._extract_munit_resource_references(suite_xml)
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
                "salesforce:delete", "salesforce:upsert", "salesforce:retrieve",
                "sap:synchronous-remote-function-call", "sap:send", "sap:query",
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

    def _extract_munit_resource_references(self, suite_xml: str) -> List[str]:
        """Return sidecar resource paths referenced by MunitTools::getResourceAsString."""
        normalized_xml = (suite_xml or "").replace("&quot;", '"').replace("&apos;", "'")
        refs = re.findall(
            r"MunitTools::getResourceAsString\(\s*(['\"])(.*?)\1\s*\)",
            normalized_xml,
        )
        return [path for _, path in refs if path]

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

    def _unique_test_name(self, base_name: str, used_names: Optional[set]) -> str:
        """Return a suite-local unique munit:test name."""
        if used_names is None:
            return base_name
        candidate = base_name
        suffix = 2
        while candidate in used_names:
            candidate = f"{base_name}-{suffix}"
            suffix += 1
        used_names.add(candidate)
        return candidate

    def _resource_folder_name(self, target_flow: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9]", "", target_flow or "flow")
        if clean.lower().endswith("flow"):
            clean = clean[:-4]
        if not clean:
            clean = "flow"
        return f"{clean}Flowtest"

    def _resource_suffix_for_scenario(self, scenario: Dict[str, Any], index: int) -> str:
        """Return stable, human-readable suffixes for generated DWL resources."""
        scenario_type = scenario.get("type") or ""
        name = scenario.get("name") or scenario_type or f"scenario-{index}"

        if scenario_type == "happy_path" or name in {"happy_path", "valid"}:
            return "valid"
        if scenario_type in {"empty_payload", "invalid_input", "validation_error"}:
            if name in {"validation_error", "invalid_input"}:
                return "invalid"
            base = self._slugify(name).replace("-", "_")
            if not base.startswith("invalid") and base not in {"empty_payload"}:
                base = f"invalid_{base}"
            return base or f"invalid_{index}"
        if scenario_type in {"downstream_failure", "downstream_api_failure", "error_scenario"}:
            base = self._slugify(name).replace("-", "_")
            return base or f"error_{index}"

        base = self._slugify(name).replace("-", "_")
        return base or f"scenario_{index}"

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
        "salesforce:update",
        "salesforce:delete",
        "salesforce:upsert",
        "salesforce:retrieve",
        "sap:synchronous-remote-function-call",
        "sap:send",
        "sap:query",
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
    else:
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
    field = field or ""
    normalized_field = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", field)
    lowered = re.sub(r"[^a-z0-9]+", "_", normalized_field.lower()).strip("_")
    tokens = {token for token in lowered.split("_") if token}
    compact = lowered.replace("_", "")

    if lowered in {"country", "country_name"}:
        return "India"
    if lowered in {"latitude", "lat"}:
        return 26.889278
    if lowered in {"longitude", "lon", "lng"}:
        return 75.83149
    if lowered in {"city", "city_name"}:
        return "Jaipur"
    if lowered in {"unit", "units", "temperature_unit"}:
        return "celsius"
    if lowered in {"name", "full_name", "customer_name", "account_name"} or lowered.endswith("_name"):
        return "Test Record"
    if lowered in {"first_name", "firstname"}:
        return "Test"
    if lowered in {"last_name", "lastname", "surname"}:
        return "User"
    if lowered.endswith("id") or lowered.endswith("_id") or lowered == "id" or compact.endswith("id"):
        return "MOCK-001"
    if lowered in {"email", "email_address"} or "email" in tokens:
        return "test@example.com"
    if lowered in {"status", "state"}:
        return "ACTIVE"
    if lowered in {"type", "category"}:
        return "STANDARD"
    if lowered in {"code", "state_code", "country_code"} or lowered.endswith("_code"):
        return "TEST-CODE"
    if "currency" in tokens:
        return "USD"
    if "phone" in tokens or "mobile" in tokens:
        return "+911234567890"
    if "postal" in tokens or lowered in {"zip", "zipcode", "zip_code"}:
        return "560001"
    if "date" in tokens or lowered.endswith("_date"):
        return "2026-01-01"
    if "time" in tokens or "timestamp" in tokens or lowered.endswith("_time"):
        return "2026-01-01T00:00:00Z"
    if lowered.startswith("is_") or lowered.startswith("has_") or tokens & {"active", "enabled", "disabled", "valid", "flag"}:
        return True
    if tokens & {"count", "number", "num", "qty", "quantity", "age", "limit", "offset", "page", "size", "score", "duration"}:
        return 1
    if tokens & {"amount", "price", "total", "rate", "balance", "cost", "fee", "tax"}:
        return 100.0
    if lowered in {"states", "items", "records", "results"}:
        return [{"name": "Sample", "state_code": "XX"}]
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
