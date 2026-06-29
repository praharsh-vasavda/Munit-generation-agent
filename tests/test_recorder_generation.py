import json
import re

from core.deterministic_munit_builder import DeterministicMUnitBuilder
from core.xml_analyzer import XMLAnalyzer
from core.pipeline import MultiPassGenerator
from core.prompt_builder import PromptBuilder
from munitWriter.munit_writer import MUnitWriter
from app import _analysis_fingerprint


def assert_assert_module(content, expected_fragment):
    assert content.startswith("%dw 2.0\nimport * from dw::test::Asserts\n")
    assert "payload must equalTo(" in content
    assert expected_fragment in content


def test_prompt_includes_static_analysis_compliance_policy():
    prompt = PromptBuilder(max_tokens=8000).build_prompt(
        flow_summary={
            "job_type": "REST API",
            "flows": ["apiFlow"],
            "sub_flows": [],
            "test_targets": ["apiFlow"],
            "connectors": ["http:request"],
            "transformers": [],
            "error_handlers": [],
            "http_endpoints": [],
            "flow_details": [],
        },
        scenarios=[],
        ruleset={},
        flow_context={
            "target_flow": "apiFlow",
            "target_type": "flow",
            "source_file": "api.xml",
            "execution_flows": ["apiFlow", "childFlow"],
            "execution_paths": [
                {"name": "main_path", "flows": ["apiFlow", "childFlow"], "connectors": ["http:request"]}
            ],
            "connectors": ["http:request"],
            "mock_plan": [],
        },
        document_context={"scenarios": []},
    )

    assert "DATA SECURITY AND COMPLIANCE POLICY" in prompt
    assert "Do not connect to external systems" in prompt
    assert "Live database queries" in prompt
    assert "Execution Paths:" in prompt


def test_analysis_fingerprint_changes_when_project_content_changes():
    base = {
        "xml_file": '<flow name="A"><logger message="one"/></flow>',
        "project_dwl_files": {"src/main/resources/a.dwl": "output application/json\n--- {}"},
    }
    same = {
        "xml_file": '<flow name="A"><logger message="one"/></flow>',
        "project_dwl_files": {"src/main/resources/a.dwl": "output application/json\n--- {}"},
    }
    changed_xml = {
        "xml_file": '<flow name="A"><logger message="two"/></flow>',
        "project_dwl_files": {"src/main/resources/a.dwl": "output application/json\n--- {}"},
    }
    changed_dwl = {
        "xml_file": '<flow name="A"><logger message="one"/></flow>',
        "project_dwl_files": {"src/main/resources/a.dwl": "output application/json\n--- {id: 1}"},
    }

    assert _analysis_fingerprint(base) == _analysis_fingerprint(same)
    assert _analysis_fingerprint(base) != _analysis_fingerprint(changed_xml)
    assert _analysis_fingerprint(base) != _analysis_fingerprint(changed_dwl)


def test_recorder_mode_uses_dwl_files_and_no_inline_connector_content(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "getCustomerFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {
                "method": "GET",
                "requestPath": "/abc/path",
                "queryParams": {},
            },
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
        "output_fields": ["status", "id", "name"],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert metadata["test_count"] == 3
    assert metadata["munit_plan"]["execution"]["callOnlySelectedFlow"] is True
    assert metadata["munit_plan"]["execution"]["setEventLocation"] == "execution"
    assert metadata["munit_plan"]["behavior"]["mockWhen"][0]["processor"] == "http:request"
    assert metadata["munit_plan"]["validation"][0]["assertions"][0]["kind"] == "assert-that"
    assert metadata["munit_plan"]["validation"][0]["assertions"][0]["target"] == "payload.status"
    assert metadata["scenario_plan"][1]["type"] == "empty_downstream_response"
    assert metadata["scenario_plan"][2]["type"] == "downstream_failure"
    assert metadata["preflight_validation"]["valid"] is True
    behavior_start = suite_xml.index("<munit:behavior>")
    behavior_end = suite_xml.index("</munit:behavior>")
    execution_start = suite_xml.index("<munit:execution>")
    execution_end = suite_xml.index("</munit:execution>")
    assert "<munit:set-event" not in suite_xml[behavior_start:behavior_end]
    assert "<munit:set-event" in suite_xml[execution_start:execution_end]
    assert "MunitTools::getResourceAsString('getCustomerFlowtest/mock_get-customer_1_1.dwl')" in suite_xml
    assert (
        "MunitTools::getResourceAsString('getCustomerFlowtest/mock_get-customer_1_1_attributes.dwl')"
        in suite_xml
    )
    assert "#[{'status': 200}]" not in suite_xml
    assert "#[{\"status\": 200}]" not in suite_xml

    mock_payload = metadata["resource_files"]["mock_get-customer_1_1.dwl"]
    mock_attrs = metadata["resource_files"]["mock_get-customer_1_1_attributes.dwl"]
    set_attrs = metadata["resource_files"]["set-event_attributes_1.dwl"]

    assert not mock_payload.startswith("%dw 2.0")
    assert not mock_attrs.startswith("%dw 2.0")
    assert '"status": "ACTIVE"' in mock_payload
    assert mock_attrs == '{\n  "status": 200\n}\n'
    assert 'mediaType="application/java"' in suite_xml
    assert "set-event_payload_1.dwl" not in metadata["resource_files"]
    assert "set-event_payload_1.dwl" not in suite_xml
    assert '<munit:payload value="#[\'\']" mediaType="application/java"/>' in suite_xml
    assert '<munit:attributes value="#[read(MunitTools::getResourceAsString' in suite_xml
    assert '<munit-tools:attributes value="#[read(MunitTools::getResourceAsString' in suite_xml
    assert "mock_get-customer_1_1_attributes.dwl'), 'application/json')]" in suite_xml
    assert not set_attrs.startswith("%dw 2.0")
    assert set_attrs == '{\n  "method": "GET",\n  "requestPath": "/abc/path",\n  "queryParams": {}\n}\n'
    assert '"method": "GET"' in set_attrs
    assert '"requestPath": "/abc/path"' in set_attrs
    assert "assert_expression_payload_1.dwl" not in metadata["resource_files"]
    assert 'expression="#[payload.status]"' in suite_xml
    assert "MunitTools::equalTo('ACTIVE')" in suite_xml
    assert 'expression="#[payload.id]"' in suite_xml
    assert "MunitTools::equalTo('MOCK-001')" in suite_xml
    assert 'expectedErrorType="HTTP:CONNECTIVITY"' in suite_xml


def test_identical_set_event_attributes_are_reused_across_scenarios(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "getCustomerFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {
                "method": "GET",
                "requestPath": "/customers",
                "queryParams": {},
                "headers": {"content-type": "application/json"},
            },
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
        "output_fields": ["status"],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    attribute_files = [
        name for name in metadata["resource_files"]
        if name.startswith("set-event_attributes_")
    ]

    assert metadata["test_count"] == 3
    assert attribute_files == ["set-event_attributes_1.dwl"]
    assert not any(name.startswith("set-event_payload_") for name in metadata["resource_files"])
    assert "set-event_attributes_2.dwl" not in suite_xml
    assert "set-event_attributes_3.dwl" not in suite_xml
    assert suite_xml.count("set-event_attributes_1.dwl") == 3


def test_identical_set_event_payloads_are_reused_across_scenarios(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "createCustomerFlow",
        "set_event_plan": {
            "payload_expression": '{"id": "MOCK-001", "name": "Test Record"}',
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/customers"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Create Customer",
                "match_attribute": "doc:name",
                "match_value": "Create Customer",
                "return_attributes": {"statusCode": 200},
                "media_type": "application/json",
                "result_shape": "object",
            }
        ],
        "output_fields": ["status"],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    payload_files = [
        name for name in metadata["resource_files"]
        if name.startswith("set-event_payload_")
    ]

    assert metadata["test_count"] == 3
    assert payload_files == ["set-event_payload_1.dwl"]
    assert "set-event_payload_2.dwl" not in suite_xml
    assert "set-event_payload_3.dwl" not in suite_xml
    assert suite_xml.count("set-event_payload_1.dwl") == 3


def test_identical_assertion_expression_files_are_reused_across_scenarios(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "sameAssertionFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/same"},
        },
        "final_processor": {
            "dwl_excerpt": "%dw 2.0\noutput application/json\n---\n{status: \"OK\"}"
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Same",
                "match_attribute": "doc:name",
                "match_value": "Get Same",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
                "result_shape": "object",
            }
        ],
    }

    suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        scenarios=[
            {"name": "happy_path_a", "type": "happy_path", "description": "Happy path A"},
            {"name": "happy_path_b", "type": "happy_path", "description": "Happy path B"},
        ],
    )
    assertion_files = [
        name for name in metadata["resource_files"]
        if name.startswith("assert_expression_payload_")
    ]

    assert metadata["test_count"] == 2
    assert assertion_files == ["assert_expression_payload_1.dwl"]
    assert "assert_expression_payload_2.dwl" not in suite_xml
    assert "assert_expression_payload_2" not in suite_xml
    assert suite_xml.count("assert_expression_payload_1") == 4


def test_different_assertion_expression_files_are_kept_separate(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "differentAssertionFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/different"},
        },
        "final_processor": {
            "dwl_excerpt": "%dw 2.0\noutput application/json\n---\npayload map (item) -> { id: item.id }"
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "db:select",
                "doc_name": "Select Rows",
                "match_attribute": "doc:name",
                "match_value": "Select Rows",
                "result_shape": "array",
                "media_type": "application/java",
            }
        ],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    assertion_files = sorted(
        name for name in metadata["resource_files"]
        if name.startswith("assert_expression_payload_")
    )

    assert assertion_files == ["assert_expression_payload_1.dwl", "assert_expression_payload_2.dwl"]
    assert "assert_expression_payload_1" in suite_xml
    assert "assert_expression_payload_2" in suite_xml
    assert metadata["resource_files"]["assert_expression_payload_1.dwl"] != metadata["resource_files"]["assert_expression_payload_2.dwl"]


def test_set_event_payload_uses_flow_payload_shape_when_flow_reads_payload(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "createCustomerFlow",
        "set_event_plan": {
            "payload_expression": '{"id": "MOCK-001", "name": "Test Record"}',
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/customers"},
        },
        "mock_plan": [],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    set_payload = metadata["resource_files"]["set-event_payload_1.dwl"]

    assert 'mediaType="application/json"' in suite_xml
    assert not set_payload.startswith("%dw 2.0")
    assert set_payload.startswith("{\n")
    assert '"id": "MOCK-001"' in set_payload
    assert '"" as Binary' not in set_payload


def test_assertion_payload_uses_sample_response_when_provided(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "createCustomerFlow",
        "set_event_plan": {
            "payload_expression": '{"name": "Test Record"}',
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/customers"},
        },
        "mock_plan": [],
        "output_fields": ["status"],
    }
    sample_payload = '{"request": {"name": "mike"}, "response": {"status": 201, "id": 12345, "name": "mike"}}'

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        sample_payload=sample_payload,
    )
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]
    set_attrs = metadata["resource_files"]["set-event_attributes_1.dwl"]

    assert_assert_module(assert_payload, '"status": 201')
    assert '"id": 12345' in assert_payload
    assert '"name": "mike"' in assert_payload
    assert not set_attrs.startswith("%dw 2.0")


def test_connector_sample_response_overrides_inferred_mock_payload(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "getCustomerFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/customers"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
    }
    connector_key = "getCustomerFlow_http:request_Get_Customer"

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        connector_samples={
            connector_key: {
                "request": '{"id": 12345}',
                "response": '{"status": 200, "id": 12345, "name": "mike"}',
            }
        },
    )
    mock_payload = metadata["resource_files"]["mock_get-customer_1_1.dwl"]

    assert mock_payload == '{\n  "status": 200,\n  "id": 12345,\n  "name": "mike"\n}\n'
    assert "Test Record" not in mock_payload


def test_mock_media_type_is_inferred_from_sample_response_content(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "getCustomerFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/customers"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
    }
    connector_key = "getCustomerFlow_http:request_Get_Customer"

    suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        connector_samples={
            connector_key: {
                "response": "<customer><id>12345</id><name>mike</name></customer>",
            }
        },
    )
    mock_payload = metadata["resource_files"]["mock_get-customer_1_1.dwl"]

    assert mock_payload == "<customer><id>12345</id><name>mike</name></customer>\n"
    assert 'mediaType="application/xml"' in suite_xml


def test_assertion_payload_uses_final_transform_and_connector_sample(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "getCustomerFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/customers"},
        },
        "final_processor": {
            "dwl_excerpt": """%dw 2.0
output application/json
---
{
  customerId: payload.id,
  customerName: payload.name,
  activeStatus: payload.status,
  source: "crm"
}"""
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
        "output_fields": ["customerId", "customerName", "activeStatus", "source"],
    }
    connector_key = "getCustomerFlow_http:request_Get_Customer"

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        connector_samples={
            connector_key: {
                "response": '{"id": 12345, "name": "mike", "status": "ACTIVE"}',
            }
        },
    )
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]

    assert_assert_module(assert_payload, '"customerId": 12345')
    assert '"customerName": "mike"' in assert_payload
    assert '"activeStatus": "ACTIVE"' in assert_payload
    assert '"source": "crm"' in assert_payload


def test_dynamic_uuid_output_uses_field_level_assertions_not_payload_equality(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "createOrderFlow",
        "set_event_plan": {
            "payload_expression": '{"name": "Test Record"}',
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/orders"},
        },
        "final_processor": {
            "type": "ee:set-payload",
            "dwl_excerpt": "%dw 2.0\noutput application/json\n---\n{\n  id: uuid(),\n  status: \"SUCCESS\"\n}",
        },
        "inline_dwl": [],
        "output_fields": ["id", "status"],
        "mock_plan": [],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert "assert_expression_payload_1.dwl" not in metadata["resource_files"]
    assert 'expression="#[payload.id]"' in suite_xml
    assert "MunitTools::matchesRegex" in suite_xml
    assert 'expression="#[payload.status]"' in suite_xml
    assert "MunitTools::equalTo('SUCCESS')" in suite_xml


def test_assertion_payload_handles_nested_dataweave_object_and_array_output(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "nestedResponseFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/nested"},
        },
        "final_processor": {
            "dwl_excerpt": """%dw 2.0
output application/json
---
{
  customer: {
    id: payload.id,
    name: payload.name,
    active: true
  },
  tags: [
    "gold",
    payload.segment
  ],
  status: if (payload.active) "ACTIVE" else "INACTIVE"
}"""
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
    }
    connector_key = "nestedResponseFlow_http:request_Get_Customer"

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        connector_samples={
            connector_key: {
                "response": '{"id": 12345, "name": "mike", "segment": "vip", "active": true}',
            }
        },
    )
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]

    assert_assert_module(assert_payload, '"customer": {')
    assert '"id": 12345' in assert_payload
    assert '"name": "mike"' in assert_payload
    assert '"active": true' in assert_payload
    assert '"tags": [\n    "gold",\n    "vip"\n  ]' in assert_payload
    assert '"status": "ACTIVE"' in assert_payload


def test_dataweave_transform_generates_spy_plan_and_behavior(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "spyFlow",
        "set_event_plan": {
            "payload_expression": '{"id": "MOCK-001"}',
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/spy"},
        },
        "processor_chain": [
            {
                "type": "ee:transform",
                "doc_name": "Build Response",
                "dwl_excerpt": "%dw 2.0\noutput application/json\n---\n{status: \"OK\"}",
            }
        ],
        "final_processor": {
            "type": "ee:transform",
            "doc_name": "Build Response",
            "dwl_excerpt": "%dw 2.0\noutput application/json\n---\n{status: \"OK\"}",
        },
        "output_fields": ["status"],
        "mock_plan": [],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert metadata["munit_plan"]["behavior"]["spy"][0]["doc_name"] == "Build Response"
    assert '<munit-tools:spy doc:name="Spy Build Response" processor="ee:transform">' in suite_xml
    assert 'whereValue="Build Response"' in suite_xml
    assert "DataWeave output should be present" in suite_xml


def test_missing_samples_create_clarification_requests(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "needsSamplesFlow",
        "required_inputs": {"payloadRequired": True},
        "set_event_plan": {
            "payload_expression": '{"id": "MOCK-001"}',
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/needs-samples"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Unknown Shape API",
                "match_attribute": "doc:name",
                "match_value": "Unknown Shape API",
                "media_type": "application/json",
            }
        ],
    }

    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    requests = metadata["munit_plan"]["clarificationRequests"]

    assert any(item["type"] == "sample_request_response" for item in requests)
    assert any(item["type"] == "connector_mock_response" for item in requests)
    assert all("Do not include secrets" in item["security_note"] or "synthetic" in item["security_note"] for item in requests)


def test_generic_placeholder_fields_create_grouped_request_sample_request(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "searchFlow",
        "set_event_plan": {
            "payload_expression": '{"segment": "MOCK-VALUE", "quantity": 1}',
            "payload_media_type": "application/json",
            "attributes_template": {
                "method": "GET",
                "requestPath": "/search",
                "queryParams": {"region": "MOCK-VALUE", "pageSize": 1},
            },
        },
        "mock_plan": [],
    }

    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    requests = metadata["munit_plan"]["clarificationRequests"]
    sample_requests = [item for item in requests if item["type"] == "sample_request_response"]

    assert len(sample_requests) == 1
    assert sample_requests[0]["requested_fields"] == {
        "payload": ["segment"],
        "queryParams": ["region"],
    }
    assert not any(item["type"] == "field_value" for item in requests)


def test_variable_input_fields_are_grouped_into_single_request_sample(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "variableInputFlow",
        "set_event_plan": {
            "payload_expression": "{}",
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/variable"},
        },
        "variable_writes": [
            {"name": "customerName", "value": "#[payload.customerName]", "value_type": "string"},
            {"name": "region", "value": "#[attributes.queryParams.region]", "value_type": "string"},
            {"name": "customerId", "value": "#[attributes.uriParams.customerId]", "value_type": "string"},
            {"name": "auth", "value": "#[attributes.headers.authorization]", "value_type": "string"},
        ],
        "mock_plan": [],
    }

    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    requests = metadata["munit_plan"]["clarificationRequests"]
    sample_requests = [item for item in requests if item["type"] == "sample_request_response"]

    assert len(sample_requests) == 1
    assert sample_requests[0]["requested_fields"] == {
        "headers": ["authorization"],
        "payload": ["customerName"],
        "queryParams": ["region"],
        "uriParams": ["customerId"],
    }
    assert not any(item["type"] == "field_value" for item in requests)


def test_payload_mock_values_use_inferred_types_for_numeric_and_boolean_fields(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
  <flow name="createOrderFlow">
    <http:listener doc:name="Listener" path="/orders" allowedMethods="POST"/>
    <ee:transform doc:name="Build Request">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  amount: payload.orderAmount,
  count: payload.itemCount,
  active: payload.isActive
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["createOrderFlow"]

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    set_payload = metadata["resource_files"]["set-event_payload_1.dwl"]

    assert '"orderAmount": 100.0' in set_payload
    assert '"itemCount": 1' in set_payload
    assert '"isActive": true' in set_payload
    assert '"orderAmount": "MOCK-VALUE"' not in set_payload


def test_web_generation_preflight_pauses_for_missing_field_values(tmp_path):
    from app import WebMUnitGenerator, active_jobs

    generator = WebMUnitGenerator()
    flow_summary = {
        "job_type": "REST API",
        "test_targets": ["searchFlow"],
        "flow_contexts": {
            "searchFlow": {
                "target_flow": "searchFlow",
                "set_event_plan": {
                    "payload_expression": '{"segment": "MOCK-VALUE"}',
                    "payload_media_type": "application/json",
                    "attributes_template": {
                        "method": "GET",
                        "requestPath": "/search",
                        "queryParams": {"region": "MOCK-VALUE"},
                    },
                },
                "mock_plan": [],
            }
        },
    }

    requests = generator._collect_generation_clarification_requests(
        flow_summary,
        {},
        {"scenarios": []},
        sample_payloads={},
        connector_samples={},
    )
    result = generator._needs_user_input_result(
        "job-needs-values",
        flow_summary,
        requests,
        output_path=str(tmp_path),
    )

    assert result["needs_user_input"] is True
    assert active_jobs["job-needs-values"]["status"] == "needs_user_input"
    sample_request = next(item for item in result["clarification_requests"] if item["type"] == "sample_request_response")
    assert sample_request["requested_fields"] == {
        "payload": ["segment"],
        "queryParams": ["region"],
    }
    assert "Do not provide production PII" in result["security"]["warnings"][1]


def test_web_field_value_answers_become_recorder_sample_payloads():
    from app import WebMUnitGenerator

    generator = WebMUnitGenerator()
    samples = generator._build_sample_payloads_dict({
        "field_values": """[
          {"flow":"createOrderFlow","location":"payload","field":"orderAmount","expected_type":"number","value":"42.5"},
          {"flow":"createOrderFlow","location":"payload","field":"requestId","expected_type":"string","value":"{{uuid}}"},
          {"flow":"createOrderFlow","location":"queryParams","field":"region","expected_type":"string","value":"west"},
          {"flow":"createOrderFlow","location":"headers","field":"correlationId","expected_type":"string","value":"{{correlationId}}"}
        ]"""
    })
    parsed = json.loads(samples["createOrderFlow"])

    assert parsed["request"]["payload"]["orderAmount"] == 42.5
    assert parsed["request"]["payload"]["requestId"] == "11111111-1111-4111-8111-111111111111"
    assert parsed["request"]["queryParams"]["region"] == "west"
    assert parsed["request"]["headers"]["correlationId"] == "test-correlation-id"
    assert json.loads(samples["_all"]) == parsed


def test_web_plain_request_sample_is_not_treated_as_empty_payload():
    from app import WebMUnitGenerator

    generator = WebMUnitGenerator()
    samples = generator._build_sample_payloads_dict({
        "sample_payload": '{"customerId":"CUST-123","amount":42,"requestId":"{{uuid}}"}'
    })
    parsed = json.loads(samples["_all"])

    assert parsed["request"]["payload"] == {
        "customerId": "CUST-123",
        "amount": 42,
        "requestId": "11111111-1111-4111-8111-111111111111",
    }

    builder = DeterministicMUnitBuilder()
    payload_dwl, _attrs_dwl = builder._split_sample_payload(samples["_all"], {
        "attributes_template": {"method": "POST", "requestPath": "/customers"}
    })

    assert '"customerId": "CUST-123"' in payload_dwl
    assert payload_dwl.strip() != "{}"


def test_web_flow_specific_sample_payloads_override_global_and_keep_resource_naming():
    from app import WebMUnitGenerator

    generator = WebMUnitGenerator()
    samples = generator._build_sample_payloads_dict({
        "sample_payload": '{"globalOnly":true}',
        "sample_payloads": json.dumps([
            {
                "flow": "createCustomerFlow",
                "sample": json.dumps({
                    "request": {"payload": {"customerId": "CUST-123"}},
                    "response": {"status": "CREATED"},
                }),
            }
        ]),
    })

    parsed = json.loads(samples["createCustomerFlow"])
    assert parsed["request"]["payload"]["customerId"] == "CUST-123"
    assert json.loads(samples["_all"])["request"]["payload"]["globalOnly"] is True

    builder = DeterministicMUnitBuilder()
    _suite_xml, metadata = builder.build_suite(
        {
            "target_flow": "createCustomerFlow",
            "set_event_plan": {
                "payload_expression": "{}",
                "payload_media_type": "application/json",
                "attributes_template": {"method": "POST", "requestPath": "/customers"},
            },
            "mock_plan": [],
            "output_fields": ["status"],
        },
        generation_mode="recorder",
        sample_payload=samples["createCustomerFlow"],
    )

    assert "set_event_payload_valid.dwl" in metadata["resource_files"]
    assert "set_event_payload_1.dwl" not in metadata["resource_files"]
    assert '"customerId": "CUST-123"' in metadata["resource_files"]["set_event_payload_valid.dwl"]


def test_more_test_data_drives_set_event_and_assertion_resources():
    from app import WebMUnitGenerator

    generator = WebMUnitGenerator()
    samples = generator._build_sample_payloads_dict({
        "sample_payloads": json.dumps([
            {
                "flow": "weatherFlow",
                "sample": json.dumps({
                    "request": {
                        "payload": {"city": "Pune", "units": "metric"},
                        "queryParams": {"country": "IN"},
                    },
                    "response": {
                        "temperature": 27,
                        "condition": "Cloudy",
                    },
                }),
            }
        ]),
    })

    builder = DeterministicMUnitBuilder()
    _suite_xml, metadata = builder.build_suite(
        {
            "target_flow": "weatherFlow",
            "set_event_plan": {
                "payload_expression": '""',
                "payload_media_type": "application/json",
                "attributes_template": {"method": "POST", "requestPath": "/weather"},
            },
            "mock_plan": [],
            "output_fields": ["temperature", "condition"],
        },
        generation_mode="recorder",
        sample_payload=samples["weatherFlow"],
    )

    resource_files = metadata["resource_files"]
    assert resource_files["set_event_payload_valid.dwl"].strip() == json.dumps(
        {"city": "Pune", "units": "metric"},
        indent=2,
    )
    assert '"country": "IN"' in resource_files["set_event_attributes_valid.dwl"]
    assert "assert_expression_payload_valid.dwl" in resource_files
    assert '"temperature": 27' in resource_files["assert_expression_payload_valid.dwl"]
    assert '"condition": "Cloudy"' in resource_files["assert_expression_payload_valid.dwl"]
    assert not any(name.startswith("set_event_payload_1") for name in resource_files)


def test_more_test_data_request_payload_and_response_are_split_exactly():
    from app import WebMUnitGenerator

    generator = WebMUnitGenerator()
    sample = {
        "request": {
            "payload": {"field1": "asdfg", "field2": "poiuyt"},
            "queryParams": {},
            "uriParams": {},
            "headers": {},
        },
        "response": {"filed1": "lkjhyui"},
    }
    samples = generator._build_sample_payloads_dict({
        "sample_payloads": json.dumps([
            {"flow": "selectedFlow", "sample": json.dumps(sample)}
        ])
    })

    builder = DeterministicMUnitBuilder()
    _suite_xml, metadata = builder.build_suite(
        {
            "target_flow": "selectedFlow",
            "set_event_plan": {
                "payload_expression": '""',
                "payload_media_type": "application/json",
                "attributes_template": {"method": "POST", "requestPath": "/selected"},
            },
            "mock_plan": [],
            "output_fields": ["filed1"],
        },
        generation_mode="recorder",
        sample_payload=samples["selectedFlow"],
    )

    assert metadata["resource_files"]["set_event_payload_valid.dwl"].strip() == json.dumps(
        sample["request"]["payload"],
        indent=2,
    )
    assert '"filed1": "lkjhyui"' in metadata["resource_files"]["assert_expression_payload_valid.dwl"]
    assert '"request"' not in metadata["resource_files"]["set_event_payload_valid.dwl"]
    assert '"response"' not in metadata["resource_files"]["set_event_payload_valid.dwl"]


def test_more_test_data_payload_key_with_recorder_wrapper_is_unwrapped():
    from app import WebMUnitGenerator

    recorder_sample = {
        "request": {
            "payload": {"field1": "asdfg", "field2": "poiuyt"},
            "queryParams": {},
            "uriParams": {},
            "headers": {},
        },
        "response": {"filed1": "lkjhyui"},
    }
    generator = WebMUnitGenerator()
    samples = generator._build_sample_payloads_dict({
        "sample_payloads": json.dumps([
            {"flow": "selectedFlow", "payload": recorder_sample}
        ])
    })

    builder = DeterministicMUnitBuilder()
    _suite_xml, metadata = builder.build_suite(
        {
            "target_flow": "selectedFlow",
            "set_event_plan": {
                "payload_expression": '""',
                "payload_media_type": "application/json",
                "attributes_template": {"method": "POST", "requestPath": "/selected"},
            },
            "mock_plan": [],
            "output_fields": ["filed1"],
        },
        generation_mode="recorder",
        sample_payload=samples["selectedFlow"],
    )

    set_payload = metadata["resource_files"]["set_event_payload_valid.dwl"]
    assert set_payload.strip() == json.dumps(recorder_sample["request"]["payload"], indent=2)
    assert '"request"' not in set_payload
    assert '"response"' not in set_payload


def test_set_event_payload_resource_sanitizer_strips_full_recorder_wrapper():
    builder = DeterministicMUnitBuilder()
    bad_resource_content = json.dumps({
        "request": {
            "payload": {"field1": "asdfg", "field2": "poiuyt"},
            "queryParams": {},
            "uriParams": {},
            "headers": {},
        },
        "response": {"filed1": "lkjhyui"},
    }, indent=2)

    sanitized = builder._sanitize_set_event_payload_resource_content(bad_resource_content)

    assert sanitized.strip() == json.dumps(
        {"field1": "asdfg", "field2": "poiuyt"},
        indent=2,
    )
    assert '"request"' not in sanitized
    assert '"response"' not in sanitized


def test_negative_scenario_gets_named_invalid_set_event_payload_from_sample():
    sample_payload = json.dumps({
        "request": {
            "payload": {"field1": "asdfg", "field2": "poiuyt"},
            "queryParams": {},
            "uriParams": {},
            "headers": {},
        },
        "response": {"filed1": "lkjhyui"},
    })

    builder = DeterministicMUnitBuilder()
    _suite_xml, metadata = builder.build_suite(
        {
            "target_flow": "selectedFlow",
            "set_event_plan": {
                "payload_expression": json.dumps({"field1": "asdfg", "field2": "poiuyt"}),
                "payload_media_type": "application/json",
                "attributes_template": {"method": "POST", "requestPath": "/selected"},
            },
            "mock_plan": [],
            "output_fields": ["filed1"],
        },
        generation_mode="recorder",
        sample_payload=sample_payload,
        scenarios=[
            {"name": "happy_path", "type": "happy_path", "description": "Valid request"},
            {
                "name": "validation_error",
                "type": "validation_error",
                "description": "Invalid request",
                "assertion_strategy": "expected_error",
                "expected_error_type": "VALIDATION:INVALID_BOOLEAN",
            },
        ],
    )

    resource_files = metadata["resource_files"]
    assert "set_event_payload_valid.dwl" in resource_files
    assert "set_event_payload_invalid.dwl" in resource_files
    assert '"field1": "asdfg"' in resource_files["set_event_payload_valid.dwl"]
    assert '"field1": "asdfg"' not in resource_files["set_event_payload_invalid.dwl"]
    assert '"field2": "poiuyt"' in resource_files["set_event_payload_invalid.dwl"]
    assert "set_event_payload_invalid.dwl" in _suite_xml


def test_request_sample_replaces_mock_values_in_all_generated_scenarios(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "sampledFlow",
        "set_event_plan": {
            "payload_expression": '{"segment": "MOCK-VALUE"}',
            "payload_media_type": "application/json",
            "attributes_template": {
                "method": "GET",
                "requestPath": "/sample/{customerId}",
                "queryParams": {"region": "MOCK-VALUE"},
                "uriParams": {"customerId": "MOCK-001"},
                "headers": {"authorization": "Bearer test-token"},
            },
        },
        "mock_plan": [],
    }
    sample_payload = json.dumps({
        "request": {
            "payload": {"segment": "premium"},
            "queryParams": {"region": "west"},
            "uriParams": {"customerId": "CUST-123"},
            "headers": {"authorization": "Bearer synthetic-token"},
        },
        "response": {"status": "SUCCESS"},
    })

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        sample_payload=sample_payload,
        scenarios=[
            {"name": "happy_path", "type": "happy_path", "description": "Happy path"},
            {"name": "edge_path", "type": "branch_path", "description": "Edge path"},
        ],
    )

    set_event_files = {
        name: content
        for name, content in metadata["resource_files"].items()
        if name.startswith("set-event_")
    }
    combined = "\n".join(set_event_files.values())

    assert '"segment": "premium"' in combined
    assert '"region": "west"' in combined
    assert '"customerId": "CUST-123"' in combined
    assert '"authorization": "Bearer synthetic-token"' in combined
    assert "MOCK-VALUE" not in combined
    assert "MOCK-001" not in combined


def test_dynamic_fields_in_sample_expected_output_use_flexible_assertions(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "sampleDynamicFlow",
        "set_event_plan": {
            "payload_expression": "{}",
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/dynamic"},
        },
        "mock_plan": [],
    }
    sample_payload = json.dumps({
        "request": {"payload": {"name": "test"}},
        "response": {
            "id": "11111111-1111-4111-8111-111111111111",
            "correlationId": "test-correlation-id",
            "createdDate": "2026-01-01T00:00:00Z",
            "status": "ACTIVE",
        },
    })

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        sample_payload=sample_payload,
        scenarios=[{"name": "happy_path", "type": "happy_path", "description": "Happy path"}],
    )
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]

    assert "payload.correlationId must notNullValue()" in assert_payload
    assert "payload.createdDate must notNullValue()" in assert_payload
    assert 'payload.status must equalTo("ACTIVE")' in assert_payload
    assert "payload must equalTo" not in assert_payload


def test_assertion_payload_uses_connector_response_when_flow_passes_through(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "getCustomerFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/customers"},
        },
        "final_processor": {"type": "http:request", "doc_name": "Get Customer"},
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
    }
    connector_key = "getCustomerFlow_http:request_Get_Customer"

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        connector_samples={
            connector_key: {
                "response": '{"status": 200, "id": 12345, "name": "mike"}',
            }
        },
    )
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]

    assert_assert_module(assert_payload, '"status": 200')
    assert '"id": 12345' in assert_payload
    assert '"name": "mike"' in assert_payload


def test_http_request_mock_shape_is_array_when_downstream_dwl_maps_payload(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="arrayFlow">
    <http:listener doc:name="Listener" path="/array"/>
    <http:request doc:name="Get Records" method="GET" path="/records"/>
    <ee:transform doc:name="Final Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
payload map (item) -> {
  recordName: item.name,
  recordId: item.id
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["arrayFlow"]
    mock_item = flow_context["mock_plan"][0]

    assert mock_item["result_shape"] == "array"
    assert "payload map" in mock_item["downstream_dwl_excerpt"]

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    mock_payload = metadata["resource_files"]["mock_get-records_1_1.dwl"]

    assert mock_payload.startswith("[\n  {")
    assert '"name": "Test Record"' in mock_payload
    assert '"id": "MOCK-001"' in mock_payload


def test_analyzer_keeps_http_external_api_qualified_and_mocked(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="api-flow">
    <http:listener doc:name="Listener" path="/api/process"/>
    <set-payload doc:name="Set Payload" value='{"status": "processed"}'/>
    <http:request doc:name="Call external API" config-ref="HTTP_Request_config" path="/external" method="POST"/>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["api-flow"]

    assert summary["job_type"] == "REST API"
    assert "http:listener" in flow_context["connectors"]
    assert "http:request" in flow_context["connectors"]
    assert flow_context["mock_plan"][0]["processor"] == "http:request"

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert metadata["mock_plan_count"] == 1
    assert '<munit-tools:mock-when doc:name="Mock Call external API" processor="http:request">' in suite_xml
    assert 'whereValue="Call external API"' in suite_xml


def test_flow_selection_keeps_listener_entries_and_excludes_health_and_apikit():
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:apikit="http://www.mulesoft.org/schema/mule/apikit"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="api-main">
    <http:listener doc:name="API Listener" path="/api/*"/>
    <apikit:router doc:name="APIkit Router"/>
  </flow>
  <flow name="get:/customers:api-config">
    <http:listener doc:name="Customer Listener" path="/customers"/>
    <set-payload value='{"status":"ok"}'/>
  </flow>
  <flow name="health-check-flow">
    <http:listener doc:name="Health" path="/health"/>
    <set-payload value='{"status":"UP"}'/>
  </flow>
  <flow name="internalHelper">
    <set-payload value='{"status":"internal"}'/>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)

    assert "get:/customers:api-config" in summary["test_targets"]
    assert "api-main" not in summary["test_targets"]
    assert "health-check-flow" not in summary["test_targets"]
    assert summary["flow_contexts"]["get:/customers:api-config"]["has_source_listener"] is True
    assert summary["flow_contexts"]["health-check-flow"]["direct_munit_excluded"] is True


def test_analyzer_mocks_web_service_consumer_external_api(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:wsc="http://www.mulesoft.org/schema/mule/wsc"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="soapFlow">
    <http:listener doc:name="Listener" path="/soap"/>
    <wsc:consume doc:name="Call SOAP API" config-ref="Web_Service_Consumer_Config" operation="getCustomer"/>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["soapFlow"]

    assert "wsc:consume" in flow_context["connectors"]
    assert flow_context["mock_plan"][0]["processor"] == "wsc:consume"

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert metadata["mock_plan_count"] == 1
    assert '<munit-tools:mock-when doc:name="Mock Call SOAP API" processor="wsc:consume">' in suite_xml
    assert 'whereValue="Call SOAP API"' in suite_xml


def test_parent_flow_context_reaches_flow_ref_subflow(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="parentFlow">
    <http:listener doc:name="Listener" path="/parent"/>
    <flow-ref doc:name="Call child" name="childSubFlow"/>
  </flow>
  <sub-flow name="childSubFlow">
    <http:request doc:name="Child API" method="GET" path="/child"/>
    <ee:transform doc:name="Child Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  childStatus: "ok",
  childId: payload.id
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </sub-flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["parentFlow"]

    assert summary["test_targets"] == ["parentFlow"]
    assert flow_context["child_flows"] == ["childSubFlow"]
    assert flow_context["execution_flows"] == ["parentFlow", "childSubFlow"]
    assert any(
        item.get("flow") == "childSubFlow" and item.get("type") == "http:request"
        for item in flow_context["processor_chain"]
    )
    assert flow_context["mock_plan"][0]["doc_name"] == "Child API"
    assert flow_context["final_processor"]["flow"] == "childSubFlow"
    assert flow_context["output_fields"] == ["childStatus", "childId"]

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert '<flow-ref doc:name="Execute parentFlow" name="parentFlow"/>' in suite_xml
    assert '<munit-tools:mock-when doc:name="Mock Child API" processor="http:request">' in suite_xml
    assert any(
        name.startswith("mock_child-api_") and not name.endswith("_attributes.dwl")
        for name in metadata["resource_files"]
    )


def test_nested_flow_refs_are_expanded_in_execution_order(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="parentFlow">
    <http:listener doc:name="Listener" path="/parent"/>
    <flow-ref doc:name="Call middle" name="middleSubFlow"/>
    <ee:transform doc:name="Parent Final Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  finalStatus: payload.status,
  finalId: payload.id
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
  <sub-flow name="middleSubFlow">
    <flow-ref doc:name="Call deepest" name="deepestSubFlow"/>
  </sub-flow>
  <sub-flow name="deepestSubFlow">
    <http:request doc:name="Deep API" method="GET" path="/deep"/>
  </sub-flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["parentFlow"]

    assert summary["test_targets"] == ["parentFlow"]
    assert flow_context["execution_flows"] == ["parentFlow", "middleSubFlow", "deepestSubFlow"]

    chain_pairs = [
        (item.get("flow"), item.get("type"), item.get("doc_name"))
        for item in flow_context["processor_chain"]
        if item.get("type") in {"http:listener", "flow-ref", "http:request", "ee:transform"}
    ]
    assert chain_pairs == [
        ("parentFlow", "http:listener", "Listener"),
        ("parentFlow", "flow-ref", "Call middle"),
        ("middleSubFlow", "flow-ref", "Call deepest"),
        ("deepestSubFlow", "http:request", "Deep API"),
        ("parentFlow", "ee:transform", "Parent Final Response"),
    ]
    assert flow_context["mock_plan"][0]["doc_name"] == "Deep API"
    assert "finalStatus" in flow_context["mock_plan"][0]["downstream_dwl_excerpt"]
    assert flow_context["final_processor"]["flow"] == "parentFlow"
    assert flow_context["final_processor"]["type"] == "ee:set-payload"
    assert flow_context["output_fields"] == ["finalStatus", "finalId"]

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert '<flow-ref doc:name="Execute parentFlow" name="parentFlow"/>' in suite_xml
    assert '<munit-tools:mock-when doc:name="Mock Deep API" processor="http:request">' in suite_xml
    assert any(
        name.startswith("mock_deep-api_") and not name.endswith("_attributes.dwl")
        for name in metadata["resource_files"]
    )


def test_root_final_transform_wins_over_nested_flow_return_payload(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
  <flow name="A">
    <http:listener doc:name="Listener" path="/a"/>
    <flow-ref doc:name="Call B" name="B"/>
    <ee:transform doc:name="A Final Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  aStatus: "done",
  bName: payload.bName,
  aOwnField: "root"
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
  <sub-flow name="B">
    <flow-ref doc:name="Call C" name="C"/>
    <ee:transform doc:name="B Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  bName: payload.cName,
  bOnly: "middle"
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </sub-flow>
  <flow name="C">
    <ee:transform doc:name="C Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  cName: "charlie",
  cOnly: "leaf"
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["A"]

    assert flow_context["execution_flows"] == ["A", "B", "C"]
    assert flow_context["final_processor"]["flow"] == "A"
    assert flow_context["final_processor"]["type"] == "ee:set-payload"
    assert flow_context["output_fields"] == ["aStatus", "bName", "aOwnField"]

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]

    assert '"aStatus": "done"' in assert_payload
    assert '"aOwnField": "root"' in assert_payload
    assert '"bOnly": "middle"' not in assert_payload
    assert '"cOnly": "leaf"' not in assert_payload


def test_dynamic_flow_ref_candidates_are_expanded_and_mocked(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:db="http://www.mulesoft.org/schema/mule/db"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="get:/account:api-config">
    <flow-ref doc:name="Call orchestrator" name="orchestratorFlow"/>
  </flow>
  <flow name="orchestratorFlow">
    <flow-ref doc:name="Call database path" name="databasePathFlow"/>
    <flow-ref doc:name="Call transform path" name="transformPathFlow"/>
    <flow-ref doc:name="Call dynamic path" name="dynamicRouterFlow"/>
  </flow>
  <flow name="databasePathFlow">
    <flow-ref doc:name="Call db subflow" name="dbSubFlow"/>
  </flow>
  <sub-flow name="dbSubFlow">
    <db:select doc:name="Select Account"/>
  </sub-flow>
  <flow name="transformPathFlow">
    <ee:transform doc:name="Shape Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  status: "transformed",
  id: payload.id
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
  <flow name="dynamicRouterFlow">
    <set-variable doc:name="Choose Flow" variableName="nextFlow"><![CDATA[%dw 2.0
output application/java
---
if (attributes.queryParams.kind == "api") "dynamicHttpFlow" else "dynamicDbFlow"]]></set-variable>
    <flow-ref doc:name="Call dynamic flow" name="#[vars.nextFlow]"/>
  </flow>
  <flow name="dynamicHttpFlow">
    <http:request doc:name="Call Dynamic API" method="GET" path="/dynamic"/>
  </flow>
  <flow name="dynamicDbFlow">
    <db:select doc:name="Select Dynamic Account"/>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["get:/account:api-config"]

    assert summary["test_targets"] == ["get:/account:api-config"]
    assert flow_context["execution_flows"] == [
        "get:/account:api-config",
        "orchestratorFlow",
        "databasePathFlow",
        "dbSubFlow",
        "transformPathFlow",
        "dynamicRouterFlow",
        "dynamicHttpFlow",
        "dynamicDbFlow",
    ]

    dynamic_ref = next(
        item for item in flow_context["processor_chain"]
        if item.get("type") == "flow-ref" and item.get("doc_name") == "Call dynamic flow"
    )
    assert dynamic_ref["dynamic_flow_candidates"] == ["dynamicHttpFlow", "dynamicDbFlow"]
    assert dynamic_ref["dynamic_flow_candidate_details"] == [
        {
            "flow": "dynamicHttpFlow",
            "condition": 'attributes.queryParams.kind == "api"',
            "source": "set-variable nextFlow",
        },
        {
            "flow": "dynamicDbFlow",
            "condition": 'not (attributes.queryParams.kind == "api")',
            "source": "set-variable nextFlow",
        },
    ]
    assert flow_context["dynamic_flow_refs"] == [{
        "flow": "dynamicRouterFlow",
        "doc_name": "Call dynamic flow",
        "expression": "#[vars.nextFlow]",
        "candidates": dynamic_ref["dynamic_flow_candidate_details"],
    }]

    mock_processors = [
        (item["processor"], item["doc_name"])
        for item in flow_context["mock_plan"]
    ]
    assert ("db:select", "Select Account") in mock_processors
    assert ("http:request", "Call Dynamic API") in mock_processors
    assert ("db:select", "Select Dynamic Account") in mock_processors

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert '<munit-tools:mock-when doc:name="Mock Select Account" processor="db:select">' in suite_xml
    assert '<munit-tools:mock-when doc:name="Mock Call Dynamic API" processor="http:request">' in suite_xml
    assert '<munit-tools:mock-when doc:name="Mock Select Dynamic Account" processor="db:select">' in suite_xml
    assert metadata["mock_plan_count"] == 3
    scenario_names = [item["name"] for item in metadata["scenario_plan"]]
    assert "dynamic_dynamichttpflow" in scenario_names
    assert "dynamic_dynamicdbflow" in scenario_names
    assert "set_event_attributes_dynamic_dynamichttpflow.dwl" in metadata["resource_files"]
    assert '"kind": "api"' in metadata["resource_files"]["set_event_attributes_dynamic_dynamichttpflow.dwl"]


def test_deep_nested_flow_connectors_are_expanded_and_mocked(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:salesforce="http://www.mulesoft.org/schema/mule/salesforce"
      xmlns:sap="http://www.mulesoft.org/schema/mule/sap"
      xmlns:netsuite="http://www.mulesoft.org/schema/mule/netsuite"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="get:/account:api-config">
    <flow-ref doc:name="Call level one" name="levelOneFlow"/>
  </flow>
  <flow name="levelOneFlow">
    <flow-ref doc:name="Call level two" name="levelTwoSubFlow"/>
  </flow>
  <sub-flow name="levelTwoSubFlow">
    <flow-ref doc:name="Call level three" name="levelThreeFlow"/>
  </sub-flow>
  <flow name="levelThreeFlow">
    <flow-ref doc:name="Call system flow" name="systemConnectorSubFlow"/>
  </flow>
  <sub-flow name="systemConnectorSubFlow">
    <salesforce:query doc:name="Query Salesforce"/>
    <sap:synchronous-remote-function-call doc:name="Call SAP"/>
    <netsuite:query doc:name="Query NetSuite"/>
    <http:request doc:name="Call Partner API" method="POST" path="/partner"/>
  </sub-flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["get:/account:api-config"]

    assert flow_context["execution_flows"] == [
        "get:/account:api-config",
        "levelOneFlow",
        "levelTwoSubFlow",
        "levelThreeFlow",
        "systemConnectorSubFlow",
    ]
    assert any(
        item.get("flow") == "systemConnectorSubFlow" and item.get("type") == "salesforce:query"
        for item in flow_context["processor_chain"]
    )
    assert "salesforce:query" in flow_context["connectors"]
    assert "sap:synchronous-remote-function-call" in flow_context["connectors"]
    assert "netsuite:query" in flow_context["connectors"]
    assert "http:request" in flow_context["connectors"]
    assert flow_context["execution_paths"][0]["flows"] == flow_context["execution_flows"]
    assert "netsuite:query" in flow_context["execution_paths"][0]["connectors"]
    assert flow_context["required_inputs"]["method"] == "GET"
    assert flow_context["required_inputs"]["requestPath"] == "/account"
    assert flow_context["compliance_policy"]["live_external_data_reads_allowed"] is False

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    mock_processors = {
        (item["processor"], item["doc_name"])
        for item in flow_context["mock_plan"]
    }
    assert ("salesforce:query", "Query Salesforce") in mock_processors
    assert ("sap:synchronous-remote-function-call", "Call SAP") in mock_processors
    assert ("netsuite:query", "Query NetSuite") in mock_processors
    assert ("http:request", "Call Partner API") in mock_processors
    assert '<munit-tools:mock-when doc:name="Mock Query Salesforce" processor="salesforce:query">' in suite_xml
    assert '<munit-tools:mock-when doc:name="Mock Call SAP" processor="sap:synchronous-remote-function-call">' in suite_xml
    assert '<munit-tools:mock-when doc:name="Mock Query NetSuite" processor="netsuite:query">' in suite_xml
    assert '<munit-tools:mock-when doc:name="Mock Call Partner API" processor="http:request">' in suite_xml
    assert metadata["mock_plan_count"] == 4
    assert metadata["compliance_policy"]["mode"] == "static_analysis_only"
    assert metadata["compliance_policy"]["live_external_data_reads_allowed"] is False


def test_selected_parent_flow_context_is_rebuilt_from_full_graph_for_deep_child_mocks():
    from app import WebMUnitGenerator

    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="A">
    <flow-ref doc:name="Call B" name="B"/>
  </flow>
  <flow name="B">
    <flow-ref doc:name="Call C" name="C"/>
  </flow>
  <flow name="C">
    <flow-ref doc:name="Call D" name="D"/>
  </flow>
  <flow name="D">
    <flow-ref doc:name="Call E" name="E"/>
  </flow>
  <sub-flow name="E">
    <http:request doc:name="Call Backend In E" method="GET" path="/backend"/>
  </sub-flow>
</mule>"""
    generator = WebMUnitGenerator()
    flow_summary = generator.xml_analyzer.analyze_mule_project(mule_xml)
    initial_context = flow_summary["flow_contexts"]["A"]

    assert initial_context["execution_flows"] == ["A", "B", "C", "D", "E"]
    assert initial_context["flow_levels"] == {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4}
    assert initial_context["mock_plan"][0]["doc_name"] == "Call Backend In E"
    assert initial_context["unresolved_flow_refs"] == []
    assert initial_context["traversal_connectors"] == [
        {
            "flow": "E",
            "level": 4,
            "connector": "http:request",
            "operation": "GET",
            "config": None,
            "doc_name": "Call Backend In E",
        }
    ]

    # Simulate stale/minimal contexts from an earlier analysis response. The
    # selected-flow apply step must rebuild A from flow_graph before generation.
    flow_summary["flow_contexts"] = {"A": {"target_flow": "A", "mock_plan": []}}
    selected_summary = generator.apply_selected_flows(flow_summary, ["A"])
    context = selected_summary["flow_contexts"]["A"]

    assert selected_summary["test_targets"] == ["A"]
    assert context["execution_flows"] == ["A", "B", "C", "D", "E"]
    assert context["flow_levels"]["E"] == 4
    assert context["mock_plan"][0]["processor"] == "http:request"
    assert context["mock_plan"][0]["doc_name"] == "Call Backend In E"
    assert context["traversal_connectors"][0]["flow"] == "E"
    assert context["traversal_connectors"][0]["level"] == 4


def test_flow_traversal_ruleset_skips_circular_flow_ref_and_warns():
    from app import WebMUnitGenerator

    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:db="http://www.mulesoft.org/schema/mule/db"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="A">
    <flow-ref doc:name="Call B" name="B"/>
  </flow>
  <flow name="B">
    <db:select doc:name="Read Orders" config-ref="DB_Config"/>
    <flow-ref doc:name="Call A Again" name="A"/>
  </flow>
</mule>"""
    generator = WebMUnitGenerator()
    flow_summary = generator.xml_analyzer.analyze_mule_project(mule_xml)
    context = flow_summary["flow_contexts"]["A"]

    assert context["execution_flows"] == ["A", "B"]
    assert context["flow_levels"] == {"A": 0, "B": 1}
    assert context["traversal_connectors"] == [
        {
            "flow": "B",
            "level": 1,
            "connector": "db:select",
            "operation": "select",
            "config": "DB_Config",
            "doc_name": "Read Orders",
        }
    ]
    assert context["mock_plan"][0]["processor"] == "db:select"
    assert context["flow_traversal_warnings"][0]["flow"] == "A"
    assert "already visited" in context["flow_traversal_warnings"][0]["reason"]


def test_apikit_flow_name_derives_uri_param_set_event_attributes(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="get:/api-account/client/{clientId}:api-config">
    <ee:transform doc:name="Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  id: attributes.uriParams.clientId,
  status: "ok"
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["get:/api-account/client/{clientId}:api-config"]
    attrs = flow_context["set_event_plan"]["attributes_template"]

    assert attrs["method"] == "GET"
    assert attrs["requestPath"] == "/api-account/client/{clientId}"
    assert attrs["uriParams"]["clientId"] == "MOCK-001"

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    set_attrs = metadata["resource_files"]["set-event_attributes_1.dwl"]

    assert '"uriParams": {' in set_attrs
    assert '"clientId": "MOCK-001"' in set_attrs


def test_route_style_flow_name_derives_query_param_set_event_attributes(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name='get/api-account/client?name="jack"'>
    <ee:transform doc:name="Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  name: attributes.queryParams.name,
  status: "ok"
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]['get/api-account/client?name="jack"']
    attrs = flow_context["set_event_plan"]["attributes_template"]

    assert attrs["method"] == "GET"
    assert attrs["requestPath"] == "/api-account/client"
    assert attrs["queryParams"]["name"] == "jack"

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    set_attrs = metadata["resource_files"]["set-event_attributes_1.dwl"]

    assert '"queryParams": {' in set_attrs
    assert '"name": "jack"' in set_attrs


def test_parenthesized_uri_param_flow_name_is_normalized():
    analyzer = XMLAnalyzer()

    metadata = analyzer._extract_endpoint_metadata_from_flow_name("get/api-account/client/(clientId)")

    assert metadata["method"] == "GET"
    assert metadata["requestPath"] == "/api-account/client/{clientId}"
    assert metadata["uriParams"]["clientId"] == "MOCK-001"


def test_assertion_payload_is_array_when_final_transform_maps_payload(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "arrayFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/array"},
        },
        "final_processor": {
            "dwl_excerpt": """%dw 2.0
output application/json
---
payload map (item) -> {
  recordName: item.name,
  recordId: item.id
}"""
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Records",
                "match_attribute": "doc:name",
                "match_value": "Get Records",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
    }
    connector_key = "arrayFlow_http:request_Get_Records"

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        connector_samples={
            connector_key: {
                "response": '[{"name": "abc", "id": 123}]',
            }
        },
    )
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]

    assert_assert_module(assert_payload, '"recordName": "abc"')
    assert '"recordId": 123' in assert_payload


def test_analyzer_marks_mapobject_downstream_shape_as_object():
    analyzer = XMLAnalyzer()
    processor_chain = [
        {"type": "http:request", "doc_name": "Get Object", "config_ref": "HTTP"},
        {
            "type": "ee:transform",
            "doc_name": "Object Transform",
            "dwl_excerpt": "%dw 2.0\noutput application/json\n---\npayload mapObject ((value, key) -> {(key): value})",
            "payload_references": [],
        },
    ]

    mock_plan = analyzer._build_mock_plan(processor_chain)

    assert mock_plan[0]["result_shape"] == "object"
    assert "mapObject" in mock_plan[0]["downstream_dwl_excerpt"]


def test_assertion_payload_handles_pluck_as_array(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "pluckFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/pluck"},
        },
        "final_processor": {
            "dwl_excerpt": "%dw 2.0\noutput application/json\n---\npayload pluck $.name"
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Records",
                "match_attribute": "doc:name",
                "match_value": "Get Records",
                "return_attributes": {"status": 200},
                "media_type": "application/json",
            }
        ],
    }
    connector_key = "pluckFlow_http:request_Get_Records"

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        connector_samples={connector_key: {"response": '[{"name": "abc", "id": 123}]'}},
    )
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]

    assert_assert_module(assert_payload, '[\n  "abc"\n]')


def test_assertion_payload_evaluates_filter_selector_from_generated_mock(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "stateFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {
                "method": "GET",
                "requestPath": "/getState",
                "queryParams": {"country": "India"},
            },
            "hardcoded_literals": {"filter_country": "India"},
        },
        "final_processor": {
            "dwl_excerpt": """%dw 2.0
output application/json
---
{
  "states": (payload.data filter ((item, index) -> item.name == "India")).states[0]
}"""
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Request",
                "match_attribute": "doc:name",
                "match_value": "Request",
                "media_type": "application/json",
                "downstream_payload_references": ["payload.data"],
                "result_shape": "object",
            }
        ],
    }

    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert_assert_module(
        metadata["resource_files"]["assert_expression_payload_1.dwl"],
        '"states": [\n    {\n      "name": "Test State",\n      "state_code": "TS"\n    }\n  ]',
    )
    assert_assert_module(
        metadata["resource_files"]["assert_expression_payload_2.dwl"],
        '"states": null',
    )


def test_blueprint_mock_files_strip_dwl_header_from_llm_output(tmp_path):
    generator = MultiPassGenerator(
        lambda _prompt: "%dw 2.0\noutput application/json\n---\n{\n  \"status\": 200\n}",
        output_dir=str(tmp_path),
    )

    saved = generator.generate_mock_dwl_files(
        [{"mock_name": "mock_customer_response", "expected_payload_type": "json"}]
    )
    content = (tmp_path / "src/test/resources/mock_payloads/mock_customer_response.dwl").read_text()

    assert "mock_customer_response" in saved
    assert content == '{\n  "status": 200\n}\n'
    assert not content.startswith("%dw 2.0")
    assert "output application" not in content
    assert "---" not in content


def test_legacy_writer_mock_asset_files_do_not_add_dwl_header(tmp_path):
    writer = MUnitWriter(output_dir=str(tmp_path))

    mock_content = writer._convert_expression_to_dwl(
        '#[{"status": 200}]',
        "application/json",
        raw_resource=True,
    )
    set_event_content = writer._convert_expression_to_dwl(
        '#[{"id": "MOCK-001"}]',
        "application/json",
    )

    assert mock_content == '{"status": 200}\n'
    assert not mock_content.startswith("%dw 2.0")
    assert set_event_content == '{"id": "MOCK-001"}\n'
    assert not set_event_content.startswith("%dw 2.0")


def test_planner_targets_only_the_failed_connector_for_downstream_failure(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "twoConnectorFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/two"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"statusCode": 200},
                "media_type": "application/json",
            },
            {
                "action": "mock-when",
                "processor": "db:select",
                "doc_name": "Lookup Orders",
                "match_attribute": "doc:name",
                "match_value": "Lookup Orders",
                "return_attributes": {"statusCode": 200},
                "media_type": "application/java",
            },
        ],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert metadata["test_count"] == 5
    assert suite_xml.count("<munit-tools:error") == 2
    assert 'typeId="HTTP:CONNECTIVITY"' in suite_xml
    assert 'typeId="DB:CONNECTIVITY"' in suite_xml
    assert 'expectedErrorType="DB:CONNECTIVITY"' in suite_xml


def test_identical_mock_payload_and_attribute_files_are_reused_across_scenarios(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "duplicateMockFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/duplicate"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Get Customer",
                "match_attribute": "doc:name",
                "match_value": "Get Customer",
                "return_attributes": {"statusCode": 200},
                "media_type": "application/json",
            }
        ],
        "output_fields": ["id", "name"],
    }

    suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        scenarios=[
            {"name": "happy_path_a", "type": "happy_path", "description": "Happy path A"},
            {"name": "happy_path_b", "type": "happy_path", "description": "Happy path B"},
        ],
    )
    mock_payload_files = sorted(
        name for name in metadata["resource_files"]
        if name.startswith("mock_get-customer_") and not name.endswith("_attributes.dwl")
    )
    mock_attribute_files = sorted(
        name for name in metadata["resource_files"]
        if name.startswith("mock_get-customer_") and name.endswith("_attributes.dwl")
    )

    assert mock_payload_files == ["mock_get-customer_1_1.dwl"]
    assert mock_attribute_files == ["mock_get-customer_1_1_attributes.dwl"]
    assert "mock_get-customer_2_1.dwl" not in suite_xml
    assert "mock_get-customer_2_1_attributes.dwl" not in suite_xml
    assert suite_xml.count("mock_get-customer_1_1.dwl") == 2
    assert suite_xml.count("mock_get-customer_1_1_attributes.dwl") == 2


def test_analyzer_exposes_choice_and_error_handler_metadata():
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="choiceFlow">
    <http:listener path="/choice"/>
    <choice>
      <when expression="#[attributes.queryParams.kind == 'a']">
        <set-variable variableName="kind" value="a"/>
      </when>
      <otherwise>
        <set-variable variableName="kind" value="b"/>
      </otherwise>
    </choice>
    <http:request doc:name="Call Backend"/>
    <error-handler>
      <on-error-continue type="HTTP:CONNECTIVITY">
        <ee:transform>
          <ee:message>
            <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  status: "ERROR",
  message: "backend failed"
}]]></ee:set-payload>
          </ee:message>
        </ee:transform>
      </on-error-continue>
    </error-handler>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    context = summary["flow_contexts"]["choiceFlow"]

    assert context["branch_points"][0]["condition"] == "#[attributes.queryParams.kind == 'a']"
    assert context["branch_points"][1]["type"] == "otherwise"
    assert context["variable_writes"][0]["name"] == "kind"
    assert context["error_handler_details"][0]["type"] == "on-error-continue"
    assert context["error_handler_details"][0]["processors"][0]["type"] == "ee:transform"


def test_raise_error_choice_branch_does_not_mock_default_branch_processors(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="mainFlow">
    <http:listener path="/customers"/>
    <flow-ref name="validationFlow" doc:name="Validate request"/>
  </flow>
  <flow name="validationFlow">
    <choice doc:name="Validate choice">
      <when expression="#[payload.valid == false]">
        <raise-error type="APP:INVALID_INPUT" doc:name="Raise invalid input"/>
      </when>
      <otherwise>
        <http:request doc:name="Success API" method="POST" path="/success"/>
      </otherwise>
    </choice>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["mainFlow"]
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    raise_scenario = next(
        item for item in metadata["scenario_plan"]
        if item.get("name") == "raise-invalid-input"
    )
    assert raise_scenario["type"] == "validation_error"
    assert raise_scenario["expected_error_type"] == "APP:INVALID_INPUT"

    match = re.search(
        r'(<munit:test name="mainflow-raise-invalid-input-test"[\s\S]*?</munit:test>)',
        suite_xml,
    )
    assert match, suite_xml
    raise_test_xml = match.group(1)

    assert 'expectedErrorType="APP:INVALID_INPUT"' in raise_test_xml
    assert "Mock Success API" not in raise_test_xml
    assert "processor=\"http:request\"" not in raise_test_xml


def test_validation_choice_branch_does_not_mock_success_branch_processors(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:validation="http://www.mulesoft.org/schema/mule/validation"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="mainFlow">
    <http:listener path="/customers"/>
    <flow-ref name="validationFlow" doc:name="Validate request"/>
  </flow>
  <flow name="validationFlow">
    <choice doc:name="Validate choice">
      <when expression="#[payload.valid == false]">
        <validation:is-true expression="#[payload.valid]" doc:name="Validate flag"/>
      </when>
      <otherwise>
        <http:request doc:name="Success API" method="POST" path="/success"/>
      </otherwise>
    </choice>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["mainFlow"]
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    failure_scenario = next(
        item for item in metadata["scenario_plan"]
        if item.get("name") == "validate-flag"
    )
    assert failure_scenario["expected_error_type"] == "VALIDATION:IS_TRUE"

    match = re.search(
        r'(<munit:test name="mainflow-validate-flag-test"[\s\S]*?</munit:test>)',
        suite_xml,
    )
    assert match, suite_xml
    validation_test_xml = match.group(1)

    assert 'expectedErrorType="VALIDATION:IS_TRUE"' in validation_test_xml
    assert "Mock Success API" not in validation_test_xml
    assert "processor=\"http:request\"" not in validation_test_xml


def test_weather_style_validation_branches_get_realistic_inputs_and_no_empty_sections(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="weather-experience-flow">
    <http:listener doc:name="POST /api/weather" path="/api/weather" allowedMethods="POST"/>
    <flow-ref name="validate-request-flow" doc:name="Validate Request"/>
    <error-handler>
      <on-error-propagate type="HTTP:CONNECTIVITY" doc:name="External API Unreachable">
        <logger level="ERROR" doc:name="Log Connectivity Error" message="downstream failed"/>
      </on-error-propagate>
    </error-handler>
  </flow>
  <flow name="validate-request-flow">
    <choice doc:name="Validate Required Fields">
      <when expression="#[payload.latitude == null or payload.longitude == null]">
        <raise-error type="APP:VALIDATION_ERROR" doc:name="Missing Coordinates"/>
      </when>
      <when expression="#[payload.latitude &lt; -90.0 or payload.latitude &gt; 90.0]">
        <raise-error type="APP:VALIDATION_ERROR" doc:name="Invalid Latitude"/>
      </when>
      <when expression="#[payload.longitude &lt; -180.0 or payload.longitude &gt; 180.0]">
        <raise-error type="APP:VALIDATION_ERROR" doc:name="Invalid Longitude"/>
      </when>
      <otherwise>
        <flow-ref name="weather-api-validation-success-Flow" doc:name="Success Flow"/>
      </otherwise>
    </choice>
  </flow>
  <flow name="weather-api-validation-success-Flow">
    <ee:transform doc:name="Extract Request Variables">
      <ee:variables>
        <ee:set-variable variableName="latitude"><![CDATA[%dw 2.0
output application/java
---
payload.latitude]]></ee:set-variable>
        <ee:set-variable variableName="longitude"><![CDATA[%dw 2.0
output application/java
---
payload.longitude]]></ee:set-variable>
        <ee:set-variable variableName="cityName"><![CDATA[%dw 2.0
output application/java
---
payload.city default "Unknown"]]></ee:set-variable>
        <ee:set-variable variableName="units"><![CDATA[%dw 2.0
output application/java
---
payload.units default "celsius"]]></ee:set-variable>
      </ee:variables>
    </ee:transform>
    <flow-ref name="weather-process-flow" doc:name="Call Process Flow"/>
    <ee:transform doc:name="Build Final API Response">
      <ee:message>
        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
  "status": "success",
  "requestId": uuid(),
  "city": vars.cityName,
  "units": vars.units,
  "weather": payload
}]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
  <flow name="weather-process-flow">
    <flow-ref name="openmeteo-system-flow" doc:name="Call System API"/>
  </flow>
  <flow name="openmeteo-system-flow">
    <http:request method="GET" doc:name="GET Open-Meteo Forecast" path="/v1/forecast"/>
  </flow>
</mule>"""
    summary = XMLAnalyzer().analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["weather-experience-flow"]
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    resource_files = metadata["resource_files"]
    combined_set_events = "\n".join(
        content for name, content in resource_files.items()
        if name.startswith("set-event_payload_")
    )

    assert suite_xml.count('expectedErrorType="APP:VALIDATION_ERROR"') == 3
    assert 'name="weather-experience-flow-missing-coordinates-test"' in suite_xml
    assert 'name="weather-experience-flow-invalid-latitude-test"' in suite_xml
    assert 'name="weather-experience-flow-invalid-longitude-test"' in suite_xml
    assert "<munit:behavior/>" not in suite_xml
    assert "<munit:validation/>" not in suite_xml
    validation_block = re.search(
        r'(<munit:test name="weather-experience-flow-missing-coordinates-test"[\s\S]*?</munit:test>)',
        suite_xml,
    ).group(1)
    assert "Verify Log Connectivity Error" not in validation_block
    assert '<munit-tools:spy' not in suite_xml
    assert '"latitude": 26.889278' in combined_set_events
    assert '"longitude": 75.83149' in combined_set_events
    assert '"city": "Jaipur"' in combined_set_events
    assert '"units": "celsius"' in combined_set_events
    assert '"latitude": 91.0' in combined_set_events
    assert '"longitude": 181.0' in combined_set_events
    assert "MOCK-VALUE" not in combined_set_events


def test_downstream_failure_does_not_mock_later_success_connectors(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "orderedFlow",
        "set_event_plan": {
            "payload_expression": "{}",
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/ordered"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "First API",
                "match_attribute": "doc:name",
                "match_value": "First API",
            },
            {
                "action": "mock-when",
                "processor": "db:select",
                "doc_name": "Later DB",
                "match_attribute": "doc:name",
                "match_value": "Later DB",
            },
        ],
    }

    suite_xml, _metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        scenarios=[
            {
                "name": "first_api_failure",
                "type": "downstream_failure",
                "description": "First API fails",
                "failed_processor": "http:request",
                "failed_match_value": "First API",
                "expected_error_type": "HTTP:CONNECTIVITY",
                "assertion_strategy": "expected_error",
            }
        ],
    )

    assert "Mock First API failure" in suite_xml
    assert "Mock Later DB" not in suite_xml
    assert "processor=\"db:select\"" not in suite_xml


def test_error_handler_failure_uses_payload_assertion_not_expected_error(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "handledFlow",
        "error_handlers": ["on-error-continue"],
        "error_handler_details": [
            {
                "type": "on-error-continue",
                "dwl_excerpt": "%dw 2.0\noutput application/json\n---\n{\n  status: \"ERROR\",\n  message: \"backend failed\"\n}",
            }
        ],
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/handled"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Call Backend",
                "match_attribute": "doc:name",
                "match_value": "Call Backend",
                "return_attributes": {"statusCode": 200},
                "media_type": "application/json",
            }
        ],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    failure_assert = metadata["resource_files"]["assert_expression_payload_3.dwl"]

    assert 'handledFlow-error' not in suite_xml
    assert 'expectedErrorType="HTTP:CONNECTIVITY"' not in suite_xml
    assert "Assert error response" in suite_xml
    assert_assert_module(failure_assert, '"status": "ERROR"')
    assert '"message": "backend failed"' in failure_assert


def test_logger_only_error_handler_uses_expected_error_and_verify_call(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "loggerErrorFlow",
        "error_handlers": ["on-error-propagate"],
        "error_handler_details": [
            {
                "type": "on-error-propagate",
                "processors": [
                    {
                        "type": "logger",
                        "doc_name": "Log Backend Error",
                    }
                ],
            }
        ],
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/logger-error"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Call Backend",
                "match_attribute": "doc:name",
                "match_value": "Call Backend",
                "return_attributes": {"statusCode": 200},
                "media_type": "application/json",
            }
        ],
    }

    suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert 'expectedErrorType="HTTP:CONNECTIVITY"' in suite_xml
    assert "Assert error response" not in suite_xml
    failure_plan = metadata["munit_plan"]["validation"][2]
    assert failure_plan["expectedErrorType"] == "HTTP:CONNECTIVITY"
    assert failure_plan["assertions"] == []
    assert failure_plan["verifications"][0]["processor"] == "logger"
    assert "assert_expression_payload_3.dwl" not in metadata["resource_files"]
    assert "mock_call_backend_3_1.dwl" not in metadata["resource_files"]
    assert 'processor="logger"' in suite_xml
    assert 'whereValue="Log Backend Error"' in suite_xml


def test_duplicate_scenario_types_get_unique_munit_test_names(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "duplicateFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/duplicate"},
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Customer API",
                "match_attribute": "doc:name",
                "match_value": "Customer API",
            },
            {
                "action": "mock-when",
                "processor": "http:request",
                "doc_name": "Order API",
                "match_attribute": "doc:name",
                "match_value": "Order API",
            },
        ],
    }

    suite_xml, _metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert 'name="duplicateflow-customer-api-failure-test"' in suite_xml
    assert 'name="duplicateflow-order-api-failure-test"' in suite_xml
    assert suite_xml.count('name="duplicateflow-downstream-failure-test"') == 0


def test_empty_downstream_array_scenario_returns_empty_array(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "arrayFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/array"},
        },
        "final_processor": {
            "dwl_excerpt": "%dw 2.0\noutput application/json\n---\npayload map (item) -> { id: item.id }"
        },
        "mock_plan": [
            {
                "action": "mock-when",
                "processor": "db:select",
                "doc_name": "Select Rows",
                "match_attribute": "doc:name",
                "match_value": "Select Rows",
                "result_shape": "array",
                "media_type": "application/java",
            }
        ],
    }

    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert metadata["scenario_plan"][1]["type"] == "empty_downstream_response"
    assert metadata["resource_files"]["mock_select-rows_2_1.dwl"] == "[]\n"
    assert_assert_module(metadata["resource_files"]["assert_expression_payload_2.dwl"], "[]")


def test_branch_scenario_sets_query_param_from_choice_condition(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "choiceFlow",
        "branch_points": [
            {
                "type": "when",
                "condition": "#[attributes.queryParams.kind == 'premium']",
                "description": "premium route",
            }
        ],
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {"method": "GET", "requestPath": "/choice", "queryParams": {}},
        },
        "mock_plan": [],
    }

    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    attribute_files = [
        name for name in metadata["resource_files"]
        if name.startswith("set-event_attributes_")
    ]

    assert metadata["scenario_plan"][1]["type"] == "branch_path"
    assert attribute_files == ["set-event_attributes_1.dwl", "set-event_attributes_2.dwl"]
    assert '"kind": "premium"' in metadata["resource_files"]["set-event_attributes_2.dwl"]


def test_set_event_attributes_include_required_headers_query_and_uri_params(tmp_path):
    mule_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="secureCustomerFlow">
    <http:listener doc:name="Listener" path="/customers/{customerId}" allowedMethods="GET"/>
    <set-variable doc:name="Read Auth" variableName="authToken" value="#[attributes.headers.authorization]"/>
    <choice>
      <when expression="#[attributes.queryParams.region == 'west' and attributes.uriParams.customerId != null]">
        <set-variable variableName="region" value="#[attributes.queryParams.region]"/>
      </when>
    </choice>
    <http:request doc:name="Call external API"/>
  </flow>
</mule>"""
    analyzer = XMLAnalyzer()
    summary = analyzer.analyze_mule_project(mule_xml)
    flow_context = summary["flow_contexts"]["secureCustomerFlow"]

    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")
    set_attrs = metadata["resource_files"]["set-event_attributes_1.dwl"]

    assert '"requestPath": "/customers/{customerId}"' in set_attrs
    assert '"authorization": "Bearer test-token"' in set_attrs
    assert '"region": "MOCK-VALUE"' in set_attrs
    assert '"customerId": "MOCK-001"' in set_attrs


def test_sample_request_attributes_are_merged_into_set_event_attributes(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "secureCustomerFlow",
        "set_event_plan": {
            "payload_expression": '""',
            "payload_media_type": "application/java",
            "attributes_template": {
                "method": "GET",
                "requestPath": "/customers/{customerId}",
                "queryParams": {"region": "MOCK-VALUE"},
                "headers": {"content-type": "application/json", "authorization": "Bearer test-token"},
                "uriParams": {"customerId": "MOCK-001"},
            },
        },
        "mock_plan": [],
    }
    sample_payload = """{
      "request": {
        "headers": {"authorization": "Bearer real-test-token", "x-client-id": "client-123"},
        "queryParams": {"region": "east"},
        "uriParams": {"customerId": "CUST-12345"}
      },
      "response": {"status": "OK"}
    }"""

    _suite_xml, metadata = builder.build_suite(
        flow_context,
        generation_mode="recorder",
        sample_payload=sample_payload,
    )
    set_payload = metadata["resource_files"]["set-event_payload_1.dwl"]
    set_attrs = metadata["resource_files"]["set-event_attributes_1.dwl"]

    assert set_payload == "{}\n"
    assert '"authorization": "Bearer real-test-token"' in set_attrs
    assert '"x-client-id": "client-123"' in set_attrs
    assert '"region": "east"' in set_attrs
    assert '"customerId": "CUST-12345"' in set_attrs


def test_assertion_resolves_tracked_variable_values(tmp_path):
    builder = DeterministicMUnitBuilder(output_dir=str(tmp_path))
    flow_context = {
        "target_flow": "varFlow",
        "set_event_plan": {
            "payload_expression": '{"id": "MOCK-001"}',
            "payload_media_type": "application/json",
            "attributes_template": {"method": "POST", "requestPath": "/var"},
        },
        "variable_writes": [
            {"name": "customerName", "value": "'mike'", "value_type": "string"},
        ],
        "final_processor": {
            "dwl_excerpt": "%dw 2.0\noutput application/json\n---\n{\n  name: vars.customerName\n}"
        },
        "mock_plan": [],
    }

    _suite_xml, metadata = builder.build_suite(flow_context, generation_mode="recorder")

    assert_assert_module(metadata["resource_files"]["assert_expression_payload_1.dwl"], '"name": "mike"')
