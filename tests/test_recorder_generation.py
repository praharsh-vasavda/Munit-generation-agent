from core.deterministic_munit_builder import DeterministicMUnitBuilder
from core.xml_analyzer import XMLAnalyzer
from core.pipeline import MultiPassGenerator
from munitWriter.munit_writer import MUnitWriter


def assert_assert_module(content, expected_fragment):
    assert content.startswith("%dw 2.0\nimport * from dw::test::Asserts\n")
    assert "payload must equalTo(" in content
    assert expected_fragment in content


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
    assert metadata["scenario_plan"][1]["type"] == "empty_downstream_response"
    assert metadata["scenario_plan"][2]["type"] == "downstream_failure"
    assert metadata["preflight_validation"]["valid"] is True
    assert "MunitTools::getResourceAsString('getCustomerFlowtest/mock_get-customer_1_1.dwl')" in suite_xml
    assert (
        "MunitTools::getResourceAsString('getCustomerFlowtest/mock_get-customer_1_1_attributes.dwl')"
        in suite_xml
    )
    assert "#[{'status': 200}]" not in suite_xml
    assert "#[{\"status\": 200}]" not in suite_xml

    mock_payload = metadata["resource_files"]["mock_get-customer_1_1.dwl"]
    mock_attrs = metadata["resource_files"]["mock_get-customer_1_1_attributes.dwl"]
    set_payload = metadata["resource_files"]["set-event_payload_1.dwl"]
    set_attrs = metadata["resource_files"]["set-event_attributes_1.dwl"]
    assert_payload = metadata["resource_files"]["assert_expression_payload_1.dwl"]

    assert not mock_payload.startswith("%dw 2.0")
    assert not mock_attrs.startswith("%dw 2.0")
    assert '"status": "ACTIVE"' in mock_payload
    assert mock_attrs == '{\n  "status": 200\n}\n'
    assert 'mediaType="application/java"' in suite_xml
    assert '<munit:attributes value="#[MunitTools::getResourceAsString' in suite_xml
    assert '<munit-tools:attributes value="#[MunitTools::getResourceAsString' in suite_xml
    assert 'mock_get-customer_1_1_attributes.dwl\')]" mediaType="application/java"' in suite_xml
    assert set_payload == '"" as Binary {base: "64"}\n'
    assert not set_attrs.startswith("%dw 2.0")
    assert set_attrs == '{\n  "method": "GET",\n  "requestPath": "/abc/path",\n  "queryParams": {}\n}\n'
    assert '"method": "GET"' in set_attrs
    assert '"requestPath": "/abc/path"' in set_attrs
    assert "payload must notNullValue()" not in assert_payload
    assert_assert_module(assert_payload, '"status": "ACTIVE"')
    assert '"id": "MOCK-001"' in assert_payload
    assert "import getCustomerFlowtest::assert_expression_payload_1" in suite_xml
    assert 'expectedErrorType="HTTP:CONNECTIVITY"' in suite_xml


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

    assert metadata["scenario_plan"][1]["type"] == "branch_path"
    assert '"kind": "premium"' in metadata["resource_files"]["set-event_attributes_2.dwl"]


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
