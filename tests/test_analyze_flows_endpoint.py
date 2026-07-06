import io
import json
import zipfile

from app import analysis_cache, app


MULE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation">
  <flow name="api-flow">
    <http:listener path="/api"/>
    <http:request doc:name="Call API"/>
  </flow>
</mule>"""


def _zip_bytes(files):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    payload.seek(0)
    return payload


def test_analyze_flows_accepts_flat_mule_xml_zip():
    client = app.test_client()

    response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"api.xml": MULE_XML}), "app.zip")},
        content_type="multipart/form-data",
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["success"] is True
    assert body["flow_summary"]["flows_count"] == 1
    assert body["selection"]["recommended_flows"][0]["name"] == "api-flow"
    assert body["project_scan"]["mule_files"] == ["api.xml"]


def test_analyze_flows_accepts_nested_non_maven_code_zip():
    client = app.test_client()

    response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"exported-code/app/api.xml": MULE_XML}), "code.zip")},
        content_type="multipart/form-data",
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["success"] is True
    assert body["flow_summary"]["flows_count"] == 1


def test_analyze_flows_accepts_zip_with_nested_project_zip():
    client = app.test_client()
    nested_project = _zip_bytes({"nested-app/src/main/mule/api.xml": MULE_XML})

    response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"bundle/project-source.zip": nested_project.getvalue()}), "bundle.zip")},
        content_type="multipart/form-data",
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["success"] is True
    assert body["flow_summary"]["flows_count"] == 1
    assert body["project_scan"]["nested_archives"][0]["path"] == "bundle/project-source.zip"


def test_analyze_flows_scans_all_src_main_candidates():
    client = app.test_client()

    response = client.post(
        "/api/enhanced/analyze-flows",
        data={
            "xml_file": (
                _zip_bytes({
                    "module-a/src/main/resources/log4j2.xml": "<configuration/>",
                    "module-b/src/main/mule/api.xml": MULE_XML,
                }),
                "multi-module.zip",
            )
        },
        content_type="multipart/form-data",
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["success"] is True
    assert body["flow_summary"]["flows_count"] == 1
    assert "module-b/src/main/mule/api.xml" in body["project_scan"]["mule_files"]


def test_analyze_flows_accepts_mule_extension_config_file():
    client = app.test_client()

    response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"api.mule": MULE_XML}), "mule-extension.zip")},
        content_type="multipart/form-data",
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["success"] is True
    assert body["flow_summary"]["flows_count"] == 1
    assert body["project_scan"]["mule_files"] == ["api.mule"]


def test_dependency_resolution_rejects_upload_and_manual_links_together():
    analysis_id = "exclusive-dependency-choice"
    analysis_cache[analysis_id] = {
        "xml_file": MULE_XML,
        "base_xml_file": MULE_XML,
        "build_validation": {},
        "project_scan": {},
        "base_project_scan": {},
    }
    client = app.test_client()

    try:
        response = client.post(
            "/api/enhanced/resolve-selected-flow",
            data={
                "analysis_id": analysis_id,
                "selected_flows": json.dumps(["api-flow"]),
                "dependency_resolution_mode": "upload",
                "flow_test_data": json.dumps({
                    "externalFlowLinks": [{
                        "externalFlow": "missing-flow",
                        "linkedLocalFlows": ["api-flow"],
                    }]
                }),
                "dependency_artifact": (
                    io.BytesIO(MULE_XML.encode()),
                    "dependency.xml",
                ),
            },
            content_type="multipart/form-data",
        )
    finally:
        analysis_cache.pop(analysis_id, None)

    assert response.status_code == 400
    assert "either dependency artifact upload or manual flow declaration" in response.get_json()["error"]


def test_uploaded_dependency_flow_continues_dynamic_trace_into_local_flows():
    main_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
  <flow name="flowA">
    <http:listener path="/trace"/>
    <flow-ref name="flowB"/>
  </flow>
  <sub-flow name="flowB">
    <ee:transform>
      <ee:variables>
        <ee:set-variable variableName="flowName"><![CDATA['flowD']]></ee:set-variable>
      </ee:variables>
    </ee:transform>
    <flow-ref name="flowC"/>
  </sub-flow>
  <sub-flow name="flowD">
    <flow-ref name="flowE"/>
  </sub-flow>
  <sub-flow name="flowE">
    <logger message="trace complete"/>
  </sub-flow>
</mule>"""
    dependency_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http">
  <flow name="flowC">
    <http:request method="GET" path="/dependency" doc:name="Call dependency API"/>
    <flow-ref name="#[flowVars.flowName]" doc:name="Call dynamic local flow"/>
  </flow>
</mule>"""
    client = app.test_client()

    analysis_response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"src/main/mule/main.xml": main_xml}), "main.zip")},
        content_type="multipart/form-data",
    )
    analysis_body = analysis_response.get_json()
    assert analysis_response.status_code == 200

    resolve_response = client.post(
        "/api/enhanced/resolve-selected-flow",
        data={
            "analysis_id": analysis_body["analysis_id"],
            "selected_flows": json.dumps(["flowA"]),
            "dependency_resolution_mode": "upload",
            "dependency_artifact": (
                io.BytesIO(dependency_xml.encode()),
                "retryable-app.xml",
            ),
        },
        content_type="multipart/form-data",
    )
    body = resolve_response.get_json()

    assert resolve_response.status_code == 200
    assert body["success"] is True
    assert body["selected_flow_trace"]["external_stops"] == []
    assert body["selected_flow_trace"]["traces"][0]["execution_flows"] == [
        "flowA",
        "flowB",
        "flowC",
        "flowD",
        "flowE",
    ]
    flow_c_node = next(
        node
        for node in body["selected_flow_trace"]["traces"][0]["nodes"]
        if node["name"] == "flowC"
    )
    assert flow_c_node["source_file"] == "retryable-app.xml"
    selected_flow = next(
        flow
        for group in (
            "entry_point_flows",
            "api_resource_flows",
            "internal_flows",
        )
        for flow in body["selection"].get(group, [])
        if flow["name"] == "flowA"
    )
    assert any(
        connector.get("doc_name") == "Call dependency API"
        for connector in selected_flow["mock_connectors"]
    )


def test_uploaded_dependency_lookup_uses_flowvars_from_previous_flow():
    main_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http">
  <flow name="flowA">
    <http:listener path="/lookup"/>
    <set-variable variableName="invokeFlow" value="flowD"/>
    <flow-ref name="flowC"/>
  </flow>
  <sub-flow name="flowD"><flow-ref name="flowE"/></sub-flow>
  <sub-flow name="flowE"><logger message="done"/></sub-flow>
</mule>"""
    dependency_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
  <flow name="flowC">
    <ee:transform>
      <ee:message>
        <ee:set-payload><![CDATA[#[lookup(flowVars.invokeFlow, payload)]]]></ee:set-payload>
      </ee:message>
    </ee:transform>
  </flow>
</mule>"""
    client = app.test_client()

    analysis_response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"src/main/mule/main.xml": main_xml}), "main.zip")},
        content_type="multipart/form-data",
    )
    analysis_id = analysis_response.get_json()["analysis_id"]
    resolve_response = client.post(
        "/api/enhanced/resolve-selected-flow",
        data={
            "analysis_id": analysis_id,
            "selected_flows": json.dumps(["flowA"]),
            "dependency_resolution_mode": "upload",
            "dependency_artifact": (
                io.BytesIO(dependency_xml.encode()),
                "shared-retry.xml",
            ),
        },
        content_type="multipart/form-data",
    )
    trace = resolve_response.get_json()["selected_flow_trace"]["traces"][0]

    assert resolve_response.status_code == 200
    assert trace["execution_flows"] == ["flowA", "flowC", "flowD", "flowE"], trace
    assert trace["unresolved_flow_refs"] == []


def test_uploaded_dependency_reports_unresolved_dynamic_call_in_trace_step():
    main_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http">
  <flow name="flowA">
    <http:listener path="/trace"/>
    <flow-ref name="flowC"/>
  </flow>
  <sub-flow name="flowD"><logger message="local flow"/></sub-flow>
</mule>"""
    dependency_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core">
  <sub-flow name="flowC">
    <flow-ref name="#[vars.runtimeOnlyFlow]" doc:name="Unresolved runtime route"/>
  </sub-flow>
</mule>"""
    client = app.test_client()

    analysis_response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"src/main/mule/main.xml": main_xml}), "main.zip")},
        content_type="multipart/form-data",
    )
    analysis_body = analysis_response.get_json()

    resolve_response = client.post(
        "/api/enhanced/resolve-selected-flow",
        data={
            "analysis_id": analysis_body["analysis_id"],
            "selected_flows": json.dumps(["flowA"]),
            "dependency_resolution_mode": "upload",
            "dependency_artifact": (
                io.BytesIO(dependency_xml.encode()),
                "flow-c.xml",
            ),
        },
        content_type="multipart/form-data",
    )
    trace = resolve_response.get_json()["selected_flow_trace"]["traces"][0]

    assert resolve_response.status_code == 200
    assert trace["execution_flows"] == ["flowA", "flowC"]
    assert trace["unresolved_flow_refs"][0]["expression"] == "#[vars.runtimeOnlyFlow]"


def test_retryable_xml_inherits_dataweave_flow_name_across_two_local_flows():
    main_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core">
  <flow name="flow-1">
    <http:listener path="/employees"/>
    <ee:transform>
      <ee:variables>
        <ee:set-variable variableName="flowName"><![CDATA[%dw 2.0
output application/java
---
"sf-emp-read-sapi"
]]></ee:set-variable>
      </ee:variables>
    </ee:transform>
    <flow-ref name="flow-2"/>
  </flow>
  <sub-flow name="flow-2">
    <flow-ref name="invoke-endpoint-until-successfull"/>
  </sub-flow>
  <sub-flow name="sf-emp-read-sapi">
    <flow-ref name="employee-response-flow"/>
  </sub-flow>
  <sub-flow name="employee-response-flow">
    <logger message="complete"/>
  </sub-flow>
</mule>"""
    retryable_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core">
  <flow name="invoke-endpoint-until-successfull">
    <flow-ref name="#[vars.flowName]" doc:name="Call vars.flowName"/>
  </flow>
</mule>"""
    client = app.test_client()

    analysis_response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"src/main/mule/main.xml": main_xml}), "main.zip")},
        content_type="multipart/form-data",
    )
    analysis_id = analysis_response.get_json()["analysis_id"]
    resolve_response = client.post(
        "/api/enhanced/resolve-selected-flow",
        data={
            "analysis_id": analysis_id,
            "selected_flows": json.dumps(["flow-1"]),
            "dependency_resolution_mode": "upload",
            "dependency_artifact": (
                io.BytesIO(retryable_xml.encode()),
                "retryable.xml",
            ),
        },
        content_type="multipart/form-data",
    )
    trace = resolve_response.get_json()["selected_flow_trace"]["traces"][0]

    assert resolve_response.status_code == 200
    assert trace["execution_flows"] == [
        "flow-1",
        "flow-2",
        "invoke-endpoint-until-successfull",
        "sf-emp-read-sapi",
        "employee-response-flow",
    ]
    assert trace["unresolved_flow_refs"] == []


def test_uploaded_flow_resolves_transitive_nested_variable_alias():
    main_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http">
  <flow name="flowA">
    <http:listener path="/nested-alias"/>
    <set-variable variableName="param"
                  value='#[{ invokeEndpointFlow: "flowD" }]'/>
    <flow-ref name="flowC"/>
  </flow>
  <sub-flow name="flowD"><flow-ref name="flowE"/></sub-flow>
  <sub-flow name="flowE"><logger message="done"/></sub-flow>
</mule>"""
    dependency_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core">
  <flow name="flowC">
    <set-variable variableName="flowName"
                  value="#[vars.param.invokeEndpointFlow]"/>
    <flow-ref name="#[vars.flowName]"/>
  </flow>
</mule>"""
    client = app.test_client()

    analysis_response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"src/main/mule/main.xml": main_xml}), "main.zip")},
        content_type="multipart/form-data",
    )
    analysis_id = analysis_response.get_json()["analysis_id"]
    resolve_response = client.post(
        "/api/enhanced/resolve-selected-flow",
        data={
            "analysis_id": analysis_id,
            "selected_flows": json.dumps(["flowA"]),
            "dependency_resolution_mode": "upload",
            "dependency_artifact": (
                io.BytesIO(dependency_xml.encode()),
                "retryable.xml",
            ),
        },
        content_type="multipart/form-data",
    )
    trace = resolve_response.get_json()["selected_flow_trace"]["traces"][0]

    assert resolve_response.status_code == 200
    assert trace["execution_flows"] == [
        "flowA",
        "flowC",
        "flowD",
        "flowE",
    ]
    assert trace["unresolved_flow_refs"] == []


def test_uploaded_flow_tracks_route_across_variable_payload_and_attributes():
    main_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http">
  <flow name="flowA">
    <http:listener path="/cross-scope"/>
    <set-variable variableName="param"
                  value='#[{ invokeEndpointFlow: "flowD" }]'/>
    <flow-ref name="flowB"/>
  </flow>
  <sub-flow name="flowB">
    <set-payload value="#[{ nextFlow: vars.param.invokeEndpointFlow }]"/>
    <flow-ref name="flowC"/>
  </sub-flow>
  <sub-flow name="flowD"><flow-ref name="flowE"/></sub-flow>
  <sub-flow name="flowE"><logger message="done"/></sub-flow>
</mule>"""
    dependency_xml = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core">
  <flow name="flowC">
    <set-attributes value="#[{ route: payload.nextFlow }]"/>
    <set-variable variableName="flowName"
                  value="#[attributes.route]"/>
    <flow-ref name="#[vars.flowName]"/>
  </flow>
</mule>"""
    client = app.test_client()

    analysis_response = client.post(
        "/api/enhanced/analyze-flows",
        data={"xml_file": (_zip_bytes({"src/main/mule/main.xml": main_xml}), "main.zip")},
        content_type="multipart/form-data",
    )
    analysis_id = analysis_response.get_json()["analysis_id"]
    resolve_response = client.post(
        "/api/enhanced/resolve-selected-flow",
        data={
            "analysis_id": analysis_id,
            "selected_flows": json.dumps(["flowA"]),
            "dependency_resolution_mode": "upload",
            "dependency_artifact": (
                io.BytesIO(dependency_xml.encode()),
                "external-routes.xml",
            ),
        },
        content_type="multipart/form-data",
    )
    trace = resolve_response.get_json()["selected_flow_trace"]["traces"][0]

    assert resolve_response.status_code == 200
    assert trace["execution_flows"] == [
        "flowA",
        "flowB",
        "flowC",
        "flowD",
        "flowE",
    ]
    assert trace["unresolved_flow_refs"] == []
