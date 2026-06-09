import io
import zipfile

from app import app


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
