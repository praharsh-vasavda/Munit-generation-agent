from unittest.mock import patch
import io
import zipfile

from werkzeug.datastructures import FileStorage

import pytest

from app import generator


class FakeConfluenceReader:
    def __init__(self, url, token, email):
        self.url = url
        self.token = token
        self.email = email

    def fetch_page_content(self, page_url):
        return (
            "Scenario: Happy path customer lookup returns account details\n"
            "Business rule: authorization header is required\n"
            "Expected: status is SUCCESS"
        )


def test_confluence_url_is_fetched_as_business_use_case_content():
    params = {
        "confluence_url": "https://example.atlassian.net/wiki/spaces/API/pages/123/UseCase",
        "confluence_token": "token",
        "confluence_email": "user@example.com",
    }

    with patch("app.ConfluenceReader", FakeConfluenceReader):
        content = generator._fetch_usecase_content(params)

    assert "Happy path customer lookup" in content
    assert "authorization header is required" in content


def test_confluence_source_requires_credentials():
    params = {
        "usecase_source": "confluence",
        "confluence_url": "https://example.atlassian.net/wiki/spaces/API/pages/123/UseCase",
    }

    with pytest.raises(Exception, match="email/token is missing"):
        generator._fetch_usecase_content(params)


def test_local_uploaded_usecase_text_is_used_as_business_context():
    upload = FileStorage(
        stream=io.BytesIO(b"Scenario: Validate premium customer success\nExpected: status SUCCESS"),
        filename="usecase.md",
    )

    content = generator._read_uploaded_usecase_file(upload)

    assert "Validate premium customer success" in content
    assert "status SUCCESS" in content


def test_local_uploaded_usecase_zip_is_combined_as_business_context():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("docs/scenario.md", "Scenario: Missing authorization header returns error")
        zip_file.writestr("docs/rules.txt", "Business rule: authorization header is mandatory")
    archive.seek(0)
    upload = FileStorage(stream=archive, filename="usecases.zip")

    content = generator._read_uploaded_usecase_file(upload)

    assert "docs/scenario.md" in content
    assert "Missing authorization header returns error" in content
    assert "authorization header is mandatory" in content
