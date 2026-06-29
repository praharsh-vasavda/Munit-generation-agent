"""
Compliance policy for MUnit generation.

The generator is a static-analysis tool. It may use project artifacts and
explicit user-provided examples, but it must not fetch live business data from
external systems while generating tests.
"""

from __future__ import annotations

from typing import Dict, List


class CompliancePolicy:
    """Static policy shared by analyzers, builders, validators, and prompts."""

    ALLOWED_DATA_SOURCES: List[str] = [
        "Uploaded Mule XML, RAML, DataWeave, properties, and project files",
        "Uploaded business use case files",
        "User-provided request/response and connector mock samples",
        "Confluence content explicitly provided by the user",
        "Static literals and schemas found in the Mule project",
    ]

    FORBIDDEN_DATA_SOURCES: List[str] = [
        "Live database queries",
        "Live Salesforce, SAP, NetSuite, or SaaS connector calls",
        "Live outbound HTTP/SOAP calls",
        "Runtime secrets, tokens, credentials, or production records",
        "Any external system call made only to discover test data",
    ]

    @classmethod
    def metadata(cls) -> Dict:
        return {
            "mode": "static_analysis_only",
            "live_external_data_reads_allowed": False,
            "allowed_data_sources": list(cls.ALLOWED_DATA_SOURCES),
            "forbidden_data_sources": list(cls.FORBIDDEN_DATA_SOURCES),
            "mock_data_rule": (
                "External connector data must come from user-provided samples, "
                "project examples/schemas, downstream DataWeave usage, or safe synthetic values."
            ),
        }

    @classmethod
    def prompt_text(cls) -> str:
        allowed = "\n".join(f"- {item}" for item in cls.ALLOWED_DATA_SOURCES)
        forbidden = "\n".join(f"- {item}" for item in cls.FORBIDDEN_DATA_SOURCES)
        return (
            "## DATA SECURITY AND COMPLIANCE POLICY\n"
            "MUnit generation must use static analysis only. Do not connect to external systems.\n"
            "Allowed data sources:\n"
            f"{allowed}\n"
            "Forbidden data sources:\n"
            f"{forbidden}\n"
            "Mock payloads must be derived from allowed sources or safe synthetic values only."
        )
