"""
Semantic validation for generated MUnit XML against flow analysis artifacts.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Set


class MUnitSemanticValidator:
    """Validate that generated MUnit matches analyzer mock_plan and MUnit syntax rules."""

    INVALID_PROCESSOR_PATTERN = re.compile(r'processor="[^"]*::')

    def validate(
        self,
        suite_xml: str,
        flow_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "mock_coverage": {},
            "assertion_count": 0,
            "mock_count": 0,
        }

        try:
            root = ET.fromstring(suite_xml)
        except ET.ParseError as exc:
            result["valid"] = False
            result["errors"].append(f"Invalid XML: {exc}")
            return result

        if self.INVALID_PROCESSOR_PATTERN.search(suite_xml):
            result["valid"] = False
            result["errors"].append(
                'Invalid mock/verify processor syntax (found "::"). Use processor="http:request" not "http:request::operation".'
            )

        expected_mocks = {
            item.get("match_value") or item.get("doc_name")
            for item in (flow_context.get("mock_plan") or [])
            if item.get("action") == "mock-when" and (item.get("match_value") or item.get("doc_name"))
        }

        found_mocks = self._extract_mock_doc_names(suite_xml)
        result["mock_count"] = len(found_mocks)
        result["assertion_count"] = len(re.findall(r"munit-tools:assert", suite_xml))

        missing = expected_mocks - found_mocks
        extra = found_mocks - expected_mocks

        result["mock_coverage"] = {
            "expected": sorted(expected_mocks),
            "found": sorted(found_mocks),
            "missing": sorted(missing),
            "extra": sorted(extra),
        }

        if missing:
            result["valid"] = False
            result["errors"].append(
                f"Missing mock-when for outbound connector(s): {', '.join(sorted(missing))}"
            )

        if extra:
            result["warnings"].append(
                f"Extra mock-when entries (not in mock_plan): {', '.join(sorted(extra))}"
            )

        if result["assertion_count"] > 5:
            result["warnings"].append(
                f"High assertion count ({result['assertion_count']}); Studio recorder style typically uses 1 expression assert."
            )

        set_event = flow_context.get("set_event_plan") or {}
        if set_event.get("attributes_template", {}).get("queryParams"):
            if "queryParams" not in suite_xml and "set-event_attributes_" not in suite_xml:
                result["warnings"].append(
                    "Flow reads attributes.queryParams but generated set-event may not include queryParams."
                )

        return result

    def _extract_mock_doc_names(self, suite_xml: str) -> Set[str]:
        names: Set[str] = set()
        for match in re.finditer(
            r'<munit-tools:mock-when[^>]*>.*?<munit-tools:with-attribute\s+attributeName="doc:name"\s+whereValue="([^"]+)"',
            suite_xml,
            re.DOTALL,
        ):
            names.add(match.group(1))
        return names
