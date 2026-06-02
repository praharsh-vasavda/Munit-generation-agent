"""
MUnit XML writer for formatting and saving generated test files.
"""

import os
import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
from pathlib import Path
from typing import Dict, Optional
from rich.console import Console


class MUnitWriter:
    """Writes and formats MUnit XML files."""

    def __init__(self, output_dir: str = "./output"):
        """
        Initialize MUnit writer.
        
        Args:
            output_dir: Directory to save generated files
        """
        self.console = Console()
        self.output_dir = Path(output_dir)
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_munit_file(self, xml_content: str, flow_name: str, metadata: Optional[Dict] = None) -> str:
        """
        Clean, validate, format and save MUnit XML file.
        
        Args:
            xml_content: Raw XML content from LLM
            flow_name: Name of the main flow being tested
            metadata: Optional metadata about generation
            
        Returns:
            Path to saved file
            
        Raises:
            Exception: If XML is invalid or cannot be saved
        """
        try:
            # Clean the XML content
            cleaned_xml = self._clean_xml_content(xml_content)

            # Normalize suite/test naming so each generated file has
            # deterministic, file-specific MUnit test names.
            cleaned_xml = self._normalize_munit_names(cleaned_xml, flow_name, metadata)
            
            # Validate XML structure
            if not self._validate_xml(cleaned_xml):
                raise Exception("Generated content is not valid XML")
            
            # Format/pretty print the XML
            formatted_xml = self._format_xml(cleaned_xml)
            
            # Generate filename
            filename = self._generate_filename(flow_name)
            file_path = self.output_dir / filename
            
            # Write to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(formatted_xml)

            mock_asset_files = self._write_mock_support_files(formatted_xml, flow_name, metadata)
            
            # Log success
            self.console.print(f"[green]MUnit file saved successfully:[/green]")
            self.console.print(f"  File: {file_path}")
            self.console.print(f"  Size: {len(formatted_xml)} characters")
            if mock_asset_files:
                self.console.print(f"  Mock assets: {len(mock_asset_files)} DWL file(s)")
            
            if metadata:
                self.console.print(f"  Model: {metadata.get('model_used', 'unknown')}")
                self.console.print(f"  Generation time: {metadata.get('generation_time', 0):.2f}s")
                metadata["mock_asset_files"] = mock_asset_files
            
            return str(file_path)
            
        except Exception as e:
            raise Exception(f"Failed to write MUnit file: {str(e)}")

    def _normalize_munit_names(self, content: str, flow_name: str, metadata: Optional[Dict] = None) -> str:
        """Rewrite suite and test names to deterministic, target-specific values."""
        try:
            namespaces = {
                "munit": "http://www.mulesoft.org/schema/mule/munit"
            }
            ET.register_namespace("munit", namespaces["munit"])
            ET.register_namespace("munit-tools", "http://www.mulesoft.org/schema/mule/munit-tools")
            ET.register_namespace("", "http://www.mulesoft.org/schema/mule/core")
            ET.register_namespace("doc", "http://www.mulesoft.org/schema/mule/documentation")

            root = ET.fromstring(content)
            base_name = self._derive_base_name(flow_name, metadata)

            config = root.find(".//munit:config", namespaces)
            if config is not None:
                config.set("name", f"{base_name}-test-suite")

            used_names = set()
            tests = root.findall(".//munit:test", namespaces)
            for index, test in enumerate(tests, start=1):
                scenario_slug = self._derive_scenario_slug(test, index)
                test_name = self._dedupe_name(f"{base_name}-test-{scenario_slug}", used_names)
                test.set("name", test_name)

                doc_id = test.get("{http://www.mulesoft.org/schema/mule/documentation}id")
                if doc_id:
                    test.set("{http://www.mulesoft.org/schema/mule/documentation}id", f"test-{test_name}")

            return ET.tostring(root, encoding="unicode")
        except ET.ParseError:
            return content

    def _derive_base_name(self, flow_name: str, metadata: Optional[Dict] = None) -> str:
        """Build the base test name from the actual target flow, not just the source file."""
        metadata = metadata or {}
        target_flow = metadata.get("target_flow") or flow_name
        clean_name = self._slugify_name(target_flow)
        return clean_name or "main-flow"

    def _derive_scenario_slug(self, test: ET.Element, index: int) -> str:
        """Derive a readable scenario suffix from description or existing name."""
        description = test.get("description", "").strip()
        existing_name = test.get("name", "").strip()

        for candidate in (description, existing_name):
            slug = self._slugify_name(candidate)
            if slug:
                return slug

        return f"scenario-{index}"

    def _dedupe_name(self, base_name: str, used_names: set) -> str:
        """Ensure names stay unique within a generated suite."""
        if base_name not in used_names:
            used_names.add(base_name)
            return base_name

        suffix = 2
        while f"{base_name}-{suffix}" in used_names:
            suffix += 1

        deduped_name = f"{base_name}-{suffix}"
        used_names.add(deduped_name)
        return deduped_name

    def _slugify_name(self, value: str) -> str:
        """Convert free-form text into a stable kebab-case name."""
        normalized = value.replace("_", "-").replace(" ", "-").lower()
        normalized = re.sub(r"[^a-z0-9-]+", "-", normalized)
        normalized = re.sub(r"-{2,}", "-", normalized)
        return normalized.strip("-")

    def _clean_xml_content(self, content: str) -> str:
        """
        Clean XML content from LLM response.
        
        Args:
            content: Raw content from LLM
            
        Returns:
            Cleaned XML content
        """
        # Remove markdown code fences
        if content.startswith("```xml"):
            content = content[6:]
        elif content.startswith("```"):
            content = content[3:]
        
        if content.endswith("```"):
            content = content[:-3]
        
        # Remove any leading/trailing whitespace
        content = content.strip()
        
        # Remove any explanatory text before XML
        xml_start_patterns = ['<?xml', '<mule', '<munit']
        for pattern in xml_start_patterns:
            index = content.find(pattern)
            if index != -1:
                content = content[index:]
                break
        
        # Remove any text after XML closing tag
        xml_end_patterns = ['</mule>', '</munit:test-suite>']
        for pattern in xml_end_patterns:
            index = content.find(pattern)
            if index != -1:
                end_index = content.find('>', index) + 1
                content = content[:end_index]
                break
        
        return content

    def _validate_xml(self, content: str) -> bool:
        """
        Validate XML content.
        
        Args:
            content: XML content to validate
            
        Returns:
            True if valid XML
        """
        try:
            ET.fromstring(content)
            return True
        except ET.ParseError as e:
            self.console.print(f"[red]XML validation failed: {str(e)}[/red]")
            return False

    def _format_xml(self, content: str) -> str:
        """
        Format XML with proper indentation.
        
        Args:
            content: XML content to format
            
        Returns:
            Formatted XML string
        """
        try:
            # Parse the XML
            root = ET.fromstring(content)
            
            # Convert to string and pretty print
            rough_string = ET.tostring(root, encoding='unicode')
            
            # Use minidom for pretty printing
            parsed = minidom.parseString(rough_string)
            pretty_xml = parsed.toprettyxml(indent="    ")
            
            # Clean up minidom output
            lines = pretty_xml.split('\n')
            cleaned_lines = []
            
            for line in lines:
                # Remove empty lines
                if line.strip():
                    cleaned_lines.append(line.rstrip())
            
            # Ensure XML declaration is present
            if not cleaned_lines[0].startswith('<?xml'):
                cleaned_lines.insert(0, '<?xml version="1.0" encoding="UTF-8"?>')
            
            return '\n'.join(cleaned_lines)
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: XML formatting failed, returning original: {str(e)}[/yellow]")
            return content

    def _generate_filename(self, flow_name: str) -> str:
        """
        Generate filename for MUnit file.
        
        Args:
            flow_name: Name of the flow being tested
            
        Returns:
            Generated filename
        """
        # Clean flow name for filename
        clean_name = flow_name.replace(' ', '-').replace('_', '-')
        clean_name = ''.join(c for c in clean_name if c.isalnum() or c == '-')
        
        # Remove leading/trailing hyphens
        clean_name = clean_name.strip('-')
        
        # Ensure lowercase
        clean_name = clean_name.lower()
        
        # Generate filename
        filename = f"{clean_name}-munit-test.xml"
        
        return filename

    def _write_mock_support_files(self, xml_content: str, flow_name: str, metadata: Optional[Dict] = None) -> list:
        """Generate companion DWL files for inline mock payloads and set-event payloads when useful."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return []

        namespaces = {
            "munit": "http://www.mulesoft.org/schema/mule/munit",
            "munit-tools": "http://www.mulesoft.org/schema/mule/munit-tools"
        }

        asset_dir = self.output_dir / "mock-assets" / self._slugify_name(flow_name)
        asset_dir.mkdir(parents=True, exist_ok=True)
        written_files = []

        # Extract payloads from set-event and mock-when blocks.
        set_event_payloads = root.findall(".//munit:set-event/munit:payload", namespaces)
        mock_payloads = root.findall(".//munit-tools:mock-when/munit-tools:then-return/munit-tools:payload", namespaces)

        counters = {"set-event": 0, "mock": 0}

        for payload_node, family in [(node, "set-event") for node in set_event_payloads] + [(node, "mock") for node in mock_payloads]:
            raw_value = payload_node.attrib.get("value", "").strip()
            media_type = payload_node.attrib.get("mediaType", "application/json")
            if not raw_value or len(raw_value) < 12:
                continue

            dwl_body = self._convert_expression_to_dwl(raw_value, media_type, raw_resource=(family == "mock"))
            if not dwl_body:
                continue

            counters[family] += 1
            filename = f"{self._slugify_name(flow_name)}-{family}-{counters[family]}.dwl"
            file_path = asset_dir / filename
            with open(file_path, "w", encoding="utf-8") as handle:
                handle.write(dwl_body)
            written_files.append(str(file_path))

        return written_files

    def _convert_expression_to_dwl(
        self,
        expression: str,
        media_type: str,
        raw_resource: bool = False,
    ) -> Optional[str]:
        """Convert a simple inline Mule expression payload into a raw resource file."""
        expression = expression.strip()
        if not expression.startswith("#[") or not expression.endswith("]"):
            return None

        inner = expression[2:-1].strip()
        if not inner:
            return None

        return inner + "\n"

    def validate_munit_structure(self, content: str) -> Dict:
        """
        Validate MUnit-specific structure.
        
        Args:
            content: XML content to validate
            
        Returns:
            Validation results
        """
        results = {
            "valid_xml": False,
            "has_munit_namespace": False,
            "has_munit_tools_namespace": False,
            "has_test_suite": False,
            "has_tests": False,
            "test_count": 0,
            "errors": []
        }
        
        try:
            # Parse XML
            root = ET.fromstring(content)
            results["valid_xml"] = True
            
            # Check namespaces
            namespaces = self._extract_namespaces(root)
            if 'munit' in namespaces:
                results["has_munit_namespace"] = True
            else:
                results["errors"].append("Missing munit namespace")
            
            if 'munit-tools' in namespaces:
                results["has_munit_tools_namespace"] = True
            else:
                results["errors"].append("Missing munit-tools namespace")
            
            # Check for test suite config
            test_configs = root.findall(".//munit:config", namespaces)
            if test_configs:
                results["has_test_suite"] = True
            else:
                results["errors"].append("Missing munit:config")
            
            # Count tests
            tests = root.findall(".//munit:test", namespaces)
            results["test_count"] = len(tests)
            results["has_tests"] = len(tests) > 0
            
            if not tests:
                results["errors"].append("No munit:test elements found")
            
        except ET.ParseError as e:
            results["errors"].append(f"XML parsing error: {str(e)}")
        
        return results

    def _extract_namespaces(self, root: ET.Element) -> Dict[str, str]:
        """Extract namespace mappings from root element."""
        namespaces = {}
        
        # Extract from root attributes - convert to list to avoid dict changed size during iteration
        attrib_items = list(root.attrib.items())
        for key, value in attrib_items:
            if key.startswith('xmlns:'):
                ns_key = key.split(':')[1]
                namespaces[ns_key] = value
        
        # Also extract from tag if using default namespace
        if '}' in root.tag:
            default_ns = root.tag.split('}')[0][1:]
            # Map common namespaces to their prefixes
            ns_mappings = {
                'http://www.mulesoft.org/schema/mule/munit': 'munit',
                'http://www.mulesoft.org/schema/mule/munit-tools': 'munit-tools',
                'http://www.mulesoft.org/schema/mule/core': 'core'
            }
            for ns_url, prefix in ns_mappings.items():
                if ns_url in default_ns:
                    namespaces[prefix] = ns_url
                    break
        
        return namespaces

    def get_file_info(self, file_path: str) -> Dict:
        """
        Get information about generated file.
        
        Args:
            file_path: Path to MUnit file
            
        Returns:
            File information dictionary
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                return {"exists": False}
            
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Basic file info
            info = {
                "exists": True,
                "size": path.stat().st_size,
                "lines": len(content.splitlines()),
                "characters": len(content)
            }
            
            # MUnit-specific info
            validation = self.validate_munit_structure(content)
            info.update(validation)
            
            return info
            
        except Exception as e:
            return {"exists": False, "error": str(e)}
