"""
XML analyzer for extracting key information from MuleSoft application XML files.
"""

import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from rich.console import Console


class XMLAnalyzer:
    """Analyzes Mule XML files to extract flow information for MUnit generation."""

    EXTERNAL_MOCK_PROCESSORS = {
        "http:request",
        "wsc:consume",
        "db:select",
        "db:insert",
        "db:update",
        "db:delete",
        "salesforce:query",
        "salesforce:create",
        "salesforce:update",
        "sftp:read",
        "file:read",
        "jms:publish-consume",
        "vm:publish-consume",
        "objectstore:retrieve",
    }

    VOID_VERIFY_PROCESSORS = {
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

    SOURCE_PROCESSORS = {
        "http:listener",
        "anypoint-mq:subscriber",
        "kafka:consumer",
        "sftp:listener",
        "jms:listener",
        "vm:listener",
        "scheduler",
    }

    EXCLUDED_FLOW_NAME_PATTERNS = (
        "apikit-console",
        "api-console",
        "console-flow",
        "console",
    )

    EXCLUDED_PROCESSOR_PATTERNS = (
        "apikit:router",
        "apikit:console",
    )

    # Well-known MuleSoft / Spring namespace URIs used to synthesise missing
    # xmlns declarations when a project XML omits them.
    _KNOWN_NS_URIS: Dict[str, str] = {
        'doc':          'http://www.mulesoft.org/schema/mule/documentation',
        'http':         'http://www.mulesoft.org/schema/mule/http',
        'db':           'http://www.mulesoft.org/schema/mule/db',
        'ee':           'http://www.mulesoft.org/schema/mule/ee/core',
        'dw':           'http://www.mulesoft.org/schema/mule/ee/dw',
        'apikit':       'http://www.mulesoft.org/schema/mule/apikit',
        'batch':        'http://www.mulesoft.org/schema/mule/batch',
        'sftp':         'http://www.mulesoft.org/schema/mule/sftp',
        'file':         'http://www.mulesoft.org/schema/mule/file',
        'ftp':          'http://www.mulesoft.org/schema/mule/ftp',
        'jms':          'http://www.mulesoft.org/schema/mule/jms',
        'vm':           'http://www.mulesoft.org/schema/mule/vm',
        'amqp':         'http://www.mulesoft.org/schema/mule/amqp',
        'salesforce':   'http://www.mulesoft.org/schema/mule/salesforce',
        'objectstore':  'http://www.mulesoft.org/schema/mule/objectstore',
        'kafka':        'http://www.mulesoft.org/schema/mule/kafka',
        'anypoint-mq':  'http://www.mulesoft.org/schema/mule/anypoint-mq',
        'email':        'http://www.mulesoft.org/schema/mule/email',
        'wsc':          'http://www.mulesoft.org/schema/mule/wsc',
        'tls':          'http://www.mulesoft.org/schema/mule/tls',
        'oauth':        'http://www.mulesoft.org/schema/mule/oauth',
        'xsi':          'http://www.w3.org/2001/XMLSchema-instance',
        'spring':       'http://www.springframework.org/schema/beans',
        'munit':        'http://www.mulesoft.org/schema/mule/munit',
        'munit-tools':  'http://www.mulesoft.org/schema/mule/munit-tools',
        'aggregators':  'http://www.mulesoft.org/schema/mule/aggregators',
        'sockets':      'http://www.mulesoft.org/schema/mule/sockets',
        'validation':   'http://www.mulesoft.org/schema/mule/validation',
        'crypto':       'http://www.mulesoft.org/schema/mule/crypto',
        'compression':  'http://www.mulesoft.org/schema/mule/compression',
    }

    @staticmethod
    def _sanitize_xml_string(content: str) -> str:
        """
        Prepare a raw XML string so ET.fromstring can parse it reliably.

        Three transforms are applied:

        1. BOM removal — strips UTF-8/UTF-16 byte-order marks (\\ufeff) that
           Python carries after decoding and that cause 'not well-formed
           (invalid token): line 1, column 0'.

        2. Illegal control-character removal — XML 1.0 forbids all C0 controls
           except TAB (\\x09), LF (\\x0a), CR (\\x0d), plus DEL (\\x7f) and C1
           (\\x80-\\x9f).  These appear in Windows-saved files and cause the
           same 'not well-formed' error.

        3. Missing namespace-prefix injection — MuleSoft projects routinely use
           doc:name="…" (and sometimes ee:, apikit:, etc.) without declaring
           xmlns:doc on the root element.  ET.fromstring is strict about
           undeclared prefixes and raises 'unbound prefix'.  This step detects
           every prefix used in the document, compares it against the declared
           xmlns:* attributes, and injects synthetic declarations into the root
           <mule> tag for any that are missing.
        """
        # 1. Strip BOM
        content = content.lstrip('\ufeff')

        # 2. Remove XML-illegal control characters
        content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]', '', content)

        # 3. Inject missing namespace declarations
        # Collect every prefix used in element tag names: <prefix:local or </prefix:local
        tag_prefixes = set(re.findall(r'</?([a-zA-Z][a-zA-Z0-9_.-]*):[a-zA-Z]', content))
        # Collect every prefix used in attribute names: prefix:attrname="..."
        attr_prefixes = set(re.findall(
            r'\b([a-zA-Z][a-zA-Z0-9_.-]*):[a-zA-Z][a-zA-Z0-9_.-]*\s*=', content
        ))
        # 'xml' and 'xmlns' are reserved and must never be redeclared
        used = (tag_prefixes | attr_prefixes) - {'xml', 'xmlns'}
        declared = set(re.findall(r'xmlns:([a-zA-Z][a-zA-Z0-9_.-]*)\s*=', content))
        missing = used - declared

        if missing:
            injections = ' '.join(
                'xmlns:{p}="{uri}"'.format(
                    p=p,
                    uri=XMLAnalyzer._KNOWN_NS_URIS.get(
                        p, f'http://www.mulesoft.org/schema/mule/{p}'
                    )
                )
                for p in sorted(missing)
            )
            # Insert the new declarations before the closing '>' of the root opening tag
            content = re.sub(
                r'(<mule\b[^>]*?)(\s*/?>)',
                rf'\1 {injections}\2',
                content,
                count=1,
            )

        return content

    def __init__(self):
        """Initialize XML analyzer."""
        self.console = Console()

    def analyze_mule_xml(self, xml_content: str) -> Dict:
        """
        Analyze Mule XML content and extract key information.

        Args:
            xml_content: Raw XML content string

        Returns:
            Dictionary containing extracted information

        Raises:
            Exception: If XML cannot be parsed or is not a valid Mule app
        """
        # Sanitize before parsing: strips BOM, illegal control chars, and
        # injects any missing xmlns declarations (e.g. xmlns:doc) that
        # ET.fromstring requires but Anypoint Studio sometimes omits.
        xml_content = self._sanitize_xml_string(xml_content)

        try:
            # Parse XML with additional error handling
            try:
                root = ET.fromstring(xml_content)
            except ET.ParseError as e:
                raise Exception(f"XML Parse Error: {str(e)}")
            except Exception as e:
                # Catch any other parsing related errors
                raise Exception(f"XML parsing failed: {str(e)}")
            
            # Extract namespace information
            namespaces = self._extract_namespaces(root)
            
            # Detect job type
            job_type = self._detect_job_type(root, namespaces)
            
            # Extract flows and sub-flows
            flows_info = self._extract_flows(root, namespaces)
            
            # Extract connectors
            connectors = self._extract_connectors(root, namespaces)
            
            # Extract transformers
            transformers = self._extract_transformers(root, namespaces)
            
            # Extract error handlers
            error_handlers = self._extract_error_handlers(root, namespaces)
            
            # Extract external HTTP endpoints
            http_endpoints = self._extract_http_endpoints(root, namespaces)

            analysis_result = {
                "job_type": job_type,
                "flows": flows_info["flows"],
                "sub_flows": flows_info["sub_flows"],
                "connectors": connectors,
                "transformers": transformers,
                "error_handlers": error_handlers,
                "http_endpoints": http_endpoints,
                "namespaces": namespaces,
                "flow_details": self._extract_flow_details(root),
                "test_targets": [],
                "source_files": []
            }

            # source_file is stamped later by analyze_mule_project; for the
            # single-file path we use a placeholder that _build_flow_graph will
            # receive as-is.  The caller (analyze_mule_project) overwrites it
            # before building the graph, so this only matters when
            # analyze_mule_xml is called directly.
            for detail in analysis_result["flow_details"]:
                detail.setdefault("source_file", analysis_result.get("source_file", "input.xml"))

            analysis_result["test_targets"] = self._build_test_targets(
                analysis_result["flows"],
                analysis_result["sub_flows"],
                analysis_result["flow_details"]
            )
            analysis_result["flow_graph"] = self._build_flow_graph(analysis_result["flow_details"])
            analysis_result["flow_contexts"] = self._build_flow_contexts(
                analysis_result["test_targets"],
                analysis_result["flow_graph"]
            )

            self.console.print(f"[green]XML Analysis Complete:[/green]")
            self.console.print(f"  Job Type: {job_type}")
            self.console.print(f"  Flows: {len(flows_info['flows'])}")
            self.console.print(f"  Sub-flows: {len(flows_info['sub_flows'])}")
            self.console.print(f"  Connectors: {len(connectors)}")
            self.console.print(f"  Transformers: {len(transformers)}")
            self.console.print(f"  Error Handlers: {len(error_handlers)}")
            self.console.print(f"  HTTP Endpoints: {len(http_endpoints)}")

            return analysis_result

        except ET.ParseError as e:
            raise Exception(f"Invalid XML format: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to analyze XML: {str(e)}")

    def analyze_mule_project(self, xml_content: str) -> Dict:
        """
        Analyze a Mule project represented as either a single XML document or a
        concatenation of multiple XML files separated by file headers.
        """
        documents = self._extract_xml_documents(xml_content)

        if not documents:
            raise Exception("No valid Mule XML documents found in input")

        analyses = []
        parse_errors: List[str] = []
        for document in documents:
            try:
                analysis = self.analyze_mule_xml(document["content"])
                analysis["source_file"] = document["name"]
                analyses.append(analysis)
            except Exception as exc:
                msg = f"{document['name']}: {str(exc)}"
                parse_errors.append(msg)
                self.console.print(
                    f"[yellow]Skipping unreadable XML source {msg}[/yellow]"
                )

        if not analyses:
            detail = "; ".join(parse_errors) if parse_errors else "unknown reason"
            raise Exception(
                f"Unable to analyze any Mule XML documents from the provided project. "
                f"Parse failures — {detail}"
            )

        return self._merge_project_analyses(analyses)

    def _extract_namespaces(self, root: ET.Element) -> Dict[str, str]:
        """Extract XML namespaces from root element."""
        namespaces = {}
        
        # Extract default namespace
        if '}' in root.tag:
            default_ns = root.tag.split('}')[0][1:]
            namespaces['default'] = default_ns
        
        # Extract all namespaces - convert to list to avoid dict changed size during iteration
        attrib_items = list(root.attrib.items())
        for key, value in attrib_items:
            if key.startswith('xmlns:'):
                ns_key = key.split(':')[1]
                namespaces[ns_key] = value
            elif key == 'xmlns':
                namespaces['default'] = value
        
        return namespaces

    def _detect_job_type(self, root: ET.Element, namespaces: Dict[str, str]) -> str:
        """Detect job type based on root listener type."""
        # Check for different listener types
        listener_checks = [
            ("http:listener", "REST API"),
            ("batch:job", "Batch Job"),
            ("scheduler", "Scheduler"),
            ("anypoint-mq:subscriber", "MQ Consumer"),
            ("kafka:consumer", "Kafka Consumer"),
            ("sftp:listener", "SFTP Listener")
        ]

        for listener_tag, job_type in listener_checks:
            if self._find_element_by_tag(root, listener_tag, namespaces) is not None:
                return job_type
        
        return "Generic Mule Flow"

    def _extract_flows(self, root: ET.Element, namespaces: Dict[str, str]) -> Dict:
        """Extract flow and sub-flow names."""
        flows = []
        sub_flows = []
        
        # Find all flow elements
        for flow in root.iter():
            if flow.tag.endswith('flow'):
                flow_name = flow.attrib.get('name', 'unnamed-flow')
                if 'sub-flow' in flow.tag:
                    sub_flows.append(flow_name)
                else:
                    flows.append(flow_name)
        
        return {
            "flows": flows,
            "sub_flows": sub_flows
        }

    def _extract_flow_details(self, root: ET.Element) -> List[Dict]:
        """Extract per-flow execution details for targeted MUnit generation."""
        flow_details = []

        for element in root.iter():
            local_name = self._local_tag_name(element.tag)
            if local_name not in {"flow", "sub-flow", "subflow"}:
                continue

            flow_name = element.attrib.get("name", "unnamed-flow")
            processors = []
            processor_chain = []
            referenced_flows = []
            connectors = set()
            http_endpoints = []
            error_handlers = set()
            dwl_refs = set()
            inline_dwl_scripts = []
            branch_points = []
            variable_writes = []
            error_handler_details = []

            for index, child in enumerate(element.iter()):
                child_name = self._local_tag_name(child.tag)
                if child is not element:
                    processors.append(child_name)

                if child is not element:
                    processor_meta = self._extract_processor_metadata(child, child_name, index)
                    if processor_meta:
                        processor_chain.append(processor_meta)

                if child_name == "flow-ref":
                    ref_name = child.attrib.get("name")
                    if ref_name:
                        referenced_flows.append(ref_name)

                processor_type = self._qualify_processor_type(child, child_name)
                if (
                    processor_type in self.EXTERNAL_MOCK_PROCESSORS
                    or processor_type in self.VOID_VERIFY_PROCESSORS
                    or processor_type in self.SOURCE_PROCESSORS
                ):
                    connectors.add(processor_type)
                elif child_name in {
                    "choice", "foreach", "scatter-gather", "until-successful",
                    "parallel-foreach", "try", "async", "scheduler"
                }:
                    connectors.add(child_name)

                if child_name == "request":
                    http_endpoints.append({
                        "method": child.attrib.get("method", "GET"),
                        "path": child.attrib.get("path", "/"),
                        "config_ref": child.attrib.get("config-ref", "unknown")
                    })

                if child_name.startswith("on-error"):
                    error_handlers.add(child_name)
                    error_handler_details.append(self._extract_error_handler_detail(child, child_name))

                if child_name == "choice":
                    branch_points.extend(self._extract_choice_branches(child))

                if child_name == "set-variable":
                    value = child.attrib.get("value", "")
                    inline_value = self._extract_inline_dwl(child)
                    variable_writes.append({
                        "name": child.attrib.get("variableName") or child.attrib.get("target"),
                        "value": value,
                        "dwl_excerpt": (inline_value or {}).get("script", ""),
                        "value_type": self._infer_expression_type(value or (inline_value or {}).get("script", "")),
                        "doc_name": self._get_documentation_name(child),
                    })

                dwl_path = self._extract_dwl_resource_reference(child)
                if dwl_path:
                    dwl_refs.add(dwl_path)

                inline_dwl = self._extract_inline_dwl(child)
                if inline_dwl:
                    inline_dwl_scripts.append(inline_dwl)

            trigger_processor = processor_chain[0] if processor_chain else {}
            business_processors = [
                processor for processor in processor_chain
                if processor.get("type") not in {"error-handler", "on-error-propagate", "on-error-continue"}
            ]
            final_processor = business_processors[-1] if business_processors else trigger_processor
            downstream_payload_refs = self._extract_payload_references(
                "\n".join(script.get("script", "") for script in inline_dwl_scripts)
            )
            mock_plan = self._build_mock_plan(processor_chain)

            flow_details.append({
                "name": flow_name,
                "type": "sub-flow" if local_name in {"sub-flow", "subflow"} else "flow",
                "processors": sorted(set(processors)),
                "processor_chain": processor_chain,
                "referenced_flows": sorted(set(referenced_flows)),
                "connectors": sorted(connectors),
                "http_requests": http_endpoints,
                "error_handlers": sorted(error_handlers),
                "error_handler_details": error_handler_details[:6],
                "branch_points": branch_points[:8],
                "variable_writes": variable_writes[:12],
                "trigger": trigger_processor,
                "final_processor": final_processor,
                "dwl_files": sorted(dwl_refs),
                "inline_dwl": inline_dwl_scripts[:6],
                "payload_references": downstream_payload_refs[:20],
                "mock_plan": mock_plan,
                "xml_snippet": ET.tostring(element, encoding="unicode")
            })

        return flow_details

    def _extract_processor_metadata(self, element: ET.Element, child_name: str, index: int) -> Optional[Dict]:
        """Build ordered processor metadata for prompt construction."""
        doc_name = self._get_documentation_name(element)
        processor_type = self._qualify_processor_type(element, child_name)
        metadata = {
            "index": index,
            "type": processor_type,
            "doc_name": doc_name,
        }

        for attr_key in (
            "name", "path", "method", "allowedMethods", "config-ref",
            "value", "variableName", "ref", "url", "expression",
        ):
            if attr_key in element.attrib:
                metadata[attr_key.replace("-", "_")] = element.attrib.get(attr_key)

        summary = self._build_processor_summary(metadata)
        if summary:
            metadata["summary"] = summary

        inline_dwl = self._extract_inline_dwl(element)
        if inline_dwl:
            metadata["payload_references"] = self._extract_payload_references(inline_dwl.get("script", ""))
            metadata["dwl_excerpt"] = inline_dwl.get("script", "")[:1200]

        return metadata

    def _extract_choice_branches(self, choice_element: ET.Element) -> List[Dict]:
        """Extract high-level choice branch conditions for scenario planning."""
        branches = []
        branch_index = 0
        for child in list(choice_element):
            child_name = self._local_tag_name(child.tag)
            if child_name not in {"when", "otherwise"}:
                continue
            branch_index += 1
            condition = child.attrib.get("expression", "") if child_name == "when" else "otherwise"
            branches.append({
                "type": child_name,
                "condition": condition,
                "description": f"{child_name} branch {branch_index}: {condition or 'otherwise'}",
            })
        return branches

    def _extract_error_handler_detail(self, element: ET.Element, child_name: str) -> Dict:
        """Capture enough error-handler detail to plan failure assertions."""
        return {
            "type": child_name,
            "doc_name": self._get_documentation_name(element),
            "error_type": element.attrib.get("type", ""),
            "enable_notifications": element.attrib.get("enableNotifications", ""),
            "dwl_excerpt": (self._extract_inline_dwl(element) or {}).get("script", ""),
        }

    def _infer_expression_type(self, expression: str) -> str:
        """Best-effort type label for variable and route planning."""
        text = (expression or "").strip()
        body = text.split("---", 1)[1].strip() if "---" in text else text
        if not body:
            return "unknown"
        if re.search(r"\b(?:map|filter|flatMap|pluck|distinctBy|orderBy)\b", body) or body.startswith("["):
            return "array"
        if re.search(r"\b(?:mapObject|groupBy|reduce)\b", body) or body.startswith("{"):
            return "object"
        if re.match(r"^['\"].*['\"]$", body):
            return "string"
        if re.match(r"^\d+(?:\.\d+)?$", body):
            return "number"
        if body in {"true", "false"}:
            return "boolean"
        if body == "null":
            return "null"
        return "expression"

    def _get_documentation_name(self, element: ET.Element) -> str:
        """Extract doc:name without depending on namespace registration."""
        for key, value in element.attrib.items():
            if key.endswith("}name") or key == "doc:name":
                return value
        return ""

    def _qualify_processor_type(self, element: ET.Element, local_name: str) -> str:
        """Return a Mule-like processor type label."""
        namespace = ""
        if element.tag.startswith("{") and "}" in element.tag:
            namespace = element.tag[1:].split("}", 1)[0]

        namespace_map = {
            "http://www.mulesoft.org/schema/mule/http": "http",
            "http://www.mulesoft.org/schema/mule/wsc": "wsc",
            "http://www.mulesoft.org/schema/mule/ee/core": "ee",
            "http://www.mulesoft.org/schema/mule/db": "db",
            "http://www.mulesoft.org/schema/mule/salesforce": "salesforce",
            "http://www.mulesoft.org/schema/mule/apikit": "apikit",
            "http://www.mulesoft.org/schema/mule/scripting": "scripting",
            "http://www.mulesoft.org/schema/mule/validation": "validation",
            "http://www.mulesoft.org/schema/mule/file": "file",
            "http://www.mulesoft.org/schema/mule/sftp": "sftp",
            "http://www.mulesoft.org/schema/mule/mq": "anypoint-mq",
            "http://www.mulesoft.org/schema/mule/kafka": "kafka",
            "http://www.mulesoft.org/schema/mule/email": "email",
            "http://www.mulesoft.org/schema/mule/jms": "jms",
            "http://www.mulesoft.org/schema/mule/vm": "vm",
            "http://www.mulesoft.org/schema/mule/os": "objectstore",
            "http://www.mulesoft.org/schema/mule/objectstore": "objectstore",
        }

        prefix = namespace_map.get(namespace)
        if prefix:
            return f"{prefix}:{local_name}"
        return local_name

    def _build_mock_plan(self, processor_chain: List[Dict]) -> List[Dict]:
        """Create deterministic mock/verify guidance from the ordered processor chain."""
        mock_plan = []

        for index, processor in enumerate(processor_chain):
            processor_type = processor.get("type", "")
            if processor_type not in self.EXTERNAL_MOCK_PROCESSORS and processor_type not in self.VOID_VERIFY_PROCESSORS:
                continue

            downstream_refs = []
            downstream_script = ""
            for later in processor_chain[index + 1:]:
                refs = later.get("payload_references", []) or []
                script = later.get("dwl_excerpt", "") or ""
                if refs or script:
                    downstream_refs = refs
                    downstream_script = script
                    break

            item = {
                "processor": processor_type,
                "doc_name": processor.get("doc_name", ""),
                "match_attribute": "doc:name" if processor.get("doc_name") else "config-ref",
                "match_value": processor.get("doc_name") or processor.get("config_ref", ""),
                "action": "verify-call" if processor_type in self.VOID_VERIFY_PROCESSORS else "mock-when",
                "downstream_payload_references": downstream_refs[:12],
                "downstream_dwl_excerpt": downstream_script[:1200],
                "media_type": self._default_media_type_for_processor(processor_type),
                "result_shape": self._infer_result_shape_for_processor(processor_type, downstream_script),
            }

            if processor_type == "http:request":
                item["return_attributes"] = {
                    "statusCode": 200,
                    "headers": {"content-type": "application/json"}
                }

            mock_plan.append(item)

        return mock_plan

    def _default_media_type_for_processor(self, processor_type: str) -> str:
        """Return the safest MUnit media type for a mocked processor."""
        if processor_type.startswith("db:") or processor_type.startswith("salesforce:"):
            return "application/java"
        if processor_type.startswith("sftp:") or processor_type.startswith("file:"):
            return "text/plain"
        return "application/json"

    def _default_result_shape_for_processor(self, processor_type: str) -> str:
        """Return the expected shape of a successful mocked result."""
        if processor_type in {"db:select", "salesforce:query"}:
            return "array"
        if processor_type in {"db:insert", "db:update", "db:delete"}:
            return "affectedRows"
        if processor_type in self.VOID_VERIFY_PROCESSORS:
            return "void"
        return "object"

    def _infer_result_shape_for_processor(self, processor_type: str, downstream_script: str = "") -> str:
        """Infer connector result shape from the next DataWeave consumer."""
        default_shape = self._default_result_shape_for_processor(processor_type)
        script = self._strip_dwl_header(downstream_script or "")

        if re.search(r"\bpayload\s+(?:mapObject|groupBy|reduce)\b", script):
            return "object"
        if re.search(r"\bpayload\s+(?:map|filter|flatMap|distinctBy|orderBy)\b", script):
            return "array"
        if re.search(r"\bpayload\s+pluck\b", script):
            return "array"
        if re.search(r"\bpayload\s*\[[^\]]+\]", script):
            return "array"
        if re.search(r"^\s*\{", script):
            return "object"
        if re.search(r"^\s*\[", script):
            return "array"
        return default_shape

    def _strip_dwl_header(self, script: str) -> str:
        """Return the executable body portion of a DWL script."""
        return script.split("---", 1)[1].strip() if "---" in script else script.strip()

    def _build_processor_summary(self, metadata: Dict) -> str:
        """Create a compact human-readable summary for prompts."""
        parts = [metadata.get("type", "processor")]
        if metadata.get("doc_name"):
            parts.append(f'doc:name="{metadata["doc_name"]}"')
        for attr in ("method", "path", "config_ref", "name", "variableName", "ref"):
            normalized = attr.replace("-", "_")
            value = metadata.get(normalized) if normalized in metadata else metadata.get(attr)
            if value and attr not in {"name"}:
                label = attr.replace("_", "-")
                parts.append(f'{label}="{value}"')
        return " ".join(parts)

    def _extract_dwl_resource_reference(self, element: ET.Element) -> Optional[str]:
        """Extract referenced DataWeave resource path from a transform element."""
        for key, value in element.attrib.items():
            lowered_key = key.lower()
            if value and value.lower().endswith(".dwl") and (
                "resource" in lowered_key or lowered_key.endswith("name")
            ):
                return value.lstrip("/")
        return None

    def _extract_inline_dwl(self, element: ET.Element) -> Optional[Dict]:
        """Extract inline DataWeave scripts from transform/set-payload blocks."""
        script_parts = []
        for child in element.iter():
            text = (child.text or "").strip()
            if "%dw" in text:
                script_parts.append(text)

        if not script_parts:
            return None

        script = "\n".join(script_parts)
        return {
            "processor": self._qualify_processor_type(element, self._local_tag_name(element.tag)),
            "doc_name": self._get_documentation_name(element),
            "script": script[:2500]
        }

    def _extract_payload_references(self, text: str) -> List[str]:
        """Extract payload/vars/attributes references from DWL to guide mocks/assertions."""
        if not text:
            return []
        matches = re.findall(r"\b(?:payload|vars|attributes)\.[A-Za-z0-9_.\[\]'\"]+", text)
        ordered = []
        for match in matches:
            if match not in ordered:
                ordered.append(match)
        return ordered

    def _extract_connectors(self, root: ET.Element, namespaces: Dict[str, str]) -> List[str]:
        """Extract connector types used in the application."""
        connectors = set()

        for element in root.iter():
            local_name = self._local_tag_name(element.tag)
            processor_type = self._qualify_processor_type(element, local_name)
            if (
                processor_type in self.EXTERNAL_MOCK_PROCESSORS
                or processor_type in self.VOID_VERIFY_PROCESSORS
                or processor_type in self.SOURCE_PROCESSORS
            ):
                connectors.add(processor_type)
        
        return sorted(list(connectors))

    def _extract_transformers(self, root: ET.Element, namespaces: Dict[str, str]) -> List[str]:
        """Extract transformer types used."""
        transformers = set()
        
        transformer_patterns = [
            'transform:message',
            'ee:transform',
            'transform:json-to-xml',
            'transform:xml-to-json',
            'dataweave:transform'
        ]
        
        for element in root.iter():
            local_name = self._local_tag_name(element.tag)
            tag = self._qualify_processor_type(element, local_name)
            for pattern in transformer_patterns:
                if pattern in tag:
                    transformers.add(pattern)
        
        return sorted(list(transformers))

    def _extract_error_handlers(self, root: ET.Element, namespaces: Dict[str, str]) -> List[str]:
        """Extract error handler types."""
        error_handlers = set()
        
        error_patterns = [
            'on-error-propagate',
            'on-error-continue',
            'on-error'
        ]
        
        for element in root.iter():
            tag = element.tag
            for pattern in error_patterns:
                if pattern in tag:
                    error_handlers.add(pattern)
        
        return sorted(list(error_handlers))

    def _extract_http_endpoints(self, root: ET.Element, namespaces: Dict[str, str]) -> List[Dict]:
        """Extract external HTTP endpoints."""
        endpoints = []
        
        for element in root.iter():
            if self._qualify_processor_type(element, self._local_tag_name(element.tag)) == 'http:request':
                config_ref = element.attrib.get('config-ref', 'unknown')
                path = element.attrib.get('path', '/')
                method = element.attrib.get('method', 'GET')
                
                endpoints.append({
                    "config_ref": config_ref,
                    "path": path,
                    "method": method
                })
        
        return endpoints

    def _find_element_by_tag(self, root: ET.Element, tag_pattern: str, namespaces: Dict[str, str]) -> Optional[ET.Element]:
        """Find first element matching tag pattern."""
        # Mule XML uses namespace-qualified tags like "{...}listener". Matching on the
        # literal "http:listener" substring will fail. Instead, compare against our
        # qualified processor type (e.g. "http:listener", "db:select").
        for element in root.iter():
            local_name = self._local_tag_name(element.tag)
            qualified = self._qualify_processor_type(element, local_name)
            if qualified == tag_pattern:
                return element
        return None

    def _extract_xml_documents(self, xml_content: str) -> List[Dict[str, str]]:
        """Extract and sanitize XML documents from a combined project payload."""
        header_pattern = r"\n?--- Content from (?P<name>.+?) ---\n"
        matches = list(re.finditer(header_pattern, xml_content))

        if not matches:
            cleaned_content = self._sanitize_xml_string(xml_content.strip())
            return [{"name": "input.xml", "content": cleaned_content}] if cleaned_content else []

        documents = []
        for index, match in enumerate(matches):
            start = match.end()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(xml_content)
            content = self._sanitize_xml_string(xml_content[start:end].strip())
            if content:
                documents.append({
                    "name": match.group("name").strip(),
                    "content": content
                })

        return documents

    def _merge_project_analyses(self, analyses: List[Dict]) -> Dict:
        """Merge multiple XML analysis results into a project-level summary."""
        flows = []
        sub_flows = []
        connectors = set()
        transformers = set()
        error_handlers = set()
        http_endpoints = []
        namespaces = {}
        flow_details = []
        job_types = []
        source_files = []

        for analysis in analyses:
            flows.extend(analysis.get("flows", []))
            sub_flows.extend(analysis.get("sub_flows", []))
            connectors.update(analysis.get("connectors", []))
            transformers.update(analysis.get("transformers", []))
            error_handlers.update(analysis.get("error_handlers", []))
            http_endpoints.extend(analysis.get("http_endpoints", []))
            namespaces.update(analysis.get("namespaces", {}))

            source_file = analysis.get("source_file", "unknown.xml")
            source_files.append(source_file)

            for detail in analysis.get("flow_details", []):
                flow_details.append({
                    **detail,
                    "source_file": source_file
                })

            job_type = analysis.get("job_type", "Generic Mule Flow")
            if job_type and job_type != "Generic Mule Flow":
                job_types.append(job_type)

        unique_flows = list(dict.fromkeys(flows))
        unique_sub_flows = list(dict.fromkeys(sub_flows))
        unique_flow_details = self._dedupe_flow_details(flow_details)

        merged = {
            "job_type": job_types[0] if job_types else "Generic Mule Flow",
            "flows": unique_flows,
            "sub_flows": unique_sub_flows,
            "connectors": sorted(connectors),
            "transformers": sorted(transformers),
            "error_handlers": sorted(error_handlers),
            "http_endpoints": http_endpoints,
            "namespaces": namespaces,
            "flow_details": unique_flow_details,
            "test_targets": self._build_test_targets(unique_flows, unique_sub_flows, unique_flow_details),
            "source_files": source_files
        }
        merged["flow_graph"] = self._build_flow_graph(unique_flow_details)
        merged["flow_contexts"] = self._build_flow_contexts(
            merged["test_targets"],
            merged["flow_graph"]
        )

        self.console.print("[green]Project Analysis Complete:[/green]")
        self.console.print(f"  Source Files: {len(source_files)}")
        self.console.print(f"  Flows: {len(unique_flows)}")
        self.console.print(f"  Sub-flows: {len(unique_sub_flows)}")

        return merged

    def _dedupe_flow_details(self, flow_details: List[Dict]) -> List[Dict]:
        """Deduplicate flow details by flow name and source file."""
        seen = set()
        deduped = []

        for detail in flow_details:
            key = (detail.get("name"), detail.get("source_file"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(detail)

        return deduped

    def _build_test_targets(self, flows: List[str], sub_flows: List[str], flow_details: List[Dict]) -> List[str]:
        """Build the ordered list of flow names that should get MUnit coverage.

        MUnit best-practice: only top-level flows need dedicated tests.
        Sub-flows and private flows are exercised indirectly when their
        parent flow is tested, so they are excluded from test targets.

        A flow is considered a test target if:
          - It is a main flow (not a sub-flow), AND
          - It is NOT referenced by any other flow (i.e. it is not a private
            helper flow that is only ever called via flow-ref).

        Sub-flows are excluded entirely — parent flow tests provide coverage.
        """
        # Build a set of all flows that are called by someone else via flow-ref
        referenced_by_others: set = set()
        for detail in flow_details:
            for ref in detail.get("referenced_flows", []):
                referenced_by_others.add(ref)

        sub_flow_set = set(sub_flows)
        details_by_name = {detail.get("name"): detail for detail in flow_details}
        ordered_targets = []

        for flow_name in flows:
            flow_detail = details_by_name.get(flow_name, {})

            # Skip sub-flows
            if flow_name in sub_flow_set:
                continue
            # Skip Mule/APIkit framework-generated flows that should not get
            # dedicated MUnit suites.
            if self._should_exclude_from_direct_munit(flow_name, flow_detail):
                continue
            # Skip private helper flows that are only called internally
            if flow_name in referenced_by_others:
                continue
            if flow_name not in ordered_targets:
                ordered_targets.append(flow_name)

        # If every flow is referenced by others (e.g. all flows call each other),
        # fall back to including all main flows so we generate at least something.
        if not ordered_targets:
            for flow_name in flows:
                flow_detail = details_by_name.get(flow_name, {})
                if flow_name in sub_flow_set:
                    continue
                if self._should_exclude_from_direct_munit(flow_name, flow_detail):
                    continue
                if flow_name not in ordered_targets:
                    ordered_targets.append(flow_name)

        return ordered_targets

    def _should_exclude_from_direct_munit(self, flow_name: str, flow_detail: Dict) -> bool:
        """Return True when a flow is framework-generated and not a direct MUnit target."""
        normalized_name = (flow_name or "").strip().lower()
        processors = [processor.lower() for processor in flow_detail.get("processors", [])]
        connectors = [connector.lower() for connector in flow_detail.get("connectors", [])]

        # APIkit console and router flows are framework entry points. Coverage
        # should come from testing implementation/business flows instead.
        if any(pattern in normalized_name for pattern in self.EXCLUDED_FLOW_NAME_PATTERNS):
            return True

        if any(pattern in normalized_name for pattern in ("apikit", "api-main")):
            if any("router" in item or "console" in item for item in processors + connectors):
                return True

        if any(pattern in item for item in processors + connectors for pattern in self.EXCLUDED_PROCESSOR_PATTERNS):
            return True

        return False

    def _build_flow_graph(self, flow_details: List[Dict]) -> Dict[str, Dict]:
        """Build a flow dependency graph with parent-child relationships."""
        graph = {}

        for detail in flow_details:
            graph[detail["name"]] = {
                "name": detail["name"],
                "type": detail.get("type", "flow"),
                "source_file": detail.get("source_file", "unknown.xml"),
                "children": list(detail.get("referenced_flows", [])),
                "parents": [],
                "connectors": list(detail.get("connectors", [])),
                "error_handlers": list(detail.get("error_handlers", [])),
                "error_handler_details": list(detail.get("error_handler_details", [])),
                "branch_points": list(detail.get("branch_points", [])),
                "variable_writes": list(detail.get("variable_writes", [])),
                "http_requests": list(detail.get("http_requests", [])),
                "processors": list(detail.get("processors", [])),
                "processor_chain": list(detail.get("processor_chain", [])),
                "trigger": dict(detail.get("trigger", {})),
                "final_processor": dict(detail.get("final_processor", {})),
                "dwl_files": list(detail.get("dwl_files", [])),
                "inline_dwl": list(detail.get("inline_dwl", [])),
                "payload_references": list(detail.get("payload_references", [])),
                "mock_plan": list(detail.get("mock_plan", [])),
                "xml_snippet": detail.get("xml_snippet", "")
            }

        # Convert to list to avoid dictionary changed size during iteration
        graph_items = list(graph.items())
        for flow_name, node in graph_items:
            for child_name in node["children"]:
                if child_name not in graph:
                    graph[child_name] = {
                        "name": child_name,
                        "type": "referenced-flow",
                        "source_file": "unknown.xml",
                        "children": [],
                        "parents": [],
                        "connectors": [],
                        "error_handlers": [],
                        "error_handler_details": [],
                        "branch_points": [],
                        "variable_writes": [],
                        "http_requests": [],
                        "processors": [],
                        "processor_chain": [],
                        "trigger": {},
                        "final_processor": {},
                        "dwl_files": [],
                        "inline_dwl": [],
                        "payload_references": [],
                        "mock_plan": [],
                        "xml_snippet": ""
                    }
                if flow_name not in graph[child_name]["parents"]:
                    graph[child_name]["parents"].append(flow_name)

        return graph

    def _build_flow_contexts(self, test_targets: List[str], flow_graph: Dict[str, Dict]) -> Dict[str, Dict]:
        """Build target-specific context packets for focused MUnit generation."""
        contexts = {}

        for target in test_targets:
            node = flow_graph.get(target, {
                "name": target,
                "type": "unknown",
                "source_file": "unknown.xml",
                "children": [],
                "parents": [],
                "connectors": [],
                "error_handlers": [],
                "http_requests": [],
                "processors": [],
                "xml_snippet": ""
            })

            related_flows = [target]
            descendants = self._collect_descendant_flows(target, flow_graph)
            for child in descendants:
                if child not in related_flows:
                    related_flows.append(child)
            for parent in node.get("parents", []):
                if parent not in related_flows:
                    related_flows.append(parent)

            inherited_connectors = set(node.get("connectors", []))
            inherited_error_handlers = set(node.get("error_handlers", []))
            inherited_error_handler_details = list(node.get("error_handler_details", []))
            inherited_branch_points = list(node.get("branch_points", []))
            inherited_variable_writes = list(node.get("variable_writes", []))
            inherited_dwl_files = set(node.get("dwl_files", []))
            inherited_payload_refs = list(node.get("payload_references", []))
            inline_dwl = list(node.get("inline_dwl", []))
            inherited_mock_plan = list(node.get("mock_plan", []))
            related_flow_details = []

            for related in related_flows:
                related_node = flow_graph.get(related, {})
                related_flow_details.append({
                    "name": related,
                    "type": related_node.get("type", "unknown"),
                    "source_file": related_node.get("source_file", "unknown.xml"),
                    "processor_chain": related_node.get("processor_chain", []),
                    "xml_snippet": related_node.get("xml_snippet", ""),
                })

            for child in descendants:
                child_node = flow_graph.get(child, {})
                inherited_connectors.update(child_node.get("connectors", []))
                inherited_error_handlers.update(child_node.get("error_handlers", []))
                inherited_error_handler_details.extend(child_node.get("error_handler_details", []))
                inherited_branch_points.extend(child_node.get("branch_points", []))
                inherited_variable_writes.extend(child_node.get("variable_writes", []))
                inherited_dwl_files.update(child_node.get("dwl_files", []))
                inline_dwl.extend(child_node.get("inline_dwl", []))
                inherited_mock_plan.extend(child_node.get("mock_plan", []))
                for ref in child_node.get("payload_references", []):
                    if ref not in inherited_payload_refs:
                        inherited_payload_refs.append(ref)

            from .deterministic_munit_builder import build_set_event_plan, extract_output_fields

            set_event_plan = build_set_event_plan(
                node.get("processor_chain", []),
                inline_dwl[:8],
                node.get("trigger", {}) or {},
            )
            output_fields = extract_output_fields(
                inline_dwl[:8],
                node.get("final_processor", {}) or {},
            )

            contexts[target] = {
                "target_flow": target,
                "target_type": node.get("type", "unknown"),
                "source_file": node.get("source_file", "unknown.xml"),
                "parent_flows": node.get("parents", []),
                "child_flows": node.get("children", []),
                "related_flows": related_flows,
                "connectors": sorted(inherited_connectors),
                "error_handlers": sorted(inherited_error_handlers),
                "error_handler_details": inherited_error_handler_details[:8],
                "branch_points": inherited_branch_points[:8],
                "variable_writes": inherited_variable_writes[:16],
                "http_requests": node.get("http_requests", []),
                "processors": node.get("processors", []),
                "processor_chain": node.get("processor_chain", []),
                "trigger": node.get("trigger", {}),
                "final_processor": node.get("final_processor", {}),
                "dwl_files": sorted(inherited_dwl_files),
                "inline_dwl": inline_dwl[:8],
                "payload_references": inherited_payload_refs[:30],
                "mock_plan": inherited_mock_plan[:20],
                "set_event_plan": set_event_plan,
                "output_fields": output_fields,
                "related_flow_details": related_flow_details[:8],
                "xml_snippet": node.get("xml_snippet", "")
            }

        return contexts

    def _collect_descendant_flows(self, flow_name: str, flow_graph: Dict[str, Dict]) -> List[str]:
        """Return child flow refs recursively in traversal order."""
        descendants = []
        seen = set()

        def visit(current: str):
            for child in flow_graph.get(current, {}).get("children", []):
                if child in seen:
                    continue
                seen.add(child)
                descendants.append(child)
                visit(child)

        visit(flow_name)
        return descendants

    def _local_tag_name(self, tag: str) -> str:
        """Return the local tag name without namespace."""
        return tag.split("}", 1)[-1] if "}" in tag else tag

    def validate_mule_xml(self, xml_content: str) -> bool:
        """
        Validate that XML appears to be a Mule application.
        
        Args:
            xml_content: Raw XML content
            
        Returns:
            True if appears to be valid Mule XML
        """
        try:
            # Debug: Show what we're trying to validate
            self.console.print(f"[cyan]🔍 Validating XML content (first 200 chars):[/cyan]")
            self.console.print(f"[cyan]{repr(xml_content[:200])}[/cyan]")
            
            # First check if it's valid XML at all
            root = ET.fromstring(xml_content)
            
            # Debug: Show root element info
            self.console.print(f"[cyan]📋 Root element tag: {root.tag}[/cyan]")
            self.console.print(f"[cyan]📋 Root attributes: {root.attrib}[/cyan]")
            
            # Enhanced Mule detection with more patterns
            mule_indicators = []
            
            # Check for Mule namespaces (more comprehensive)
            attrib_items = list(root.attrib.items())
            for attr, value in attrib_items:
                if 'mulesoft.org/schema/mule' in value:
                    mule_indicators.append(f"mulesoft namespace: {attr}={value}")
            
            # Check for Mule-specific elements (expanded list)
            mule_elements = [
                'flow', 'sub-flow', 'subflow',  # Flow elements
                'http:listener', 'http:request', 'http:response',  # HTTP elements
                'batch:job', 'batch:step', 'batch:aggregator',  # Batch elements
                'db:select', 'db:insert', 'db:update', 'db:delete',  # Database elements
                'logger', 'set-variable', 'transform', 'flow-ref',  # Common elements
                'apikit:router', 'apikit:config',  # API Kit elements
                'error-handler', 'on-error-propagate',  # Error handling
                'scheduler', 'poll', 'until-successful',  # Scheduling elements
                'jms:listener', 'jms:publish',  # JMS elements
                'vm:listener', 'vm:publish',  # VM elements
                'file:read', 'file:write',  # File elements
                'ftp:read', 'ftp:write',  # FTP elements
                'salesforce:create', 'salesforce:update',  # Salesforce elements
                'json:transform', 'xml:transform',  # Transform elements
                'dw:transform', 'ee:transform',  # DataWeave elements
                'choice', 'when', 'otherwise',  # Choice elements
                'foreach', 'for',  # Loop elements
                'scatter-gather',  # Scatter-gather
                'async', 'sync'  # Async elements
            ]
            
            for element in root.iter():
                element_tag = element.tag.lower()
                for mule_elem in mule_elements:
                    if mule_elem.lower() in element_tag:
                        mule_indicators.append(f"mule element: {element_tag}")
                        break
            
            # Check for common Mule file patterns in content
            content_lower = xml_content.lower()
            content_patterns = [
                'mule xmlns:',
                'xmlns:mule=',
                'xmlns:http=',
                'xmlns:db=',
                'xmlns:batch=',
                'xmlns:apikit=',
                'xmlns:dw=',
                'xmlns:ee=',
                '<flow name=',
                '<sub-flow',
                '<subflow',
                '<http:listener',
                '<logger message=',
                '<set-variable',
                '<flow-ref',
                '<transform',
                '<error-handler'
            ]
            
            for pattern in content_patterns:
                if pattern in content_lower:
                    mule_indicators.append(f"content pattern: {pattern}")
            
            # Debug logging
            if mule_indicators:
                self.console.print(f"[green]✓ Mule XML detected - Found {len(mule_indicators)} indicators[/green]")
                for indicator in mule_indicators[:3]:  # Show first 3 indicators
                    self.console.print(f"  • {indicator}")
                if len(mule_indicators) > 3:
                    self.console.print(f"  • ... and {len(mule_indicators) - 3} more")
                return True
            else:
                # If no Mule indicators found, but it's valid XML, still accept it
                # (some Mule XML files might be minimal)
                self.console.print("[yellow]⚠ No specific Mule indicators found, but XML is valid[/yellow]")
                self.console.print("[yellow]  Accepting as potential Mule XML[/yellow]")
                return True
            
        except ET.ParseError as e:
            self.console.print(f"[red]❌ XML Parse Error: {str(e)}[/red]")
            return False
        except Exception as e:
            self.console.print(f"[red]❌ XML Validation Error: {str(e)}[/red]")
            return False
