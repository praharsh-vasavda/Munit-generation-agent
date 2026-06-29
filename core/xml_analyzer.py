"""
XML analyzer for extracting key information from MuleSoft application XML files.
"""

import os
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from rich.console import Console
from .compliance_policy import CompliancePolicy


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
        "salesforce:delete",
        "salesforce:upsert",
        "salesforce:retrieve",
        "sap:synchronous-remote-function-call",
        "sap:send",
        "sap:query",
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
        # HTTP / HTTPS
        "http:listener",
        "httpn:listener",
        # JMS
        "jms:listener",
        "jms:consume",
        # AMQP / RabbitMQ
        "amqp:listener",
        "amqp:consume",
        "rabbitmq:listener",
        # Kafka
        "kafka:consumer",
        "kafka:message-listener",
        # Anypoint MQ
        "anypoint-mq:subscriber",
        "anypoint-mq:listener",
        # VM (in-memory)
        "vm:listener",
        "vm:receive",
        # File / SFTP / FTP
        "file:listener",
        "sftp:listener",
        "ftp:listener",
        # Scheduler / poller
        "scheduler",
        "poll",
        # Salesforce streaming
        "salesforce:replay-channel-listener",
        "salesforce:subscribe-channel-listener",
        "salesforce:subscribe-streaming-channel",
        # Object Store CDC
        "os:listener",
        # Database CDC
        "db:listener",
        # Sockets / WebSocket
        "sockets:listener",
        "websocket:inbound-listener",
        # Generic / custom
        "trigger",
        "source",
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
        'sap':          'http://www.mulesoft.org/schema/mule/sap',
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
                self._build_context_targets(analysis_result["flow_graph"], analysis_result["test_targets"]),
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

                processor_type = self._qualify_processor_type(child, child_name)
                if (
                    self._is_external_mock_processor(processor_type)
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
            referenced_flows = self._extract_static_referenced_flows(processor_chain)

            # ── Full dynamic ref resolution (Phase A+B of DynamicFlowResolver) ─
            # This covers: variable-based flow-refs, choice-branch variables,
            # if/else expressions, string concat patterns, map dispatch, and
            # DataWeave lookup() calls — all resolved against the full flow name set.
            all_project_flow_names = set(
                (d.get("name") or "") for d in flow_details
            )  # includes flows already processed in this pass
            # Merge in the registry being built (may be incomplete mid-loop — that's OK)

            dynamic_analysis = self._extract_dynamic_refs_from_element(
                element, all_project_flow_names
            )
            dynamic_flow_refs  = dynamic_analysis.get("dynamic_flow_refs", [])
            dw_lookup_refs     = dynamic_analysis.get("dw_lookup_refs", [])
            unresolved_refs    = dynamic_analysis.get("unresolved_refs", [])
            var_value_map      = dynamic_analysis.get("var_value_map", {})

            # Merge dynamic + dw_lookup into referenced_flows (unique, preserving order)
            all_resolved_dynamic = dynamic_flow_refs + dw_lookup_refs
            for r in all_resolved_dynamic:
                if r and r not in referenced_flows:
                    referenced_flows.append(r)

            # Also run the legacy DWL lookup extractor as a cross-check
            legacy_dw_lookups = self._extract_dw_lookup_refs(element)
            for r in legacy_dw_lookups:
                if r and r not in dw_lookup_refs:
                    dw_lookup_refs.append(r)
                if r and r not in referenced_flows:
                    referenced_flows.append(r)

            # ── Parent-flow flag ─────────────────────────────────────────
            is_sub = local_name in {"sub-flow", "subflow"}
            is_parent = (not is_sub) and bool(
                trigger_processor.get("type") and
                trigger_processor.get("type") in self.SOURCE_PROCESSORS
            )
            if not is_parent and not is_sub:
                is_parent = any(c in self.SOURCE_PROCESSORS for c in connectors)

            flow_details.append({
                "name": flow_name,
                "type": "sub-flow" if is_sub else "flow",
                "is_parent_flow": is_parent,
                "has_source_listener": is_parent,
                "processors": sorted(set(processors)),
                "processor_chain": processor_chain,
                "referenced_flows": sorted(set(referenced_flows)),
                "dynamic_flow_refs": dynamic_flow_refs,
                "dw_lookup_refs": dw_lookup_refs,
                "unresolved_refs": unresolved_refs,
                "var_value_map": var_value_map,
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
                "raw_xml": ET.tostring(element, encoding="unicode"),
                "xml_snippet": ET.tostring(element, encoding="unicode"),
            })

        return flow_details

    def _extract_static_referenced_flows(self, processor_chain: List[Dict]) -> List[str]:
        referenced = []
        for processor in processor_chain or []:
            if processor.get("type") != "flow-ref":
                continue
            ref_name = processor.get("name") or processor.get("ref") or processor.get("target")
            if ref_name and not self._is_dynamic_flow_ref(ref_name) and ref_name not in referenced:
                referenced.append(ref_name)
            # Handle simple literal expression: #["my-flow"]
            elif ref_name and ref_name.startswith('#["') and ref_name.endswith('"]'):
                literal = ref_name[3:-2]
                if literal and literal not in referenced:
                    referenced.append(literal)
        return referenced

    def _extract_dw_lookup_refs(self, element) -> List[str]:
        """
        Scan all children for DataWeave lookup() calls and return the referenced flow names.
        Handles both inline scripts and attribute values.
        Syntax matched: lookup("flow-name", ...) or lookup('flow-name', ...)
        """
        LOOKUP_RE = re.compile(r"""lookup\s*\(\s*['"]([^'"]+)['"]\s*,""")
        found: List[str] = []

        def _scan(text: str) -> None:
            for m in LOOKUP_RE.finditer(text or ""):
                name = m.group(1)
                if name and name not in found:
                    found.append(name)

        for child in element.iter():
            _scan(child.text or "")
            _scan(child.tail or "")
            for val in child.attrib.values():
                _scan(val)

        return found

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
            "operation", "value", "variableName", "ref", "url", "expression",
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
        elif child_name == "set-variable":
            text_value = (element.text or "").strip()
            if text_value:
                metadata["dwl_excerpt"] = text_value[:1200]

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
            branch_processors = []
            raise_error = None
            validation_failure = None
            for processor_index, branch_child in enumerate(child.iter()):
                if branch_child is child:
                    continue
                branch_child_name = self._local_tag_name(branch_child.tag)
                branch_processor_type = self._qualify_processor_type(branch_child, branch_child_name)
                processor_meta = self._extract_processor_metadata(
                    branch_child,
                    branch_child_name,
                    processor_index,
                )
                if processor_meta:
                    branch_processors.append(processor_meta)
                if branch_child_name == "raise-error":
                    raise_error = {
                        "type": branch_child.attrib.get("type", ""),
                        "description": branch_child.attrib.get("description", ""),
                        "doc_name": self._get_documentation_name(branch_child),
                    }
                elif branch_processor_type.startswith("validation:"):
                    validation_failure = {
                        "type": self._validation_error_type_for_processor(branch_processor_type),
                        "processor": branch_processor_type,
                        "doc_name": self._get_documentation_name(branch_child),
                    }
            error_info = raise_error or validation_failure or {}
            branches.append({
                "type": child_name,
                "condition": condition,
                "description": f"{child_name} branch {branch_index}: {condition or 'otherwise'}",
                "processors": branch_processors[:20],
                "terminates_with_error": bool(error_info),
                "raise_error": raise_error or {},
                "validation_failure": validation_failure or {},
                "expected_error_type": error_info.get("type", ""),
            })
        return branches

    def _validation_error_type_for_processor(self, processor_type: str) -> str:
        """Infer the Mule validation error emitted by a validation module processor."""
        local_name = (processor_type or "").split(":", 1)[-1].replace("-", "_").upper()
        return f"VALIDATION:{local_name or 'INVALID_VALUE'}"

    def _extract_error_handler_detail(self, element: ET.Element, child_name: str) -> Dict:
        """Capture enough error-handler detail to plan failure assertions."""
        handler_processors = []
        dwl_excerpts = []
        for index, child in enumerate(element.iter()):
            if child is element:
                continue
            processor_name = self._local_tag_name(child.tag)
            processor_meta = self._extract_processor_metadata(child, processor_name, index)
            if processor_meta:
                handler_processors.append(processor_meta)
                if processor_meta.get("dwl_excerpt"):
                    dwl_excerpts.append(processor_meta["dwl_excerpt"])

        handler_dwl = (self._extract_inline_dwl(element) or {}).get("script", "")
        if handler_dwl:
            dwl_excerpts.insert(0, handler_dwl)

        return {
            "type": child_name,
            "doc_name": self._get_documentation_name(element),
            "error_type": element.attrib.get("type", ""),
            "enable_notifications": element.attrib.get("enableNotifications", ""),
            "dwl_excerpt": dwl_excerpts[0] if dwl_excerpts else "",
            "dwl_excerpts": dwl_excerpts[:6],
            "processors": handler_processors[:12],
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
            "http://www.mulesoft.org/schema/mule/sap": "sap",
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
        if not prefix:
            prefix = self._infer_mule_namespace_prefix(namespace)
        if prefix == "core":
            return local_name
        if prefix:
            return f"{prefix}:{local_name}"
        return local_name

    def _infer_mule_namespace_prefix(self, namespace: str) -> str:
        """Infer connector prefix from Mule schema URIs not listed explicitly."""
        match = re.search(r"/schema/mule/([A-Za-z0-9_-]+)$", namespace or "")
        return match.group(1) if match else ""

    def _build_mock_plan(self, processor_chain: List[Dict]) -> List[Dict]:
        """Create deterministic mock/verify guidance from the ordered processor chain."""
        mock_plan = []

        for index, processor in enumerate(processor_chain):
            processor_type = processor.get("type", "")
            if not self._is_external_mock_processor(processor_type) and processor_type not in self.VOID_VERIFY_PROCESSORS:
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

    def _is_external_mock_processor(self, processor_type: str) -> bool:
        """Return True for outbound connectors that MUnit must mock."""
        processor = processor_type or ""
        if processor in self.EXTERNAL_MOCK_PROCESSORS:
            return True
        if processor in self.SOURCE_PROCESSORS or ":" not in processor:
            return False

        prefix, local_name = processor.split(":", 1)
        if prefix in {
            "ee",
            "apikit",
            "batch",
            "core",
            "doc",
            "dw",
            "http",
            "munit",
            "munit-tools",
            "oauth",
            "spring",
            "tls",
            "validation",
            "xsi",
        }:
            return False
        if local_name in {
            "config",
            "connection",
            "consumer-config",
            "global-endpoint",
            "headers",
            "listener",
            "listener-config",
            "operation",
            "query-params",
            "request-builder",
            "request-config",
            "response-validator",
            "uri-params",
        }:
            return False
        return True

    def _default_media_type_for_processor(self, processor_type: str) -> str:
        """Return the safest MUnit media type for a mocked processor."""
        if processor_type.startswith("db:") or processor_type.startswith("salesforce:") or processor_type.startswith("sap:"):
            return "application/java"
        if processor_type.startswith("sftp:") or processor_type.startswith("file:"):
            return "text/plain"
        return "application/json"

    def _default_result_shape_for_processor(self, processor_type: str) -> str:
        """Return the expected shape of a successful mocked result."""
        if processor_type in {"db:select", "salesforce:query"} or processor_type.startswith("sap:"):
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
                self._is_external_mock_processor(processor_type)
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
            self._build_context_targets(merged["flow_graph"], merged["test_targets"]),
            merged["flow_graph"]
        )

        self.console.print("[green]Project Analysis Complete:[/green]")
        self.console.print(f"  Source Files: {len(source_files)}")
        self.console.print(f"  Flows: {len(unique_flows)}")
        self.console.print(f"  Sub-flows: {len(unique_sub_flows)}")

        return merged

    def _build_context_targets(self, flow_graph: Dict[str, Dict], preferred_targets: List[str]) -> List[str]:
        """Build rich contexts for all real flows while keeping recommended targets first."""
        targets = []
        for name in preferred_targets or []:
            if name in flow_graph and name not in targets:
                targets.append(name)
        for name, node in (flow_graph or {}).items():
            if node.get("type") == "referenced-flow":
                continue
            if name not in targets:
                targets.append(name)
        return targets

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
        """
        Build the ordered list of flow names that should get their own MUnit suite.

        Three categories are included:
          1. entry_point  — has a listener (HTTP, scheduler, JMS, etc.) Always included.
          2. api_resource — APIKit resource flow. Each endpoint needs isolated tests.
          3. unreachable  — excluded (dead code, no test value).
          4. internal     — excluded (covered by entry_point parent tests).
        """
        referenced_by_others: set = set()
        all_flow_names = {detail.get("name") for detail in flow_details if detail.get("name")}
        for detail in flow_details:
            for ref in detail.get("referenced_flows", []):
                referenced_by_others.add(ref)
            for ref in self._dynamic_references_from_detail(detail, all_flow_names):
                referenced_by_others.add(ref)

        sub_flow_set = set(sub_flows)
        details_by_name = {detail.get("name"): detail for detail in flow_details}
        ordered_targets = []

        for flow_name in flows:
            flow_detail = details_by_name.get(flow_name, {})

            if self._should_exclude_from_direct_munit(flow_name, flow_detail):
                continue

            category = self._classify_flow_category(
                flow_name, flow_detail, referenced_by_others, sub_flow_set
            )

            if category in ("entry_point", "api_resource"):
                if flow_name not in ordered_targets:
                    ordered_targets.append(flow_name)
            # internal and unreachable are excluded

        # Fallback: nothing selected -> include all non-sub, non-excluded flows
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

    def build_flow_categories(
        self,
        flows: List[str],
        sub_flows: List[str],
        flow_details: List[Dict],
    ) -> Dict[str, List[str]]:
        """
        Return flows grouped into the four categories.
        Used by build_flow_selection_payload in app.py.
        """
        referenced_by_others: set = set()
        all_flow_names = {d.get("name") for d in flow_details if d.get("name")}
        for detail in flow_details:
            for ref in detail.get("referenced_flows", []):
                referenced_by_others.add(ref)
            for ref in self._dynamic_references_from_detail(detail, all_flow_names):
                referenced_by_others.add(ref)

        sub_flow_set = set(sub_flows)
        details_by_name = {d.get("name"): d for d in flow_details}

        categories: Dict[str, List[str]] = {
            "entry_point": [],
            "api_resource": [],
            "unreachable": [],
            "internal": [],
        }

        for flow_name in flows:
            flow_detail = details_by_name.get(flow_name, {})
            if self._should_exclude_from_direct_munit(flow_name, flow_detail):
                continue
            cat = self._classify_flow_category(
                flow_name, flow_detail, referenced_by_others, sub_flow_set
            )
            categories[cat].append(flow_name)

        return categories

    def _classify_flow_category(
        self,
        flow_name: str,
        flow_detail: Dict,
        referenced_by_others: set,
        sub_flow_set: set,
    ) -> str:
        """
        Classify a flow into one of four categories:

        entry_point  — has a listener/source (HTTP, scheduler, JMS, etc.)
                       These always get their own MUnit test.

        api_resource — APIKit resource flow with no listener of its own.
                       Routed to by an apikit:router. Each endpoint needs
                       its own MUnit test to isolate business logic.

        unreachable  — no listener AND never called by any other flow.
                       Dead code — flag to developer, skip test generation.

        internal     — called by other flows via flow-ref / DW lookup.
                       Covered indirectly when the parent flow is tested.
        """
        if flow_name in sub_flow_set:
            return "internal"

        # entry_point: has a source listener
        if self._flow_has_source_listener(flow_detail):
            return "entry_point"

        # api_resource: APIKit-routed endpoint flow
        if self._is_apikit_resource_flow(flow_name, flow_detail):
            return "api_resource"

        # unreachable: never called and no listener
        if flow_name not in referenced_by_others:
            return "unreachable"

        # internal: called by someone else
        return "internal"

    def _is_apikit_resource_flow(self, flow_name: str, flow_detail: Dict) -> bool:
        """
        Detect APIKit resource flows.

        Patterns:
          - Name matches HTTP-method prefix:
            get:\\orders:api-config
            post:\\orders\\(id):api-config
            delete:\\customers\\(customerId):api-config
          - Name contains a backslash path segment (MuleSoft APIKit convention)
          - Processor chain or connectors reference apikit namespace
        """
        import re as _re
        name_lower = (flow_name or "").lower().strip()
        # Standard APIKit: get:\orders:api-config or post:\customers\(id):api-config
        if _re.match(r"^(get|post|put|patch|delete|head|options)[:\\]", name_lower):
            return True
        # Alternative slash style
        if _re.match(r"^(get|post|put|patch|delete|head|options)/", name_lower):
            return True
        # Backslash in name + HTTP method word
        if chr(92) in flow_name and any(
            m in name_lower for m in ("get","post","put","patch","delete")
        ):
            return True
        return False

    def _dynamic_references_from_detail(self, detail: Dict, all_flow_names: set) -> List[str]:
        processors = detail.get("processor_chain", []) or []
        references = []
        for index, processor in enumerate(processors):
            if processor.get("type") != "flow-ref":
                continue
            ref_expression = processor.get("name") or processor.get("ref") or processor.get("target") or ""
            if not self._is_dynamic_flow_ref(ref_expression):
                continue
            for candidate in self._dynamic_flow_ref_candidates(
                ref_expression,
                processors[:index],
                all_flow_names,
            ):
                if candidate not in references:
                    references.append(candidate)
        return references

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

        if self._is_health_check_flow(flow_name, flow_detail):
            return True

        return False

    def _flow_has_source_listener(self, flow_detail: Dict) -> bool:
        """Return True for flows started by HTTP, queue, scheduler, file, or similar sources."""
        # Check is_parent_flow flag set during extraction (fastest path)
        if flow_detail.get("is_parent_flow"):
            return True
        trigger_type = ((flow_detail.get("trigger") or {}).get("type") or "").lower()
        connectors = [str(c).lower() for c in flow_detail.get("connectors", [])]
        return (
            trigger_type in self.SOURCE_PROCESSORS
            or any(c in self.SOURCE_PROCESSORS for c in connectors)
            # Also catch partial matches like "amqp:subscriber" or "kafka:batch-consumer"
            or any(
                any(src.split(":")[0] in c for src in self.SOURCE_PROCESSORS if ":" in src)
                for c in connectors
                if "listener" in c or "subscriber" in c or "consumer" in c or "scheduler" in c
            )
        )

    def _is_health_check_flow(self, flow_name: str, flow_detail: Dict) -> bool:
        """Exclude low-value health/ping/status listener flows from recommended MUnit targets."""
        normalized_name = (flow_name or "").strip().lower()
        if re.search(r"\b(?:health|healthcheck|health-check|ping|liveness|readiness)\b", normalized_name):
            return True

        paths = []
        trigger = flow_detail.get("trigger") or {}
        if trigger.get("path"):
            paths.append(str(trigger.get("path")))
        for request in flow_detail.get("http_requests", []) or []:
            if request.get("path"):
                paths.append(str(request.get("path")))

        health_paths = {
            "/health",
            "/healthcheck",
            "/health-check",
            "/ping",
            "/status",
            "/liveness",
            "/readiness",
        }
        return any(path.strip().lower() in health_paths for path in paths)

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
                "dynamic_flow_refs": list(detail.get("dynamic_flow_refs", [])),
                "dw_lookup_refs": list(detail.get("dw_lookup_refs", [])),
                "unresolved_refs": list(detail.get("unresolved_refs", [])),
                "var_value_map": dict(detail.get("var_value_map", {})),
                "xml_snippet": detail.get("xml_snippet", "")
            }

        self._resolve_dynamic_flow_refs(graph)

        # ── Second-pass dynamic resolution with full flow name set ────────────
        # First pass resolved dynamics against a partial name set (flows parsed
        # so far). Now that the entire graph is built, re-run DynamicFlowResolver
        # on every flow that has unresolved_refs, using the complete set.
        self._reresolve_dynamic_refs_full_pass(graph)
        self._resolve_dynamic_flow_refs_with_inherited_vars(graph)

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

    def _resolve_dynamic_flow_refs(self, graph: Dict[str, Dict]) -> None:
        """
        Attach best-effort candidate child flows for dynamic flow-ref expressions.
        Uses DynamicFlowResolver-enriched data already stored in each node's
        'dynamic_flow_refs' and 'dw_lookup_refs' lists (set during _extract_flow_details),
        then falls back to expression-level resolution for any remaining ones.
        """
        flow_names = set(graph.keys())

        for flow_name, node in graph.items():
            children = list(node.get("children", []) or [])

            # ── Fast path: use pre-resolved refs from _extract_flow_details ─
            for ref in node.get("dynamic_flow_refs", []) or []:
                if ref and ref in flow_names and ref not in children:
                    children.append(ref)
            for ref in node.get("dw_lookup_refs", []) or []:
                if ref and ref in flow_names and ref not in children:
                    children.append(ref)

            # ── Fallback: process-chain level resolution ──────────────────
            processors = node.get("processor_chain", []) or []
            for index, processor in enumerate(processors):
                if processor.get("type") != "flow-ref":
                    continue
                ref_expression = (
                    processor.get("name")
                    or processor.get("ref")
                    or processor.get("target")
                    or ""
                )
                if not self._is_dynamic_flow_ref(ref_expression):
                    continue

                candidates = self._dynamic_flow_ref_candidates(
                    ref_expression,
                    processors[:index],
                    flow_names,
                )
                if candidates:
                    processor["dynamic_flow_candidates"] = candidates
                    processor["dynamic"] = True
                    processor["summary"] = (
                        f"{processor.get('summary', 'flow-ref')} "
                        f"dynamic→[{', '.join(candidates)}]"
                    )
                    for candidate in candidates:
                        if candidate not in children:
                            children.append(candidate)
                else:
                    # Mark as unresolvable for UI display
                    processor["dynamic"] = True
                    processor["dynamic_unresolved"] = True
                    if "unresolved_refs" not in node:
                        node["unresolved_refs"] = []
                    if ref_expression not in node["unresolved_refs"]:
                        node["unresolved_refs"].append(ref_expression)

            node["children"] = children

    def _dynamic_flow_ref_candidates(
        self,
        ref_expression: str,
        prior_processors: List[Dict],
        flow_names: set,
    ) -> List[str]:
        """
        IMPROVED: delegate to DynamicFlowResolver which handles all 9 dynamic
        ref patterns (variable lookup, if/else, concat, map dispatch, etc.).

        Prior processors are still accepted for backward compatibility but the
        resolver uses the full XML element scan instead.

        This method is called from _dynamic_references_from_detail() which
        operates on the processor_chain dict list (no raw XML available).
        For that path we use the limited fallback below; the main path is
        _extract_dynamic_refs_from_element() which has the raw XML.
        """
        from .dynamic_flow_resolver import DynamicFlowResolver, _is_dynamic

        if not flow_names:
            return []

        resolver = DynamicFlowResolver(set(flow_names))

        # Build a minimal variable value map from prior_processors
        for proc in prior_processors or []:
            if proc.get("type") != "set-variable":
                continue
            vname = (
                proc.get("variableName")
                or proc.get("variable_name")
                or proc.get("target", "")
            )
            for val in [proc.get("value", ""), proc.get("dwl_excerpt", "")]:
                for lit in resolver._extract_string_literals(val):
                    resolver._record_var(vname, lit)

        # Feed the single expression
        if _is_dynamic(ref_expression):
            resolver._dynamic_flow_ref_exprs.append(ref_expression)

        result = resolver.resolve_all()
        return result.dynamic_refs

    def _resolve_dynamic_flow_refs_with_inherited_vars(self, graph: Dict[str, Dict]) -> None:
        """
        Resolve dynamic flow-refs whose target variable is assigned in an
        upstream flow before the current flow is invoked.

        Mule variables propagate through flow-ref calls, so a child flow may
        contain <flow-ref name="#[vars.flowName]"/> while flowName was set by
        the parent. Static per-flow analysis cannot see that without walking
        the call path.
        """
        flow_names = set(graph.keys())
        roots = [
            name for name, node in graph.items()
            if self._graph_node_has_source_listener(node) or not node.get("parents")
        ]
        changed = True
        while changed:
            changed = False
            for root in roots:
                if root not in graph:
                    continue
                if self._propagate_dynamic_refs_from_flow(root, graph, flow_names, {}, set()):
                    changed = True

    def _propagate_dynamic_refs_from_flow(
        self,
        flow_name: str,
        graph: Dict[str, Dict],
        flow_names: set,
        inherited_vars: Dict[str, set],
        visiting: set,
    ) -> bool:
        if flow_name in visiting:
            return False
        node = graph.get(flow_name)
        if not node:
            return False

        visiting = set(visiting)
        visiting.add(flow_name)
        vars_map = {key: set(values) for key, values in (inherited_vars or {}).items()}
        changed = False

        for processor in node.get("processor_chain", []) or []:
            self._record_processor_var_literals(processor, vars_map)
            if processor.get("type") != "flow-ref":
                continue

            ref_expression = (
                processor.get("name")
                or processor.get("ref")
                or processor.get("target")
                or ""
            )
            candidates: List[str] = []
            if self._is_dynamic_flow_ref(ref_expression):
                candidates = self._resolve_dynamic_expression_with_vars(
                    ref_expression,
                    vars_map,
                    flow_names,
                )
                if candidates:
                    existing = list(processor.get("dynamic_flow_candidates", []) or [])
                    merged = list(dict.fromkeys(existing + candidates))
                    processor["dynamic_flow_candidates"] = merged
                    processor["dynamic"] = True
                    if processor.get("dynamic_unresolved"):
                        processor["dynamic_unresolved"] = False
                        changed = True
                    if merged != existing:
                        changed = True
            else:
                candidates = [ref_expression] if ref_expression in flow_names else []

            for child in candidates:
                if child not in graph:
                    continue
                if child not in node.get("children", []):
                    node.setdefault("children", []).append(child)
                    changed = True
                child_node = graph.get(child)
                if child_node is not None and flow_name not in child_node.get("parents", []):
                    child_node.setdefault("parents", []).append(flow_name)
                    changed = True
                if self._propagate_dynamic_refs_from_flow(child, graph, flow_names, vars_map, visiting):
                    changed = True

        return changed

    def _record_processor_var_literals(self, processor: Dict, vars_map: Dict[str, set]) -> None:
        processor_type = processor.get("type", "")
        if not (
            processor_type.endswith("set-variable")
            or processor_type.endswith("set-payload")
            or processor_type.endswith("set-attributes")
        ):
            return
        var_name = (
            processor.get("variableName")
            or processor.get("variable_name")
            or processor.get("target")
            or ""
        )
        is_payload_write = processor_type.endswith("set-payload")
        is_attributes_write = processor_type.endswith("set-attributes")
        if not var_name and not is_payload_write and not is_attributes_write:
            return

        values = []
        for key in ("value", "dwl_excerpt"):
            text = processor.get(key) or ""
            for field, literal in self._extract_object_string_fields(text).items():
                if is_payload_write:
                    vars_map.setdefault(f"payload.{field}", set()).add(literal)
                elif is_attributes_write:
                    vars_map.setdefault(f"attributes.{field}", set()).add(literal)
                else:
                    vars_map.setdefault(f"{var_name}.{field}", set()).add(literal)
                    if field.lower() in {"flowname", "flow_name", "targetflow", "target_flow"}:
                        vars_map.setdefault(var_name, set()).add(literal)
            values.extend(re.findall(r"""['"]([^'"]+)['"]""", text))
            body = text.split("---", 1)[1].strip() if "---" in text else text.strip()
            if body and len(body) < 200 and not re.search(r"\b(payload|vars|attributes)\b", body):
                values.append(body.strip("'\""))

        if is_payload_write or is_attributes_write:
            return

        for value in values:
            if value and value in vars_map.get(var_name, set()):
                continue
            if value:
                vars_map.setdefault(var_name, set()).add(value)

    def _resolve_dynamic_expression_with_vars(
        self,
        expression: str,
        vars_map: Dict[str, set],
        flow_names: set,
    ) -> List[str]:
        candidates = []
        for var_name in self._dynamic_reference_keys(expression):
            for value in vars_map.get(var_name, set()):
                cleaned = (value or "").strip().strip("'\"")
                if cleaned in flow_names and cleaned not in candidates:
                    candidates.append(cleaned)
        if candidates:
            return candidates
        return self._flow_names_from_expression(expression, flow_names)

    @staticmethod
    def _extract_object_string_fields(text: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        for match in re.finditer(
            r"""['"]?([A-Za-z_][A-Za-z0-9_\-]*)['"]?\s*:\s*['"]([^'"]{1,200})['"]""",
            text or "",
        ):
            fields[match.group(1)] = match.group(2)
        return fields

    @staticmethod
    def _dynamic_reference_keys(expression: str) -> List[str]:
        keys: List[str] = []

        def add(key: str) -> None:
            if key and key not in keys:
                keys.append(key)

        text = expression or ""
        for scope, path in re.findall(
            r"""\b(vars|variables|payload|attributes)\.([A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z_][A-Za-z0-9_\-]*)*)""",
            text,
        ):
            if scope in {"payload", "attributes"}:
                add(f"{scope}.{path}")
                if "." in path:
                    add(f"{scope}.{path.split('.')[-1]}")
            else:
                add(path)
                add(path.split(".", 1)[0])

        for scope, base, field in re.findall(
            r"""\b(vars|variables|payload|attributes)(?:\.([A-Za-z_][A-Za-z0-9_\-]*))?\s*\[\s*['"]([^'"]+)['"]\s*\]""",
            text,
        ):
            if scope in {"payload", "attributes"}:
                add(f"{scope}.{field}" if not base else f"{scope}.{base}.{field}")
            elif base:
                add(f"{base}.{field}")
                add(base)
            else:
                add(field)

        for var_name in re.findall(r"\b(?:vars|variables)\.([A-Za-z_][A-Za-z0-9_-]*)", text):
            add(var_name)
        return keys

    def _extract_dynamic_refs_from_element(
        self,
        flow_element,       # ET.Element
        all_flow_names: set,
    ) -> dict:
        """
        Full scan of a raw XML element for dynamic flow-refs and DW lookup()
        calls. Returns a dict compatible with the flow_detail structure.

        This is the *preferred* path — called from _extract_flow_details when
        we still have the ET.Element available.
        """
        from .dynamic_flow_resolver import resolve_dynamic_refs
        result = resolve_dynamic_refs(flow_element, set(all_flow_names))
        return {
            "dynamic_flow_refs": result.dynamic_refs,
            "dw_lookup_refs":    result.dw_lookup_refs,
            "unresolved_refs":   result.unresolved,
            "var_value_map":     result.var_value_map,
        }

    def _flow_names_from_expression(self, expression: str, flow_names: set) -> List[str]:
        matches = []
        for literal in re.findall(r"""['"]([^'"]+)['"]""", expression or ""):
            if literal in flow_names and literal not in matches:
                matches.append(literal)
        return matches

    def _vars_referenced_by_expression(self, expression: str) -> List[str]:
        variable_names = []
        for name in re.findall(r"\bvars\.([A-Za-z_][A-Za-z0-9_-]*)", expression or ""):
            if name not in variable_names:
                variable_names.append(name)
        return variable_names

    def _is_dynamic_flow_ref(self, ref_name: str) -> bool:
        text = (ref_name or "").strip()
        return text.startswith("#[") or "vars." in text or "${" in text

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

            traversal = self._traverse_flow_graph(target, flow_graph)
            execution_flows = traversal["execution_flows"]
            expanded_processor_chain = traversal["processor_chain"]
            flow_levels = traversal["flow_levels"]
            traversal_connectors = traversal["connectors"]
            traversal_warnings = traversal["warnings"]
            dynamic_flow_sources = self._munit_enable_flow_sources_for_traversal(
                target,
                expanded_processor_chain,
                flow_graph,
            )
            unresolved_flow_refs = self._find_unresolved_flow_refs(expanded_processor_chain, flow_graph)
            effective_final_processor = self._effective_final_processor_for_target(
                target,
                node.get("processor_chain", []),
                expanded_processor_chain,
            )
            inherited_mock_plan = self._build_mock_plan(expanded_processor_chain)
            execution_paths = self._build_execution_paths(
                target,
                execution_flows,
                expanded_processor_chain,
                inherited_branch_points,
                inherited_mock_plan,
            )

            from .deterministic_munit_builder import build_set_event_plan, extract_output_fields

            set_event_plan = build_set_event_plan(
                expanded_processor_chain,
                inline_dwl[:8],
                node.get("trigger", {}) or {},
            )
            endpoint_metadata = self._extract_endpoint_metadata_from_flow_name(target)
            if endpoint_metadata:
                set_event_plan = self._merge_endpoint_metadata_into_set_event_plan(
                    set_event_plan,
                    endpoint_metadata,
                )
            output_fields = extract_output_fields(
                inline_dwl[:8],
                effective_final_processor,
            )
            required_inputs = self._required_inputs_from_set_event_plan(set_event_plan)

            contexts[target] = {
                "target_flow": target,
                "target_type": node.get("type", "unknown"),
                "source_file": node.get("source_file", "unknown.xml"),
                "has_source_listener": self._graph_node_has_source_listener(node),
                # FIX: is_parent_flow = has a listener/source element.
                # A flow is an entry point because it HAS a listener, not because
                # nobody else calls it. A flow with both a listener AND callers
                # (e.g. called via flow-ref from an error handler) is still a
                # parent flow and needs its own MUnit test.
                "is_parent_flow": self._graph_node_has_source_listener(node),
                "direct_munit_excluded": self._should_exclude_from_direct_munit(target, node),
                "parent_flows": node.get("parents", []),
                "child_flows": node.get("children", []),
                "related_flows": related_flows,
                "execution_flows": execution_flows,
                "flow_levels": flow_levels,
                "execution_paths": execution_paths,
                "unresolved_flow_refs": unresolved_flow_refs,
                "flow_traversal_warnings": traversal_warnings,
                "dynamic_flow_sources": dynamic_flow_sources,
                "munit_enable_flow_sources": dynamic_flow_sources,
                "traversal_connectors": traversal_connectors,
                "connectors": sorted(inherited_connectors),
                "error_handlers": sorted(inherited_error_handlers),
                "error_handler_details": inherited_error_handler_details[:8],
                "branch_points": inherited_branch_points[:8],
                "variable_writes": inherited_variable_writes[:16],
                "http_requests": node.get("http_requests", []),
                "processors": node.get("processors", []),
                "processor_chain": expanded_processor_chain,
                "own_processor_chain": node.get("processor_chain", []),
                "trigger": node.get("trigger", {}),
                "final_processor": effective_final_processor,
                "own_final_processor": self._effective_final_processor_from_chain(node.get("processor_chain", [])),
                "dwl_files": sorted(inherited_dwl_files),
                "inline_dwl": inline_dwl[:8],
                "payload_references": inherited_payload_refs[:30],
                "mock_plan": inherited_mock_plan[:20],
                "set_event_plan": set_event_plan,
                "required_inputs": required_inputs,
                "endpoint_metadata": endpoint_metadata,
                "compliance_policy": CompliancePolicy.metadata(),
                "output_fields": output_fields,
                "related_flow_details": related_flow_details[:8],
                "xml_snippet": node.get("xml_snippet", "")
            }

        return contexts

    def _munit_enable_flow_sources_for_traversal(
        self,
        target: str,
        processor_chain: List[Dict],
        flow_graph: Dict[str, Dict],
    ) -> List[str]:
        """
        Identify dynamically resolved flow-ref targets that should be declared
        in <munit:enable-flow-sources>.

        MUnit can fail to find dynamically referenced flows at runtime even
        when static analysis can resolve them. Emitting the resolved names in
        the suite-level flow-source list gives MUnit the same explicit list the
        developer would add by hand.
        """
        enabled = []
        seen = set()
        for processor in processor_chain or []:
            if processor.get("type") != "flow-ref":
                continue
            if not processor.get("dynamic"):
                continue
            for flow_name in processor.get("dynamic_flow_candidates", []) or []:
                candidate = str(flow_name or "").strip()
                if (
                    not candidate
                    or candidate == target
                    or candidate in seen
                    or candidate not in flow_graph
                ):
                    continue
                seen.add(candidate)
                enabled.append(candidate)
        return enabled

    def _graph_node_has_source_listener(self, node: Dict) -> bool:
        trigger_type = ((node.get("trigger") or {}).get("type") or "").lower()
        connectors = [str(connector).lower() for connector in node.get("connectors", [])]
        return trigger_type in self.SOURCE_PROCESSORS or any(connector in self.SOURCE_PROCESSORS for connector in connectors)

    def _find_unresolved_flow_refs(self, processor_chain: List[Dict], flow_graph: Dict[str, Dict]) -> List[Dict]:
        unresolved = []
        for processor in processor_chain or []:
            if processor.get("type") != "flow-ref":
                continue
            child_names = list(processor.get("dynamic_flow_candidates", []) or [])
            child_name = processor.get("name") or processor.get("ref") or processor.get("target")
            if child_name and not self._is_dynamic_flow_ref(child_name) and child_name not in child_names:
                child_names.append(child_name)
            if not child_names:
                unresolved.append({
                    "flow": processor.get("flow", ""),
                    "doc_name": processor.get("doc_name", ""),
                    "expression": child_name or "",
                    "reason": self._dynamic_flow_ref_unresolved_reason(child_name or ""),
                })
                continue
            for candidate in child_names:
                if candidate and candidate not in flow_graph:
                    unresolved.append({
                        "flow": processor.get("flow", ""),
                        "doc_name": processor.get("doc_name", ""),
                        "expression": candidate,
                        "reason": "target flow not found in analyzed Mule project",
                    })
        return unresolved

    def _dynamic_flow_ref_unresolved_reason(self, expression: str) -> str:
        expr = expression or ""
        if re.search(r"\battributes\.(queryParams|headers|uriParams)\b", expr):
            return "dynamic flow-ref target depends on runtime request attributes"
        if re.search(r"\b(payload|attributes)\.", expr):
            return "dynamic flow-ref target depends on runtime message data"
        if re.search(r"\b(?:vars|variables)\.", expr):
            return "dynamic flow-ref target variable could not be resolved from XML or inline DataWeave"
        if "p(" in expr or "Mule::p" in expr:
            return "dynamic flow-ref target depends on property/config lookup"
        return "flow-ref target is empty or fully dynamic"

    def _extract_endpoint_metadata_from_flow_name(self, flow_name: str) -> Dict:
        """Infer API endpoint attributes from APIKit-style implementation flow names."""
        if not flow_name:
            return {}

        methods = "get|post|put|patch|delete|head|options"
        match = re.match(
            rf"^\s*(?P<method>{methods})(?:(?P<colon>:)|\s+|(?=/))(?P<route>.+?)\s*$",
            flow_name,
            re.IGNORECASE,
        )
        if not match:
            return {}

        method = match.group("method").upper()
        route = (match.group("route") or "").strip()
        if match.group("colon") and route.startswith(":"):
            route = route[1:].strip()
        route = self._strip_apikit_config_suffix(route)

        if not route or route.startswith("#"):
            return {}

        path, query_string = self._split_endpoint_query(route)
        path = self._normalize_endpoint_path(path)
        if not path:
            return {}

        query_params = self._parse_endpoint_query_params(query_string)
        uri_params = {
            field: self._mock_attribute_value("uriParams", field)
            for field in re.findall(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}", path)
        }

        return {
            "method": method,
            "requestPath": path,
            "queryParams": query_params,
            "uriParams": uri_params,
        }

    def _strip_apikit_config_suffix(self, route: str) -> str:
        """Remove trailing APIKit config suffix, e.g. /path/{id}:api-config."""
        candidate = (route or "").strip()
        colon_index = candidate.rfind(":")
        if colon_index <= 0:
            return candidate

        suffix = candidate[colon_index + 1:].strip()
        if re.search(r"(api|config|router)", suffix, re.IGNORECASE):
            return candidate[:colon_index].strip()
        return candidate

    def _split_endpoint_query(self, route: str) -> tuple:
        if "?" not in route:
            return route, ""
        path, query_string = route.split("?", 1)
        return path, query_string

    def _normalize_endpoint_path(self, path: str) -> str:
        normalized = (path or "").strip()
        if not normalized:
            return ""
        normalized = re.sub(
            r"\(([A-Za-z_][A-Za-z0-9_-]*)\)",
            r"{\1}",
            normalized,
        )
        normalized = re.sub(
            r"/:([A-Za-z_][A-Za-z0-9_-]*)",
            r"/{\1}",
            normalized,
        )
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized

    def _parse_endpoint_query_params(self, query_string: str) -> Dict:
        query_params = {}
        if not query_string:
            return query_params

        for item in query_string.split("&"):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                key, value = item.split("=", 1)
                value = value.strip().strip("'\"")
            else:
                key, value = item, ""
            key = key.strip()
            if not key:
                continue
            query_params[key] = value or self._mock_attribute_value("queryParams", key)
        return query_params

    def _merge_endpoint_metadata_into_set_event_plan(self, plan: Dict, endpoint_metadata: Dict) -> Dict:
        """Apply endpoint metadata to the set-event attributes used by generated MUnits."""
        merged = dict(plan or {})
        attrs = dict(merged.get("attributes_template") or {})
        attrs["method"] = endpoint_metadata.get("method") or attrs.get("method", "GET")
        attrs["requestPath"] = endpoint_metadata.get("requestPath") or attrs.get("requestPath", "/")

        headers = dict(attrs.get("headers") or {})
        headers.setdefault("content-type", "application/json")
        attrs["headers"] = headers

        attrs["queryParams"] = self._merge_attribute_maps(
            attrs.get("queryParams"),
            endpoint_metadata.get("queryParams"),
        )
        attrs["uriParams"] = self._merge_attribute_maps(
            attrs.get("uriParams"),
            endpoint_metadata.get("uriParams"),
        )

        merged["attributes_template"] = attrs
        if attrs.get("method", "").upper() == "GET":
            merged.setdefault("payload_expression", '""')
            if merged.get("payload_expression") == "{}":
                merged["payload_expression"] = '""'
                merged["payload_media_type"] = "application/java"
        return merged

    def _merge_attribute_maps(self, existing: Optional[Dict], inferred: Optional[Dict]) -> Dict:
        merged = dict(existing or {})
        for key, value in (inferred or {}).items():
            if value not in (None, ""):
                merged[key] = value
            else:
                merged.setdefault(key, self._mock_attribute_value("queryParams", key))
        return merged

    def _mock_attribute_value(self, source: str, field: str) -> str:
        field_lower = (field or "").lower()
        if field_lower in {"id", "clientid", "client_id", "customerid", "customer_id", "accountid", "account_id"}:
            return "MOCK-001"
        if "email" in field_lower:
            return "test@example.com"
        if "name" in field_lower:
            return "Test Name"
        if "token" in field_lower or source == "headers":
            return "Bearer test-token"
        return "test-value"

    def _expanded_processor_chain(self, flow_names: List[str], flow_graph: Dict[str, Dict]) -> List[Dict]:
        """Return the ordered processor chain for the target plus reachable child flows."""
        expanded = []
        for flow_name in flow_names:
            for processor in flow_graph.get(flow_name, {}).get("processor_chain", []) or []:
                item = dict(processor)
                item.setdefault("flow", flow_name)
                expanded.append(item)
        return expanded

    def _expand_execution_plan(self, target: str, flow_graph: Dict[str, Dict]) -> tuple:
        """Inline flow-ref calls recursively in the order Mule will execute them."""
        traversal = self._traverse_flow_graph(target, flow_graph)
        return traversal["execution_flows"] or [target], traversal["processor_chain"]

    def _traverse_flow_graph(self, target: str, flow_graph: Dict[str, Dict]) -> Dict:
        """
        Apply the flow traversal ruleset:
        level the root flow, discover flow-ref children, recurse into each child,
        collect every non-flow-ref processor across levels, and skip already
        visited flows to avoid loops.
        """
        execution_flows: List[str] = []
        expanded_chain: List[Dict] = []
        traversal_connectors: List[Dict] = []
        warnings: List[Dict] = []
        visited = set()
        flow_levels: Dict[str, int] = {}

        def record_connector(processor: Dict, flow_name: str, level: int) -> None:
            processor_type = processor.get("type", "")
            if not processor_type or processor_type == "flow-ref":
                return
            traversal_connectors.append({
                "flow": flow_name,
                "level": level,
                "connector": processor_type,
                "operation": self._processor_operation(processor),
                "config": processor.get("config_ref") or None,
                "doc_name": processor.get("doc_name", ""),
            })

        def child_targets(processor: Dict) -> List[str]:
            children = list(processor.get("dynamic_flow_candidates", []) or [])
            child_name = processor.get("name") or processor.get("ref") or processor.get("target")
            if child_name and not self._is_dynamic_flow_ref(child_name) and child_name not in children:
                children.append(child_name)
            return children

        def visit(flow_name: str, level: int, parent: str = "") -> None:
            if flow_name in visited:
                warnings.append({
                    "flow": flow_name,
                    "parent": parent,
                    "level": level,
                    "reason": "flow-ref target already visited; skipped to prevent circular traversal",
                })
                return

            node = flow_graph.get(flow_name)
            if not node:
                warnings.append({
                    "flow": flow_name,
                    "parent": parent,
                    "level": level,
                    "reason": "flow-ref target not found in analyzed Mule project",
                })
                return

            visited.add(flow_name)
            flow_levels[flow_name] = level
            execution_flows.append(flow_name)

            for processor in node.get("processor_chain", []) or []:
                item = dict(processor)
                item.setdefault("flow", flow_name)
                item["level"] = level
                expanded_chain.append(item)
                record_connector(item, flow_name, level)

                if item.get("type") != "flow-ref":
                    continue

                children = child_targets(item)
                if not children:
                    warnings.append({
                        "flow": flow_name,
                        "doc_name": item.get("doc_name", ""),
                        "level": level,
                        "reason": "flow-ref target is empty or fully dynamic",
                    })
                    continue
                for child in children:
                    if child in flow_graph:
                        visit(child, level + 1, flow_name)
                    else:
                        warnings.append({
                            "flow": child,
                            "parent": flow_name,
                            "doc_name": item.get("doc_name", ""),
                            "level": level + 1,
                            "reason": "flow-ref target not found in analyzed Mule project",
                        })

        visit(target, 0)
        return {
            "execution_flows": execution_flows or [target],
            "flow_levels": flow_levels,
            "processor_chain": expanded_chain,
            "connectors": traversal_connectors,
            "warnings": warnings,
        }

    def _processor_operation(self, processor: Dict) -> Optional[str]:
        """Return the best operation label for the flat traversal contract."""
        processor_type = processor.get("type", "")
        if processor_type == "http:request":
            return processor.get("method") or "REQUEST"
        if processor_type == "http:listener":
            return processor.get("method") or processor.get("allowedMethods") or "LISTEN"
        if processor_type == "logger":
            return "log"
        if processor.get("operation"):
            return processor.get("operation")
        if ":" in processor_type:
            return processor_type.split(":", 1)[1]
        return processor_type or None

    def _build_execution_paths(
        self,
        target: str,
        execution_flows: List[str],
        expanded_processor_chain: List[Dict],
        branch_points: List[Dict],
        mock_plan: List[Dict],
    ) -> List[Dict]:
        """Summarize the selected flow's end-to-end static execution paths."""
        connectors = []
        for item in mock_plan or []:
            processor = item.get("processor")
            if processor and processor not in connectors:
                connectors.append(processor)

        path_processors = [
            {
                "flow": item.get("flow", target),
                "type": item.get("type"),
                "doc_name": item.get("doc_name", ""),
            }
            for item in (expanded_processor_chain or [])
            if item.get("type")
        ]

        paths = [{
            "name": "main_path",
            "flows": list(execution_flows or [target]),
            "connectors": connectors,
            "processors": path_processors[:40],
            "static_analysis_only": True,
        }]

        for index, branch in enumerate((branch_points or [])[:6], start=1):
            paths.append({
                "name": f"branch_{index}",
                "condition": branch.get("condition", ""),
                "description": branch.get("description", ""),
                "flows": list(execution_flows or [target]),
                "connectors": connectors,
                "static_analysis_only": True,
            })
        return paths

    def _required_inputs_from_set_event_plan(self, set_event_plan: Dict) -> Dict:
        attrs = (set_event_plan or {}).get("attributes_template") or {}
        payload_expression = (set_event_plan or {}).get("payload_expression")
        payload_fields = []
        try:
            parsed = json.loads(payload_expression or "{}")
            if isinstance(parsed, dict):
                payload_fields = list(parsed.keys())
        except Exception:
            payload_fields = []
        return {
            "method": attrs.get("method", "GET"),
            "requestPath": attrs.get("requestPath", "/"),
            "headers": sorted((attrs.get("headers") or {}).keys()),
            "queryParams": sorted((attrs.get("queryParams") or {}).keys()),
            "uriParams": sorted((attrs.get("uriParams") or {}).keys()),
            "payloadFields": payload_fields,
            "payloadRequired": bool(payload_fields),
        }

    def _effective_final_processor_from_chain(self, processor_chain: List[Dict]) -> Dict:
        """Use the last response-shaping processor in the expanded execution chain."""
        ignored_types = {
            "http:listener",
            "scheduler",
            "anypoint-mq:subscriber",
            "kafka:consumer",
            "sftp:listener",
            "jms:listener",
            "vm:listener",
            "flow-ref",
            "error-handler",
            "on-error-propagate",
            "on-error-continue",
            "logger",
            "set-variable",
            "remove-variable",
            "set-property",
            "remove-property",
        }
        for processor in reversed(processor_chain or []):
            processor_type = processor.get("type", "")
            if processor_type in ignored_types:
                continue
            return dict(processor)
        return {}

    def _effective_final_processor_for_target(
        self,
        target: str,
        own_processor_chain: List[Dict],
        expanded_processor_chain: List[Dict],
    ) -> Dict:
        """Prefer the selected root flow's own final payload producer over child flow processors."""
        own_final = self._effective_final_processor_from_chain(own_processor_chain)
        if own_final:
            own_final = dict(own_final)
            own_final.setdefault("flow", target)
            own_final.setdefault("level", 0)
            return own_final
        return self._effective_final_processor_from_chain(expanded_processor_chain)

    def _reresolve_dynamic_refs_full_pass(self, graph: Dict[str, Dict]) -> None:
        """
        Second-pass dynamic flow-ref resolution using the COMPLETE flow name set.

        Problem: at XML parse time, DynamicFlowResolver only knows flows parsed
        so far (partial set). So Flow D setting vars.targetFlow = "FlowE" and
        calling flow-ref #[vars.targetFlow] may not match "FlowE" if it was in
        a file parsed after D.

        This pass runs after the full graph is assembled, so all flow names are
        known. For every flow that has unresolved refs OR dynamic_flow_refs that
        weren't matched, we re-run the resolver and update children.
        """
        from .dynamic_flow_resolver import resolve_dynamic_refs
        import xml.etree.ElementTree as ET

        all_names = set(graph.keys())

        for flow_name, node in graph.items():
            raw_xml = node.get("xml_snippet") or node.get("raw_xml", "")
            if not raw_xml:
                continue

            unresolved = node.get("unresolved_refs", [])
            # Also re-check any node whose dynamic_flow_candidates is empty
            has_dynamic_processor = any(
                p.get("dynamic") and not p.get("dynamic_flow_candidates")
                for p in (node.get("processor_chain") or [])
            )

            if not unresolved and not has_dynamic_processor:
                continue

            try:
                element = ET.fromstring(raw_xml)
            except ET.ParseError:
                continue

            result = resolve_dynamic_refs(element, all_names)

            # Merge newly resolved refs into children
            current_children = set(node.get("children", []))
            newly_resolved = []
            for ref in result.dynamic_refs + result.dw_lookup_refs:
                if ref and ref in all_names and ref not in current_children:
                    current_children.add(ref)
                    newly_resolved.append(ref)

            resolved_refs = [
                ref for ref in result.dynamic_refs + result.dw_lookup_refs
                if ref and ref in all_names
            ]
            if resolved_refs:
                for processor in node.get("processor_chain", []) or []:
                    if processor.get("type") != "flow-ref":
                        continue
                    ref_expression = (
                        processor.get("name")
                        or processor.get("ref")
                        or processor.get("target")
                        or ""
                    )
                    if not self._is_dynamic_flow_ref(ref_expression):
                        continue
                    processor["dynamic"] = True
                    processor["dynamic_unresolved"] = False
                    processor["dynamic_flow_candidates"] = list(dict.fromkeys(
                        list(processor.get("dynamic_flow_candidates", []) or []) + resolved_refs
                    ))

            if newly_resolved:
                node["children"] = sorted(current_children)
                # Update parent pointers on newly found children
                for child_name in newly_resolved:
                    child_node = graph.get(child_name)
                    if child_node and flow_name not in child_node.get("parents", []):
                        child_node.setdefault("parents", []).append(flow_name)
                # Clear unresolved flags that are now resolved
                node["unresolved_refs"] = [
                    r for r in unresolved
                    if r not in current_children
                ]

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
