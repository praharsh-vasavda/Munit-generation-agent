"""
Document parser for extracting business scenarios from use case documents.
"""

import re
from typing import Dict, List, Optional
from rich.console import Console


class DocumentParser:
    """Parses business use case documents to extract scenarios and requirements."""

    def __init__(self):
        """Initialize document parser."""
        self.console = Console()

    def parse_document(self, content: str, job_type: str) -> Dict:
        """
        Parse document content to extract business scenarios.
        
        Args:
            content: Document text content
            job_type: Type of Mule job being tested
            
        Returns:
            Dictionary containing extracted scenarios and metadata
        """
        try:
            self.console.print(f"[blue]Parsing business use case document...[/blue]")
            
            # Extract scenarios
            scenarios = self._extract_scenarios(content)
            
            # Extract expected inputs/outputs
            inputs_outputs = self._extract_inputs_outputs(content)
            
            # Extract business rules
            business_rules = self._extract_business_rules(content)
            
            # If no scenarios found, generate default based on job type
            if not scenarios:
                scenarios = self._generate_default_scenarios(job_type)
                self.console.print(f"[yellow]No scenarios found in document, generating defaults for {job_type}[/yellow]")
            
            result = {
                "scenarios": scenarios,
                "inputs_outputs": inputs_outputs,
                "business_rules": business_rules,
                "raw_content_length": len(content),
                "raw_content_excerpt": content[:3000] if content else "",
                "scenario_count": len(scenarios)
            }

            self.console.print(f"[green]Document parsing complete:[/green]")
            self.console.print(f"  Scenarios: {len(scenarios)}")
            self.console.print(f"  Business Rules: {len(business_rules)}")
            self.console.print(f"  Input/Output pairs: {len(inputs_outputs)}")

            return result

        except Exception as e:
            raise Exception(f"Failed to parse document: {str(e)}")

    def _extract_scenarios(self, content: str) -> List[Dict]:
        """Extract test scenarios from document content."""
        scenarios = []
        
        # Common scenario indicators
        scenario_patterns = [
            r'(?i)(?:scenario|test case|use case):\s*(.+?)(?=\n|$)',
            r'(?i)(?:happy path|success case|positive test):\s*(.+?)(?=\n|$)',
            r'(?i)(?:error case|negative test|failure case):\s*(.+?)(?=\n|$)',
            r'(?i)(?:edge case|edge case|boundary):\s*(.+?)(?=\n|$)',
            r'(?i)(?:validation|verify):\s*(.+?)(?=\n|$)'
        ]
        
        for pattern in scenario_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                scenario_type = self._classify_scenario(match)
                scenarios.append({
                    "description": match.strip(),
                    "type": scenario_type,
                    "source": "extracted"
                })
        
        # Look for bullet points or numbered lists that might be scenarios
        bullet_patterns = [
            r'^\s*[-*+]\s*(.+?)(?=\n|$)',
            r'^\s*\d+\.\s*(.+?)(?=\n|$)'
        ]
        
        for pattern in bullet_patterns:
            matches = re.findall(pattern, content, re.MULTILINE)
            for match in matches:
                if self._is_scenario_description(match):
                    scenario_type = self._classify_scenario(match)
                    scenarios.append({
                        "description": match.strip(),
                        "type": scenario_type,
                        "source": "bullet"
                    })
        
        return scenarios

    def _extract_inputs_outputs(self, content: str) -> List[Dict]:
        """Extract expected inputs and outputs."""
        inputs_outputs = []
        
        # Look for input/output patterns
        patterns = [
            r'(?i)input:\s*(.+?)(?=\n|output:)',
            r'(?i)output:\s*(.+?)(?=\n|input:)',
            r'(?i)request:\s*(.+?)(?=\n|response:)',
            r'(?i)response:\s*(.+?)(?=\n|request:)',
            r'(?i)expected:\s*(.+?)(?=\n|actual:)',
            r'(?i)actual:\s*(.+?)(?=\n|expected:)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.strip():
                    inputs_outputs.append({
                        "description": match.strip(),
                        "type": "input" if "input" in pattern.lower() or "request" in pattern.lower() else "output"
                    })
        
        return inputs_outputs

    def _extract_business_rules(self, content: str) -> List[str]:
        """Extract business rules from document."""
        rules = []
        
        # Look for rule patterns
        rule_patterns = [
            r'(?i)(?:rule|business rule|requirement):\s*(.+?)(?=\n|$)',
            r'(?i)(?:must|shall|should|required):\s*(.+?)(?=\n|$)',
            r'(?i)(?:validation|constraint):\s*(.+?)(?=\n|$)'
        ]
        
        for pattern in rule_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match.strip():
                    rules.append(match.strip())
        
        return rules

    def _classify_scenario(self, description: str) -> str:
        """Classify scenario type based on description."""
        desc_lower = description.lower()
        
        if any(word in desc_lower for word in ['happy', 'success', 'valid', 'normal', 'positive']):
            return "happy_path"
        elif any(word in desc_lower for word in ['error', 'fail', 'invalid', 'negative', 'exception']):
            return "error_scenario"
        elif any(word in desc_lower for word in ['empty', 'null', 'blank', 'missing']):
            return "empty_payload"
        elif any(word in desc_lower for word in ['validation', 'verify', 'check', 'validate']):
            return "validation_error"
        elif any(word in desc_lower for word in ['edge', 'boundary', 'corner', 'limit']):
            return "edge_case"
        else:
            return "general"

    def _is_scenario_description(self, text: str) -> bool:
        """Determine if text appears to be a scenario description."""
        # Heuristics to identify scenario descriptions
        scenario_indicators = [
            'test', 'scenario', 'case', 'verify', 'validate', 'check',
            'when', 'if', 'given', 'then', 'expect', 'should', 'must'
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in scenario_indicators)

    def _generate_default_scenarios(self, job_type: str) -> List[Dict]:
        """Generate default scenarios based on job type."""
        default_scenarios = {
            "REST API": [
                {"description": "Happy path - valid request returns successful response", "type": "happy_path", "source": "default"},
                {"description": "Empty payload request", "type": "empty_payload", "source": "default"},
                {"description": "Downstream API failure", "type": "downstream_failure", "source": "default"},
                {"description": "Invalid input validation", "type": "validation_error", "source": "default"}
            ],
            "Batch Job": [
                {"description": "All records processed successfully", "type": "batch_success", "source": "default"},
                {"description": "Partial record failure", "type": "batch_partial_failure", "source": "default"},
                {"description": "Empty input batch", "type": "empty_input", "source": "default"},
                {"description": "All records fail processing", "type": "batch_all_failure", "source": "default"}
            ],
            "Scheduler": [
                {"description": "Normal scheduled execution", "type": "scheduler_success", "source": "default"},
                {"description": "Downstream system failure", "type": "downstream_failure", "source": "default"}
            ],
            "MQ Consumer": [
                {"description": "Valid message processed successfully", "type": "mq_consumer_success", "source": "default"},
                {"description": "Malformed message handling", "type": "mq_consumer_failure", "source": "default"},
                {"description": "Downstream processing failure", "type": "downstream_failure", "source": "default"}
            ],
            "SFTP Listener": [
                {"description": "Valid file processed successfully", "type": "sftp_file_success", "source": "default"},
                {"description": "Empty file handling", "type": "empty_payload", "source": "default"},
                {"description": "Malformed file content", "type": "validation_error", "source": "default"}
            ],
            "Kafka Consumer": [
                {"description": "Valid message consumed and processed", "type": "mq_consumer_success", "source": "default"},
                {"description": "Malformed message handling", "type": "mq_consumer_failure", "source": "default"},
                {"description": "Downstream processing failure", "type": "downstream_failure", "source": "default"}
            ]
        }
        
        return default_scenarios.get(job_type, [
            {"description": "Happy path scenario", "type": "happy_path", "source": "default"},
            {"description": "Error handling scenario", "type": "error_scenario", "source": "default"}
        ])

    def validate_document_content(self, content: str) -> bool:
        """
        Validate that document contains meaningful content.
        
        Args:
            content: Document content
            
        Returns:
            True if content appears meaningful
        """
        if not content or len(content.strip()) < 50:
            return False
        
        # Check for common document indicators
        content_lower = content.lower()
        indicators = [
            'scenario', 'test', 'use case', 'requirement', 'business',
            'process', 'flow', 'input', 'output', 'validate', 'verify'
        ]
        
        return any(indicator in content_lower for indicator in indicators)

    def map_scenarios_to_flows(self, scenarios: List[Dict], flow_summary: Dict) -> Dict[str, List[Dict]]:
        """
        Map scenarios to target flows using simple keyword overlap.
        Scenarios with no strong match are attached to every target so no flow is skipped.
        """
        targets = flow_summary.get("test_targets") or flow_summary.get("flows") or ["main-flow"]
        flow_contexts = flow_summary.get("flow_contexts", {})
        mapped = {target: [] for target in targets}

        for scenario in scenarios:
            matched_targets = []
            scenario_text = f"{scenario.get('description', '')} {scenario.get('type', '')}".lower()

            for target in targets:
                context = flow_contexts.get(target, {})
                keywords = self._build_flow_keywords(target, context)
                if any(keyword and keyword in scenario_text for keyword in keywords):
                    matched_targets.append(target)

            if not matched_targets:
                matched_targets = list(targets)

            for target in matched_targets:
                mapped[target].append(dict(scenario))

        return mapped

    def _build_flow_keywords(self, flow_name: str, context: Dict) -> List[str]:
        """Build searchable keywords for a flow context."""
        keywords = set()

        for raw in [flow_name] + context.get("parent_flows", []) + context.get("child_flows", []):
            for token in re.split(r'[^a-zA-Z0-9]+', raw.lower()):
                if len(token) >= 3:
                    keywords.add(token)

        for connector in context.get("connectors", []):
            for token in re.split(r'[^a-zA-Z0-9]+', connector.lower()):
                if len(token) >= 3:
                    keywords.add(token)

        return sorted(keywords)
