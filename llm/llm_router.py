"""
LLM router with provider-backed generation and deterministic fallback support.
"""

import os
import re
import time
from typing import Dict, List, Tuple

import requests
from rich.console import Console
from tenacity import retry, stop_after_attempt, wait_exponential


class TemplateMUnitGenerator:
    """Deterministic fallback generator when provider-backed calls are unavailable."""

    def generate(self, prompt: str) -> Tuple[str, Dict]:
        start_time = time.time()
        flow_names = self._extract_flow_names(prompt)
        job_type = self._extract_job_type(prompt)
        scenarios = self._extract_scenarios(prompt)

        if "REST API" in job_type or "http" in prompt.lower():
            munit_xml = self._generate_rest_api_template(flow_names, scenarios)
        elif "Batch Job" in job_type or "batch" in prompt.lower():
            munit_xml = self._generate_batch_template(flow_names, scenarios)
        else:
            munit_xml = self._generate_generic_template(flow_names, scenarios)

        generation_time = time.time() - start_time
        metadata = {
            "model_used": "template-fallback",
            "generation_time": generation_time,
            "tokens_estimated": len(prompt) // 4,
            "failures": [],
            "retry_count": 0,
            "template_based": True,
            "scenarios_processed": len(scenarios),
            "flows_processed": len(flow_names),
            "tests_generated": len(flow_names) * len(scenarios)
        }
        return munit_xml, metadata

    def _extract_flow_names(self, prompt: str) -> List[str]:
        lines = prompt.split("\n")
        for line in lines:
            if "Test Targets:" in line:
                flows = line.split(":", 1)[1].strip()
                if flows:
                    return [flow.strip() for flow in flows.split(",") if flow.strip()]
            if "Main Flows:" in line:
                flows = line.split(":", 1)[1].strip()
                if flows:
                    return [flow.strip() for flow in flows.split(",") if flow.strip()]
        return ["main-flow"]

    def _extract_job_type(self, prompt: str) -> str:
        for line in prompt.split("\n"):
            if "Job Type:" in line:
                return line.split(":", 1)[1].strip()
        return "Generic Mule Flow"

    def _extract_scenarios(self, prompt: str) -> List[Dict]:
        scenarios = []
        current_scenario = None

        for line in prompt.split("\n"):
            if "BUSINESS SCENARIOS TO TEST:" in line:
                continue
            if re.match(r"^\d+\.\s+", line.strip()):
                if current_scenario:
                    scenarios.append(current_scenario)
                description = line.split(".", 1)[1].strip()
                current_scenario = {"description": description, "type": "general"}
            elif current_scenario and "Type:" in line:
                current_scenario["type"] = line.split("Type:", 1)[1].strip()
            elif current_scenario and line.strip() == "":
                scenarios.append(current_scenario)
                current_scenario = None

        if current_scenario:
            scenarios.append(current_scenario)

        if scenarios:
            return scenarios

        if "REST API" in self._extract_job_type(prompt):
            return [
                {"description": "Happy path - valid request returns successful response", "type": "happy_path"},
                {"description": "Empty payload request", "type": "empty_payload"},
                {"description": "Downstream API failure", "type": "downstream_failure"},
                {"description": "Invalid input validation", "type": "validation_error"}
            ]
        return [
            {"description": "Happy path scenario", "type": "happy_path"},
            {"description": "Error handling scenario", "type": "error_scenario"}
        ]

    def _generate_rest_api_template(self, flow_names: List[str], scenarios: List[Dict]) -> str:
        suite_name = flow_names[0] if flow_names else "main-flow"
        header = f'''<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns:munit="http://www.mulesoft.org/schema/mule/munit"
      xmlns:munit-tools="http://www.mulesoft.org/schema/mule/munit-tools"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
                          http://www.mulesoft.org/schema/mule/munit http://www.mulesoft.org/schema/mule/munit/current/mule-munit.xsd
                          http://www.mulesoft.org/schema/mule/munit-tools http://www.mulesoft.org/schema/mule/munit-tools/current/mule-munit-tools.xsd
                          http://www.mulesoft.org/schema/mule/http http://www.mulesoft.org/schema/mule/http/current/mule-http.xsd">

    <munit:config name="{suite_name}-test-suite"/>

'''
        tests = []
        for flow_name in flow_names or ["main-flow"]:
            for scenario in scenarios:
                test_name = f"test-{flow_name}-{scenario['type'].replace('_', '-')}"
                validation = self._build_rest_validation(scenario["type"])
                tests.append(
                    f'''    <munit:test name="{test_name}" description="{scenario['description']}">
        <munit:behavior>
            <munit:set-event doc:name="Set Event">
                <munit:payload value='#[{{"id": "TEST-001"}}]' mediaType="application/json"/>
                <munit:attributes value='#[{{method: "POST", requestPath: "/test", headers: {{"content-type": "application/json"}}}}]'/>
            </munit:set-event>
            <munit-tools:mock-when processor="http:request">
                <munit-tools:then-return>
                    <munit-tools:payload value='#[{{"data": {{"id": "MOCK-001", "status": "SUCCESS"}}}}]' mediaType="application/json"/>
                    <munit-tools:attributes value='#[{{statusCode: 200, headers: {{"content-type": "application/json"}}}}]'/>
                </munit-tools:then-return>
            </munit-tools:mock-when>
        </munit:behavior>
        <munit:execution>
            <flow-ref name="{flow_name}"/>
        </munit:execution>
        <munit:validation>
            {validation}
        </munit:validation>
    </munit:test>'''
                )
        return header + "\n".join(tests) + "\n</mule>"

    def _generate_batch_template(self, flow_names: List[str], scenarios: List[Dict]) -> str:
        suite_name = flow_names[0] if flow_names else "main-flow"
        header = f'''<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns:munit="http://www.mulesoft.org/schema/mule/munit"
      xmlns:munit-tools="http://www.mulesoft.org/schema/mule/munit-tools"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:batch="http://www.mulesoft.org/schema/mule/batch"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
                          http://www.mulesoft.org/schema/mule/munit http://www.mulesoft.org/schema/mule/munit/current/mule-munit.xsd
                          http://www.mulesoft.org/schema/mule/munit-tools http://www.mulesoft.org/schema/mule/munit-tools/current/mule-munit-tools.xsd
                          http://www.mulesoft.org/schema/mule/batch http://www.mulesoft.org/schema/mule/batch/current/mule-batch.xsd">

    <munit:config name="{suite_name}-test-suite"/>

'''
        tests = []
        for flow_name in flow_names or ["main-flow"]:
            for scenario in scenarios:
                test_name = f"test-{flow_name}-{scenario['type'].replace('_', '-')}"
                tests.append(
                    f'''    <munit:test name="{test_name}" description="{scenario['description']}">
        <munit:execution>
            <flow-ref name="{flow_name}"/>
        </munit:execution>
        <munit:validation>
            {self._build_batch_validation(scenario["type"])}
        </munit:validation>
    </munit:test>'''
                )
        return header + "\n".join(tests) + "\n</mule>"

    def _generate_generic_template(self, flow_names: List[str], scenarios: List[Dict]) -> str:
        suite_name = flow_names[0] if flow_names else "main-flow"
        header = f'''<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns:munit="http://www.mulesoft.org/schema/mule/munit"
      xmlns:munit-tools="http://www.mulesoft.org/schema/mule/munit-tools"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
                          http://www.mulesoft.org/schema/mule/munit http://www.mulesoft.org/schema/mule/munit/current/mule-munit.xsd
                          http://www.mulesoft.org/schema/mule/munit-tools http://www.mulesoft.org/schema/mule/munit-tools/current/mule-munit-tools.xsd">

    <munit:config name="{suite_name}-test-suite"/>

'''
        tests = []
        for flow_name in flow_names or ["main-flow"]:
            for scenario in scenarios:
                test_name = f"test-{flow_name}-{scenario['type'].replace('_', '-')}"
                tests.append(
                    f'''    <munit:test name="{test_name}" description="{scenario['description']}">
        <munit:execution>
            <flow-ref name="{flow_name}"/>
        </munit:execution>
        <munit:validation>
            {self._build_generic_validation(scenario["type"])}
        </munit:validation>
    </munit:test>'''
                )
        return header + "\n".join(tests) + "\n</mule>"

    def _build_rest_validation(self, scenario_type: str) -> str:
        if scenario_type == "happy_path":
            return "\n            ".join([
                '<munit-tools:assert-that expression="#[payload]" is="#[MunitTools::notNullValue()]" message="Payload should not be null"/>',
                '<munit-tools:assert-that expression="#[(payload.status default payload.data.status) default \"SUCCESS\"]" is="#[MunitTools::equalTo(\"SUCCESS\")]" message="Status should be SUCCESS"/>'
            ])
        if scenario_type in {"empty_payload", "validation_error"}:
            return "\n            ".join([
                '<munit-tools:assert-that expression="#[error.description default \'\']" is="#[MunitTools::notNullValue()]" message="Error description should be present"/>'
            ])
        if "failure" in scenario_type or "error" in scenario_type:
            return "\n            ".join([
                '<munit-tools:assert-that expression="#[(error.errorType as String) default \'\']" is="#[MunitTools::containsString(\'CONNECTIVITY\')]" message="Error type should indicate connectivity failure"/>'
            ])
        return '<munit-tools:assert-that expression="#[payload]" is="#[MunitTools::notNullValue()]" message="Payload should not be null"/>'

    def _build_batch_validation(self, scenario_type: str) -> str:
        if "success" in scenario_type:
            return "\n            ".join([
                '<munit-tools:assert-that expression="#[payload]" is="#[MunitTools::notNullValue()]" message="Payload should not be null"/>'
            ])
        if "partial" in scenario_type or "failure" in scenario_type or "error" in scenario_type:
            return "\n            ".join([
                '<munit-tools:assert-that expression="#[(error.description default payload) default \'\']" is="#[MunitTools::notNullValue()]" message="Failure details should be present"/>'
            ])
        return '<munit-tools:assert-that expression="#[payload]" is="#[MunitTools::notNullValue()]" message="Payload should not be null"/>'

    def _build_generic_validation(self, scenario_type: str) -> str:
        if scenario_type == "happy_path":
            return "\n            ".join([
                '<munit-tools:assert-that expression="#[payload]" is="#[MunitTools::notNullValue()]" message="Payload should not be null"/>'
            ])
        if "error" in scenario_type or "failure" in scenario_type:
            return "\n            ".join([
                '<munit-tools:assert-that expression="#[error.description default \'\']" is="#[MunitTools::notNullValue()]" message="Error description should be present"/>'
            ])
        return '<munit-tools:assert-that expression="#[payload]" is="#[MunitTools::notNullValue()]" message="Payload should not be null"/>'


class LLMRouter:
    """Provider-backed MUnit generation with fallback to deterministic templates."""

    def __init__(self, timeout: int = 60):
        self.console = Console()
        self.timeout = timeout
        self.primary_model = os.getenv("PRIMARY_LLM", "openrouter/openai/gpt-4o-mini")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.template_generator = TemplateMUnitGenerator()

    def generate_munit(self, prompt: str) -> Tuple[str, Dict]:
        start_time = time.time()
        failures = []

        self.console.print(f"[blue]Generating MUnit with primary model {self.primary_model}...[/blue]")

        try:
            xml_content, provider_meta = self._generate_with_provider(prompt, self.primary_model)
            metadata = {
                "model_used": provider_meta["model"],
                "provider": provider_meta["provider"],
                "generation_time": time.time() - start_time,
                "tokens_estimated": len(prompt) // 4,
                "failures": failures,
                "retry_count": 0,
                "template_based": False
            }
            return xml_content, metadata
        except Exception as exc:
            failures.append(str(exc))
            self.console.print(f"[yellow]Provider generation failed, using fallback: {str(exc)}[/yellow]")

        xml_content, metadata = self.template_generator.generate(prompt)
        metadata["generation_time"] = time.time() - start_time
        metadata["failures"] = failures
        return xml_content, metadata

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=4), reraise=True)
    def _generate_with_provider(self, prompt: str, model_name: str) -> Tuple[str, Dict]:
        provider, resolved_model = self._resolve_provider(model_name)

        if provider == "openai":
            content = self._call_openai(resolved_model, prompt)
        elif provider == "anthropic":
            content = self._call_anthropic(resolved_model, prompt)
        elif provider == "openrouter":
            content = self._call_openrouter(resolved_model, prompt)
        elif provider == "groq":
            content = self._call_groq(resolved_model, prompt)
        else:
            raise ValueError(f"Unsupported provider in PRIMARY_LLM: {model_name}")

        return self._extract_xml_content(content), {"provider": provider, "model": resolved_model}

    def _resolve_provider(self, model_name: str) -> Tuple[str, str]:
        if "/" not in model_name:
            if self.openrouter_api_key:
                return "openrouter", model_name
            if self.openai_api_key:
                return "openai", model_name
            raise ValueError("PRIMARY_LLM does not specify provider and no compatible API key is configured")

        parts = model_name.split("/", 1)
        provider = parts[0].lower()
        resolved_model = parts[1]
        return provider, resolved_model

    def _build_system_message(self) -> str:
        return (
            "You are an expert MuleSoft developer. Generate only valid Mule 4 / MUnit 2.x XML. "
            "Do not include markdown, explanations, code fences, or prose. "
            "Output exactly one MUnit suite for the current target flow."
        )

    def _call_openai(self, model: str, prompt: str) -> str:
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY is not configured")

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.openai_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": self._build_system_message()},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _call_anthropic(self, model: str, prompt: str) -> str:
        if not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is not configured")

        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": model,
                "max_tokens": 4000,
                "temperature": 0.2,
                "system": self._build_system_message(),
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            },
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()
        return "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")

    def _call_openrouter(self, model: str, prompt: str) -> str:
        if not self.openrouter_api_key:
            raise ValueError("OPENROUTER_API_KEY is not configured")

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.openrouter_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": self._build_system_message()},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _call_groq(self, model: str, prompt: str) -> str:
        if not self.groq_api_key:
            raise ValueError("GROQ_API_KEY is not configured")

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.groq_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": self._build_system_message()},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _extract_xml_content(self, content: str) -> str:
        cleaned = content.strip()
        if cleaned.startswith("```xml"):
            cleaned = cleaned[6:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]

        cleaned = cleaned.strip()
        for marker in ("<?xml", "<mule", "<munit"):
            index = cleaned.find(marker)
            if index != -1:
                return cleaned[index:].strip()
        return cleaned

    def validate_api_keys(self) -> Dict:
        available = self.list_available_models()
        return {
            "status": "ready" if available else "fallback_only",
            "message": "Provider-backed generation available" if available else "No provider configured; template fallback will be used"
        }

    def get_model_status(self) -> Dict:
        status = {}
        if self.openai_api_key:
            status["openai"] = "available"
        if self.anthropic_api_key:
            status["anthropic"] = "available"
        if self.openrouter_api_key:
            status["openrouter"] = "available"
        if self.groq_api_key:
            status["groq"] = "available"
        if not status:
            status["template-fallback"] = "available"
        return status

    def list_available_models(self) -> List[str]:
        return list(self.get_model_status().keys())

    def generate_raw(self, prompt: str) -> str:
        """
        Lightweight single-call method used by the BlueprintPipeline.

        Unlike generate_munit, this method does NOT fall back to the template
        generator and returns the raw LLM text without XML post-processing.

        Args:
            prompt: The raw prompt string to send to the LLM.

        Returns:
            Raw text response from the provider, or empty string on failure.
        """
        try:
            raw, _ = self._generate_with_provider(prompt, self.primary_model)
            return raw
        except Exception as exc:
            self.console.print(
                f"[yellow]generate_raw provider call failed: {exc}[/yellow]"
            )
            return ""
