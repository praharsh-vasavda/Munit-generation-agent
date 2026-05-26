"""
Blueprint Pipeline — Phases 1-3 of the Architectural Blueprint.

Implements:
  Step 3  – Localized Flow Context Isolation
  Step 4  – Deterministic Mock Mapping (pre-generation plan)
  Step 5  – Multi-Pass Artifact Generation (DWL files + test XML independently)
  Step 6  – Three structured test scenarios per flow (happy path, error, edge)
  Step 7  – Backend-controlled XML template assembly + XML sanity check
  Step 8  – Automated self-healing Maven execution loop
"""

import json
import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Step 7 — The canonical Mule XML wrapper template.
# The LLM is NEVER asked to generate the <mule> root or namespace headers.
# The backend splices the LLM-generated <munit:test> blocks into this template.
# ---------------------------------------------------------------------------
MUNIT_XML_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:munit="http://www.mulesoft.org/schema/mule/munit"
      xmlns:munit-tools="http://www.mulesoft.org/schema/mule/munit-tools"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xsi:schemaLocation="
        http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
        http://www.mulesoft.org/schema/mule/munit http://www.mulesoft.org/schema/mule/munit/current/mule-munit.xsd
        http://www.mulesoft.org/schema/mule/munit-tools http://www.mulesoft.org/schema/mule/munit-tools/current/mule-munit-tools.xsd">

    <munit:config name="{suite_name}"/>

    {config_refs}

    {test_blocks}

</mule>
"""

# ---------------------------------------------------------------------------
# Step 4 — LLM prompt to produce a mock blueprint JSON
# ---------------------------------------------------------------------------
MOCK_BLUEPRINT_PROMPT = """\
Context: The user has selected the flow: {flow_name}.
Here is the isolated flow XML:
{flow_xml}

Task: Identify every outbound connector processor within this flow that interacts \
with an external system (e.g., `<http:request>`, `<db:select>`, `<salesforce:create>`).

Output Requirement: Return a JSON array detailing every component that needs to be \
mocked. Do not include markdown syntax or any other text:
[
  {{
    "processor_type": "http:request",
    "doc_id": "1234-abcd",
    "mock_name": "mock_get_invoice_response",
    "expected_payload_type": "json"
  }}
]
"""

# ---------------------------------------------------------------------------
# Step 5 — DWL mock file prompt (executed per mock item)
# ---------------------------------------------------------------------------
DWL_MOCK_PROMPT = """\
Context: You are generating mock payload files based on an architectural blueprint.
Task: For the mock requirement "{mock_name}", generate a valid DataWeave 2.0 (%dw 2.0) \
script representing a realistic mock response payload.
The expected payload type is: {expected_payload_type}.
Rules:
- If expected payload type is java for db:select or salesforce:query, return an Array of Objects.
- If expected payload type is json, return an Object with realistic fields likely to be consumed downstream.
- Do not return secrets, real URLs, credentials, or environment-specific values.
Constraint: Output ONLY raw DataWeave code starting with %dw 2.0. \
Do not wrap in markdown code blocks. Do not add conversational text.
"""

# ---------------------------------------------------------------------------
# Step 5 — Core test logic prompt (once per flow, references DWL files)
# ---------------------------------------------------------------------------
CORE_TEST_PROMPT = """\
Context: You are generating the core MUnit test logic for the selected flow: {flow_name}.
Here is the isolated flow XML and its global config references:
{flow_xml}

Mock blueprint (already generated as DWL files):
{mock_blueprint_json}

Task: Generate three <munit:test> blocks covering:
  1. Happy Path Scenario — all mocks return successful payloads (HTTP 200). \
     Assert the final payload matches happy-path criteria.
  2. Error Handling / Failure Path Scenario — at least one key mock throws an error \
     using <munit-tools:error typeId="HTTP:UNAUTHORIZED"/> or <munit-tools:error typeId="DB:CONNECTIVITY"/> \
     inside <munit-tools:then-return> \
     to exercise the flow's error handler.
  3. Edge Case Scenario — mocks return blank, null, or missing values to test \
     data validation robustness.

Constraint 1: For mock payloads, reference the external DWL files using:
  #[readUrl('classpath://mock_payloads/{mock_name}.dwl')]
Constraint 2: Never embed inline JSON, XML, or multi-line DataWeave in attributes.
Constraint 3: Match every mock with <munit-tools:with-attribute attributeName="doc:name" whereValue="..."/>.
Constraint 4: Do not mock transform, logger, set-variable, set-payload, choice, or flow-ref processors.
Constraint 5: Output ONLY the raw inner <munit:test> code blocks.  \
Do NOT include <mule> tags, namespace declarations, or <munit:config>.
"""

# ---------------------------------------------------------------------------
# Step 8 — Self-healing repair prompt
# ---------------------------------------------------------------------------
SELF_HEAL_PROMPT = """\
Context: The MUnit test you generated failed execution with the following error:
{error_log}

Task: Analyze the error log, locate the incorrect or unmapped tag inside the \
previous MUnit implementation, and return only the corrected, functional \
<munit:test> XML blocks. Do NOT include <mule> wrappers or namespace declarations.
"""


class FlowIsolator:
    """
    Step 3 — Localized Flow Context Isolation.

    Given the combined project XML and a selected flow name:
      1. Extracts the raw <flow> ... </flow> XML block.
      2. Scans all files for global connector <*:config> elements whose names
         appear as config-ref values inside that flow block.
      3. Returns (flow_xml, global_configs) as an in-memory payload.
    """

    # Regex to extract <flow name="X"> ... </flow> (non-greedy, dotall)
    _FLOW_RE = re.compile(
        r'(<(?:flow|sub-flow)\b[^>]*\bname=["\']({name})["\'][^>]*>.*?</(?:flow|sub-flow)>)',
        re.DOTALL,
    )

    # Matches any *:config element: <http:request-config name="..." .../>
    _GLOBAL_CONFIG_RE = re.compile(
        r'<[a-zA-Z][a-zA-Z0-9_-]*:[a-zA-Z][a-zA-Z0-9_-]*-config\b[^/]*/?>',
        re.DOTALL,
    )

    def isolate(self, combined_xml: str, flow_name: str) -> Tuple[str, List[str]]:
        """
        Returns (flow_xml_snippet, list_of_global_config_snippets).
        Raises ValueError if the flow cannot be found.
        """
        pattern = re.compile(
            r'(<(?:flow|sub-flow)\b[^>]*\bname=["\']'
            + re.escape(flow_name)
            + r'["\'][^>]*>.*?</(?:flow|sub-flow)>)',
            re.DOTALL,
        )
        match = pattern.search(combined_xml)
        if not match:
            raise ValueError(f"Flow '{flow_name}' not found in project XML.")

        flow_xml = match.group(1)

        # Collect all config-ref values from this flow block
        config_ref_values = set(re.findall(r'config-ref=["\']([^"\']+)["\']', flow_xml))

        # Find matching global config definitions in the full XML
        global_configs = []
        for cfg_match in self._GLOBAL_CONFIG_RE.finditer(combined_xml):
            snippet = cfg_match.group(0)
            name_match = re.search(r'\bname=["\']([^"\']+)["\']', snippet)
            if name_match and name_match.group(1) in config_ref_values:
                global_configs.append(snippet)

        return flow_xml, global_configs


class MockBlueprintBuilder:
    """
    Step 4 — Deterministic Mock Mapping.

    Calls the LLM with the isolated flow XML to produce a JSON array of
    mock descriptors before any test code is written.
    """

    def __init__(self, llm_caller):
        """
        Args:
            llm_caller: Callable(prompt: str) -> str  (raw LLM text response)
        """
        self._call = llm_caller

    def build(self, flow_name: str, flow_xml: str) -> List[Dict]:
        """
        Returns a list of mock descriptor dicts, e.g.:
          [{"processor_type": "http:request", "doc_id": "...", "mock_name": "...", ...}]
        """
        prompt = MOCK_BLUEPRINT_PROMPT.format(
            flow_name=flow_name,
            flow_xml=flow_xml,
        )
        raw = self._call(prompt)
        parsed = self._parse_json(raw)
        if parsed:
            return parsed

        fallback = self._build_deterministic_blueprint(flow_xml)
        if fallback:
            logger.info(
                "Using deterministic mock blueprint fallback with %d mock(s)",
                len(fallback),
            )
        return fallback

    @staticmethod
    def _parse_json(raw: str) -> List[Dict]:
        """Strip markdown fences then parse JSON array."""
        cleaned = raw.strip()
        # Remove ```json ... ``` or ``` ... ```
        cleaned = re.sub(r'^```(?:json)?\s*', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'\s*```$', '', cleaned, flags=re.MULTILINE)
        cleaned = cleaned.strip()

        # Locate the first '[' in case there is preamble text
        start = cleaned.find('[')
        if start != -1:
            cleaned = cleaned[start:]

        try:
            result = json.loads(cleaned)
            if isinstance(result, list):
                return result
        except json.JSONDecodeError as exc:
            logger.warning("Mock blueprint JSON parse error: %s — returning empty list", exc)

        return []

    @staticmethod
    def _build_deterministic_blueprint(flow_xml: str) -> List[Dict]:
        """Derive a conservative mock blueprint directly from the flow XML."""
        external_processors = {
            "http:request": "json",
            "db:select": "java",
            "db:insert": "java",
            "db:update": "java",
            "db:delete": "java",
            "salesforce:query": "java",
            "salesforce:create": "java",
            "salesforce:update": "java",
            "sftp:read": "text",
            "file:read": "text",
            "jms:publish-consume": "java",
            "vm:publish-consume": "java",
            "objectstore:retrieve": "java",
        }
        void_processors = {
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

        tag_re = re.compile(
            r"<(?P<tag>[a-zA-Z][\w.-]*:[a-zA-Z][\w.-]*)\b(?P<attrs>[^>]*)/?\s*>",
            re.DOTALL,
        )
        blueprint = []
        used_names = set()

        for match in tag_re.finditer(flow_xml):
            processor_type = match.group("tag")
            if processor_type not in external_processors and processor_type not in void_processors:
                continue

            attrs = match.group("attrs")
            doc_name = MockBlueprintBuilder._extract_attr(attrs, "doc:name")
            if not doc_name:
                doc_name = MockBlueprintBuilder._extract_attr(attrs, "name") or processor_type

            mock_name = MockBlueprintBuilder._slugify(f"mock_{doc_name or processor_type}_response")
            if mock_name in used_names:
                suffix = 2
                while f"{mock_name}_{suffix}" in used_names:
                    suffix += 1
                mock_name = f"{mock_name}_{suffix}"
            used_names.add(mock_name)

            blueprint.append({
                "processor_type": processor_type,
                "doc_name": doc_name,
                "config_ref": MockBlueprintBuilder._extract_attr(attrs, "config-ref"),
                "mock_name": mock_name,
                "expected_payload_type": external_processors.get(processor_type, "void"),
                "action": "verify-call" if processor_type in void_processors else "mock-when",
            })

        return blueprint

    @staticmethod
    def _extract_attr(attrs: str, name: str) -> str:
        """Extract an XML attribute value from a raw attribute string."""
        if ":" in name:
            pattern = re.compile(
                rf'(?:\b|:){re.escape(name.split(":", 1)[-1])}\s*=\s*["\']([^"\']+)["\']'
            )
        else:
            pattern = re.compile(rf'\b{re.escape(name)}\s*=\s*["\']([^"\']+)["\']')
        match = pattern.search(attrs or "")
        return match.group(1) if match else ""

    @staticmethod
    def _slugify(value: str) -> str:
        """Build a filesystem-safe mock payload name."""
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", value or "mock_payload")
        slug = re.sub(r"_+", "_", slug).strip("_").lower()
        return slug or "mock_payload"


class MultiPassGenerator:
    """
    Steps 5 & 6 — Multi-Pass Artifact Generation.

    Pass 1: For each mock descriptor, call the LLM to generate a DWL file and
            save it to src/test/resources/mock_payloads/<mock_name>.dwl.
    Pass 2: Call the LLM to generate the three <munit:test> blocks, referencing
            the DWL files via MunitTools::getResourceAsString.
    """

    def __init__(self, llm_caller, output_dir: str = "./output"):
        self._call = llm_caller
        self.output_dir = Path(output_dir)
        self._mock_payload_dir = self.output_dir / "src" / "test" / "resources" / "mock_payloads"
        self._mock_payload_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Pass 1 — DWL mock files
    # ------------------------------------------------------------------
    def generate_mock_dwl_files(self, mock_blueprint: List[Dict]) -> Dict[str, str]:
        """
        For each entry in mock_blueprint, generate and save a DWL file.

        Returns:
            {mock_name: saved_file_path}
        """
        saved = {}
        for item in mock_blueprint:
            mock_name = item.get("mock_name", "mock_payload")
            expected_type = item.get("expected_payload_type", "json")

            prompt = DWL_MOCK_PROMPT.format(
                mock_name=mock_name,
                expected_payload_type=expected_type,
            )
            dwl_code = self._call(prompt).strip()
            # Ensure it starts with %dw 2.0
            if not dwl_code.startswith("%dw"):
                dwl_code = "%dw 2.0\noutput application/json\n---\n" + dwl_code

            file_path = self._mock_payload_dir / f"{mock_name}.dwl"
            file_path.write_text(dwl_code, encoding="utf-8")
            saved[mock_name] = str(file_path)
            logger.info("DWL mock file written: %s", file_path)

        return saved

    # ------------------------------------------------------------------
    # Pass 2 — Core test blocks (three scenarios per flow)
    # ------------------------------------------------------------------
    def generate_test_blocks(
        self,
        flow_name: str,
        flow_xml: str,
        global_configs: List[str],
        mock_blueprint: List[Dict],
    ) -> str:
        """
        Calls the LLM to generate raw <munit:test> blocks.
        Returns the LLM output string (not wrapped in <mule>).
        """
        context_xml = flow_xml
        if global_configs:
            context_xml = "\n".join(global_configs) + "\n\n" + flow_xml

        prompt = CORE_TEST_PROMPT.format(
            flow_name=flow_name,
            flow_xml=context_xml,
            mock_blueprint_json=json.dumps(mock_blueprint, indent=2),
        )
        raw = self._call(prompt)
        return self._extract_test_blocks(raw)

    @staticmethod
    def _extract_test_blocks(raw: str) -> str:
        """
        Strip any <mule> wrapper or markdown fences, keeping only
        <munit:test>...</munit:test> blocks.
        """
        # Remove markdown fences
        cleaned = re.sub(r'```(?:xml)?\s*', '', raw)
        cleaned = re.sub(r'\s*```', '', cleaned)

        # If LLM wrapped in <mule>, extract the inner content
        mule_match = re.search(r'<mule\b[^>]*>(.*)</mule>', cleaned, re.DOTALL)
        if mule_match:
            cleaned = mule_match.group(1)

        # Remove <munit:config .../>
        cleaned = re.sub(r'<munit:config\b[^/]*/>', '', cleaned)

        return cleaned.strip()


class TemplateAssembler:
    """
    Step 7 — Automated Assembly and Structural Wrapping.

    The backend owns the <mule> root template. The LLM only provides the
    inner <munit:test> blocks. This class splices them together and runs
    an XML parser sanity check before writing to disk.
    """

    def assemble(
        self,
        suite_name: str,
        config_refs: List[str],
        test_blocks: str,
        output_path: str,
    ) -> str:
        """
        Builds the final XML file and writes it to output_path.

        Returns:
            The absolute path of the written file.

        Raises:
            ValueError: If the assembled XML fails the sanity check.
        """
        config_block = "\n    ".join(config_refs) if config_refs else ""

        xml_str = MUNIT_XML_TEMPLATE.format(
            suite_name=suite_name,
            config_refs=config_block,
            test_blocks=test_blocks,
        )

        # Step 7 — XML sanity check
        self._validate_xml(xml_str)

        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(xml_str, encoding="utf-8")
        logger.info("Assembled MUnit file written: %s", out_path)
        return str(out_path)

    @staticmethod
    def _validate_xml(xml_str: str) -> None:
        """Raises ValueError if xml_str is not well-formed XML."""
        try:
            ET.fromstring(xml_str)
        except ET.ParseError as exc:
            raise ValueError(f"Assembled XML failed sanity check: {exc}") from exc


class SelfHealingRunner:
    """
    Step 8 — Automated Self-Healing Execution Loop.

    Spawns `mvn test` for the generated suite file, monitors output,
    and if a BUILD FAILURE occurs: calls the LLM to repair the test
    blocks, re-assembles the XML, and retries up to max_retries times.
    """

    def __init__(
        self,
        llm_caller,
        assembler: TemplateAssembler,
        max_retries: int = 2,
    ):
        self._call = llm_caller
        self._assembler = assembler
        self.max_retries = max_retries

    def run(
        self,
        suite_file_path: str,
        suite_name: str,
        config_refs: List[str],
        project_root: Optional[str] = None,
    ) -> Dict:
        """
        Executes `mvn test` for the given suite file.

        Returns a dict with keys:
          success (bool), build_output (str), attempts (int),
          healed (bool), error (str or None)
        """
        current_test_blocks = self._read_test_blocks(suite_file_path)
        attempts = 0
        healed = False

        for attempt in range(self.max_retries + 1):
            attempts = attempt + 1
            build_output, success = self._run_maven(suite_file_path, project_root)

            if success:
                logger.info("BUILD SUCCESS on attempt %d for %s", attempts, suite_file_path)
                return {
                    "success": True,
                    "build_output": build_output,
                    "attempts": attempts,
                    "healed": healed,
                    "error": None,
                }

            logger.warning("BUILD FAILURE on attempt %d — attempting self-heal", attempts)

            if attempt >= self.max_retries:
                break

            # Self-heal: ask LLM to repair the broken blocks
            repaired_blocks = self._self_heal(current_test_blocks, build_output)
            if not repaired_blocks:
                logger.error("Self-heal produced empty output, aborting.")
                break

            current_test_blocks = repaired_blocks
            healed = True

            # Re-assemble and overwrite the file
            try:
                self._assembler.assemble(
                    suite_name=suite_name,
                    config_refs=config_refs,
                    test_blocks=current_test_blocks,
                    output_path=suite_file_path,
                )
            except ValueError as exc:
                logger.error("Re-assembled XML failed sanity check: %s", exc)
                break

        return {
            "success": False,
            "build_output": build_output,
            "attempts": attempts,
            "healed": healed,
            "error": "Build failed after all self-healing attempts.",
        }

    def _run_maven(self, suite_file: str, project_root: Optional[str]) -> Tuple[str, bool]:
        """Runs mvn test; returns (stdout+stderr, success_bool)."""
        suite_name_flag = Path(suite_file).name
        cmd = ["mvn", "test", f"-Dtest={suite_name_flag}", "-B"]

        cwd = project_root or str(Path(suite_file).parent)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=300,
            )
            combined = result.stdout + result.stderr
            success = "BUILD SUCCESS" in combined
            return combined, success
        except FileNotFoundError:
            msg = "mvn not found — Maven is not installed or not on PATH."
            logger.warning(msg)
            return msg, False
        except subprocess.TimeoutExpired:
            msg = "Maven build timed out after 300 seconds."
            logger.warning(msg)
            return msg, False

    def _self_heal(self, broken_blocks: str, build_output: str) -> str:
        """Calls LLM with the error log; returns repaired <munit:test> blocks."""
        # Extract a trimmed error snippet (last 3 KB is usually enough)
        error_snippet = build_output[-3000:] if len(build_output) > 3000 else build_output

        prompt = SELF_HEAL_PROMPT.format(error_log=error_snippet)
        raw = self._call(prompt)
        return MultiPassGenerator._extract_test_blocks(raw)

    @staticmethod
    def _read_test_blocks(suite_file: str) -> str:
        """Reads the inner <munit:test> blocks from an assembled file."""
        try:
            content = Path(suite_file).read_text(encoding="utf-8")
            root = ET.fromstring(content)
            ns = {"munit": "http://www.mulesoft.org/schema/mule/munit"}
            blocks = root.findall("munit:test", ns)
            return "\n".join(ET.tostring(b, encoding="unicode") for b in blocks)
        except Exception:
            return ""


class BlueprintPipeline:
    """
    Orchestrates Steps 3-8 from the architectural blueprint for a single
    selected flow.

    Usage::

        pipeline = BlueprintPipeline(
            llm_caller=lambda prompt: llm_router.generate_raw(prompt),
            output_dir="./output",
        )
        result = pipeline.run(
            flow_name="get-customer-flow",
            combined_xml=project_combined_xml,
            run_maven=False,   # set True to trigger Step 8
        )
    """

    def __init__(
        self,
        llm_caller,
        output_dir: str = "./output",
        max_heal_retries: int = 2,
    ):
        self._call = llm_caller
        self._isolator = FlowIsolator()
        self._mock_builder = MockBlueprintBuilder(llm_caller)
        self._multi_pass = MultiPassGenerator(llm_caller, output_dir=output_dir)
        self._assembler = TemplateAssembler()
        self._healer = SelfHealingRunner(
            llm_caller=llm_caller,
            assembler=self._assembler,
            max_retries=max_heal_retries,
        )
        self.output_dir = Path(output_dir)

    def run(
        self,
        flow_name: str,
        combined_xml: str,
        run_maven: bool = False,
        project_root: Optional[str] = None,
    ) -> Dict:
        """
        Full pipeline run for one flow.

        Returns a result dict with keys:
          success, flow_name, output_file, dwl_files, mock_blueprint,
          maven_result (only when run_maven=True), error
        """
        result: Dict = {
            "success": False,
            "flow_name": flow_name,
            "output_file": None,
            "dwl_files": {},
            "mock_blueprint": [],
            "maven_result": None,
            "error": None,
        }

        try:
            # Step 3 — Isolate flow context
            logger.info("[Step 3] Isolating flow context for '%s'", flow_name)
            flow_xml, global_configs = self._isolator.isolate(combined_xml, flow_name)

            # Step 4 — Deterministic mock mapping
            logger.info("[Step 4] Building mock blueprint for '%s'", flow_name)
            mock_blueprint = self._mock_builder.build(flow_name, flow_xml)
            result["mock_blueprint"] = mock_blueprint

            # Step 5, Pass 1 — Generate DWL mock files
            logger.info("[Step 5a] Generating DWL mock files (%d mocks)", len(mock_blueprint))
            dwl_files = self._multi_pass.generate_mock_dwl_files(mock_blueprint)
            result["dwl_files"] = dwl_files

            # Step 5, Pass 2 + Step 6 — Generate three test scenarios
            logger.info("[Step 5b/6] Generating multi-scenario test blocks")
            test_blocks = self._multi_pass.generate_test_blocks(
                flow_name=flow_name,
                flow_xml=flow_xml,
                global_configs=global_configs,
                mock_blueprint=mock_blueprint,
            )

            # Step 7 — Assemble final XML with backend template
            logger.info("[Step 7] Assembling final MUnit XML")
            suite_name = self._build_suite_name(flow_name)
            output_path = str(
                self.output_dir / "src" / "test" / "munit" / f"{suite_name}.xml"
            )
            assembled_path = self._assembler.assemble(
                suite_name=suite_name,
                config_refs=global_configs,
                test_blocks=test_blocks,
                output_path=output_path,
            )
            result["output_file"] = assembled_path

            # Step 8 — Self-healing Maven loop (opt-in)
            if run_maven:
                logger.info("[Step 8] Running Maven self-healing loop")
                maven_result = self._healer.run(
                    suite_file_path=assembled_path,
                    suite_name=suite_name,
                    config_refs=global_configs,
                    project_root=project_root,
                )
                result["maven_result"] = maven_result
                result["success"] = maven_result["success"]
            else:
                result["success"] = True

        except Exception as exc:
            logger.exception("BlueprintPipeline error for flow '%s': %s", flow_name, exc)
            result["error"] = str(exc)

        return result

    @staticmethod
    def _build_suite_name(flow_name: str) -> str:
        slug = re.sub(r"[^a-z0-9-]", "-", flow_name.lower())
        slug = re.sub(r"-{2,}", "-", slug).strip("-")
        return f"{slug}-test-suite"
