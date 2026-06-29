"""
Core modules for analyzing XML, parsing documents, building prompts, and loading rulesets.
"""

from .xml_analyzer import XMLAnalyzer
from .doc_parser import DocumentParser
from .prompt_builder import PromptBuilder
from .ruleset_loader import RulesetLoader
from .pipeline import (
    BlueprintPipeline,
    FlowIsolator,
    MockBlueprintBuilder,
    MultiPassGenerator,
    TemplateAssembler,
    SelfHealingRunner,
)
from .deterministic_munit_builder import DeterministicMUnitBuilder
from .munit_semantic_validator import MUnitSemanticValidator
from .compliance_policy import CompliancePolicy
from .version_config import (
    get_full_version_map,
    get_munit_versions_for_runtime,
    get_recommended_munit_version,
    get_pom_snippet,
    RUNTIME_VERSIONS,
)
from .dynamic_flow_resolver import DynamicFlowResolver, resolve_dynamic_refs

__all__ = [
    "XMLAnalyzer",
    "DocumentParser",
    "PromptBuilder",
    "RulesetLoader",
    "BlueprintPipeline",
    "FlowIsolator",
    "MockBlueprintBuilder",
    "MultiPassGenerator",
    "TemplateAssembler",
    "SelfHealingRunner",
    "DeterministicMUnitBuilder",
    "MUnitSemanticValidator",
    "CompliancePolicy",
    "get_full_version_map",
    "get_munit_versions_for_runtime",
    "get_recommended_munit_version",
    "get_pom_snippet",
    "RUNTIME_VERSIONS",
    "DynamicFlowResolver",
    "resolve_dynamic_refs",
]
