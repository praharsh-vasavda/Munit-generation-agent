"""
Ruleset loader for loading and merging YAML rule files.
"""

import os
import yaml
from typing import Dict, List
from pathlib import Path
from rich.console import Console


class RulesetLoader:
    """Loads and merges YAML ruleset files for MUnit generation."""

    def __init__(self, rulesets_dir: str = "rulesets"):
        """
        Initialize ruleset loader.
        
        Args:
            rulesets_dir: Directory containing YAML rule files
        """
        self.console = Console()
        self.rulesets_dir = Path(rulesets_dir)

    def load_ruleset(self) -> Dict:
        """
        Load and merge all YAML ruleset files.
        
        Returns:
            Merged ruleset dictionary
            
        Raises:
            Exception: If ruleset cannot be loaded
        """
        try:
            if not self.rulesets_dir.exists():
                raise FileNotFoundError(f"Rulesets directory not found: {self.rulesets_dir}")
            
            merged_ruleset = {}
            loaded_files = []
            
            # Load all YAML files
            for yaml_file in self.rulesets_dir.glob("*.yaml"):
                self.console.print(f"[blue]Loading ruleset: {yaml_file.name}[/blue]")
                
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    ruleset_content = yaml.safe_load(f)
                
                if ruleset_content:
                    # Merge using filename as top-level key
                    ruleset_name = yaml_file.stem
                    merged_ruleset[ruleset_name] = ruleset_content
                    loaded_files.append(yaml_file.name)
                else:
                    self.console.print(f"[yellow]Warning: Empty ruleset file: {yaml_file.name}[/yellow]")
            
            if not merged_ruleset:
                raise Exception("No valid ruleset files found")
            
            self.console.print(f"[green]Successfully loaded {len(loaded_files)} ruleset files:[/green]")
            for filename in loaded_files:
                self.console.print(f"  - {filename}")
            
            return merged_ruleset

        except yaml.YAMLError as e:
            raise Exception(f"Invalid YAML format in ruleset file: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to load ruleset: {str(e)}")

    def get_ruleset(self) -> Dict:
        """
        Get merged ruleset (alias for load_ruleset).
        
        Returns:
            Merged ruleset dictionary
        """
        return self.load_ruleset()

    def validate_ruleset_structure(self, ruleset: Dict) -> bool:
        """
        Validate that ruleset has required structure.
        
        Args:
            ruleset: Ruleset dictionary to validate
            
        Returns:
            True if structure is valid
        """
        required_files = [
            'munit_structure',
            'mock_rules',
            'assertion_rules',
            'scenario_rules'
        ]
        
        missing_files = [file for file in required_files if file not in ruleset]
        
        if missing_files:
            self.console.print(f"[red]Missing required ruleset files: {missing_files}[/red]")
            return False
        
        # Validate specific structure
        try:
            # Check munit_structure
            structure = ruleset['munit_structure']
            if not all(key in structure for key in ['xml_namespaces', 'test_naming_convention']):
                self.console.print("[red]Invalid munit_structure ruleset[/red]")
                return False
            
            # Check mock_rules
            mock_rules = ruleset['mock_rules']
            if 'mock_strategies' not in mock_rules:
                self.console.print("[red]Invalid mock_rules ruleset[/red]")
                return False
            
            # Check assertion_rules
            assertion_rules = ruleset['assertion_rules']
            if 'assertion_types' not in assertion_rules:
                self.console.print("[red]Invalid assertion_rules ruleset[/red]")
                return False
            
            # Check scenario_rules
            scenario_rules = ruleset['scenario_rules']
            if 'job_type_scenarios' not in scenario_rules:
                self.console.print("[red]Invalid scenario_rules ruleset[/red]")
                return False
            
            return True
            
        except Exception as e:
            self.console.print(f"[red]Ruleset validation error: {str(e)}[/red]")
            return False

    def get_job_type_scenarios(self, ruleset: Dict, job_type: str) -> Dict:
        """
        Get scenarios for specific job type.
        
        Args:
            ruleset: Loaded ruleset
            job_type: Job type (e.g., 'REST API', 'Batch Job')
            
        Returns:
            Scenarios configuration for job type
        """
        job_scenarios = ruleset.get('scenario_rules', {}).get('job_type_scenarios', {})
        
        # Normalize job type for lookup
        normalized_job_type = job_type.lower().replace(' ', '_')
        
        # Try exact match first
        if job_type in job_scenarios:
            return job_scenarios[job_type]
        
        # Try normalized match
        for job_key, scenarios in job_scenarios.items():
            if job_key.lower().replace(' ', '_') == normalized_job_type:
                return scenarios
        
        # Fallback to generic
        return job_scenarios.get('generic_mule_flow', {
            'required_scenarios': [
                {'name': 'happy_path', 'description': 'Normal execution'},
                {'name': 'error_handling', 'description': 'Error condition'}
            ]
        })

    def get_mock_strategy(self, ruleset: Dict, connector_type: str) -> Dict:
        """
        Get mock strategy for connector type.
        
        Args:
            ruleset: Loaded ruleset
            connector_type: Connector type (e.g., 'http:request')
            
        Returns:
            Mock strategy configuration
        """
        mock_strategies = ruleset.get('mock_rules', {}).get('mock_strategies', {})
        return mock_strategies.get(connector_type, {})

    def get_assertion_rules(self, ruleset: Dict, scenario_type: str) -> Dict:
        """
        Get assertion rules for scenario type.
        
        Args:
            ruleset: Loaded ruleset
            scenario_type: Scenario type (e.g., 'happy_path')
            
        Returns:
            Assertion rules configuration
        """
        assertion_types = ruleset.get('assertion_rules', {}).get('assertion_types', {})
        return assertion_types.get(scenario_type, {})

    def list_available_connectors(self, ruleset: Dict) -> List[str]:
        """
        List all connector types with mock strategies.
        
        Args:
            ruleset: Loaded ruleset
            
        Returns:
            List of connector types
        """
        mock_strategies = ruleset.get('mock_rules', {}).get('mock_strategies', {})
        return list(mock_strategies.keys())

    def list_available_job_types(self, ruleset: Dict) -> List[str]:
        """
        List all job types with scenario rules.
        
        Args:
            ruleset: Loaded ruleset
            
        Returns:
            List of job types
        """
        job_scenarios = ruleset.get('scenario_rules', {}).get('job_type_scenarios', {})
        return list(job_scenarios.keys())
