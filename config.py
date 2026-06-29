"""
Configuration management for MUnit Generation Agent.
"""

import os
import tempfile
from typing import Optional
from dotenv import load_dotenv
from rich.console import Console


class Config:
    """Configuration manager for the MUnit Generation Agent."""

    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            env_file: Path to .env file (optional)
        """
        self.console = Console()
        
        # Load environment variables
        if env_file:
            load_dotenv(env_file)
        else:
            load_dotenv()  # Load from .env by default

    # LLM Configuration
    @property
    def anthropic_api_key(self) -> Optional[str]:
        """Get Anthropic API key."""
        return os.getenv("ANTHROPIC_API_KEY")

    @property
    def openai_api_key(self) -> Optional[str]:
        """Get OpenAI API key."""
        return os.getenv("OPENAI_API_KEY")

    @property
    def groq_api_key(self) -> Optional[str]:
        """Get Groq API key."""
        return os.getenv("GROQ_API_KEY")

    @property
    def gemini_api_key(self) -> Optional[str]:
        """Get Gemini API key."""
        return os.getenv("GEMINI_API_KEY")

    @property
    def openrouter_api_key(self) -> Optional[str]:
        """Get OpenRouter API key."""
        return os.getenv("OPENROUTER_API_KEY")

    @property
    def primary_llm(self) -> str:
        """Get primary LLM model."""
        return os.getenv("PRIMARY_LLM", "anthropic/claude-sonnet-4-20250514")

    @property
    def max_prompt_tokens(self) -> int:
        """Get maximum prompt tokens."""
        return int(os.getenv("MAX_PROMPT_TOKENS", "6000"))

    @property
    def llm_timeout(self) -> int:
        """Get LLM timeout in seconds."""
        return int(os.getenv("LLM_TIMEOUT", "60"))

    # GitHub Configuration
    @property
    def github_token(self) -> Optional[str]:
        """Get GitHub token."""
        return os.getenv("GITHUB_TOKEN")

    # Confluence Configuration
    @property
    def confluence_token(self) -> Optional[str]:
        """Get Confluence API token."""
        return os.getenv("CONFLUENCE_TOKEN")

    @property
    def confluence_email(self) -> Optional[str]:
        """Get Confluence email."""
        return os.getenv("CONFLUENCE_EMAIL")

    # Output Configuration
    @property
    def output_path(self) -> str:
        """Get output path for generated files."""
        return os.getenv("OUTPUT_PATH", os.path.join(tempfile.gettempdir(), "munit-generation-agent-output"))
    
    @output_path.setter
    def output_path(self, value: str):
        """Set output path for generated files."""
        os.environ["OUTPUT_PATH"] = value

    # Ruleset Configuration
    @property
    def rulesets_dir(self) -> str:
        """Get rulesets directory."""
        return os.getenv("RULESETS_DIR", "./rulesets")

    # Validation Methods
    def validate_llm_config(self) -> dict:
        """
        Validate LLM configuration.
        
        Returns:
            Dictionary with validation results
        """
        results = {
            "valid": True,
            "missing_keys": [],
            "available_models": []
        }

        # Check API keys
        api_keys = {
            "anthropic": self.anthropic_api_key,
            "openai": self.openai_api_key,
            "groq": self.groq_api_key,
            "gemini": self.gemini_api_key,
            "openrouter": self.openrouter_api_key
        }

        for provider, key in api_keys.items():
            if key:
                results["available_models"].append(provider)
            else:
                results["missing_keys"].append(f"{provider.upper()}_API_KEY")

        if not results["available_models"]:
            results["valid"] = False

        return results

    def validate_github_config(self) -> dict:
        """
        Validate GitHub configuration.
        
        Returns:
            Dictionary with validation results
        """
        return {
            "has_token": bool(self.github_token),
            "token_set": bool(self.github_token)
        }

    def validate_confluence_config(self) -> dict:
        """
        Validate Confluence configuration.
        
        Returns:
            Dictionary with validation results
        """
        return {
            "has_token": bool(self.confluence_token),
            "has_email": bool(self.confluence_email),
            "valid": bool(self.confluence_token and self.confluence_email)
        }

    def validate_output_config(self) -> dict:
        """
        Validate output configuration.
        
        Returns:
            Dictionary with validation results
        """
        output_dir = os.path.dirname(self.output_path)
        
        return {
            "output_path": self.output_path,
            "dir_exists": os.path.exists(output_dir),
            "dir_writable": os.access(output_dir, os.W_OK) if os.path.exists(output_dir) else False,
            "valid": True  # Will create directory if needed
        }

    def validate_all(self) -> dict:
        """
        Validate all configuration sections.
        
        Returns:
            Dictionary with all validation results
        """
        return {
            "llm": self.validate_llm_config(),
            "github": self.validate_github_config(),
            "confluence": self.validate_confluence_config(),
            "output": self.validate_output_config()
        }

    def print_config_summary(self):
        """Print configuration summary to console."""
        self.console.print("[blue]Configuration Summary:[/blue]")
        
        # LLM Config
        llm_config = self.validate_llm_config()
        self.console.print(f"  LLM Models Available: {len(llm_config['available_models'])}")
        if llm_config['available_models']:
            for model in llm_config['available_models']:
                self.console.print(f"    - {model}")
        
        # GitHub Config
        github_config = self.validate_github_config()
        self.console.print(f"  GitHub Token: {'Set' if github_config['has_token'] else 'Not set'}")
        
        # Confluence Config
        confluence_config = self.validate_confluence_config()
        self.console.print(f"  Confluence: {'Configured' if confluence_config['valid'] else 'Not configured'}")
        
        # Output Config
        output_config = self.validate_output_config()
        self.console.print(f"  Output Path: {output_config['output_path']}")
        
        # LLM Settings
        self.console.print(f"  Max Prompt Tokens: {self.max_prompt_tokens}")
        self.console.print(f"  LLM Timeout: {self.llm_timeout}s")

    def get_env_template(self) -> str:
        """
        Get .env file template.
        
        Returns:
            Template string for .env file
        """
        template = """# LLM API Keys
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GROQ_API_KEY=
GEMINI_API_KEY=
OPENROUTER_API_KEY=

# GitHub
GITHUB_TOKEN=

# Confluence
CONFLUENCE_TOKEN=
CONFLUENCE_EMAIL=

# LLM Settings
PRIMARY_LLM=anthropic/claude-sonnet-4-20250514
MAX_PROMPT_TOKENS=6000
LLM_TIMEOUT=60

# Output
OUTPUT_PATH=/tmp/munit-generation-agent-output
"""
        return template

    def create_env_file(self, file_path: str = ".env"):
        """
        Create .env file with template.
        
        Args:
            file_path: Path to create .env file
        """
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(self.get_env_template())
            self.console.print(f"[green]Created .env file: {file_path}[/green]")
        else:
            self.console.print(f"[yellow].env file already exists: {file_path}[/yellow]")

    def get_config_dict(self) -> dict:
        """
        Get configuration as dictionary.
        
        Returns:
            Configuration dictionary
        """
        return {
            "llm": {
                "primary_model": self.primary_llm,
                "max_tokens": self.max_prompt_tokens,
                "timeout": self.llm_timeout
            },
            "github": {
                "token_set": bool(self.github_token)
            },
            "confluence": {
                "token_set": bool(self.confluence_token),
                "email_set": bool(self.confluence_email)
            },
            "output": {
                "path": self.output_path
            },
            "rulesets": {
                "directory": self.rulesets_dir
            }
        }
