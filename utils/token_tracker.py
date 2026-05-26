"""
Token tracking utilities for MUnit Generation Agent.
Monitors token usage and provides optimization suggestions.
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class TokenUsage:
    """Token usage for a single operation."""
    operation: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class TokenBudget:
    """
    Token budget management with tracking and optimization suggestions.
    """
    total_budget: int
    used_tokens: int = 0
    operations: List[TokenUsage] = field(default_factory=list)
    
    @property
    def remaining_tokens(self) -> int:
        """Get remaining token budget."""
        return max(0, self.total_budget - self.used_tokens)
    
    @property
    def usage_percentage(self) -> float:
        """Get usage as percentage."""
        if self.total_budget == 0:
            return 0.0
        return (self.used_tokens / self.total_budget) * 100
    
    def can_afford(self, tokens: int) -> bool:
        """Check if operation can be afforded within budget."""
        return self.remaining_tokens >= tokens
    
    def use_tokens(self, tokens: int, operation: str = "unknown") -> bool:
        """
        Use tokens from budget.
        
        Args:
            tokens: Number of tokens to use
            operation: Description of the operation
            
        Returns:
            True if tokens were used, False if budget exceeded
        """
        if self.can_afford(tokens):
            self.used_tokens += tokens
            self.operations.append(TokenUsage(
                operation=operation,
                input_tokens=tokens,  # Simplified - can be split if needed
                output_tokens=0,
                total_tokens=tokens
            ))
            logger.debug(f"Used {tokens} tokens for '{operation}'. Remaining: {self.remaining_tokens}")
            return True
        
        logger.warning(f"Cannot afford {tokens} tokens for '{operation}'. Remaining: {self.remaining_tokens}")
        return False
    
    def record_llm_usage(self, operation: str, input_tokens: int, output_tokens: int):
        """
        Record LLM API usage.
        
        Args:
            operation: Description of the LLM operation
            input_tokens: Tokens in the prompt
            output_tokens: Tokens in the response
        """
        total = input_tokens + output_tokens
        self.used_tokens += total
        self.operations.append(TokenUsage(
            operation=operation,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total
        ))
        logger.info(f"LLM usage for '{operation}': {input_tokens} in, {output_tokens} out, total: {total}")
    
    def get_optimization_suggestions(self) -> List[str]:
        """Get optimization suggestions based on current usage."""
        suggestions = []
        usage_ratio = self.used_tokens / max(1, self.total_budget)
        
        if usage_ratio > 0.9:
            suggestions.append("⚠️ Token budget nearly exhausted (>90%)")
            suggestions.append("Consider increasing token budget for complex flows")
            suggestions.append("Use flow-specific generation instead of full project")
        elif usage_ratio > 0.7:
            suggestions.append("ℹ️ Token usage is high (>70%)")
            suggestions.append("Consider prioritizing critical flows only")
        elif usage_ratio < 0.3:
            suggestions.append("✅ Token budget has plenty of headroom")
            suggestions.append("Consider enabling more detailed test generation")
        
        # Analyze operation patterns
        if self.operations:
            avg_per_op = self.used_tokens / len(self.operations)
            if avg_per_op > 5000:
                suggestions.append("Large average token usage per operation - consider chunking")
        
        return suggestions
    
    def get_usage_summary(self) -> Dict:
        """Get a summary of token usage."""
        return {
            'total_budget': self.total_budget,
            'used_tokens': self.used_tokens,
            'remaining_tokens': self.remaining_tokens,
            'usage_percentage': round(self.usage_percentage, 1),
            'operation_count': len(self.operations),
            'suggestions': self.get_optimization_suggestions()
        }
    
    def reset(self):
        """Reset token tracking."""
        self.used_tokens = 0
        self.operations = []


class TokenEstimator:
    """
    Estimate token counts for content.
    Uses simple heuristics when tiktoken is not available.
    """
    
    _tokenizer = None
    _initialized = False
    
    @classmethod
    def _init_tokenizer(cls):
        """Initialize tokenizer (lazy loading)."""
        if cls._initialized:
            return
        
        cls._initialized = True
        try:
            import tiktoken
            cls._tokenizer = tiktoken.get_encoding("cl100k_base")
            logger.debug("Tiktoken tokenizer initialized")
        except ImportError:
            logger.debug("Tiktoken not available, using fallback estimation")
        except Exception as e:
            logger.warning(f"Tiktoken initialization failed: {e}")
    
    @classmethod
    def estimate_tokens(cls, text: str) -> int:
        """
        Estimate token count for text.
        
        Args:
            text: Text to estimate tokens for
            
        Returns:
            Estimated token count
        """
        if not text:
            return 0
        
        cls._init_tokenizer()
        
        if cls._tokenizer:
            try:
                return len(cls._tokenizer.encode(text))
            except Exception as e:
                logger.debug(f"Tokenizer failed, using fallback: {e}")
        
        # Fallback: ~4 characters per token (rough estimate for code/XML)
        return len(text) // 4
    
    @classmethod
    def estimate_prompt_tokens(cls, flow_xml: str, use_case: str, rules: str) -> int:
        """
        Estimate tokens for a full MUnit generation prompt.
        
        Args:
            flow_xml: The Mule flow XML content
            use_case: Business use case content
            rules: Ruleset content
            
        Returns:
            Estimated total tokens
        """
        # Estimate each component
        xml_tokens = cls.estimate_tokens(flow_xml)
        usecase_tokens = cls.estimate_tokens(use_case)
        rules_tokens = cls.estimate_tokens(rules)
        
        # Add overhead for prompt structure (~500 tokens)
        overhead = 500
        
        return xml_tokens + usecase_tokens + rules_tokens + overhead
