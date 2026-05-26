"""
Security utilities for MUnit Generation Agent.
Handles sensitive data detection and content sanitization.
"""

import re
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SecurityAnalysis:
    """Security analysis results."""
    sensitive_data_detected: List[str]
    sanitized_content: str
    security_warnings: List[str]
    is_safe: bool


class SecuritySanitizer:
    """
    Security sanitizer for detecting and redacting sensitive data
    before sending content to LLM.
    """
    
    # Patterns that indicate sensitive data
    SENSITIVE_PATTERNS = [
        # Credentials
        (r'password\s*[=:]\s*["\']([^"\']+)["\']', 'password'),
        (r'secret\s*[=:]\s*["\']([^"\']+)["\']', 'secret'),
        (r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'api_key'),
        (r'client[_-]?secret\s*[=:]\s*["\']([^"\']+)["\']', 'client_secret'),
        (r'access[_-]?token\s*[=:]\s*["\']([^"\']+)["\']', 'access_token'),
        (r'private[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'private_key'),
        (r'auth[_-]?token\s*[=:]\s*["\']([^"\']+)["\']', 'auth_token'),
        
        # Connection strings
        (r'jdbc:[^\s<>"\']+', 'jdbc_connection'),
        (r'mongodb://[^\s<>"\']+', 'mongodb_connection'),
        (r'redis://[^\s<>"\']+', 'redis_connection'),
        
        # AWS/Cloud credentials
        (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
        (r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'aws_secret'),
        
        # Bearer tokens
        (r'Bearer\s+[A-Za-z0-9\-_\.]+', 'bearer_token'),
        
        # Basic auth
        (r'Basic\s+[A-Za-z0-9+/=]+', 'basic_auth'),
    ]
    
    # XML attribute patterns for secure properties
    SECURE_PROPERTY_PATTERNS = [
        r'<secure-properties[^>]*>.*?</secure-properties>',
        r'<secure-property[^>]*/>',
        r'\$\{secure::[^}]+\}',
    ]
    
    @classmethod
    def analyze_and_sanitize(cls, content: str) -> SecurityAnalysis:
        """
        Analyze content for sensitive data and return sanitized version.
        
        Args:
            content: Raw content to analyze
            
        Returns:
            SecurityAnalysis with detection results and sanitized content
        """
        detected = []
        warnings = []
        sanitized = content
        
        # Check for sensitive patterns
        for pattern, data_type in cls.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                detected.append(f"{data_type}: {len(matches)} occurrence(s)")
                warnings.append(f"Detected {data_type} in content - will be redacted")
                
                # Redact the sensitive values
                sanitized = re.sub(
                    pattern,
                    lambda m: cls._create_redacted_replacement(m, data_type),
                    sanitized,
                    flags=re.IGNORECASE
                )
        
        # Check for secure property references (these are safe, just log them)
        for pattern in cls.SECURE_PROPERTY_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                logger.debug("Found secure property references (safe pattern)")
        
        is_safe = len(detected) == 0
        
        return SecurityAnalysis(
            sensitive_data_detected=detected,
            sanitized_content=sanitized,
            security_warnings=warnings,
            is_safe=is_safe
        )
    
    @classmethod
    def _create_redacted_replacement(cls, match, data_type: str) -> str:
        """Create a redacted replacement that preserves structure."""
        original = match.group(0)
        
        # Preserve the key/attribute name, only redact the value
        if '=' in original:
            key_part = original.split('=')[0]
            return f'{key_part}="***REDACTED_{data_type.upper()}***"'
        elif ':' in original:
            key_part = original.split(':')[0]
            return f'{key_part}: "***REDACTED_{data_type.upper()}***"'
        else:
            return f"***REDACTED_{data_type.upper()}***"
    
    @classmethod
    def is_content_safe(cls, content: str) -> bool:
        """Quick check if content is safe without full analysis."""
        for pattern, _ in cls.SENSITIVE_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return False
        return True
    
    @classmethod
    def sanitize_for_logging(cls, content: str, max_length: int = 500) -> str:
        """
        Create a safe version of content for logging.
        Truncates and redacts sensitive data.
        """
        # First sanitize
        analysis = cls.analyze_and_sanitize(content)
        safe_content = analysis.sanitized_content
        
        # Then truncate
        if len(safe_content) > max_length:
            safe_content = safe_content[:max_length] + "... [truncated]"
        
        return safe_content
