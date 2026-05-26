"""
File utilities for robust file reading with encoding detection
"""

import os
from typing import Optional, Union
import logging

# Try to import chardet, but provide fallback if not available
try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False
    logging.warning("chardet not available, using fallback encoding detection")

logger = logging.getLogger(__name__)

class FileReader:
    """Robust file reader with automatic encoding detection"""
    
    @staticmethod
    def read_file_with_encoding_detection(file_content: bytes, filename: str = "") -> str:
        """
        Read file content with automatic encoding detection
        
        Args:
            file_content: Raw file bytes
            filename: Optional filename for logging
            
        Returns:
            Decoded file content as string
        """
        if not file_content:
            return ""
        
        # First try to detect encoding if chardet is available
        if CHARDET_AVAILABLE:
            try:
                detected = chardet.detect(file_content)
                encoding = detected.get('encoding', 'utf-8')
                confidence = detected.get('confidence', 0)
                
                logger.debug(f"Detected encoding: {encoding} with confidence {confidence:.2f} for file: {filename}")
                
                # If confidence is high, use detected encoding
                if confidence > 0.7:
                    try:
                        return file_content.decode(encoding)
                    except UnicodeDecodeError:
                        logger.warning(f"Failed to decode with detected encoding {encoding}, falling back")
                
            except Exception as e:
                logger.debug(f"Encoding detection failed: {e}")
        else:
            logger.debug("chardet not available, skipping encoding detection")
        
        # Fallback encoding list in order of preference
        fallback_encodings = [
            'utf-8',           # Most common
            'utf-8-sig',       # UTF-8 with BOM
            'latin-1',         # Common in Windows
            'cp1252',          # Windows default
            'iso-8859-1',      # Western European
            'ascii',           # ASCII fallback
        ]
        
        for encoding in fallback_encodings:
            try:
                content = file_content.decode(encoding)
                logger.debug(f"Successfully decoded with {encoding} for file: {filename}")
                return content
            except UnicodeDecodeError as e:
                logger.debug(f"Failed to decode with {encoding}: {e}")
                continue
        
        # Last resort: decode with error handling
        try:
            content = file_content.decode('utf-8', errors='replace')
            logger.warning(f"Used UTF-8 with error replacement for file: {filename}")
            return content
        except Exception as e:
            logger.error(f"Failed to decode file {filename} with all methods: {e}")
            return f"[Error reading file {filename}: Unable to decode content]"
    
    @staticmethod
    def read_uploaded_file(uploaded_file, max_size_mb: int = 10) -> str:
        """
        Read uploaded file with robust encoding handling
        
        Args:
            uploaded_file: FileStorage object from Flask
            max_size_mb: Maximum file size in MB
            
        Returns:
            Decoded file content as string
        """
        try:
            # Check file size
            uploaded_file.seek(0, 2)  # Seek to end
            file_size = uploaded_file.tell()
            uploaded_file.seek(0)     # Seek back to start
            
            max_size_bytes = max_size_mb * 1024 * 1024
            if file_size > max_size_bytes:
                logger.warning(f"File {uploaded_file.filename} too large: {file_size} bytes")
                return f"[File too large: {uploaded_file.filename} - Max size: {max_size_mb}MB]"
            
            # Read file content
            file_content = uploaded_file.read()
            
            # Detect and decode
            return FileReader.read_file_with_encoding_detection(file_content, uploaded_file.filename)
            
        except Exception as e:
            logger.error(f"Error reading uploaded file {uploaded_file.filename}: {e}")
            return f"[Error reading file {uploaded_file.filename}: {str(e)}]"
    
    @staticmethod
    def read_local_file(file_path: str, max_size_mb: int = 10) -> str:
        """
        Read local file with robust encoding handling
        
        Args:
            file_path: Path to local file
            max_size_mb: Maximum file size in MB
            
        Returns:
            Decoded file content as string
        """
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            max_size_bytes = max_size_mb * 1024 * 1024
            
            if file_size > max_size_bytes:
                logger.warning(f"File {file_path} too large: {file_size} bytes")
                return f"[File too large: {file_path} - Max size: {max_size_mb}MB]"
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Detect and decode
            return FileReader.read_file_with_encoding_detection(file_content, os.path.basename(file_path))
            
        except Exception as e:
            logger.error(f"Error reading local file {file_path}: {e}")
            return f"[Error reading file {file_path}: {str(e)}]"
    
    @staticmethod
    def is_xml_file(content: str) -> bool:
        """
        Check if content appears to be XML
        
        Args:
            content: File content to check
            
        Returns:
            True if content appears to be XML
        """
        if not content:
            return False
        
        # Look for XML indicators
        content_lower = content.lower()
        xml_indicators = [
            '<?xml',
            '<mule',
            '<flow',
            '<http:',
            '<db:',
            '<apikit:',
            '<logger',
            '<set-variable',
            '<transform'
        ]
        
        # Check first few lines for XML indicators
        lines = content.split('\n')[:10]  # Check first 10 lines
        for line in lines:
            line = line.strip()
            if any(indicator in line for indicator in xml_indicators):
                return True
        
        return False
    
    @staticmethod
    def clean_xml_content(content: str) -> str:
        """
        Clean and normalize XML content
        
        Args:
            content: Raw XML content
            
        Returns:
            Cleaned XML content
        """
        if not content:
            return ""
        
        # Remove common encoding issues
        # Replace common problematic characters
        replacements = {
            '\x9b': '',  # Control character that causes issues
            '\x8b': '',  # Another control character
            '\x7f': '',  # DEL character
            '\x1b': '',  # Escape character
        }
        
        for old, new in replacements.items():
            content = content.replace(old, new)
        
        # Remove null bytes
        content = content.replace('\x00', '')
        
        # Normalize line endings
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        
        return content.strip()

# Global instance for easy access
file_reader = FileReader()
