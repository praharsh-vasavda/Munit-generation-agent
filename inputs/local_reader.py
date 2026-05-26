"""
Local file reader for Mule XML files and business use case documents.
"""

import os
from pathlib import Path
from typing import Optional
from rich.console import Console


class LocalReader:
    """Reads local files including XML, PDF, DOCX, and TXT formats."""

    def __init__(self):
        """Initialize local reader."""
        self.console = Console()

    def read_xml_file(self, file_path: str) -> str:
        """
        Read XML file content.
        
        Args:
            file_path: Path to XML file
            
        Returns:
            File content as string
            
        Raises:
            Exception: If file cannot be read
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            if not path.is_file():
                raise ValueError(f"Path is not a file: {file_path}")
            
            if path.suffix.lower() not in ['.xml']:
                raise ValueError(f"File must be XML: {file_path}")

            self.console.print(f"[blue]Reading local XML file...[/blue]")
            self.console.print(f"  Path: {file_path}")

            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.console.print(f"[green]Successfully read {len(content)} characters[/green]")
            return content
            
        except Exception as e:
            raise Exception(f"Failed to read XML file: {str(e)}")

    def read_document(self, file_path: str) -> str:
        """
        Read document content (PDF, DOCX, or TXT).
        
        Args:
            file_path: Path to document file
            
        Returns:
            Document content as string
            
        Raises:
            Exception: If file cannot be read
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            if not path.is_file():
                raise ValueError(f"Path is not a file: {file_path}")

            self.console.print(f"[blue]Reading local document...[/blue]")
            self.console.print(f"  Path: {file_path}")
            self.console.print(f"  Type: {path.suffix.upper()}")

            # Read based on file type
            if path.suffix.lower() == '.txt':
                content = self._read_txt(path)
            elif path.suffix.lower() == '.pdf':
                content = self._read_pdf(path)
            elif path.suffix.lower() in ['.docx', '.doc']:
                content = self._read_docx(path)
            else:
                raise ValueError(f"Unsupported file format: {path.suffix}")

            self.console.print(f"[green]Successfully read {len(content)} characters[/green]")
            return content
            
        except Exception as e:
            raise Exception(f"Failed to read document: {str(e)}")

    def _read_txt(self, path: Path) -> str:
        """Read TXT file."""
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()

    def _read_pdf(self, path: Path) -> str:
        """Read PDF file using pdfplumber."""
        try:
            import pdfplumber
        except ImportError:
            raise ImportError("pdfplumber is required for PDF reading. Install with: pip install pdfplumber")

        text_content = []
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_content.append(page_text)
        
        return "\n".join(text_content)

    def _read_docx(self, path: Path) -> str:
        """Read DOCX file using python-docx."""
        try:
            from docx import Document
        except ImportError:
            raise ImportError("python-docx is required for DOCX reading. Install with: pip install python-docx")

        doc = Document(path)
        paragraphs = []
        
        for paragraph in doc.paragraphs:
            if paragraph.text.strip():
                paragraphs.append(paragraph.text)
        
        return "\n".join(paragraphs)

    def validate_file_exists(self, file_path: str) -> bool:
        """
        Validate that file exists and is readable.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file exists and is readable
        """
        try:
            path = Path(file_path)
            return path.exists() and path.is_file()
        except Exception:
            return False

    def get_file_info(self, file_path: str) -> dict:
        """
        Get file information.
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary with file info
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return {"exists": False}
            
            stat = path.stat()
            return {
                "exists": True,
                "size": stat.st_size,
                "extension": path.suffix.lower(),
                "name": path.name,
                "readable": os.access(path, os.R_OK)
            }
        except Exception:
            return {"exists": False}
