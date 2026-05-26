"""
Confluence API client for fetching business use case documents.
"""

import re
from typing import Optional
from atlassian import Confluence
from bs4 import BeautifulSoup
from rich.console import Console


class ConfluenceReader:
    """Fetches and parses Confluence page content for business use cases."""

    def __init__(self, url: str, token: str, email: Optional[str] = None):
        """
        Initialize Confluence client.
        
        Args:
            url: Confluence base URL
            token: API token for authentication
            email: Email for token authentication (required for some setups)
        """
        self.console = Console()
        self.url = url
        self.token = token
        self.email = email or os.getenv("CONFLUENCE_EMAIL")
        
        try:
            self.confluence = Confluence(
                url=self.url,
                token=self.token,
                username=self.email
            )
        except Exception as e:
            raise Exception(f"Failed to initialize Confluence client: {str(e)}")

    def fetch_page_content(self, page_url: str) -> str:
        """
        Fetch and clean Confluence page content.
        
        Args:
            page_url: Full URL to Confluence page
            
        Returns:
            Clean text content from the page
            
        Raises:
            Exception: If page cannot be fetched
        """
        try:
            # Extract page ID from URL
            page_id = self._extract_page_id(page_url)
            if not page_id:
                raise ValueError(f"Could not extract page ID from URL: {page_url}")

            self.console.print(f"[blue]Fetching Confluence page...[/blue]")
            self.console.print(f"  Page ID: {page_id}")

            # Get page content
            page = self.confluence.get_page_by_id(page_id, expand='body.storage')
            
            if not page:
                raise Exception(f"Page not found: {page_id}")

            # Extract HTML content from storage format
            html_content = page.get('body', {}).get('storage', {}).get('value', '')
            
            if not html_content:
                raise Exception("No content found in page")

            # Clean HTML and extract text
            clean_text = self._clean_html_content(html_content)
            
            self.console.print(f"[green]Successfully fetched and cleaned {len(clean_text)} characters[/green]")
            return clean_text
            
        except Exception as e:
            raise Exception(f"Failed to fetch Confluence page: {str(e)}")

    def _extract_page_id(self, page_url: str) -> Optional[str]:
        """
        Extract Confluence page ID from URL.
        
        Args:
            page_url: Confluence page URL
            
        Returns:
            Page ID as string or None if not found
        """
        # Common patterns for Confluence URLs
        patterns = [
            r'/pages/(\d+)',
            r'/viewpage\?pageId=(\d+)',
            r'/wiki/spaces/[^/]+/pages/(\d+)',
            r'/wiki/pages/(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, page_url)
            if match:
                return match.group(1)
        
        return None

    def _clean_html_content(self, html_content: str) -> str:
        """
        Clean HTML content and extract meaningful text.
        
        Args:
            html_content: Raw HTML content from Confluence
            
        Returns:
            Clean text content
        """
        try:
            # Parse HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            
            # Get text content
            text = soup.get_text()
            
            # Clean up whitespace
            # Replace multiple newlines with single newline
            text = re.sub(r'\n+', '\n', text)
            # Replace multiple spaces with single space
            text = re.sub(r' +', ' ', text)
            # Clean up leading/trailing whitespace
            text = '\n'.join(line.strip() for line in text.split('\n') if line.strip())
            
            return text
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: HTML cleaning failed, returning raw content: {str(e)}[/yellow]")
            return html_content

    def validate_page_access(self, page_url: str) -> bool:
        """
        Validate that we can access the Confluence page.
        
        Args:
            page_url: Confluence page URL
            
        Returns:
            True if accessible, False otherwise
        """
        try:
            page_id = self._extract_page_id(page_url)
            if not page_id:
                return False
            
            # Try to get minimal page info
            page = self.confluence.get_page_by_id(page_id, expand='title')
            return page is not None and 'title' in page
            
        except Exception:
            return False

    def get_page_info(self, page_url: str) -> dict:
        """
        Get basic page information.
        
        Args:
            page_url: Confluence page URL
            
        Returns:
            Dictionary with page info
        """
        try:
            page_id = self._extract_page_id(page_url)
            if not page_id:
                return {"accessible": False, "error": "Could not extract page ID"}
            
            page = self.confluence.get_page_by_id(page_id, expand='title,version')
            
            if not page:
                return {"accessible": False, "error": "Page not found"}
            
            return {
                "accessible": True,
                "id": page_id,
                "title": page.get('title', 'Unknown'),
                "version": page.get('version', {}).get('number', 'Unknown'),
                "url": page_url
            }
            
        except Exception as e:
            return {"accessible": False, "error": str(e)}
