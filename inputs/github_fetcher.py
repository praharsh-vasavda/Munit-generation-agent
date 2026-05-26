"""
GitHub API client for fetching Mule XML files from repositories.
"""

import os
from typing import Optional
from github import Github, GithubException
from rich.console import Console


class GitHubFetcher:
    """Fetches single XML files from GitHub repositories using the Contents API."""

    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub client.
        
        Args:
            token: GitHub personal access token for private repos
        """
        self.console = Console()
        self.token = token or os.getenv("GITHUB_TOKEN")
        
        if not self.token:
            self.console.print("[yellow]Warning: No GitHub token provided. Public repos only.[/yellow]")
        
        self.github = Github(self.token) if self.token else Github()

    def fetch_file(self, repo_url: str, branch: str, file_path: str) -> str:
        """
        Fetch a single file from GitHub repository.
        
        Args:
            repo_url: GitHub repository URL (e.g., 'owner/repo-name')
            branch: Branch name (e.g., 'main', 'develop')
            file_path: Path to file within repository
            
        Returns:
            File content as string
            
        Raises:
            Exception: If file cannot be fetched
        """
        try:
            # Extract owner and repo name from URL
            if "github.com/" in repo_url:
                parts = repo_url.split("github.com/")[-1].split("/")
                if len(parts) >= 2:
                    owner, repo = parts[0], parts[1]
                else:
                    raise ValueError(f"Invalid GitHub URL format: {repo_url}")
            else:
                # Assume format is already 'owner/repo'
                parts = repo_url.split("/")
                if len(parts) == 2:
                    owner, repo = parts[0], parts[1]
                else:
                    raise ValueError(f"Invalid repo format: {repo_url}")

            self.console.print(f"[blue]Fetching file from GitHub...[/blue]")
            self.console.print(f"  Repository: {owner}/{repo}")
            self.console.print(f"  Branch: {branch}")
            self.console.print(f"  File: {file_path}")

            # Get repository
            repository = self.github.get_repo(f"{owner}/{repo}")
            
            # Get file content
            file_content = repository.get_contents(file_path, ref=branch)
            
            if file_content.type == "file":
                content = file_content.decoded_content.decode("utf-8")
                self.console.print(f"[green]Successfully fetched {len(content)} characters[/green]")
                return content
            else:
                raise ValueError(f"Path {file_path} is not a file")
                
        except GithubException as e:
            error_msg = f"GitHub API error: {e}"
            if e.status == 404:
                error_msg += " (File not found or access denied)"
            elif e.status == 403:
                error_msg += " (Access denied - check token permissions)"
            raise Exception(error_msg)
        except Exception as e:
            raise Exception(f"Failed to fetch file from GitHub: {str(e)}")

    def validate_repo_access(self, repo_url: str) -> bool:
        """
        Validate that we can access the repository.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            True if accessible, False otherwise
        """
        try:
            if "github.com/" in repo_url:
                parts = repo_url.split("github.com/")[-1].split("/")
                if len(parts) >= 2:
                    owner, repo = parts[0], parts[1]
                else:
                    return False
            else:
                parts = repo_url.split("/")
                if len(parts) == 2:
                    owner, repo = parts[0], parts[1]
                else:
                    return False

            repository = self.github.get_repo(f"{owner}/{repo}")
            # Try to get basic repo info
            repository.name
            return True
            
        except Exception:
            return False
