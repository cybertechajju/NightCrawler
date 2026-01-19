"""
NightCrawler - Console Output Module
Rich terminal output for findings
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List

console = Console()


class ConsoleOutput:
    """Handler for console output formatting"""
    
    @staticmethod
    def print_finding(pattern_name: str, url: str, value: str, confidence: int):
        """Print a single finding"""
        confidence_color = "green" if confidence >= 80 else "yellow" if confidence >= 60 else "red"
        
        console.print(f"[{confidence_color}]●[/] [{confidence_color}][{confidence}%][/] [bold cyan]{pattern_name}[/]")
        console.print(f"  [dim]URL:[/] {url}")
        console.print(f"  [dim]Value:[/] {value[:80]}{'...' if len(value) > 80 else ''}")
        console.print()
    
    @staticmethod
    def print_error(message: str):
        """Print an error message"""
        console.print(f"[bold red][!] Error:[/] {message}")
    
    @staticmethod
    def print_success(message: str):
        """Print a success message"""
        console.print(f"[bold green][+][/] {message}")
    
    @staticmethod
    def print_info(message: str):
        """Print an info message"""
        console.print(f"[bold yellow][*][/] {message}")
    
    @staticmethod
    def print_verbose(message: str):
        """Print a verbose/debug message"""
        console.print(f"[dim]{message}[/dim]")
