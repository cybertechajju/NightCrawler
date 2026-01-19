"""
NightCrawler v3.1 - UI Banner Module
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

console = Console()

BANNER = """
[bold green]
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
[/bold green]
"""

def print_banner():
    """Print the NightCrawler banner with version info"""
    console.print(BANNER)
    
    # Create info line
    info = Text()
    info.append("v3.1", style="bold green")
    info.append(" │ ", style="dim")
    info.append("Red Team JS Scanner", style="yellow")
    info.append(" │ ", style="dim")
    info.append("75+ KeyHacks Validators", style="bold red")
    info.append(" │ ", style="dim")
    info.append("CyberTechAjju", style="bold magenta")
    
    console.print(Panel(info, border_style="green", padding=(0, 2)))
    
    # Feature highlights
    features = Text()
    features.append("🦇 ", style="bold")
    features.append("200+ Patterns", style="green")
    features.append("  •  ", style="dim")
    features.append("Auto-Validate Secrets", style="red")
    features.append("  •  ", style="dim")
    features.append("Subdomain Scan", style="yellow")
    features.append("  •  ", style="dim") 
    features.append("HackerOne Reports", style="cyan")
    
    console.print(Panel(features, border_style="dim", padding=(0, 1)))
    console.print("[dim]Keep Learning // Keep Hacking   •   ⚠️  Ethical Use Only[/dim]\n")
