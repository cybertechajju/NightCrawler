#!/usr/bin/env python3
"""
NightCrawler v5.0 - Interactive Mode
Fully interactive JS secret scanner with all tools
by CyberTechAjju | Keep Learning // Keep Hacking
"""

import os
import sys
import shutil
import subprocess
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.prompt import Prompt, Confirm, IntPrompt
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "aiohttp", "jsbeautifier", "click", "-q"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.prompt import Prompt, Confirm, IntPrompt

console = Console()

REQUIRED_TOOLS = {
    "subfinder": {"name": "Subfinder", "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "required": True},
    "httpx": {"name": "Httpx", "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "required": True},
    "katana": {"name": "Katana", "install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest", "required": True},
    "gau": {"name": "GAU", "install": "go install -v github.com/lc/gau/v2/cmd/gau@latest", "required": False},
    "waybackurls": {"name": "Waybackurls", "install": "go install -v github.com/tomnomnom/waybackurls@latest", "required": False},
    "subjs": {"name": "SubJS", "install": "go install -v github.com/lc/subjs@latest", "required": False},
    "jsluice": {"name": "JSLuice", "install": "go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest", "required": False},
    "hakrawler": {"name": "Hakrawler", "install": "go install -v github.com/hakluke/hakrawler@latest", "required": False},
    "getjs": {"name": "GetJS", "install": "go install -v github.com/003random/getJS@latest", "required": False},
}

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


def find_tool(tool_id):
    """Find tool in PATH or common locations"""
    path = shutil.which(tool_id)
    if path:
        return path
    
    go_bin = os.path.expanduser(f"~/go/bin/{tool_id}")
    if os.path.exists(go_bin):
        return go_bin
    
    local_bin = f"/usr/local/bin/{tool_id}"
    if os.path.exists(local_bin):
        return local_bin
    
    return None


def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')


def print_banner():
    clear_screen()
    console.print(BANNER)
    
    info = Text()
    info.append("v5.0", style="bold green")
    info.append(" │ ", style="dim")
    info.append("All Tools", style="yellow")
    info.append(" │ ", style="dim")
    info.append("75+ KeyHacks", style="bold red")
    info.append(" │ ", style="dim")
    info.append("No Timeouts", style="bold magenta")
    console.print(Panel(info, border_style="green"))
    console.print("[dim]⚠️  Ethical Use Only • Keep Learning // Keep Hacking[/dim]\n")


def check_dependencies():
    """Check all tools and offer to install missing ones"""
    console.print("\n[bold cyan]🔍 Checking Dependencies...[/bold cyan]\n")
    
    table = Table(title="Tool Status", show_header=True, header_style="bold cyan")
    table.add_column("Tool", style="white", width=15)
    table.add_column("Status", justify="center", width=12)
    table.add_column("Path", style="dim", width=40)
    
    missing_required = []
    tool_paths = {}
    
    for tool_id, tool_info in REQUIRED_TOOLS.items():
        path = find_tool(tool_id)
        tool_paths[tool_id] = path
        
        if path:
            status = "[green]✓ Found[/green]"
            display_path = path[:38] + ".." if len(path) > 40 else path
        else:
            if tool_info.get("required"):
                status = "[red]✗ Missing[/red]"
                missing_required.append(tool_id)
            else:
                status = "[yellow]○ Optional[/yellow]"
            display_path = "-"
        
        table.add_row(tool_info["name"], status, display_path)
    
    console.print(table)
    
    for dep in ["aiohttp", "rich", "jsbeautifier", "click"]:
        try:
            __import__(dep.replace("-", "_"))
        except ImportError:
            subprocess.run([sys.executable, "-m", "pip", "install", dep, "-q"])
    
    if missing_required:
        console.print(f"\n[red]⚠️  Missing required tools: {', '.join(missing_required)}[/red]")
        if Confirm.ask("[yellow]Install missing tools?[/yellow]", default=True):
            for tool_id in missing_required:
                tool = REQUIRED_TOOLS.get(tool_id, {})
                console.print(f"[cyan]Installing {tool['name']}...[/cyan]")
                subprocess.run(tool["install"], shell=True)
    
    console.print("\n[green]✓ Dependency check complete![/green]")
    time.sleep(1)
    return True


def get_target():
    console.print("\n[bold cyan]┌─────────────────────────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│               🎯  TARGET CONFIGURATION                      │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────────────────────────┘[/bold cyan]\n")
    
    target = Prompt.ask("[bold white]Enter target domain[/bold white]", default="example.com")
    
    if not target or target == "example.com":
        console.print("[yellow]⚠️  Please enter a valid target domain![/yellow]")
        return get_target()
    
    console.print(f"\n[green]✓ Target: {target}[/green]")
    return target


def get_scan_mode():
    console.print("\n[bold cyan]┌─────────────────────────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│               ⚙️  SCAN MODE                                  │[/bold cyan]")
    console.print("[bold cyan]├─────────────────────────────────────────────────────────────┤[/bold cyan]")
    console.print("[bold cyan]│  [/bold cyan][bold green][1][/bold green] Main Domain Only[bold cyan]                                  │[/bold cyan]")
    console.print("[bold cyan]│      [/bold cyan][dim]→ Fast scan on main domain[/dim][bold cyan]                        │[/bold cyan]")
    console.print("[bold cyan]│  [/bold cyan][bold yellow][2][/bold yellow] Include Subdomains[bold cyan]                                │[/bold cyan]")
    console.print("[bold cyan]│      [/bold cyan][dim]→ Subfinder + GAU + Katana[/dim][bold cyan]                         │[/bold cyan]")
    console.print("[bold cyan]│  [/bold cyan][bold red][3][/bold red] Deep Scan (ALL TOOLS)[bold cyan]                              │[/bold cyan]")
    console.print("[bold cyan]│      [/bold cyan][dim]→ All 9 tools, no timeout, full recon[/dim][bold cyan]              │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────────────────────────┘[/bold cyan]\n")
    
    choice = IntPrompt.ask("[bold white]Select mode[/bold white]", choices=["1", "2", "3"], default=1)
    
    modes = {1: "main", 2: "subdomains", 3: "deep"}
    mode_names = {1: "Main Domain Only", 2: "Subdomains", 3: "Deep Scan (All Tools)"}
    
    console.print(f"\n[green]✓ Mode: {mode_names[choice]}[/green]")
    return modes[choice]


def get_validate_keys():
    console.print("\n[bold cyan]┌─────────────────────────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│               🔑  KEY VALIDATION                            │[/bold cyan]")
    console.print("[bold cyan]│  Auto-validate secrets using 75+ API checks                │[/bold cyan]")
    console.print("[bold cyan]│  [/bold cyan][yellow]⚠️  For authorized testing only![/yellow][bold cyan]                         │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────────────────────────┘[/bold cyan]\n")
    
    validate = Confirm.ask("[bold white]Validate discovered keys?[/bold white]", default=True)
    
    if validate:
        console.print("\n[green]✓ Key validation enabled[/green]")
    else:
        console.print("\n[yellow]○ Key validation disabled[/yellow]")
    
    return validate


def get_report_config():
    console.print("\n[bold cyan]┌─────────────────────────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│               📄  REPORT CONFIGURATION                      │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────────────────────────┘[/bold cyan]\n")
    
    generate = Confirm.ask("[bold white]Generate HTML report?[/bold white]", default=True)
    
    if not generate:
        return None
    
    console.print("\n[bold cyan]Report Format:[/bold cyan]")
    console.print("  [green][1][/green] HackerOne")
    console.print("  [yellow][2][/yellow] BugCrowd")
    console.print("  [blue][3][/blue] Email\n")
    
    format_choice = IntPrompt.ask("[bold white]Select format[/bold white]", choices=["1", "2", "3"], default=1)
    formats = {1: "hackerone", 2: "bugcrowd", 3: "email"}
    
    reporter_name = Prompt.ask("[bold white]Your name[/bold white]", default="Hunter")
    program_name = Prompt.ask("[bold white]Program name (optional)[/bold white]", default="")
    
    console.print(f"\n[green]✓ Report: {formats[format_choice].upper()}[/green]")
    
    return {"generate": True, "format": formats[format_choice], "reporter": reporter_name, "program": program_name}


def run_scan(target, mode, validate_keys, report_config):
    console.print("\n[bold cyan]┌─────────────────────────────────────────────────────────────┐[/bold cyan]")
    console.print("[bold cyan]│               🚀  STARTING SCAN                             │[/bold cyan]")
    console.print("[bold cyan]└─────────────────────────────────────────────────────────────┘[/bold cyan]\n")
    
    cmd = [sys.executable, "main.py", "-t", target, "--mode", mode, "--no-prompt"]
    
    if validate_keys:
        cmd.append("--validate-keys")
    
    if report_config:
        output_file = f"report_{target.replace('.', '_')}_{int(time.time())}.html"
        cmd.extend(["-o", output_file, "--template", report_config["format"], "--reporter", report_config["reporter"]])
        if report_config.get("program"):
            cmd.extend(["--program", report_config["program"]])
    
    console.print(f"[dim]Command: {' '.join(cmd)}[/dim]\n")
    
    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        
        if result.returncode == 0:
            console.print("\n[bold green]✓ Scan completed successfully![/bold green]")
            if report_config:
                console.print(f"[green]📄 Report saved: {output_file}[/green]")
        else:
            console.print("\n[yellow]⚠️  Scan completed with warnings[/yellow]")
            
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]✗ Error: {e}[/red]")


def main():
    try:
        print_banner()
        
        if not check_dependencies():
            return
        
        target = get_target()
        mode = get_scan_mode()
        validate_keys = get_validate_keys()
        report_config = get_report_config()
        
        console.print("\n[bold cyan]┌─────────────────────────────────────────────────────────────┐[/bold cyan]")
        console.print("[bold cyan]│               ✅  SCAN SUMMARY                              │[/bold cyan]")
        console.print("[bold cyan]├─────────────────────────────────────────────────────────────┤[/bold cyan]")
        console.print(f"[bold cyan]│  Target: [/bold cyan][white]{target:<48}[/white][bold cyan]│[/bold cyan]")
        console.print(f"[bold cyan]│  Mode: [/bold cyan][white]{mode:<50}[/white][bold cyan]│[/bold cyan]")
        console.print(f"[bold cyan]│  Validate Keys: [/bold cyan][white]{'Yes' if validate_keys else 'No':<41}[/white][bold cyan]│[/bold cyan]")
        console.print(f"[bold cyan]│  Report: [/bold cyan][white]{report_config['format'].upper() if report_config else 'No':<48}[/white][bold cyan]│[/bold cyan]")
        console.print("[bold cyan]└─────────────────────────────────────────────────────────────┘[/bold cyan]\n")
        
        if not Confirm.ask("[bold white]Start scan?[/bold white]", default=True):
            console.print("[yellow]Scan cancelled.[/yellow]")
            return
        
        run_scan(target, mode, validate_keys, report_config)
        
        console.print("\n[bold green]🦇 NightCrawler v5.0 scan complete![/bold green]\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")


if __name__ == "__main__":
    main()
