"""
NightCrawler v5.0 - External Tool Integrations
All recon tools with auto-detect paths and no timeouts
"""

import subprocess
import shutil
import os
from pathlib import Path
from typing import List, Optional, Dict
from rich.console import Console

console = Console()

# Tool configuration
TOOL_CONFIG = {
    "subfinder": {
        "name": "Subfinder",
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    },
    "httpx": {
        "name": "Httpx", 
        "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    },
    "katana": {
        "name": "Katana",
        "install": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    },
    "gau": {
        "name": "GAU",
        "install": "go install -v github.com/lc/gau/v2/cmd/gau@latest"
    },
    "waybackurls": {
        "name": "Waybackurls",
        "install": "go install -v github.com/tomnomnom/waybackurls@latest"
    },
    "subjs": {
        "name": "SubJS",
        "install": "go install -v github.com/lc/subjs@latest"
    },
    "jsluice": {
        "name": "JSLuice",
        "install": "go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest"
    },
    "hakrawler": {
        "name": "Hakrawler",
        "install": "go install -v github.com/hakluke/hakrawler@latest"
    },
    "getjs": {
        "name": "GetJS",
        "install": "go install -v github.com/003random/getJS@latest"
    }
}


def find_tool(tool_name: str) -> Optional[str]:
    """Find tool in PATH or common locations"""
    path = shutil.which(tool_name)
    if path:
        return path
    
    go_bin = os.path.expanduser(f"~/go/bin/{tool_name}")
    if os.path.exists(go_bin):
        return go_bin
    
    local_bin = f"/usr/local/bin/{tool_name}"
    if os.path.exists(local_bin):
        return local_bin
    
    usr_bin = f"/usr/bin/{tool_name}"
    if os.path.exists(usr_bin):
        return usr_bin
    
    return None


def install_tool(tool_name: str) -> bool:
    """Install a tool using go install"""
    config = TOOL_CONFIG.get(tool_name)
    if not config:
        return False
    
    console.print(f"[cyan][*] Installing {config['name']}...[/]")
    try:
        result = subprocess.run(config["install"], shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"[green][+] {config['name']} installed![/]")
            return True
        else:
            console.print(f"[red][!] Failed to install {config['name']}: {result.stderr}[/]")
            return False
    except Exception as e:
        console.print(f"[red][!] Error installing {config['name']}: {e}[/]")
        return False


def get_all_tool_paths() -> Dict[str, Optional[str]]:
    """Get paths for all configured tools"""
    paths = {}
    for tool_name in TOOL_CONFIG:
        paths[tool_name] = find_tool(tool_name)
    return paths


class SubfinderIntegration:
    """Wrapper for Subfinder subdomain enumeration"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or find_tool('subfinder')
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def enumerate(self, domain: str, recursive: bool = True, silent: bool = True) -> List[str]:
        """Run Subfinder - NO TIMEOUT for full enumeration"""
        if not self.is_available():
            console.print("[yellow][!] Subfinder not found. Skipping subdomain enumeration.[/]")
            return [domain]
        
        cmd = [self.tool_path, '-d', domain]
        if recursive:
            cmd.extend(['-all', '-recursive'])
        if silent:
            cmd.append('-silent')
        
        try:
            console.print(f"[cyan][*] Running Subfinder on {domain}...[/]")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                console.print(f"[green][+] Found {len(subdomains)} subdomains[/]")
                return subdomains if subdomains else [domain]
            else:
                console.print(f"[yellow][!] Subfinder returned no results[/]")
                return [domain]
                
        except Exception as e:
            console.print(f"[red][!] Error running Subfinder: {e}[/]")
            return [domain]


class KatanaIntegration:
    """Wrapper for Katana web crawler"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or find_tool('katana')
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def crawl(self, targets: List[str], depth: int = 3, js_only: bool = True) -> List[str]:
        """Crawl targets - NO TIMEOUT for full deep crawl"""
        if not self.is_available():
            console.print("[yellow][!] Katana not found. Skipping deep crawl.[/]")
            return []
        
        cmd = [self.tool_path, '-d', str(depth), '-c', '50', '-silent']
        if js_only:
            cmd.append('-jc')
        
        try:
            console.print(f"[cyan][*] Running Katana crawler (depth={depth})...[/]")
            result = subprocess.run(cmd, input='\n'.join(targets), capture_output=True, text=True)
            
            if result.returncode == 0:
                urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                console.print(f"[green][+] Katana found {len(urls)} URLs[/]")
                return urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running Katana: {e}[/]")
            return []


class GauIntegration:
    """Wrapper for GAU (GetAllURLs)"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or find_tool('gau')
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def fetch(self, domains: List[str], threads: int = 5) -> List[str]:
        """Fetch archived URLs - NO TIMEOUT"""
        if not self.is_available():
            console.print("[yellow][!] GAU not found. Skipping archive search.[/]")
            return []
        
        cmd = [self.tool_path, '--threads', str(threads)]
        
        try:
            console.print(f"[cyan][*] Fetching archived URLs with GAU...[/]")
            result = subprocess.run(cmd, input='\n'.join(domains), capture_output=True, text=True)
            
            if result.returncode == 0:
                urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                js_urls = [u for u in urls if '.js' in u.lower()]
                console.print(f"[green][+] GAU found {len(js_urls)} JS URLs from archives[/]")
                return js_urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running GAU: {e}[/]")
            return []


class WaybackurlsIntegration:
    """Wrapper for Waybackurls"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or find_tool('waybackurls')
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def fetch(self, domains: List[str]) -> List[str]:
        """Fetch Wayback Machine URLs - NO TIMEOUT"""
        if not self.is_available():
            console.print("[yellow][!] Waybackurls not found. Skipping.[/]")
            return []
        
        try:
            console.print(f"[cyan][*] Fetching Wayback URLs...[/]")
            result = subprocess.run([self.tool_path], input='\n'.join(domains), capture_output=True, text=True)
            
            if result.returncode == 0:
                urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                js_urls = [u for u in urls if '.js' in u.lower()]
                console.print(f"[green][+] Waybackurls found {len(js_urls)} JS URLs[/]")
                return js_urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running Waybackurls: {e}[/]")
            return []


class SubJSIntegration:
    """Wrapper for SubJS - fetches JS from subdomains"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or find_tool('subjs')
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def fetch(self, urls: List[str]) -> List[str]:
        """Fetch JS files from URLs - NO TIMEOUT"""
        if not self.is_available():
            console.print("[yellow][!] SubJS not found. Skipping.[/]")
            return []
        
        try:
            console.print(f"[cyan][*] Fetching JS with SubJS...[/]")
            result = subprocess.run([self.tool_path], input='\n'.join(urls), capture_output=True, text=True)
            
            if result.returncode == 0:
                js_urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                console.print(f"[green][+] SubJS found {len(js_urls)} JS files[/]")
                return js_urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running SubJS: {e}[/]")
            return []


class HakrawlerIntegration:
    """Wrapper for Hakrawler web crawler"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or find_tool('hakrawler')
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def crawl(self, urls: List[str], depth: int = 2) -> List[str]:
        """Crawl URLs - NO TIMEOUT"""
        if not self.is_available():
            console.print("[yellow][!] Hakrawler not found. Skipping.[/]")
            return []
        
        cmd = [self.tool_path, '-d', str(depth), '-t', '20']
        
        try:
            console.print(f"[cyan][*] Running Hakrawler...[/]")
            result = subprocess.run(cmd, input='\n'.join(urls), capture_output=True, text=True)
            
            if result.returncode == 0:
                all_urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                js_urls = [u for u in all_urls if '.js' in u.lower()]
                console.print(f"[green][+] Hakrawler found {len(js_urls)} JS URLs[/]")
                return js_urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running Hakrawler: {e}[/]")
            return []


class GetJSIntegration:
    """Wrapper for GetJS - extracts JS from pages"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or find_tool('getJS') or find_tool('getjs')
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def extract(self, urls: List[str]) -> List[str]:
        """Extract JS from URLs - NO TIMEOUT"""
        if not self.is_available():
            console.print("[yellow][!] GetJS not found. Skipping.[/]")
            return []
        
        cmd = [self.tool_path, '--complete']
        
        try:
            console.print(f"[cyan][*] Extracting JS with GetJS...[/]")
            result = subprocess.run(cmd, input='\n'.join(urls), capture_output=True, text=True)
            
            if result.returncode == 0:
                js_urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                console.print(f"[green][+] GetJS found {len(js_urls)} JS files[/]")
                return js_urls
            return []
                
        except Exception as e:
            console.print(f"[red][!] Error running GetJS: {e}[/]")
            return []


class JSLuiceIntegration:
    """Wrapper for JSLuice - extracts secrets from JS"""
    
    def __init__(self, tool_path: Optional[str] = None):
        self.tool_path = tool_path or find_tool('jsluice')
    
    def is_available(self) -> bool:
        return self.tool_path is not None and Path(self.tool_path).exists()
    
    def extract_urls(self, js_content: str) -> List[str]:
        """Extract URLs from JS content"""
        if not self.is_available():
            return []
        
        cmd = [self.tool_path, 'urls']
        
        try:
            result = subprocess.run(cmd, input=js_content, capture_output=True, text=True)
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
            return []
        except:
            return []
    
    def extract_secrets(self, js_content: str) -> List[dict]:
        """Extract secrets from JS content"""
        if not self.is_available():
            return []
        
        cmd = [self.tool_path, 'secrets']
        
        try:
            result = subprocess.run(cmd, input=js_content, capture_output=True, text=True)
            if result.returncode == 0:
                import json
                secrets = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            secrets.append(json.loads(line))
                        except:
                            pass
                return secrets
            return []
        except:
            return []
