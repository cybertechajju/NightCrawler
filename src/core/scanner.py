"""
NightCrawler v3.0 - Enhanced Core Scanner with KeyHacks Validation
Async, concurrent JS file scanner with Rich Live UI and Auto-Validation
"""

import asyncio
import aiohttp
import re
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import time
import hashlib

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from jsbeautifier import beautify

from src.patterns.secrets import ALL_PATTERNS, SecretPattern, PatternValidator, TOTAL_PATTERNS
from src.integrations.tools import (
    SubfinderIntegration, KatanaIntegration, GauIntegration,
    WaybackurlsIntegration, SubJSIntegration, HakrawlerIntegration,
    GetJSIntegration, JSLuiceIntegration, find_tool, get_all_tool_paths
)

console = Console()


@dataclass
class Finding:
    """Represents a secret finding with validation status"""
    url: str
    pattern_name: str
    category: str
    matched_value: str
    confidence: int
    validated: bool = True
    line_number: Optional[int] = None
    context: Optional[str] = None
    # KeyHacks validation fields
    keyhacks_status: str = "NOT_CHECKED"  # VALID, INVALID, UNKNOWN, ERROR, NOT_CHECKED
    keyhacks_message: str = ""
    keyhacks_command: str = ""
    
    def severity(self) -> str:
        """Get severity based on confidence"""
        if self.confidence >= 90:
            return "CRITICAL"
        elif self.confidence >= 75:
            return "HIGH"
        elif self.confidence >= 60:
            return "MEDIUM"
        else:
            return "LOW"
    
    def is_keyhacks_valid(self) -> bool:
        """Check if KeyHacks validation confirmed the secret is valid"""
        return self.keyhacks_status == "VALID"


@dataclass
class ScanResult:
    """Aggregated scan results"""
    target: str
    total_urls_scanned: int = 0
    total_js_files: int = 0
    total_findings: int = 0
    total_validated: int = 0
    keyhacks_valid: int = 0  # Count of secrets confirmed VALID by KeyHacks
    keyhacks_invalid: int = 0  # Count of secrets confirmed INVALID
    subdomains_found: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_time: float = 0.0


class NightCrawlerScanner:
    """Main scanner class for NightCrawler v3.0 with KeyHacks validation"""
    
    def __init__(
        self,
        concurrency: int = 50,
        timeout: int = 30,
        depth: int = 2,
        use_external_tools: bool = True,
        custom_patterns: Optional[str] = None,
        verbose: bool = False,
        validate: bool = True
    ):
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.depth = depth
        self.use_external_tools = use_external_tools
        self.verbose = verbose
        self.validate = validate
        
        # Pattern validator
        self.validator = PatternValidator()
        
        # Compile patterns
        self.patterns: List[Tuple[SecretPattern, re.Pattern]] = []
        for p in ALL_PATTERNS:
            try:
                self.patterns.append((p, p.compile()))
            except re.error as e:
                if self.verbose:
                    console.print(f"[dim][!] Skipping invalid pattern '{p.name}': {e}[/dim]")
        
        # External tools - all available integrations
        self.subfinder = SubfinderIntegration()
        self.katana = KatanaIntegration()
        self.gau = GauIntegration()
        self.waybackurls = WaybackurlsIntegration()
        self.subjs = SubJSIntegration()
        self.hakrawler = HakrawlerIntegration()
        self.getjs = GetJSIntegration()
        self.jsluice = JSLuiceIntegration()
        
        # Results
        self.results = ScanResult(target="")
        self.scanned_urls: Set[str] = set()
        
        # User agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        ]
        self._ua_index = 0
    
    def _get_user_agent(self) -> str:
        """Rotate through user agents"""
        ua = self.user_agents[self._ua_index % len(self.user_agents)]
        self._ua_index += 1
        return ua
    
    def _generate_stats_panel(self) -> Panel:
        """Generate live stats panel"""
        stats = Table.grid(padding=1)
        stats.add_column(style="cyan", justify="right")
        stats.add_column(style="white")
        
        stats.add_row("Target:", self.results.target)
        stats.add_row("Subdomains:", str(self.results.subdomains_found))
        stats.add_row("URLs Scanned:", str(self.results.total_urls_scanned))
        stats.add_row("JS Files:", str(self.results.total_js_files))
        stats.add_row("Findings:", f"[bold red]{self.results.total_findings}[/]" if self.results.total_findings else "0")
        stats.add_row("Validated:", f"[bold green]{self.results.total_validated}[/]")
        
        return Panel(stats, title="[bold cyan]📊 Live Stats[/]", border_style="cyan")
    
    async def _fetch_url(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetch a URL and return its content"""
        if url in self.scanned_urls:
            return None
        
        self.scanned_urls.add(url)
        
        try:
            headers = {"User-Agent": self._get_user_agent()}
            async with session.get(url, headers=headers, ssl=False, allow_redirects=True) as response:
                if response.status == 200:
                    content_type = response.headers.get('content-type', '')
                    # Only process text content
                    if 'text' in content_type or 'javascript' in content_type or 'json' in content_type:
                        return await response.text()
                return None
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            if self.verbose:
                console.print(f"[dim][!] Error: {url}: {str(e)[:50]}[/dim]")
            return None
    
    def _extract_js_urls(self, base_url: str, html_content: str) -> List[str]:
        """Extract JavaScript URLs from HTML content"""
        js_urls = []
        
        # Multiple patterns for comprehensive extraction
        patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if '.js' not in match.lower():
                    continue
                    
                # Skip common libraries (configurable in future)
                skip_libs = ['jquery', 'react', 'angular', 'vue', 'bootstrap', 'lodash']
                if any(lib in match.lower() for lib in skip_libs):
                    continue
                
                # Resolve URL
                if match.startswith('http'):
                    js_urls.append(match)
                elif match.startswith('//'):
                    js_urls.append('https:' + match)
                elif match.startswith('/'):
                    parsed = urlparse(base_url)
                    js_urls.append(f"{parsed.scheme}://{parsed.netloc}{match}")
                else:
                    js_urls.append(urljoin(base_url, match))
        
        # Deduplicate
        seen = set()
        unique = []
        for url in js_urls:
            base = url.split('?')[0]
            if base not in seen:
                seen.add(base)
                unique.append(url)
        
        return unique
    
    def _scan_content(self, url: str, content: str) -> List[Finding]:
        """Scan content for secrets with validation"""
        findings = []
        
        # Beautify JS for better matching
        try:
            content = beautify(content)
        except:
            pass
        
        # Split into lines for context
        lines = content.split('\n')
        
        for pattern, compiled in self.patterns:
            try:
                matches = compiled.findall(content)
            except:
                continue
            
            for match in matches:
                # Handle tuple matches
                if isinstance(match, tuple):
                    match = next((m for m in match if m), '')
                
                if not match or len(match) < 8:
                    continue
                
                # Validate match
                is_valid = True
                if self.validate:
                    is_valid = self.validator.validate(pattern, str(match))
                
                if not is_valid:
                    continue
                
                # Find line number
                line_num = None
                context = None
                for i, line in enumerate(lines):
                    if str(match) in line:
                        line_num = i + 1
                        context = line.strip()[:150]
                        break
                
                finding = Finding(
                    url=url,
                    pattern_name=pattern.name,
                    category=pattern.category,
                    matched_value=str(match)[:100],
                    confidence=pattern.confidence,
                    validated=is_valid,
                    line_number=line_num,
                    context=context
                )
                findings.append(finding)
        
        return findings
    
    async def _scan_js_url(self, session: aiohttp.ClientSession, url: str) -> List[Finding]:
        """Scan a single JS URL"""
        content = await self._fetch_url(session, url)
        if content:
            self.results.total_js_files += 1
            return self._scan_content(url, content)
        return []
    
    async def scan_target(self, target: str):
        """Scan a single target domain with subdomain enumeration"""
        start_time = time.time()
        self.results.target = target
        
        # Ensure target has protocol
        if not target.startswith('http'):
            base_target = f"https://{target}"
        else:
            base_target = target
            target = urlparse(target).netloc
        
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print(f"[bold green]🦇 NightCrawler v2.0 - Starting Scan[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
        console.print(f"[bold]Target:[/] [yellow]{target}[/]")
        console.print(f"[bold]Patterns:[/] [cyan]{len(self.patterns)}[/] active")
        console.print(f"[bold]Concurrency:[/] [cyan]{self.concurrency}[/]")
        console.print(f"[bold]Validation:[/] [{'green' if self.validate else 'red'}]{'Enabled' if self.validate else 'Disabled'}[/]")
        console.print()
        
        all_js_urls = set()
        
        # Phase 1: Subdomain Enumeration
        if self.use_external_tools and self.subfinder.is_available():
            subdomains = self.subfinder.enumerate(target)
            self.results.subdomains_found = len(subdomains)
        else:
            subdomains = [target]
            self.results.subdomains_found = 1
        
        # Phase 2: URL Gathering with ALL external tools
        if self.use_external_tools:
            live_urls = [f"https://{s}" for s in subdomains]
            
            # GAU (archived URLs)
            if self.gau.is_available():
                archived_js = self.gau.fetch(subdomains)
                all_js_urls.update(archived_js)
            
            # Waybackurls (Wayback Machine)
            if self.waybackurls.is_available():
                wayback_js = self.waybackurls.fetch(subdomains)
                all_js_urls.update(wayback_js)
            
            # Katana (live crawling)
            if self.katana.is_available():
                crawled = self.katana.crawl(live_urls, depth=self.depth)
                js_from_crawl = [u for u in crawled if '.js' in u.lower()]
                all_js_urls.update(js_from_crawl)
            
            # Hakrawler (additional crawling)
            if self.hakrawler.is_available():
                hakrawler_js = self.hakrawler.crawl(live_urls, depth=self.depth)
                all_js_urls.update(hakrawler_js)
            
            # SubJS (JS from subdomains)
            if self.subjs.is_available():
                subjs_urls = self.subjs.fetch(live_urls)
                all_js_urls.update(subjs_urls)
            
            # GetJS (extract JS from pages)
            if self.getjs.is_available():
                getjs_urls = self.getjs.extract(live_urls[:50])  # Limit to prevent overload
                all_js_urls.update(getjs_urls)
        
        # Phase 3: Direct page scanning for JS
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
            # Scan main pages for JS links
            console.print(f"\n[cyan][*] Fetching pages from {len(subdomains)} subdomains...[/]")
            
            async def fetch_page_js(subdomain):
                url = f"https://{subdomain}"
                content = await self._fetch_url(session, url)
                if content:
                    return self._extract_js_urls(url, content)
                return []
            
            tasks = [fetch_page_js(s) for s in subdomains[:100]]  # Limit to 100 subdomains
            results = await asyncio.gather(*tasks)
            
            for js_list in results:
                all_js_urls.update(js_list)
            
            # Deduplicate and clean
            all_js_urls = list(all_js_urls)
            console.print(f"[green][+] Total unique JS files to scan: {len(all_js_urls)}[/]\n")
            
            # Phase 4: Scan all JS files
            if all_js_urls:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    TaskProgressColumn(),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("[cyan]🔍 Scanning JS files...", total=len(all_js_urls))
                    
                    semaphore = asyncio.Semaphore(self.concurrency)
                    
                    async def scan_with_progress(url):
                        async with semaphore:
                            findings = await self._scan_js_url(session, url)
                            self.results.findings.extend(findings)
                            self.results.total_findings = len(self.results.findings)
                            self.results.total_validated = len([f for f in self.results.findings if f.validated])
                            progress.advance(task)
                            return findings
                    
                    await asyncio.gather(*[scan_with_progress(url) for url in all_js_urls])
            
            self.results.total_urls_scanned = len(self.scanned_urls)
        
        self.results.scan_time = time.time() - start_time
    
    async def scan_urls_from_file(self, file_path: Path):
        """Scan JS URLs from a file"""
        start_time = time.time()
        
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and '.js' in line.lower()]
        
        self.results.target = str(file_path)
        
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print(f"[bold green]🦇 NightCrawler v2.0 - URL List Mode[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
        console.print(f"[bold]Source:[/] [yellow]{file_path}[/]")
        console.print(f"[bold]URLs:[/] [cyan]{len(urls)}[/]")
        console.print()
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]🔍 Scanning...", total=len(urls))
                
                semaphore = asyncio.Semaphore(self.concurrency)
                
                async def scan_with_progress(url):
                    async with semaphore:
                        findings = await self._scan_js_url(session, url)
                        self.results.findings.extend(findings)
                        progress.advance(task)
                        return findings
                
                await asyncio.gather(*[scan_with_progress(url) for url in urls])
            
            self.results.total_urls_scanned = len(self.scanned_urls)
            self.results.total_findings = len(self.results.findings)
            self.results.total_validated = len([f for f in self.results.findings if f.validated])
        
        self.results.scan_time = time.time() - start_time
    
    async def scan_targets_from_file(self, file_path: Path):
        """Scan multiple targets from a file"""
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        console.print(f"[bold green][+] Loaded {len(targets)} targets[/]")
        
        for target in targets:
            await self.scan_target(target)
    
    async def scan_directory(self, directory: Path):
        """Scan local JS files in a directory"""
        start_time = time.time()
        self.results.target = str(directory)
        
        js_files = list(directory.glob('**/*.js'))
        
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print(f"[bold green]🦇 NightCrawler v2.0 - Offline Mode[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
        console.print(f"[bold]Directory:[/] [yellow]{directory}[/]")
        console.print(f"[bold]Files:[/] [cyan]{len(js_files)}[/]")
        console.print()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]📁 Scanning local files...", total=len(js_files))
            
            for js_file in js_files:
                try:
                    content = js_file.read_text(errors='ignore')
                    findings = self._scan_content(str(js_file), content)
                    self.results.findings.extend(findings)
                    self.results.total_js_files += 1
                except Exception as e:
                    if self.verbose:
                        console.print(f"[dim][!] Error: {js_file}: {e}[/dim]")
                progress.advance(task)
        
        self.results.total_findings = len(self.results.findings)
        self.results.total_validated = len([f for f in self.results.findings if f.validated])
        self.results.scan_time = time.time() - start_time
    
    def print_summary(self):
        """Print beautiful scan summary"""
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print(f"[bold green]📊 SCAN COMPLETE[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
        
        # Summary table
        table = Table(title="[bold cyan]Scan Summary[/]", border_style="cyan", show_header=True)
        table.add_column("Metric", style="dim", width=25)
        table.add_column("Value", style="green", width=20)
        
        table.add_row("Target", self.results.target[:40])
        table.add_row("Subdomains Found", str(self.results.subdomains_found))
        table.add_row("URLs Scanned", str(self.results.total_urls_scanned))
        table.add_row("JS Files Analyzed", str(self.results.total_js_files))
        table.add_row("Total Matches", str(self.results.total_findings))
        table.add_row("Validated Secrets", f"[bold green]{self.results.total_validated}[/]")
        table.add_row("Scan Time", f"{self.results.scan_time:.2f}s")
        
        console.print(table)
        
        # Findings breakdown
        if self.results.findings:
            console.print(f"\n[bold red]🔥 SECRETS FOUND ({self.results.total_validated} validated):[/]\n")
            
            # Group by severity
            by_severity: Dict[str, List[Finding]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
            for f in self.results.findings:
                if f.validated:
                    by_severity[f.severity()].append(f)
            
            severity_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}
            
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                findings = by_severity[severity]
                if findings:
                    console.print(f"[bold {severity_colors[severity]}]━━━ {severity} ({len(findings)}) ━━━[/]")
                    
                    for f in findings[:5]:  # Limit display per severity
                        console.print(f"  [bold cyan]{f.pattern_name}[/] [{severity_colors[severity]}][{f.confidence}%][/]")
                        console.print(f"    [dim]URL:[/] {f.url[:80]}...")
                        console.print(f"    [dim]Value:[/] [yellow]{f.matched_value[:60]}...[/]")
                        console.print()
                    
                    if len(findings) > 5:
                        console.print(f"  [dim]... and {len(findings) - 5} more[/]\n")
        else:
            console.print("[dim]No secrets found.[/dim]")
        
        console.print(f"\n[bold cyan]{'='*60}[/]")
        console.print("[dim]NightCrawler v2.0 by CyberTechAjju | Keep Learning // Keep Hacking[/]")
        console.print(f"[bold cyan]{'='*60}[/]\n")
    
    def export_results(self, output_path: str):
        """Export results to file"""
        import json
        from datetime import datetime
        
        output_path = Path(output_path)
        
        if output_path.suffix == '.json':
            data = {
                "tool": "NightCrawler",
                "version": "2.0",
                "scan_date": datetime.now().isoformat(),
                "target": self.results.target,
                "scan_time": self.results.scan_time,
                "stats": {
                    "subdomains": self.results.subdomains_found,
                    "urls_scanned": self.results.total_urls_scanned,
                    "js_files": self.results.total_js_files,
                    "total_findings": self.results.total_findings,
                    "validated_findings": self.results.total_validated,
                },
                "findings": [
                    {
                        "url": f.url,
                        "pattern": f.pattern_name,
                        "category": f.category,
                        "value": f.matched_value,
                        "confidence": f.confidence,
                        "severity": f.severity(),
                        "validated": f.validated,
                        "line": f.line_number,
                        "context": f.context
                    }
                    for f in self.results.findings if f.validated
                ]
            }
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
        
        console.print(f"[green][+] Results exported to {output_path}[/]")
