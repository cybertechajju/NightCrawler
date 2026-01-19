#!/usr/bin/env python3
"""
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

NightCrawler v3.1 - Advanced JS Secret Scanner with KeyHacks Auto-Validation
by CyberTechAjju | Keep Learning // Keep Hacking

⚠️ ETHICAL USE ONLY - For authorized security testing and bug bounty programs
"""

import asyncio
import click
from pathlib import Path

from src.ui.banner import print_banner
from src.core.scanner import NightCrawlerScanner
from src.output.console import ConsoleOutput
from src.output.html_report import HtmlReportGenerator, ReportConfig
from src.validators.keyhacks import KeyHacksValidator, ValidationStatus


def show_scan_mode_menu():
    """Display scan mode selection menu"""
    click.echo()
    click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg="cyan"))
    click.echo(click.style("│               🎯  SELECT SCAN MODE                          │", fg="cyan"))
    click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[1]", fg="green", bold=True) + click.style(" Main Domain Only", fg="white") + click.style("                                  │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Scan only the target domain (faster)", dim=True) + click.style("            │", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[2]", fg="yellow", bold=True) + click.style(" Include Subdomains", fg="white") + click.style("                                │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Enumerate subdomains using Subfinder", dim=True) + click.style("          │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Scan all discovered subdomains", dim=True) + click.style("                │", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("│  ", fg="cyan") + click.style("[3]", fg="red", bold=True) + click.style(" Deep Scan (Subdomains + Archives)", fg="white") + click.style("               │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Subdomains + Wayback/GAU archives", dim=True) + click.style("             │", fg="cyan"))
    click.echo(click.style("│      ", fg="cyan") + click.style("→ Most comprehensive (slowest)", dim=True) + click.style("                  │", fg="cyan"))
    click.echo(click.style("│                                                             │", fg="cyan"))
    click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg="cyan"))
    click.echo()


@click.command()
@click.option('-t', '--target', help='Single target domain (e.g., example.com)')
@click.option('-l', '--list', 'target_list', type=click.Path(exists=True), help='File containing list of targets')
@click.option('-u', '--urls', type=click.Path(exists=True), help='File containing JS URLs to scan directly')
@click.option('-o', '--output', type=click.Path(), help='Output file (supports .json, .html)')
@click.option('-c', '--concurrency', default=50, help='Number of concurrent requests (default: 50)')
@click.option('-d', '--depth', default=2, help='Crawl depth for JS extraction (default: 2)')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.option('--offline', type=click.Path(exists=True), help='Scan local JS files in directory')
@click.option('--patterns', type=click.Path(exists=True), help='Custom patterns file (YAML)')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
@click.option('-q', '--quiet', is_flag=True, help='Only output findings')
# Scan Mode Options
@click.option('--mode', type=click.Choice(['main', 'subdomains', 'deep']), help='Scan mode: main, subdomains, or deep')
@click.option('--no-prompt', is_flag=True, help='Skip interactive prompts (use --mode to set scan mode)')
# KeyHacks Validation
@click.option('--validate-keys', is_flag=True, help='🔑 Auto-validate discovered secrets using KeyHacks (ethical use only)')
@click.option('--validate-timeout', default=10, help='Timeout for KeyHacks validation requests (default: 10)')
# Report Options
@click.option('--template', type=click.Choice(['hackerone', 'bugcrowd', 'email']), default='hackerone',
              help='Report template format (default: hackerone)')
@click.option('--reporter', default='CyberTechAjju', help='Reporter name for the report')
@click.option('--reporter-email', default='', help='Reporter email address')
@click.option('--program', default='', help='Bug bounty program name')
@click.version_option(version='3.1.0', prog_name='NightCrawler')
def main(target, target_list, urls, output, concurrency, depth, timeout, 
         offline, patterns, verbose, quiet, mode, no_prompt, validate_keys, validate_timeout,
         template, reporter, reporter_email, program):
    """
    NightCrawler v3.1 - Advanced JS Secret Scanner with KeyHacks Auto-Validation
    
    Hunt for secrets, API keys, and hidden endpoints in JavaScript files.
    Auto-validate discovered secrets using 75+ KeyHacks validators.
    Generate HackerOne, BugCrowd, or Email format reports.
    
    Built for bug bounty hunters by CyberTechAjju.
    
    \b
    ⚠️  ETHICAL USE ONLY - For authorized security testing and bug bounty programs
    
    \b
    Examples:
      # Interactive scan with mode selection
      nightcrawler -t example.com -o report.html
    
      # Direct subdomain scan
      nightcrawler -t example.com -o report.html --mode subdomains
    
      # Deep scan with validation
      nightcrawler -t example.com -o report.html --mode deep --validate-keys
    
      # Quick main domain scan (no prompts)
      nightcrawler -t example.com -o report.html --mode main --no-prompt
    
      # Full automated scan
      nightcrawler -t target.com -o findings.html --mode deep --validate-keys --template bugcrowd
    """
    
    if not quiet:
        print_banner()
    
    # Validate input
    if not any([target, target_list, urls, offline]):
        click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='red'))
        click.echo(click.style("│  ❌ Error: No target specified                              │", fg='red'))
        click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='red'))
        click.echo(click.style("\n[*] Examples:", fg='cyan'))
        click.echo("    nightcrawler -t example.com -o report.html")
        click.echo("    nightcrawler -t target.com -o report.html --mode subdomains")
        click.echo("    nightcrawler --offline ./downloaded_js/ -o report.html")
        return
    
    # Scan mode selection for single target
    use_subdomains = False
    use_archives = False
    
    if target and not no_prompt and not mode:
        # Interactive mode selection
        show_scan_mode_menu()
        
        choice = click.prompt(
            click.style('[?] Select scan mode', fg='cyan'),
            type=click.Choice(['1', '2', '3']),
            default='1'
        )
        
        if choice == '1':
            mode = 'main'
            click.echo(click.style("\n  ✓ Main Domain Only mode selected", fg='green'))
        elif choice == '2':
            mode = 'subdomains'
            use_subdomains = True
            click.echo(click.style("\n  ✓ Subdomains mode selected", fg='yellow'))
        else:
            mode = 'deep'
            use_subdomains = True
            use_archives = True
            click.echo(click.style("\n  ✓ Deep Scan mode selected", fg='red'))
    elif mode:
        if mode == 'subdomains':
            use_subdomains = True
        elif mode == 'deep':
            use_subdomains = True
            use_archives = True
    
    # Show ethical use warning for key validation
    if validate_keys and not quiet:
        keyhacks_validator = KeyHacksValidator(timeout=validate_timeout)
        keyhacks_validator.print_disclaimer()
        
        # Confirm user wants to proceed
        if not click.confirm(click.style('[?] Do you confirm you have authorization to validate these secrets?', fg='yellow'), default=True):
            click.echo(click.style("[!] Validation cancelled. Running scan without key validation.", fg='yellow'))
            validate_keys = False
    
    # Interactive mode for missing report details if output is HTML
    if output and output.endswith('.html') and not no_prompt:
        click.echo()
        if not reporter:
            reporter = click.prompt(click.style('[?] Enter your name for the report', fg='cyan'), default='CyberTechAjju')
        if not program:
            program = click.prompt(click.style('[?] Enter bug bounty program name (optional)', fg='cyan'), default='', show_default=False)
    
    # Initialize scanner
    scanner = NightCrawlerScanner(
        concurrency=concurrency,
        timeout=timeout,
        depth=depth,
        use_external_tools=use_subdomains or use_archives,
        custom_patterns=patterns,
        verbose=verbose
    )
    
    # Show scan config
    if not quiet:
        click.echo()
        click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='green'))
        click.echo(click.style("│               🦇  SCAN CONFIGURATION                        │", fg='green'))
        click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg='green'))
        click.echo(click.style(f"│  Target: {target or target_list or urls or offline:<50}│", fg='green'))
        click.echo(click.style(f"│  Mode: {(mode or 'main').upper():<52}│", fg='green'))
        click.echo(click.style(f"│  Subdomains: {'Yes' if use_subdomains else 'No':<48}│", fg='green'))
        click.echo(click.style(f"│  Archives: {'Yes' if use_archives else 'No':<50}│", fg='green'))
        click.echo(click.style(f"│  Validate Keys: {'Yes' if validate_keys else 'No':<45}│", fg='green'))
        click.echo(click.style(f"│  Report Template: {(template or 'hackerone').upper():<43}│", fg='green'))
        click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='green'))
        click.echo()
    
    # Run the scanner
    try:
        if offline:
            # Offline mode - scan local files
            asyncio.run(scanner.scan_directory(Path(offline)))
        elif urls:
            # Direct URL scanning
            asyncio.run(scanner.scan_urls_from_file(Path(urls)))
        elif target_list:
            # Multi-target mode
            asyncio.run(scanner.scan_targets_from_file(Path(target_list)))
        else:
            # Single target mode
            asyncio.run(scanner.scan_target(target))
        
        # KeyHacks validation phase
        if validate_keys and scanner.results.findings:
            click.echo()
            click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='yellow'))
            click.echo(click.style("│               🔑  KEYHACKS VALIDATION                       │", fg='yellow'))
            click.echo(click.style("│       ⚠️  This is for AUTHORIZED testing only!              │", fg='yellow'))
            click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='yellow'))
            
            keyhacks_validator = KeyHacksValidator(timeout=validate_timeout)
            
            with click.progressbar(
                scanner.results.findings,
                label=click.style('  🔑 Validating secrets', fg='cyan'),
                show_eta=True,
                show_pos=True
            ) as findings:
                for finding in findings:
                    if finding.validated:  # Only validate pattern-matched findings
                        result = asyncio.run(keyhacks_validator.validate_secret(
                            finding.pattern_name,
                            finding.matched_value
                        ))
                        
                        # Update finding with validation result
                        finding.keyhacks_status = result.status.value
                        finding.keyhacks_message = result.message
                        finding.keyhacks_command = result.validation_command or ""
                        
                        if result.status == ValidationStatus.VALID:
                            scanner.results.keyhacks_valid += 1
                        elif result.status == ValidationStatus.INVALID:
                            scanner.results.keyhacks_invalid += 1
            
            # Print validation summary
            click.echo()
            click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='green'))
            click.echo(click.style("│               ✓  VALIDATION COMPLETE                        │", fg='green'))
            click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg='green'))
            click.echo(click.style(f"│  ✅ VALID: {scanner.results.keyhacks_valid:<50}│", fg='green'))
            click.echo(click.style(f"│  ❌ INVALID: {scanner.results.keyhacks_invalid:<48}│", fg='green'))
            unknown_count = len([f for f in scanner.results.findings if f.keyhacks_status == 'UNKNOWN'])
            click.echo(click.style(f"│  ❓ UNKNOWN: {unknown_count:<48}│", fg='green'))
            click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='green'))
            
            # Print manual verification note
            click.echo(keyhacks_validator.get_manual_verification_note())
        
        # Output results
        if output:
            output_path = Path(output)
            
            if output_path.suffix.lower() == '.html':
                # Generate HTML report with selected template
                click.echo()
                click.echo(click.style(f"[*] Generating {template.upper()} format report...", fg='cyan'))
                
                config = ReportConfig(
                    reporter_name=reporter or 'CyberTechAjju',
                    reporter_email=reporter_email,
                    program_name=program,
                    template=template
                )
                
                report_gen = HtmlReportGenerator(config)
                report_gen.generate(
                    findings=[f for f in scanner.results.findings if f.validated],
                    scan_result=scanner.results,
                    output_path=str(output_path)
                )
                
                click.echo()
                click.echo(click.style("┌─────────────────────────────────────────────────────────────┐", fg='green'))
                click.echo(click.style("│               📄  REPORT GENERATED                          │", fg='green'))
                click.echo(click.style("├─────────────────────────────────────────────────────────────┤", fg='green'))
                click.echo(click.style(f"│  File: {str(output_path):<53}│", fg='green'))
                click.echo(click.style(f"│  Template: {template.upper():<50}│", fg='green'))
                click.echo(click.style(f"│  Findings: {len([f for f in scanner.results.findings if f.validated]):<50}│", fg='green'))
                if validate_keys:
                    click.echo(click.style(f"│  ✅ KeyHacks Valid: {scanner.results.keyhacks_valid:<41}│", fg='green'))
                click.echo(click.style("└─────────────────────────────────────────────────────────────┘", fg='green'))
                
            else:
                # Use default JSON/CSV export
                scanner.export_results(output)
        
        # Print summary
        if not quiet:
            scanner.print_summary()
            
    except KeyboardInterrupt:
        click.echo(click.style("\n[!] Scan interrupted by user", fg='yellow'))
    except Exception as e:
        click.echo(click.style(f"[!] Error: {e}", fg='red'))
        if verbose:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
