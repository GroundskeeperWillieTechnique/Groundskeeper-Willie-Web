"""
Willie Console - The Main CLI Entry Point
"GREASE ME UP! We're going in!"

Commands:
  scan   - Audit code and report issues
  scrub  - Iteratively fix until 100% clean
  fix    - Apply auto-fixes with Willie comments
"""

import os
import sys
import random
from pathlib import Path
from typing import List, Optional

# Rich for beautiful terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Note: Install 'rich' for prettier output: pip install rich")

# Click for CLI
try:
    import click
except ImportError:
    print("ERROR: Click is required. Install with: pip install click")
    sys.exit(1)

# Add parent to path for relative imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers import get_analyzer, ANALYZER_MAP
from analyzers.base_analyzer import (
    Issue, Severity, AnalysisResult, 
    get_willie_comment, WILLIE_INSULTS
)


# ============================================================================
# WILLIE'S PERSONALITY
# ============================================================================

WILLIE_BANNER = r"""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║   ____                           _ _                                  ║
  ║  / ___|_ __ ___  _   _ _ __   __| | | _____  ___ _ __   ___ _ __     ║
  ║ | |  _| '__/ _ \| | | | '_ \ / _` | |/ / _ \/ _ \ '_ \ / _ \ '__|    ║
  ║ | |_| | | | (_) | |_| | | | | (_| |   <  __/  __/ |_) |  __/ |       ║
  ║  \____|_|  \___/ \__,_|_| |_|\__,_|_|\_\___|\___| .__/ \___|_|       ║
  ║                                                 |_|                   ║
  ║                    WILLIE                                             ║
  ║                                                                       ║
  ║     "GREASE ME UP! We're going in to sort yer code!"                 ║
  ╚═══════════════════════════════════════════════════════════════════════╝
"""

VICTORY_MESSAGES = [
    "ACH! It's CLEAN! Finally, some code that doesn't make me weep!",
    "Well done, laddie! Even I couldn't find any grease!",
    "BONNIE! This code is cleaner than my groundskeeper shed!",
    "Ye've done it! Zero issues! I'm almost... PROUD of ye!",
]

FAILURE_MESSAGES = [
    "GREASE EVERYWHERE! This code is a DISASTER!",
    "ACH! My EYES! The issues... so many issues!",
    "Did Ralph write this?! It looks like paste and crayons!",
    "This code smells like haggis left in the sun for a WEEK!",
]

SCRUB_MESSAGES = [
    "SCRUBBIN' and DUBBIN'! Willie's on the job!",
    "Time to clean up yer mess, ye numpty!",
    "Another round of fixes comin' up!",
]


# ============================================================================
# CONSOLE HELPERS
# ============================================================================

console = Console() if RICH_AVAILABLE else None


def print_banner():
    """Print Willie's glorious banner."""
    if RICH_AVAILABLE:
        console.print(WILLIE_BANNER, style="bold red")
    else:
        print(WILLIE_BANNER)


def print_msg(msg: str, style: str = ""):
    """Print a message with optional styling."""
    if RICH_AVAILABLE:
        console.print(msg, style=style)
    else:
        print(msg)


def get_severity_style(severity: Severity) -> str:
    """Get Rich style for severity level."""
    return {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH: "bold red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }.get(severity, "")


# ============================================================================
# FILE DISCOVERY
# ============================================================================

IGNORE_DIRS = {
    '.git', '__pycache__', 'node_modules', 'venv', '.venv', 
    'env', '.env', 'dist', 'build', '.idea', '.vscode',
    'target', 'bin', 'obj', '.next', 'coverage', '.pytest_cache'
}

IGNORE_FILES = {
    '.DS_Store', 'Thumbs.db', '.gitignore', '.gitattributes',
    'package-lock.json', 'yarn.lock', 'poetry.lock', 'Cargo.lock'
}


def discover_files(path: str, extensions: Optional[List[str]] = None) -> List[str]:
    """Discover files to analyze in a directory."""
    path = Path(path)
    files = []
    
    # Supported extensions if not specified
    if extensions is None:
        extensions = list(ANALYZER_MAP.keys())
    
    if path.is_file():
        if path.suffix.lower() in extensions or not extensions:
            return [str(path)]
        return []
    
    for root, dirs, filenames in os.walk(path):
        # Filter out ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for filename in filenames:
            if filename in IGNORE_FILES:
                continue
            
            file_path = Path(root) / filename
            
            # Check extension
            if file_path.suffix.lower() in extensions or not extensions:
                files.append(str(file_path))
    
    return files


# ============================================================================
# ANALYSIS ENGINE
# ============================================================================

def analyze_path(path: str, verbose: bool = False) -> List[AnalysisResult]:
    """Analyze all files in a path and return results."""
    files = discover_files(path)
    results = []
    
    if not files:
        print_msg(f"⚠️  No supported files found in: {path}", "yellow")
        return results
    
    if verbose:
        print_msg(f"📁 Found {len(files)} files to analyze", "cyan")
    
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=len(files))
            
            for file_path in files:
                progress.update(task, description=f"Scanning: {Path(file_path).name}")
                analyzer = get_analyzer(file_path)
                result = analyzer.analyze_file(file_path)
                results.append(result)
                progress.advance(task)
    else:
        for i, file_path in enumerate(files):
            print(f"\rScanning [{i+1}/{len(files)}]: {Path(file_path).name[:40]}", end="")
            analyzer = get_analyzer(file_path)
            result = analyzer.analyze_file(file_path)
            results.append(result)
        print()
    
    return results


def print_results(results: List[AnalysisResult], verbose: bool = False):
    """Print analysis results in a beautiful table."""
    total_issues = sum(r.issue_count for r in results)
    critical_count = sum(r.critical_count for r in results)
    high_count = sum(r.high_count for r in results)
    
    # Print summary
    if total_issues == 0:
        print_msg(f"\n🏆 {random.choice(VICTORY_MESSAGES)}", "bold green")
        print_msg(f"\n✅ {len(results)} files scanned. ZERO ISSUES!", "green")
        return
    
    print_msg(f"\n💀 {random.choice(FAILURE_MESSAGES)}", "bold red")
    
    if RICH_AVAILABLE:
        # Summary table
        summary = Table(title="📊 GREASE REPORT", show_header=True)
        summary.add_column("Metric", style="cyan")
        summary.add_column("Count", justify="right")
        
        summary.add_row("Files Scanned", str(len(results)))
        summary.add_row("Total Issues", f"[bold red]{total_issues}[/]")
        summary.add_row("🔴 Critical", f"[bold white on red]{critical_count}[/]" if critical_count else "0")
        summary.add_row("🟠 High", f"[bold red]{high_count}[/]" if high_count else "0")
        
        console.print(summary)
        
        # Issues table
        issues_table = Table(title="🔍 ISSUES FOUND", show_header=True, expand=True)
        issues_table.add_column("Sev", width=4)
        issues_table.add_column("File", style="cyan", max_width=30)
        issues_table.add_column("Line", justify="right", width=5)
        issues_table.add_column("Rule", style="yellow", max_width=25)
        issues_table.add_column("Message", max_width=50)
        
        for result in results:
            for issue in result.issues:
                sev_icon = {
                    Severity.CRITICAL: "🔴",
                    Severity.HIGH: "🟠",
                    Severity.MEDIUM: "🟡",
                    Severity.LOW: "🔵",
                    Severity.INFO: "⚪",
                }.get(issue.severity, "?")
                
                issues_table.add_row(
                    sev_icon,
                    Path(issue.file_path).name,
                    str(issue.line_number),
                    issue.rule_id,
                    issue.message[:50],
                    style=get_severity_style(issue.severity)
                )
        
        console.print(issues_table)
        
        # Print Willie commentary
        if critical_count > 0:
            console.print(Panel(
                f"🏴󠁧󠁢󠁳󠁣󠁴󠁿 {get_willie_comment(Severity.CRITICAL)}",
                title="WILLIE SAYS",
                border_style="red"
            ))
    else:
        # Plain text output
        print(f"\n📊 GREASE REPORT")
        print(f"   Files Scanned: {len(results)}")
        print(f"   Total Issues:  {total_issues}")
        print(f"   Critical:      {critical_count}")
        print(f"   High:          {high_count}")
        print()
        
        for result in results:
            for issue in result.issues:
                print(f"  [{issue.severity.value}] {issue.file_path}:{issue.line_number}")
                print(f"      {issue.rule_id}: {issue.message}")


def apply_fixes(results: List[AnalysisResult], dry_run: bool = False) -> int:
    """Apply auto-fixes to files and return count of fixes applied."""
    total_fixes = 0
    
    for result in results:
        fixable = [i for i in result.issues if i.auto_fixable]
        if not fixable:
            continue
        
        analyzer = get_analyzer(result.file_path)
        analyzer.issues = result.issues
        fixed_content, fix_count = analyzer.apply_fixes(result.original_content)
        
        if fix_count > 0:
            if not dry_run:
                # Add Willie's signature comment at top
                willie_comment = f"# FIXED BY WILLIE: {fix_count} issues sorted. Ye're welcome, ya numpty.\n"
                
                # Don't add comment if it already exists
                if "FIXED BY WILLIE" not in fixed_content:
                    # Add after any shebang or encoding declaration
                    lines = fixed_content.splitlines(keepends=True)
                    insert_idx = 0
                    for i, line in enumerate(lines[:3]):
                        if line.startswith('#!') or 'coding' in line:
                            insert_idx = i + 1
                    lines.insert(insert_idx, willie_comment)
                    fixed_content = ''.join(lines)
                
                with open(result.file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                
                print_msg(f"  🔧 Fixed {fix_count} issues in {Path(result.file_path).name}", "green")
            else:
                print_msg(f"  [DRY RUN] Would fix {fix_count} issues in {Path(result.file_path).name}", "yellow")
            
            total_fixes += fix_count
    
    return total_fixes


# ============================================================================
# CLI COMMANDS
# ============================================================================

@click.group()
@click.version_option(version="1.0.0", prog_name="Groundskeeper Willie")
def cli():
    """GROUNDSKEEPER WILLIE - Zero Trust. Zero Politeness.
    
    The angriest code auditor this side of Scotland.
    
    \b
    Commands:
      scan   Audit code and report all issues found
      scrub  Iteratively fix until 100% clean
      fix    Apply auto-fixes with Willie comments
    """
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
@click.option('--strict', is_flag=True, help='Exit with error code if issues found')
def scan(path: str, verbose: bool, json_output: bool, strict: bool):
    """[SCAN] Audit code for issues without making changes.
    
    Examples:
    
    \b
      willie scan .
      willie scan ./src --verbose
      willie scan contract.sol --strict
    """
    if not json_output:
        print_banner()
        print_msg("🔍 SCANNING FOR GREASE...\n", "bold cyan")
    
    results = analyze_path(path, verbose)
    
    if json_output:
        import json
        output = {
            'files_scanned': len(results),
            'total_issues': sum(r.issue_count for r in results),
            'issues': [
                issue.to_dict() 
                for result in results 
                for issue in result.issues
            ]
        }
        click.echo(json.dumps(output, indent=2))
    else:
        print_results(results, verbose)
    
    total_issues = sum(r.issue_count for r in results)
    if strict and total_issues > 0:
        sys.exit(1)


@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--dry-run', is_flag=True, help='Show what would be fixed without changing files')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def fix(path: str, dry_run: bool, verbose: bool):
    """[FIX] Apply auto-fixes to code issues.
    
    Only fixes issues that can be safely auto-corrected.
    Adds Willie's signature comments to fixed code.
    
    Examples:
    
    \b
      willie fix .
      willie fix ./src --dry-run
    """
    print_banner()
    print_msg("[*] APPLYING FIXES...\n", "bold cyan")
    
    results = analyze_path(path, verbose)
    
    fixable_count = sum(r.fixable_count for r in results)
    if fixable_count == 0:
        print_msg("No auto-fixable issues found.", "yellow")
        return
    
    print_msg(f"Found {fixable_count} auto-fixable issues.\n", "cyan")
    
    fixes_applied = apply_fixes(results, dry_run)
    
    if dry_run:
        print_msg(f"\n[DRY RUN] Would apply {fixes_applied} fixes.", "yellow")
    else:
        print_msg(f"\n✅ Applied {fixes_applied} fixes!", "bold green")
        print_msg("// Fixed it, ya numpty. - Willie", "dim italic")


@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--max-iterations', '-n', default=10, help='Max fix iterations')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scrub(path: str, max_iterations: int, verbose: bool):
    """[SCRUB] Iteratively fix until 100% clean (or give up).
    
    Runs scan -> fix cycles until no issues remain
    or max iterations is reached.
    
    Examples:
    
    \b
      willie scrub .
      willie scrub ./src --max-iterations 5
    """
    print_banner()
    print_msg("[*] SCRUBBIN' MODE ACTIVATED!\n", "bold cyan")
    
    for iteration in range(1, max_iterations + 1):
        print_msg(f"\n{'='*50}", "dim")
        print_msg(f"🔄 SCRUB ITERATION {iteration}/{max_iterations}", "bold yellow")
        print_msg(f"{'='*50}\n", "dim")
        
        # Scan
        results = analyze_path(path, verbose)
        total_issues = sum(r.issue_count for r in results)
        
        if total_issues == 0:
            print_msg("\n🏆 100% CLEAN!", "bold green")
            print_msg(random.choice(VICTORY_MESSAGES), "green")
            return
        
        # Fix
        fixable = sum(r.fixable_count for r in results)
        if fixable == 0:
            print_msg(f"\n⚠️  {total_issues} issues found but none are auto-fixable.", "yellow")
            print_results(results, verbose)
            print_msg("\nFix these manually, ye lazy bum!", "red")
            return
        
        print_msg(f"   Issues: {total_issues} | Fixable: {fixable}", "cyan")
        print_msg(f"   {random.choice(SCRUB_MESSAGES)}", "dim italic")
        
        fixes = apply_fixes(results, dry_run=False)
        print_msg(f"   Applied {fixes} fixes this round.", "green")
    
    # Final check after max iterations
    results = analyze_path(path, verbose=False)
    total_issues = sum(r.issue_count for r in results)
    
    if total_issues == 0:
        print_msg("\n🏆 100% CLEAN!", "bold green")
    else:
        print_msg(f"\n⚠️  Max iterations reached. {total_issues} issues remain.", "yellow")
        print_results(results, verbose)


@cli.command()
def version():
    """Show version information."""
    print_banner()
    print_msg("Version: 1.0.0 (GREASE ME UP)", "cyan")
    print_msg("Author:  HUX", "dim")
    print_msg("License: MIT", "dim")


if __name__ == '__main__':
    cli()
