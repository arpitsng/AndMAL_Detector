"""
Shared terminal UI helpers (rich-based) for the LAMD pipeline scripts.

Design goals:
  - Drop-in replacements for the existing print() call sites — same
    information, same order, just styled — so this doesn't risk changing
    pipeline control flow right before a large, non-repeatable run.
  - ASCII-only symbols, no Unicode glyphs (✓/✗/⚠/etc). Verified this
    matters: on a legacy Windows console (cp1252), rich's own box-drawing
    borders auto-degrade safely, but literal Unicode characters in our own
    strings crash with UnicodeEncodeError. A crash mid-run during a
    multi-day unattended batch is far worse than a plainer symbol, so
    reliability wins over polish here — color does the visual work instead.
  - Auto-degrades to plain text when stdout isn't a real terminal (piped
    to a file, redirected in a background task) — rich's Console does this
    automatically, so captured logs stay clean and colorless.
  - One shared `console` instance so output from every script interleaves
    correctly if piped together.

Usage:
  from console_ui import console, banner, ok, fail, warn, info, dim, \\
      verdict_word, match_mark, metrics_table, confusion_table, family_table
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn

console = Console()

# =============================================================================
#  Basic styled print helpers
# =============================================================================

def banner(title: str, subtitle_lines: list[str] | None = None) -> None:
    """Panel-bordered header, replaces the old '='*65 blocks."""
    body = Text(title, style="bold cyan", justify="center")
    if subtitle_lines:
        body.append("\n")
        for line in subtitle_lines:
            body.append(f"\n{line}", style="dim")
    console.print(Panel(body, border_style="cyan", expand=False, padding=(0, 2)))


def section(title: str) -> None:
    """Small inline section divider, e.g. '--- Run Complete ---'."""
    console.print(f"\n[bold cyan]{'-' * 3} {title} {'-' * max(0, 57 - len(title))}[/bold cyan]")


def ok(text: str) -> None:
    console.print(f"[bold green][OK][/bold green] {text}")


def fail(text: str) -> None:
    console.print(f"[bold red][FAIL][/bold red] {text}")


def warn(text: str) -> None:
    console.print(f"[yellow][WARN][/yellow] {text}")


def info(text: str) -> None:
    console.print(f"[cyan][INFO][/cyan] {text}")


def dim(text: str) -> None:
    console.print(f"[dim]{text}[/dim]")


# =============================================================================
#  Domain-specific formatting
# =============================================================================

def verdict_word(verdict: str) -> str:
    """Colored MALWARE/BENIGN markup for inline use in an f-string print."""
    v = (verdict or "").upper()
    if v == "MALWARE":
        return "[bold red]MALWARE [/bold red]"
    if v == "BENIGN":
        return "[bold green]BENIGN  [/bold green]"
    return f"[yellow]{verdict}[/yellow]"


def match_mark(is_match: bool) -> str:
    return "[bold green]OK[/bold green]" if is_match else "[bold red]X [/bold red]"


def sample_result_line(
    idx: int, total: int, sha_short: str,
    prediction: str, ground_truth: str | None = None,
    elapsed: float | None = None,
) -> None:
    """
    One colored result line for a processed sample. Mirrors the old:
      [   5/15] 320f8bc79f251208...  MALWARE  (gt=MALWARE) [OK] (35.6s)
    """
    parts = [f"[dim][{idx:>5}/{total}][/dim] [dim]{sha_short}...[/dim]  {verdict_word(prediction)}"]
    if ground_truth is not None:
        is_match = prediction == ground_truth
        parts.append(f"[dim](gt={ground_truth})[/dim] [{match_mark(is_match)}]")
    if elapsed is not None:
        parts.append(f"[dim]({elapsed:.1f}s)[/dim]")
    console.print("  ".join(parts))


def sample_skip_line(idx: int, total: int, sha_short: str, reason: str) -> None:
    console.print(f"[dim][{idx:>5}/{total}] {sha_short}...  SKIP ({reason})[/dim]")


def sample_error_line(idx: int, total: int, sha_short: str, reason: str) -> None:
    console.print(f"[dim][{idx:>5}/{total}] {sha_short}...[/dim]  [bold red]FAILED[/bold red] [dim]({reason})[/dim]")


# =============================================================================
#  Progress bar — wraps the main per-sample loop without changing its logic
# =============================================================================

def make_progress() -> Progress:
    """
    Standard progress bar for the main sample loop. Use as:
        with make_progress() as progress:
            task = progress.add_task("Processing", total=len(samples))
            for sample in samples:
                ...
                progress.advance(task)
    Printing via `console.print(...)` while this is active interleaves
    correctly (rich redraws the bar below any logged lines).
    """
    return Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TextColumn("[dim]-[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


# =============================================================================
#  Summary tables
# =============================================================================

def metrics_table(metrics: dict) -> Table:
    """Overall accuracy/precision/recall/F1/FPR/FNR table for 5_evaluate.py."""
    t = Table(title="Overall Metrics", show_header=True, header_style="bold cyan", border_style="dim")
    t.add_column("Metric", style="bold")
    t.add_column("Value", justify="right")

    def pct_style(v: float, good_high: bool = True) -> str:
        v100 = v * 100
        if good_high:
            color = "green" if v100 >= 80 else ("yellow" if v100 >= 50 else "red")
        else:
            color = "green" if v100 <= 5 else ("yellow" if v100 <= 20 else "red")
        return f"[{color}]{v100:.2f}%[/{color}]"

    t.add_row("Total Samples", str(metrics["total"]))
    t.add_row("Accuracy", pct_style(metrics["accuracy"]))
    t.add_row("Precision", pct_style(metrics["precision"]))
    t.add_row("Recall", pct_style(metrics["recall"]))
    t.add_row("F1 Score", pct_style(metrics["f1"]))
    t.add_row("False Positive Rate", pct_style(metrics["fpr"], good_high=False))
    t.add_row("False Negative Rate", pct_style(metrics["fnr"], good_high=False))
    return t


def confusion_table(metrics: dict) -> Table:
    t = Table(title="Confusion Matrix", show_header=True, header_style="bold cyan", border_style="dim")
    t.add_column("")
    t.add_column("Predicted BENIGN", justify="right")
    t.add_column("Predicted MALWARE", justify="right")
    t.add_row("Actual BENIGN", f"[green]{metrics['tn']}[/green] (TN)", f"[red]{metrics['fp']}[/red] (FP)")
    t.add_row("Actual MALWARE", f"[red]{metrics['fn']}[/red] (FN)", f"[green]{metrics['tp']}[/green] (TP)")
    return t


def family_table(family_analysis: dict, limit: int = 15) -> Table:
    t = Table(title="Per-Family Detection Rates", show_header=True, header_style="bold cyan", border_style="dim")
    t.add_column("Family", style="bold")
    t.add_column("Detected/Total", justify="right")
    t.add_column("Rate", justify="right")
    t.add_column("")

    for family, stats in list(family_analysis.items())[:limit]:
        rate = stats["detection_rate"]
        rate_pct = rate * 100
        color = "green" if rate_pct >= 80 else ("yellow" if rate_pct >= 50 else "red")
        filled = int(rate_pct / 5)
        bar = f"[{color}]{'#' * filled}[/{color}][dim]{'.' * (20 - filled)}[/dim]"
        t.add_row(family, f"{stats['detected']}/{stats['total']}", f"[{color}]{rate_pct:.1f}%[/{color}]", bar)

    if len(family_analysis) > limit:
        t.add_row("...", f"+{len(family_analysis) - limit} more", "", "")
    return t
