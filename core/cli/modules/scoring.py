"""Rich CLI presentation for behavioral scoring V2."""

from rich.console import Console
from rich.table import Table

from core.detection.operations import ScoringOperations
from core.storage.database import WatchtowerDB


console = Console()


class ScoringModule:
    def __init__(self, db=None):
        self.db = db or WatchtowerDB()
        self.operations = ScoringOperations(self.db)

    def status(self):
        status = self.operations.status()
        table = Table(title="Behavioral Scoring V2.1", show_header=False)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        for key in ("mode", "model_version", "config_hash", "finding_count", "active_finding_count", "snapshot_count"):
            value = status[key]
            table.add_row(key.replace("_", " ").title(), str(value)[:20] if key == "config_hash" else str(value))
        console.print(table)
        return status

    def validate(self):
        result = self.operations.validate()
        color = "green" if result["valid"] else "red"
        console.print(f"[{color}]Scoring validation: {'PASS' if result['valid'] else 'FAIL'}[/{color}]")
        for error in result["errors"] + result["invalid_detectors"]:
            console.print(f"[red] - {error}[/red]")
        if result["uncalibrated_findings"]:
            console.print(f"[yellow]{len(result['uncalibrated_findings'])} finding type(s) are below field-calibrated trust.[/yellow]")
        return result

    def explain(self, subject, **scope):
        result = self.operations.explain(subject, **scope)
        console.print(f"[bold cyan]{subject}[/bold cyan]  [bold]{result['priority_score']:.1f}/100 {result['risk_level']}[/bold]")
        console.print(f"[dim]Assessment confidence {result['assessment_confidence']:.2f}; this is investigation priority, not threat probability.[/dim]")
        table = Table(title="Contributors")
        table.add_column("Finding", style="cyan")
        table.add_column("Contribution", justify="right")
        table.add_column("Evidence", justify="right")
        table.add_column("Explanation")
        for item in result["contributors"]:
            table.add_row(item["finding_type"], f"{item['effective_contribution']:.1f}",
                          f"{item['evidence_quality']:.2f}", item["explanation"])
        console.print(table)
        return result
