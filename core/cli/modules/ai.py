"""Rich terminal client for the shared local WatchTower analyst service."""

from __future__ import annotations

from getpass import getpass
import time
from typing import Dict, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.api.service import WatchtowerApiService
from core.ai.config import CredentialStore
from core.auth import OperatorAuthService
from core.auth.service import CLI_CREDENTIAL_REFERENCE


class AIModule:
    def __init__(self, service: Optional[WatchtowerApiService] = None, console: Optional[Console] = None):
        self.service = service or WatchtowerApiService()
        self.console = console or Console()

    @staticmethod
    def _scope(source=None, interface=None, session=None, node=None):
        return {"source": source, "interface": interface, "session_id": session, "node_id": node, "target_ips": [], "max_records": 250}

    def status(self):
        status = self.service.ai_status()
        table = Table(title="WatchTower Analyst", box=None)
        table.add_column("Provider", style="cyan")
        table.add_column("Model")
        table.add_column("Status")
        table.add_column("Detail")
        for provider in status["providers"]:
            table.add_row(str(provider["name"]), str(provider.get("model") or "-"),
                          "[green]READY[/green]" if provider.get("available") else "[yellow]UNAVAILABLE[/yellow]",
                          str(provider.get("detail") or ""))
        self.console.print(table)
        self.console.print(f"[dim]{len(status['tools'])} typed tools | {len(status['research_sources'])} controlled research sources[/dim]")
        return status

    def providers(self):
        return self.status()

    def provider_connect(self, provider: str, model: Optional[str] = None,
                         base_url: Optional[str] = None, chatgpt_alias: bool = False):
        if chatgpt_alias:
            self.console.print(
                "[yellow]This connects the OpenAI API. ChatGPT subscriptions and API billing are separate.[/yellow]"
            )
        secret = getpass("OpenAI API key: ") if provider == "openai" else None
        try:
            result = self.service.ai_provider_connect(provider, secret, model, base_url)
        finally:
            secret = None
        self.console.print(
            f"[green]{provider} connected.[/green] Default model: [cyan]{result['model']}[/cyan]"
        )
        return result

    def provider_test(self, provider: str):
        result = self.service.ai_provider_test(provider)
        self.console.print(
            f"[green]{provider} reachable.[/green] {len(result.get('models') or [])} compatible model(s). "
            f"Agentic tools: {'[green]READY[/green]' if result.get('agentic_ready') else '[yellow]NOT READY[/yellow]'}"
        )
        return result

    def provider_disconnect(self, provider: str):
        result = self.service.ai_provider_disconnect(provider)
        self.console.print(f"[yellow]{provider} disconnected.[/yellow]")
        return result

    def models(self, provider: str, refresh: bool = False):
        result = self.service.ai_provider_models(provider, refresh)
        table = Table(title=f"{provider.title()} Models", box=None)
        table.add_column("Model", style="cyan")
        table.add_column("Tools")
        table.add_column("Location")
        for item in result.get("models") or []:
            table.add_row(
                str(item["id"]),
                "yes" if item.get("supports_tools") else "no",
                "local" if item.get("local") else "hosted",
            )
        self.console.print(table)
        return result

    def model_set(self, provider: str, model: str):
        result = self.service.ai_provider_set_model(provider, model)
        self.console.print(f"[green]{provider} default model set to {model}.[/green]")
        return result

    def research_sources(self):
        items = self.service.ai_status()["research_sources"]
        table = Table(title="Analyst Research Sources", box=None)
        table.add_column("Source", style="cyan")
        table.add_column("Lane")
        table.add_column("Enabled")
        table.add_column("Credential")
        for item in items:
            table.add_row(str(item["name"]), str(item["lane"]), "yes" if item["enabled"] else "no",
                          "required" if item["credential_required"] else "not required")
        self.console.print(table)
        return items

    def conversations(self):
        rows = self.service.ai_conversations()
        table = Table(title="Analyst Conversations", box=None)
        table.add_column("ID", style="cyan")
        table.add_column("Title")
        table.add_column("Provider")
        table.add_column("Updated")
        for row in rows:
            table.add_row(str(row["id"])[:12], str(row["title"]), str(row.get("provider") or "ollama"),
                          time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(row["updated_at"]))))
        self.console.print(table)
        return rows

    def credential_set(self, reference: str):
        secret = getpass(f"Credential for {reference}: ")
        result = self.service.ai_set_credential(reference, secret)
        self.console.print(f"[green]Credential stored in Windows Credential Manager:[/green] {result['reference']}")

    def credential_delete(self, reference: str):
        result = self.service.ai_delete_credential(reference)
        self.console.print(f"[yellow]Credential {result['status']}:[/yellow] {result['reference']}")

    def chat(self, conversation_id=None, source=None, interface=None, session=None, node=None, provider="ollama", research_mode="auto",
             mode="auto", prompt: Optional[str] = None):
        scope = self._scope(source, interface, session, node)
        if prompt:
            return self._send(prompt, conversation_id, scope, provider, research_mode, mode)
        self.console.print(Panel(
            "Ask general questions, investigate stored traffic, or request a WatchTower action.\n"
            "Actions and external-provider use stop for explicit approval. Type [bold]exit[/bold] to leave.",
            title="[bold cyan]WatchTower Analyst[/bold cyan]", border_style="cyan",
        ))
        current = conversation_id
        while True:
            try:
                value = self.console.input("[bold cyan]analyst>[/bold cyan] ").strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                return None
            if value.casefold() in {"exit", "quit", "/exit"}:
                return None
            if not value:
                continue
            run = self._send(value, current, scope, provider, research_mode, mode)
            current = run.get("conversation_id", current) if run else current

    def _send(self, prompt: str, conversation_id: Optional[str], scope: Dict, provider: str, research_mode: str, mode: str):
        operator_session_id = None
        try:
            token = CredentialStore().get(CLI_CREDENTIAL_REFERENCE)
            session = OperatorAuthService(self.service.db).authenticate(token, required=False)
            operator_session_id = session.id if session else None
        except Exception:
            pass
        run = self.service.ai_start_run(
            prompt,
            conversation_id,
            provider,
            scope,
            research_mode,
            operator_session_id,
            mode,
        )
        return self._wait(run)

    def _wait(self, run: Dict):
        run_id = run["id"]
        deadline = time.monotonic() + 120.0
        while time.monotonic() < deadline:
            run = self.service.ai_run(run_id)
            status = str(run.get("status") or "").upper()
            if status == "AWAITING_APPROVAL":
                if not self._approve_pending(run):
                    return run
            elif status in {"COMPLETE", "DEGRADED", "NEEDS_SCOPE", "FAILED", "REJECTED"}:
                self._render(run)
                return run
            time.sleep(0.2)
        self.console.print("[yellow]The analyst run is still active. Open the UI or use the conversation ID to inspect it.[/yellow]")
        return self.service.ai_run(run_id)

    def _approve_pending(self, run: Dict) -> bool:
        pending = next((item for item in run.get("approvals", []) if item.get("status") == "PENDING"), None)
        if not pending:
            return True
        invocation = next((item for item in run.get("tool_calls", []) if item.get("id") == pending.get("invocation_id")), {})
        self.console.print(Panel(
            f"[bold]{pending.get('tool_name')}[/bold]\nScope: {pending.get('scope_json')}\nArguments: {invocation.get('arguments_json')}",
            title="Operator Approval Required", border_style="yellow",
        ))
        try:
            decision = self.console.input("Approve? [y/N] ").strip().casefold()
        except EOFError:
            self.service.ai_reject(pending["id"], "approval unavailable in non-interactive terminal")
            self.console.print("[yellow]Approval was not available in this terminal; the action was rejected.[/yellow]")
            return False
        if decision not in {"y", "yes"}:
            self.service.ai_reject(pending["id"], "operator rejected in terminal")
            return False
        phrase = pending.get("confirmation_phrase") or ""
        if phrase:
            try:
                confirmation = self.console.input(f"Type {phrase}: ").strip()
            except EOFError:
                self.service.ai_reject(pending["id"], "confirmation unavailable in non-interactive terminal")
                self.console.print("[yellow]Confirmation was not available in this terminal; the action was rejected.[/yellow]")
                return False
        else:
            confirmation = ""
        self.service.ai_approve(pending["id"], confirmation)
        return True

    def _render(self, run: Dict):
        status = str(run.get("status") or "UNKNOWN")
        if status in {"COMPLETE", "DEGRADED"}:
            self.console.print(Panel(run.get("final_text") or "No final analyst response.", title="Analyst Assessment", border_style="cyan"))
        else:
            self.console.print(Panel(run.get("error") or status, title=f"Analyst {status}", border_style="red"))
        citations = run.get("citations") or []
        if citations:
            table = Table(title="Evidence Citations", box=None)
            table.add_column("Kind")
            table.add_column("Reference", style="cyan")
            table.add_column("Source")
            table.add_column("Summary")
            for item in citations[:20]:
                table.add_row(str(item.get("kind")), str(item.get("reference")), str(item.get("source")), str(item.get("summary")))
            self.console.print(table)
