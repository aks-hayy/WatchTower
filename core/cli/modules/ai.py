"""Rich terminal client for the shared local WatchTower analyst service."""

from __future__ import annotations

from getpass import getpass
import time
from typing import Dict, Optional
import uuid

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.api.service import ApiServiceError, WatchtowerApiService
from core.ai.config import CredentialStore
from core.auth import OperatorAuthService
from core.auth.service import CLI_CREDENTIAL_REFERENCE


class AIModule:
    def __init__(self, service: Optional[WatchtowerApiService] = None, console: Optional[Console] = None):
        self.service = service or WatchtowerApiService()
        self.console = console or Console()
        self.last_error: Optional[ApiServiceError] = None

    def _provider_call(self, provider: str, action: str, operation):
        """Render provider service failures as actionable CLI errors, not tracebacks."""
        self.last_error = None
        try:
            return operation()
        except ApiServiceError as exc:
            self.last_error = exc
            if exc.code == "ai_provider_unavailable":
                provider_label = {"ollama": "Ollama", "openai": "OpenAI"}.get(provider, provider)
                self.console.print(
                    f"[bold red]Could not reach {provider_label}[/bold red] while {action}. "
                    "Check that the provider is running and reachable from this machine."
                )
                if action == "testing the provider":
                    self.console.print(
                        f"[dim]Next: start {provider_label} and confirm its configured endpoint is reachable, "
                        "then rerun this check.[/dim]"
                    )
                else:
                    self.console.print(
                        f"[dim]Next: run [cyan]tower ai provider test {provider}[/cyan] "
                        "to check connectivity and model readiness.[/dim]"
                    )
            else:
                self.console.print(f"[bold red]Unable to complete {action} for {provider}:[/bold red] {exc.message}")
                if exc.status_code >= 500:
                    self.console.print("[dim]Try again after checking WatchTower and provider status.[/dim]")
            return None

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
            result = self._provider_call(
                provider, "connecting", lambda: self.service.ai_provider_connect(provider, secret, model, base_url)
            )
        finally:
            secret = None
        if result is None:
            return None
        self.console.print(
            f"[green]{provider} connected.[/green] Default model: [cyan]{result['model']}[/cyan]"
        )
        return result

    def provider_test(self, provider: str):
        result = self._provider_call(provider, "testing the provider", lambda: self.service.ai_provider_test(provider))
        if result is None:
            return None
        capability = result.get("capability") or {}
        model = result.get("model") or "no model selected"
        chat = "[green]ready[/green]" if capability.get("chat_ready") else "[yellow]not ready[/yellow]"
        tools = "[green]READY[/green]" if result.get("agentic_ready") else "[yellow]NOT READY[/yellow]"
        catalog_available = result.get("model_catalog_available", result.get("available"))
        catalog = "[green]available[/green]" if catalog_available else "[yellow]unavailable[/yellow]"
        self.console.print(
            f"{provider} model catalog {catalog}. Model: [cyan]{model}[/cyan]. Chat {chat}. Agentic tools {tools}."
        )
        if result.get("selected_model_available") is False:
            self.console.print(
                "[yellow]The selected model is not in the installed model list. "
                "Choose an installed model, then test again.[/yellow]"
            )
        if capability.get("detail"):
            self.console.print(f"[dim]{capability['detail']}[/dim]")
        return result

    def provider_disconnect(self, provider: str):
        result = self._provider_call(provider, "disconnecting", lambda: self.service.ai_provider_disconnect(provider))
        if result is None:
            return None
        self.console.print(f"[yellow]{provider} disconnected.[/yellow]")
        return result

    def models(self, provider: str, refresh: bool = False):
        result = self._provider_call(
            provider, "loading the model list", lambda: self.service.ai_provider_models(provider, refresh)
        )
        if result is None:
            return None
        table = Table(title=f"{provider.title()} Models", box=None)
        table.add_column("Model", style="cyan")
        table.add_column("Tools")
        table.add_column("Location")
        for item in result.get("models") or []:
            table.add_row(
                str(item["id"]),
                "yes" if item.get("supports_tools") is True else (
                    "no" if item.get("supports_tools") is False else "not tested"
                ),
                "local" if item.get("local") else "hosted",
            )
        self.console.print(table)
        return result

    def model_set(self, provider: str, model: str):
        result = self._provider_call(
            provider, "selecting the model", lambda: self.service.ai_provider_set_model(provider, model)
        )
        if result is None:
            return None
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
        self.console.print(
            "[dim]Resume with [cyan]tower chat --conversation <ID>[/cyan]. "
            "A unique ID prefix is accepted.[/dim]"
        )
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
        self.last_error = None
        if conversation_id:
            conversation_id = self._resolve_conversation_id(str(conversation_id))
            if conversation_id is None:
                return None
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
        self.last_error = None
        operator_session_id = self._operator_session_id()
        try:
            run = self.service.ai_start_run(
                prompt,
                conversation_id,
                provider,
                scope,
                research_mode,
                operator_session_id,
                mode,
                str(uuid.uuid4()),
            )
        except ApiServiceError as exc:
            self.last_error = exc
            self.console.print(f"[bold red]Could not start the analyst run:[/bold red] {exc.message}")
            if exc.status_code == 404:
                self.console.print("[dim]Next: run [cyan]tower ai conversations[/cyan] and resume with a listed ID.[/dim]")
            return None
        return self._wait(run)

    def _resolve_conversation_id(self, value: str) -> Optional[str]:
        """Resolve the visible short ID only when it identifies one stored chat."""
        rows = self.service.ai_conversations()
        matches = [
            str(row.get("id") or "") for row in rows
            if str(row.get("id") or "").casefold().startswith(value.casefold())
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            error = f"No analyst conversation matches ID prefix '{value}'."
            self.last_error = ApiServiceError(404, "ai_conversation_not_found", error)
            self.console.print(f"[bold red]{error}[/bold red]")
            self.console.print("[dim]Next: run [cyan]tower ai conversations[/cyan] to choose a conversation.[/dim]")
            return None
        error = f"Conversation ID prefix '{value}' matches more than one conversation."
        self.last_error = ApiServiceError(409, "ai_conversation_id_ambiguous", error)
        self.console.print(f"[bold yellow]{error}[/bold yellow]")
        self.console.print("Use a longer prefix or one of these full IDs:")
        for item in matches[:10]:
            self.console.print(f"  {item}")
        return None

    def _operator_session_id(self) -> Optional[str]:
        try:
            token = CredentialStore().get(CLI_CREDENTIAL_REFERENCE)
            session = OperatorAuthService(self.service.db).authenticate(token, required=False)
            return session.id if session else None
        except Exception:
            return None

    def retry(self, run_id: str):
        try:
            result = self.service.ai_retry(run_id, operator_session_id=self._operator_session_id())
        except ApiServiceError as exc:
            self.console.print(f"[yellow]Could not retry run {run_id[:12]}:[/yellow] {exc.message}")
            return None
        self.console.print(
            f"[cyan]Started a linked retry of {run_id[:12]} without duplicating its original question.[/cyan]"
        )
        return self._wait(result)

    def cancel(self, run_id: str):
        result = self.service.ai_cancel(run_id)
        self.console.print(f"[yellow]Analyst run {run_id[:12]} cancelled.[/yellow]")
        return result

    def _wait(self, run: Dict):
        run_id = run["id"]
        deadline = time.monotonic() + 120.0
        while time.monotonic() < deadline:
            run = self.service.ai_run(run_id)
            status = str(run.get("status") or "").upper()
            if status == "AWAITING_APPROVAL":
                if not self._approve_pending(run):
                    return run
            elif status in {"COMPLETE", "DEGRADED", "NEEDS_SCOPE", "FAILED", "REJECTED", "CANCELLED", "INTERRUPTED"}:
                self._render(run)
                if status == "INTERRUPTED":
                    self.console.print(
                        f"[dim]No action was replayed. For an interrupted read-only run, use [cyan]tower ai retry {run_id}[/cyan].[/dim]"
                    )
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
        operation = run.get("operation") or {}
        if operation.get("state"):
            self.console.print(f"[bold]Operation state: {operation['state']}[/bold]")
            for action in operation.get("next_actions") or []:
                self.console.print(f"[dim]Next: {action}[/dim]")
        if status in {"COMPLETE", "DEGRADED"}:
            answer = run.get("answer") or {}
            self.console.print(Panel(
                answer.get("narrative") or run.get("final_text") or "No final analyst response.",
                title="Analyst Assessment", border_style="cyan",
            ))
            completeness = answer.get("completeness")
            if completeness:
                style = "yellow" if completeness == "partial" else "green"
                self.console.print(f"[bold {style}]Evidence completeness: {completeness}[/bold {style}]")
            scope = answer.get("effective_scope")
            scope_summary = _format_effective_scope(scope)
            if scope_summary:
                self.console.print(f"[dim]Effective scope: {scope_summary}[/dim]")
            for limitation in answer.get("limitations") or []:
                self.console.print(f"[yellow]Limitation:[/yellow] {limitation}")
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


def _format_effective_scope(scope) -> str:
    if not isinstance(scope, dict):
        return ""
    parts = []
    for key, label in (("source", "source"), ("interface", "interface"), ("session_id", "session"),
                       ("node_id", "sensor"), ("case_id", "case")):
        value = scope.get(key)
        if value:
            parts.append(f"{label}={value}")
    targets = [str(item) for item in (scope.get("target_ips") or []) if item]
    if targets:
        shown = ", ".join(targets[:3])
        suffix = f", +{len(targets) - 3}" if len(targets) > 3 else ""
        parts.append(f"targets={shown}{suffix}")
    start, end = scope.get("time_start"), scope.get("time_end")
    if start is not None or end is not None:
        parts.append(f"time={start if start is not None else '…'}–{end if end is not None else '…'}")
    return " / ".join(parts)
