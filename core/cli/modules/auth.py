"""Rich CLI adapter for the local operator trust boundary."""

from __future__ import annotations

from getpass import getpass
from typing import Optional

from rich.console import Console
from rich.table import Table

from core.ai.config import CredentialStore
from core.auth import AuthError, OperatorAuthService
from core.auth.service import CLI_CREDENTIAL_REFERENCE
from core.context import context
from core.storage.database import WatchtowerDB


class AuthModule:
    def __init__(self, console: Optional[Console] = None, db=None, credentials=None):
        self.console = console or Console()
        self.db = db or WatchtowerDB()
        self._owns_db = db is None
        self.auth = OperatorAuthService(self.db)
        self.credentials = credentials or CredentialStore()

    def close(self) -> None:
        if self._owns_db:
            self.db.close()

    def setup(self, disable: bool = False, display_name: str = "Local Operator") -> bool:
        try:
            if disable:
                self.auth.disable_first_run()
                self.console.print(
                    "[yellow]Application authentication disabled.[/yellow] "
                    "It can be enabled later with [cyan]tower auth settings --enable[/cyan]."
                )
                return True
            pin = self._new_pin()
            result = self.auth.setup_pin(pin, display_name, client_type="cli")
            self._store_token(result["token"])
            self.console.print("[bold green]WatchTower operator authentication configured.[/bold green]")
            self.console.print("[bold yellow]Recovery code (shown once):[/bold yellow]")
            self.console.print(result["recovery_code"])
            self.console.print("[dim]Store this code outside WatchTower. It cannot be displayed again.[/dim]")
            return True
        except AuthError as exc:
            self.console.print(f"[bold red]Authentication setup failed:[/bold red] {exc.message}")
            return False

    def unlock(self) -> bool:
        try:
            result = self.auth.verify_pin(getpass("WatchTower PIN: "), client_type="cli")
            self._store_token(result["token"])
            expires = result["session"]["expires_at"]
            self.console.print(f"[green]WatchTower unlocked.[/green] [dim]Session expires at {self._when(expires)}.[/dim]")
            return True
        except (AuthError, RuntimeError) as exc:
            message = exc.message if isinstance(exc, AuthError) else str(exc)
            self.console.print(f"[bold red]Unlock failed:[/bold red] {message}")
            return False

    def lock(self, all_sessions: bool = False) -> None:
        token = self._token()
        revoked = self.auth.lock(token, all_sessions=all_sessions)
        self.credentials.delete(CLI_CREDENTIAL_REFERENCE)
        self.console.print(f"[green]Locked {revoked} WatchTower session(s).[/green]")

    def status(self) -> dict:
        token = self._token()
        result = self.auth.status(token)
        table = Table(title="WatchTower Operator Trust")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("State", str(result["state"]).upper())
        table.add_row("Authentication", "enabled" if result["auth_enabled"] else "disabled")
        table.add_row("Trust store", str(self.db.db_path))
        table.add_row("Session lifetime", "8 hours absolute")
        table.add_row("Idle timeout", "none")
        table.add_row("Passkeys", str(result["credential_count"]))
        if result.get("session"):
            table.add_row("Expires", self._when(result["session"]["expires_at"]))
        self.console.print(table)
        return result

    def factors(self) -> dict:
        result = self.auth.factors()
        self.console.print_json(data=result)
        return result

    def settings(self, enabled: bool) -> bool:
        token = self._require_token(step_up=True)
        if not token:
            return False
        try:
            result = self.auth.set_enabled(enabled, token, getpass("Confirm WatchTower PIN: "))
            self.console.print(
                f"[green]Application authentication {'enabled' if enabled else 'disabled'}.[/green]"
            )
            if result.get("recovery_code"):
                self.console.print("[bold yellow]Recovery code (shown once):[/bold yellow]")
                self.console.print(result["recovery_code"])
                self.console.print("[dim]Store this code outside WatchTower. It cannot be displayed again.[/dim]")
            if not enabled:
                self.credentials.delete(CLI_CREDENTIAL_REFERENCE)
            return bool(result)
        except AuthError as exc:
            self.console.print(f"[bold red]Settings update failed:[/bold red] {exc.message}")
            return False

    def recovery_reset(self, os_admin: bool = False, reason: str = "") -> bool:
        try:
            new_pin = self._new_pin()
            if os_admin:
                result = self.auth.reset_as_os_admin(new_pin, reason, context.is_admin, client_type="cli")
            else:
                result = self.auth.reset_with_recovery(
                    getpass("One-time recovery code: "),
                    new_pin,
                    client_type="cli",
                )
            self._store_token(result["token"])
            self.console.print("[green]Operator access recovered and prior sessions revoked.[/green]")
            self.console.print("[bold yellow]New recovery code (shown once):[/bold yellow]")
            self.console.print(result["recovery_code"])
            return True
        except AuthError as exc:
            self.console.print(f"[bold red]Recovery failed:[/bold red] {exc.message}")
            return False

    def ensure_unlocked(self, step_up: bool = False, interactive: bool = True) -> bool:
        status = self.auth.status(self._token())
        if status["state"] == "disabled":
            return True
        if status["state"] == "setup_required":
            if interactive:
                self.console.print("[cyan]Set a local operator PIN to continue.[/cyan]")
                return self.setup()
            self.console.print(
                "[yellow]Complete first-run security with [cyan]tower auth setup[/cyan] "
                "or launch [cyan]tower ui[/cyan].[/yellow]"
            )
            return False
        token = self._token()
        try:
            if step_up:
                self.auth.require_step_up(token or "")
            else:
                self.auth.authenticate(token)
            return True
        except AuthError as exc:
            if not interactive:
                self.console.print(f"[yellow]{exc.message}[/yellow]")
                return False
            if exc.code == "step_up_required":
                try:
                    self.auth.step_up_pin(token or "", getpass("Re-authenticate with WatchTower PIN: "))
                    return True
                except AuthError as step_exc:
                    self.console.print(f"[bold red]Re-authentication failed:[/bold red] {step_exc.message}")
                    return False
            return self.unlock()

    def _require_token(self, step_up: bool = False) -> Optional[str]:
        if not self.ensure_unlocked(step_up=step_up):
            return None
        return self._token()

    def _store_token(self, token: str) -> None:
        self.credentials.set(CLI_CREDENTIAL_REFERENCE, token)

    def _token(self) -> Optional[str]:
        try:
            return self.credentials.get(CLI_CREDENTIAL_REFERENCE)
        except Exception:
            return None

    @staticmethod
    def _new_pin() -> str:
        first = getpass("New WatchTower PIN (6+ characters): ")
        second = getpass("Confirm PIN: ")
        if first != second:
            raise AuthError("pin_mismatch", "The PIN confirmation did not match", 422)
        return first

    @staticmethod
    def _when(timestamp: float) -> str:
        import time

        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(timestamp)))
