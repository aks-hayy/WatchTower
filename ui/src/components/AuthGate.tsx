import { Fingerprint, KeyRound, Loader2, LockKeyhole, Radar, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  disableAuthFirstRun,
  fetchAuthStatus,
  recoverAuth,
  registerPasskey,
  setupAuth,
  unlockWithPasskey,
  unlockWithPin,
  type AuthStatus,
} from "@/lib/auth";

export function AuthGate({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [pin, setPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [name, setName] = useState("Local Operator");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [recoveryInput, setRecoveryInput] = useState("");
  const [showRecovery, setShowRecovery] = useState(false);
  const authState = status?.state;

  const refresh = useCallback(
    () =>
      fetchAuthStatus()
        .then(setStatus)
        .catch((cause) =>
          setError(cause instanceof Error ? cause.message : "Authentication unavailable"),
        ),
    [],
  );

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!authState || authState === "disabled") return;
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => window.clearInterval(timer);
  }, [authState, refresh]);

  const run = async (operation: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await operation();
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Authentication failed");
    } finally {
      setBusy(false);
    }
  };

  if (!status) {
    return (
      <TrustFrame>
        <Loader2 className="h-5 w-5 animate-spin text-signal" />
        <span className="mono text-[10px] uppercase text-muted-foreground">
          Establishing local trust
        </span>
      </TrustFrame>
    );
  }

  if (status.state === "disabled" || status.state === "unlocked") {
    if (recoveryCode) {
      return (
        <TrustFrame>
          <div className="w-full max-w-xl border border-severity-medium/50 bg-severity-medium/5">
            <div className="flex items-center gap-2 border-b border-severity-medium/30 px-4 py-3">
              <ShieldCheck className="h-4 w-4 text-severity-medium" />
              <span className="mono text-[10px] uppercase text-severity-medium">
                Recovery credential
              </span>
            </div>
            <div className="p-4">
              <p className="text-[13px] text-foreground">
                Store this one-time recovery code outside WatchTower.
              </p>
              <code className="mt-3 block border border-border bg-background p-3 text-center text-sm tracking-wider text-signal">
                {recoveryCode}
              </code>
              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  onClick={() => run(() => registerPasskey())}
                  disabled={busy || !("credentials" in navigator)}
                  className="flex h-9 items-center gap-2 border border-signal px-3 mono text-[10px] uppercase text-signal hover:bg-signal hover:text-primary-foreground disabled:opacity-40"
                >
                  <Fingerprint className="h-3.5 w-3.5" /> Add Windows Hello
                </button>
                <button
                  onClick={() => setRecoveryCode("")}
                  className="h-9 border border-border px-3 mono text-[10px] uppercase text-foreground hover:border-signal"
                >
                  I stored the code
                </button>
              </div>
              {error && <AuthErrorText text={error} />}
            </div>
          </div>
        </TrustFrame>
      );
    }
    return <>{children}</>;
  }

  if (status.state === "setup_required") {
    return (
      <TrustFrame>
        <div className="w-full max-w-xl border border-border bg-surface">
          <TrustHeader title="Secure this WatchTower" subtitle="First-run operator setup" />
          <div className="space-y-4 p-4">
            <p className="text-[13px] leading-relaxed text-muted-foreground">
              Create a local PIN now. You can add Windows Hello immediately afterward.
              Authentication lasts eight hours and is never extended by activity.
            </p>
            <Field label="Operator name" value={name} onChange={setName} />
            <Field label="PIN" value={pin} onChange={setPin} secret />
            <Field label="Confirm PIN" value={confirmPin} onChange={setConfirmPin} secret />
            {error && <AuthErrorText text={error} />}
            <div className="flex flex-wrap gap-2">
              <button
                disabled={busy || pin.length < 6 || pin !== confirmPin}
                onClick={() =>
                  run(async () => {
                    const result = await setupAuth(pin, name);
                    setRecoveryCode(result.recovery_code);
                  })
                }
                className="flex h-9 items-center gap-2 border border-signal px-3 mono text-[10px] uppercase text-signal hover:bg-signal hover:text-primary-foreground disabled:opacity-35"
              >
                {busy ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <KeyRound className="h-3.5 w-3.5" />
                )}
                Enable protection
              </button>
              <button
                disabled={busy}
                onClick={() => run(disableAuthFirstRun)}
                className="h-9 border border-border px-3 mono text-[10px] uppercase text-muted-foreground hover:border-severity-medium hover:text-severity-medium"
              >
                Continue without authentication
              </button>
            </div>
          </div>
        </div>
      </TrustFrame>
    );
  }

  return (
    <TrustFrame>
      <div className="w-full max-w-md border border-border bg-surface">
        <TrustHeader title="WatchTower locked" subtitle="Local operator verification" />
        <div className="space-y-3 p-4">
          {status.credential_count > 0 && (
            <button
              onClick={() => run(unlockWithPasskey)}
              disabled={busy}
              className="flex h-10 w-full items-center justify-center gap-2 border border-signal bg-signal/5 mono text-[10px] uppercase text-signal hover:bg-signal hover:text-primary-foreground disabled:opacity-40"
            >
              <Fingerprint className="h-4 w-4" /> Use Windows Hello
            </button>
          )}
          <div className="flex">
            <input
              autoFocus
              type="password"
              inputMode="numeric"
              value={pin}
              onChange={(event) => setPin(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && pin.length >= 6) void run(() => unlockWithPin(pin));
              }}
              placeholder="Operator PIN"
              className="h-10 min-w-0 flex-1 border border-border bg-background px-3 mono text-[12px] text-foreground focus:border-signal focus:outline-none"
            />
            <button
              title="Unlock with PIN"
              onClick={() => run(() => unlockWithPin(pin))}
              disabled={busy || pin.length < 6}
              className="grid h-10 w-10 place-items-center border border-l-0 border-signal text-signal hover:bg-signal hover:text-primary-foreground disabled:opacity-35"
            >
              {busy ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <LockKeyhole className="h-4 w-4" />
              )}
            </button>
          </div>
          <button
            onClick={() => setShowRecovery((value) => !value)}
            className="mono text-[9px] uppercase text-muted-foreground hover:text-signal"
          >
            Use recovery code
          </button>
          {showRecovery && (
            <div className="space-y-2 border border-border p-3">
              <Field label="Recovery code" value={recoveryInput} onChange={setRecoveryInput} />
              <Field label="New PIN" value={confirmPin} onChange={setConfirmPin} secret />
              <button
                disabled={busy || recoveryInput.length < 12 || confirmPin.length < 6}
                onClick={() =>
                  run(async () => {
                    const result = await recoverAuth(recoveryInput, confirmPin);
                    setRecoveryCode(result.recovery_code);
                  })
                }
                className="h-8 border border-severity-medium/60 px-3 mono text-[10px] uppercase text-severity-medium disabled:opacity-35"
              >
                Recover access
              </button>
            </div>
          )}
          {error && <AuthErrorText text={error} />}
          <div className="mono text-[9px] uppercase text-muted-foreground">
            Sessions expire eight hours after authentication. There is no idle timeout.
          </div>
        </div>
      </div>
    </TrustFrame>
  );
}

function TrustFrame({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-screen place-items-center bg-background p-4 grid-bg-fine">
      <div className="flex w-full flex-col items-center gap-4">
        <div className="flex items-center gap-2 mono text-[11px] uppercase text-muted-foreground">
          <Radar className="h-4 w-4 text-signal" />
          WatchTower / Operator Trust
        </div>
        {children}
      </div>
    </div>
  );
}

function TrustHeader({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="flex items-center gap-3 border-b border-border px-4 py-3">
      <div className="grid h-8 w-8 place-items-center border border-signal/50 bg-signal/5">
        <ShieldCheck className="h-4 w-4 text-signal" />
      </div>
      <div>
        <div className="text-[14px] text-foreground">{title}</div>
        <div className="mono text-[9px] uppercase text-muted-foreground">{subtitle}</div>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  secret = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  secret?: boolean;
}) {
  return (
    <label className="block">
      <span className="section-label">{label}</span>
      <input
        type={secret ? "password" : "text"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-1.5 h-9 w-full border border-border bg-background px-3 mono text-[11px] text-foreground focus:border-signal focus:outline-none"
      />
    </label>
  );
}

function AuthErrorText({ text }: { text: string }) {
  return (
    <div className="border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 mono text-[10px] text-severity-critical">
      {text}
    </div>
  );
}
