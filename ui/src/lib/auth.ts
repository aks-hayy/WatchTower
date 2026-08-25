import { apiV2Base } from "@/lib/api-url";

export interface AuthSession {
  id: string;
  client_type: string;
  authenticated_at: number;
  step_up_at: number;
  expires_at: number;
}

export interface AuthStatus {
  state: "setup_required" | "disabled" | "locked" | "unlocked";
  setup_required: boolean;
  auth_enabled: boolean;
  authenticated: boolean;
  operator: string | null;
  credential_count: number;
  session: AuthSession | null;
  session_lifetime_seconds: number;
  step_up_max_age_seconds: number;
  idle_timeout_seconds: null;
  installation_id: string;
}

type RecordValue = Record<string, unknown>;

async function authRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiV2Base()}/auth${path}`, {
    ...init,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(
      payload?.error?.message || `Authentication request failed (${response.status})`,
    );
  }
  return payload as T;
}

export function fetchAuthStatus() {
  return authRequest<AuthStatus>("/status");
}

export function setupAuth(pin: string, displayName: string) {
  return authRequest<{ status: AuthStatus; recovery_code: string }>("/setup", {
    method: "POST",
    body: JSON.stringify({ mode: "secure", pin, display_name: displayName }),
  });
}

export function disableAuthFirstRun() {
  return authRequest<AuthStatus>("/setup", {
    method: "POST",
    body: JSON.stringify({ mode: "disabled", display_name: "Local Operator" }),
  });
}

export function unlockWithPin(pin: string) {
  return authRequest<{ status: AuthStatus }>("/pin/verify", {
    method: "POST",
    body: JSON.stringify({ pin, client_type: "browser" }),
  });
}

export function lockAuth() {
  return authRequest<{ status: string }>("/lock", { method: "POST", body: "{}" });
}

export function stepUpWithPin(pin: string) {
  return authRequest<{ status: AuthStatus }>("/step-up", {
    method: "POST",
    body: JSON.stringify({ pin, client_type: "browser" }),
  });
}

export function setAuthEnabled(enabled: boolean, pin: string) {
  return authRequest<AuthStatus & { recovery_code?: string }>("/settings", {
    method: "POST",
    body: JSON.stringify({ enabled, pin }),
  });
}

export function recoverAuth(recoveryCode: string, newPin: string) {
  return authRequest<{ status: AuthStatus; recovery_code: string }>("/recovery", {
    method: "POST",
    body: JSON.stringify({ recovery_code: recoveryCode, new_pin: newPin }),
  });
}

export async function registerPasskey(nickname = "Windows Hello") {
  const challenge = await authRequest<{
    challenge_id: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>("/challenge", {
    method: "POST",
    body: JSON.stringify({ kind: "registration", nickname }),
  });
  const credential = (await navigator.credentials.create({
    publicKey: creationOptions(challenge.options),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("The platform did not create a passkey");
  return authRequest<RecordValue>("/verify", {
    method: "POST",
    body: JSON.stringify({
      kind: "registration",
      challenge_id: challenge.challenge_id,
      credential: serializeCredential(credential),
      nickname,
      client_type: "browser",
    }),
  });
}

export async function unlockWithPasskey() {
  const challenge = await authRequest<{
    challenge_id: string;
    options: PublicKeyCredentialRequestOptionsJSON;
  }>("/challenge", {
    method: "POST",
    body: JSON.stringify({ kind: "authentication", nickname: "Windows Hello" }),
  });
  const credential = (await navigator.credentials.get({
    publicKey: requestOptions(challenge.options),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("The platform did not return a passkey");
  return authRequest<{ status: AuthStatus }>("/verify", {
    method: "POST",
    body: JSON.stringify({
      kind: "authentication",
      challenge_id: challenge.challenge_id,
      credential: serializeCredential(credential),
      client_type: "browser",
      nickname: "Windows Hello",
    }),
  });
}

function fromBase64Url(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return Uint8Array.from(raw, (character) => character.charCodeAt(0)).buffer;
}

function toBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let raw = "";
  bytes.forEach((byte) => {
    raw += String.fromCharCode(byte);
  });
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const AUTHENTICATOR_TRANSPORTS = new Set<AuthenticatorTransport>([
  "ble",
  "hybrid",
  "internal",
  "nfc",
  "usb",
]);

function normalizeTransports(values?: string[]): AuthenticatorTransport[] | undefined {
  if (!values) return undefined;
  return values.filter((value): value is AuthenticatorTransport =>
    AUTHENTICATOR_TRANSPORTS.has(value as AuthenticatorTransport),
  );
}

function creationOptions(
  options: PublicKeyCredentialCreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
  const selection = options.authenticatorSelection;
  return {
    rp: options.rp,
    challenge: fromBase64Url(options.challenge),
    user: { ...options.user, id: fromBase64Url(options.user.id) },
    pubKeyCredParams: options.pubKeyCredParams.map((item) => ({
      alg: item.alg,
      type: "public-key" as const,
    })),
    timeout: options.timeout,
    excludeCredentials: options.excludeCredentials?.map((item) => ({
      type: "public-key" as const,
      id: fromBase64Url(item.id),
      transports: normalizeTransports(item.transports),
    })),
    authenticatorSelection: selection
      ? {
          authenticatorAttachment: selection.authenticatorAttachment as
            | AuthenticatorAttachment
            | undefined,
          requireResidentKey: selection.requireResidentKey,
          residentKey: selection.residentKey as ResidentKeyRequirement | undefined,
          userVerification: selection.userVerification as UserVerificationRequirement | undefined,
        }
      : undefined,
    attestation: options.attestation as AttestationConveyancePreference | undefined,
  };
}

function requestOptions(
  options: PublicKeyCredentialRequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: fromBase64Url(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map((item) => ({
      type: "public-key" as const,
      id: fromBase64Url(item.id),
      transports: normalizeTransports(item.transports),
    })),
    userVerification: options.userVerification as UserVerificationRequirement | undefined,
  };
}

function serializeCredential(credential: PublicKeyCredential) {
  const response = credential.response;
  const base = {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if (response instanceof AuthenticatorAttestationResponse) {
    return {
      ...base,
      response: {
        clientDataJSON: toBase64Url(response.clientDataJSON),
        attestationObject: toBase64Url(response.attestationObject),
        transports: response.getTransports?.() || [],
      },
    };
  }
  const assertion = response as AuthenticatorAssertionResponse;
  return {
    ...base,
    response: {
      clientDataJSON: toBase64Url(assertion.clientDataJSON),
      authenticatorData: toBase64Url(assertion.authenticatorData),
      signature: toBase64Url(assertion.signature),
      userHandle: assertion.userHandle ? toBase64Url(assertion.userHandle) : null,
    },
  };
}
