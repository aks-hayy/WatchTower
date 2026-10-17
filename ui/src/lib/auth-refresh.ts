export type AuthStatusRefreshState<T> = {
  status: T | null;
  connectionError: string;
};

export type AuthStatusRefreshResult<T> = { ok: true; status: T } | { ok: false; cause: unknown };

export function applyAuthStatusRefresh<T>(
  previous: AuthStatusRefreshState<T>,
  result: AuthStatusRefreshResult<T>,
): AuthStatusRefreshState<T> {
  if (result.ok) return { status: result.status, connectionError: "" };
  return {
    status: previous.status,
    connectionError:
      result.cause instanceof Error ? result.cause.message : "Authentication unavailable",
  };
}
