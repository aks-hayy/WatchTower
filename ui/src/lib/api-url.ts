declare global {
  interface Window {
    __WATCHTOWER_API_URL__?: string;
  }
}

export function apiV2Base() {
  if (typeof window === "undefined") {
    const origin = (
      process.env.WATCHTOWER_API_ORIGIN ||
      process.env.WATCHTOWER_API_URL?.replace(/\/api\/v1\/?$/, "") ||
      "http://127.0.0.1:8000"
    ).replace(/\/$/, "");
    return `${origin}/api/v2`;
  }
  const configured = window.__WATCHTOWER_API_URL__ || import.meta.env.VITE_WATCHTOWER_API_URL;
  if (configured) {
    return configured.replace(/\/api\/v1\/?$/, "/api/v2").replace(/\/$/, "");
  }
  return "/api/v2";
}
