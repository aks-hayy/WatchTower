import { defineEventHandler, getRequestURL, proxyRequest } from "h3";

export default defineEventHandler((event) => {
  const origin = (process.env.WATCHTOWER_API_ORIGIN || "http://127.0.0.1:8000").replace(/\/$/, "");
  const requestUrl = getRequestURL(event);
  return proxyRequest(event, `${origin}${requestUrl.pathname}${requestUrl.search}`);
});
