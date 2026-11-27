export const formatElapsed = (milliseconds) => {
  const seconds = Math.max(0, Number(milliseconds || 0) / 1000);
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)}秒`;
  return `${Math.floor(seconds / 60)}分${Math.round(seconds % 60)}秒`;
};

export const stripTerminalAnsi = (value) => String(value ?? "")
  .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
  .replace(/\r(?!\n)/g, "");

export function validPort(value) {
  if (value === "" || value == null) return true;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

export function withVisitPath(baseUrl, visitPath) {
  const entry = String(visitPath || "").trim();
  if (!baseUrl || !entry || entry === "/") return baseUrl;
  try {
    const url = new URL(baseUrl, window.location.origin);
    const parsed = new URL(entry.startsWith("/") ? entry : `/${entry}`, url.origin);
    url.pathname = parsed.pathname;
    url.search = parsed.search;
    url.hash = parsed.hash;
    return url.toString();
  } catch {
    return `${String(baseUrl).replace(/\/+$/, "")}/${entry.replace(/^\/+/, "")}`;
  }
}

export function time(value) {
  return value ? new Date(value).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false }) : "—";
}
