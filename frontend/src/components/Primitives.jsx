import React from "react";
import { Boxes } from "lucide-react";

export const statusText = { queued: "等待中", running: "部署中", success: "运行中", failed: "失败", stopped: "已停止" };
const statusClass = { queued: "warning", running: "info", success: "success", failed: "danger", stopped: "muted" };

export function Badge({ status }) {
  return <span className={`badge ${statusClass[status] || "muted"}`}><i />{statusText[status] || status}</span>;
}

export function Toast({ toast }) {
  if (!toast) return null;
  const type = toast.type || "success";
  const title = type === "success" ? "操作成功" : type === "warning" ? "需要注意" : "操作失败";
  return <div className={`toast ${type}`}><span>{type === "success" ? "✓" : type === "warning" ? "!" : "×"}</span><div><b>{title}</b><p>{toast.text}</p></div></div>;
}

export function Empty({ icon: Icon = Boxes, text, action }) {
  return <div className="empty"><Icon /><h3>{text}</h3>{action}</div>;
}

export function Field({ label, children, hint, className = "" }) {
  return <label className={`field ${className}`.trim()}><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}

export function PortInput({ value, onChange, min = 1, max = 65535, ...props }) {
  return <input {...props} type="text" inputMode="numeric" pattern="[0-9]*" value={value ?? ""} onChange={(event) => onChange?.(event.target.value.replace(/\D/g, "").slice(0, 5))} onBlur={(event) => {
    if (!event.target.value) return;
    const normalized = Math.min(max, Math.max(min, Number(event.target.value)));
    if (String(normalized) !== event.target.value) onChange?.(String(normalized));
  }} />;
}
