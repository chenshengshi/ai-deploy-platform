import React, {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createRoot } from "react-dom/client";
import { createPortal } from "react-dom";
import {
  Activity,
  Bot,
  Boxes,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  CircleUserRound,
  CloudCog,
  Code2,
  Copy,
  Database,
  Download,
  ExternalLink,
  FileArchive,
  FolderGit2,
  Gauge,
  KeyRound,
  LoaderCircle,
  LogOut,
  MessageSquareText,
  Network,
  Play,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Star,
  Square,
  Tag,
  Terminal,
  Trash2,
  Upload,
  Users,
  X,
} from "lucide-react";
import { api, login, logout, token } from "./api";
import "./styles.css";

const statusText = {
  queued: "等待中",
  running: "部署中",
  success: "运行中",
  failed: "失败",
  stopped: "已停止",
};

const sourcePhaseText = {
  queued: "等待处理",
  pulling: "正在拉取源码",
  analyzing: "正在分析源码",
  preflight: "正在预演校验",
  completed: "分析完成",
  failed: "处理失败",
  ready: "源码已保存",
};

const stripTerminalAnsi = (value) => String(value ?? "")
  .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
  .replace(/\r(?!\n)/g, "");

function projectSourceState(project) {
  const analysis = project?.source_analysis || {};
  const phase = analysis.phase || analysis.status || "ready";
  return { ...analysis, phase, label: sourcePhaseText[phase] || "准备源码" };
}

function AnalysisSummaryDetails({ text, label = "展开分析说明" }) {
  if (!text) return null;
  const items = String(text)
    .split(/(?=\s*\d+[.)、]\s*)/)
    .map((item) => item.trim())
    .filter(Boolean);
  return (
    <details className="source-analysis-details">
      <summary>{label}</summary>
      <ol>
        {(items.length > 1 ? items : [text]).map((item, index) => (
          <li key={`${index}-${String(item).slice(0, 20)}`}>{String(item).replace(/^\d+[.)、]\s*/, "")}</li>
        ))}
      </ol>
    </details>
  );
}

function projectAnalysisFacts(project) {
  const analysis = project?.source_analysis || {};
  if ((analysis.phase || analysis.status) !== "completed") return null;
  const environment = analysis.build_environment?.find((item) => item?.runtime_version || item?.language);
  const language = String(environment?.language || "").split("/")[0].trim();
  const runtime = String(environment?.runtime_version || "").split("（")[0].trim();
  const count = analysis.preflight?.service_count;
  return {
    summary: analysis.summary || "AI 已完成源码分析",
    facts: [
      count ? `方案含 ${count} 个服务` : null,
      language || null,
      runtime || null,
      analysis.deployment_kind === "compose" ? "Compose" : analysis.deployment_kind,
      analysis.preflight?.status === "passed" ? "静态预演通过" :
        analysis.preflight?.status === "needs_configuration" ? "静态预演待配置" :
          analysis.preflight ? "静态预演失败" : "尚未预演",
    ].filter(Boolean),
    services: (analysis.services || []).join(" · "),
  };
}

function projectCardState(project, deployments, startingIds = new Set()) {
  const source = projectSourceState(project);
  if (["queued", "pulling", "analyzing", "preflight", "running"].includes(source.phase)) {
    return { kind: "working", label: source.label, action: "查看进度" };
  }
  const records = deployments
    .filter((item) => item.project_id === project.id)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const starting = records.find((item) => startingIds.has(item.id));
  if (starting) return { kind: "working", label: "启动中", action: "启动中", deployment: starting };
  const pending = records.find((item) => ["queued", "running"].includes(item.status));
  const active = records.find((item) => item.status === "success");
  if (pending && active) return {
    kind: "online",
    label: "运行中",
    secondaryLabel: pending.status === "queued" ? "新版等待" : `新版 ${Number(pending.progress || 0)}%`,
    action: "访问",
    deployment: active,
    pendingDeployment: pending,
  };
  if (pending) return {
    kind: "working",
    label: pending.status === "queued" ? "等待部署" : `部署中 ${Number(pending.progress || 0)}%`,
    action: "查看进度",
    deployment: pending,
  };
  if (active) return { kind: "online", label: "运行中", action: "访问", deployment: active };
  const stopped = records.find((item) => item.status === "stopped" && item.release && item.access_url);
  if (stopped) return { kind: "stopped", label: "已停止", action: "重新启用", deployment: stopped };
  const latest = records[0];
  if (latest?.status === "failed") {
    return { kind: "error", label: "有异常", action: "查看原因", deployment: latest };
  }
  if (latest?.status === "stopped") {
    return { kind: "ready", label: "部署已停止", action: "重新部署" };
  }
  return {
    kind: source.phase === "failed" ? "error" : "ready",
    label: source.phase === "failed" ? "分析异常" : "分析完成",
    action: source.phase === "failed" ? "查看原因" : "部署",
  };
}
const statusClass = {
  queued: "warning",
  running: "info",
  success: "success",
  failed: "danger",
  stopped: "muted",
};
const roleText = { admin: "管理员", deployer: "发布人员", viewer: "只读人员" };
const defaultBranding = {
  system_name: "自助发布平台",
  short_name: "自助发布",
  system_subtitle: "应用交付平台",
  login_slogan: "一句话，把项目安全发布到服务器",
  logo_data_url: "",
  favicon_data_url: "",
};
const defaultFavicon = `data:image/svg+xml,${encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#756dff"/><stop offset="1" stop-color="#4f46e5"/></linearGradient></defs><rect width="64" height="64" rx="17" fill="url(#g)"/><path d="M20 39a9 9 0 0 1 2-17.8A13 13 0 0 1 47 25a7.5 7.5 0 0 1-1 14H20Z" fill="none" stroke="white" stroke-width="4" stroke-linecap="round"/><path d="M27 39v7m10-7v7" stroke="white" stroke-width="4" stroke-linecap="round"/></svg>',
)}`;

function BrandLogo({ branding, large = false }) {
  return (
    <div className={`logo${large ? " large" : ""}${branding?.logo_data_url ? " custom" : ""}`}>
      {branding?.logo_data_url ? <img src={branding.logo_data_url} alt="平台 Logo" /> : <CloudCog />}
    </div>
  );
}

function Login({ onDone, branding }) {
  const [form, setForm] = useState({ username: "admin", password: "" });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const updateField = (field, value) => {
    setForm((current) => ({ ...current, [field]: value }));
    if (err) setErr("");
  };
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await login(form.username, form.password);
      onDone();
    } catch (x) {
      setErr(x.message || "登录失败，请检查账号和密码");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login-shell">
      <div className="login-brand">
        <BrandLogo branding={branding} large />
        <h1>{branding.system_name}</h1>
        <p>{branding.login_slogan}</p>
        <div className="login-capabilities">
          <span><Bot /><b>AI 分析项目</b><small>识别架构与运行依赖</small></span>
          <span><Server /><b>自动部署</b><small>构建、启动并验证访问</small></span>
          <span><Activity /><b>持续管理</b><small>查看服务、日志和版本</small></span>
        </div>
      </div>
      <form className="login-card" onSubmit={submit}>
        <h2>欢迎回来</h2>
        <p className="sub">登录后管理项目与发布任务</p>
        <label>
          用户名
          <input
            value={form.username}
            autoComplete="username"
            aria-invalid={Boolean(err)}
            onChange={(e) => updateField("username", e.target.value)}
          />
        </label>
        <label>
          密码
          <input
            type="password"
            value={form.password}
            autoComplete="current-password"
            aria-invalid={Boolean(err)}
            onChange={(e) => updateField("password", e.target.value)}
          />
        </label>
        {err && <div className="login-error" role="alert">{err}</div>}
        <button className="primary full" disabled={busy}>
          {busy ? <LoaderCircle className="spin" /> : <KeyRound />}{busy ? "登录中..." : "登录"}
        </button>
      </form>
    </div>
  );
}

const nav = [
  ["dashboard", "工作台", Gauge],
  ["chat", "AI 发布", MessageSquareText],
  ["projects", "项目管理", FolderGit2],
  ["deployments", "部署记录", Activity],
  ["images", "镜像仓库", Boxes],
  ["nodes", "服务器节点", Server],
  ["users", "用户权限", Users],
  ["settings", "系统设置", Settings],
];

const modalStack = [];

function Modal({ title, children, onClose, wide = false, drawer = false, className = "", closeOnMask = false, scrollRef = null, onScroll = null, headerActions = null }) {
  const box = useRef(null),
    scrollTop = useRef(0);
  const modalId = useRef(Symbol("modal"));
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    const id = modalId.current;
    modalStack.push(id);
    const close = (e) => {
      if (e.key === "Escape" && modalStack[modalStack.length - 1] === id) {
        if (document.querySelector(".terminal-file-menu")) return;
        e.preventDefault();
        onCloseRef.current();
      }
    };
    window.addEventListener("keydown", close);
    return () => {
      window.removeEventListener("keydown", close);
      const index = modalStack.lastIndexOf(id);
      if (index >= 0) modalStack.splice(index, 1);
    };
  }, []);
  useLayoutEffect(() => {
    if (box.current && Math.abs(box.current.scrollTop - scrollTop.current) > 2)
      box.current.scrollTop = scrollTop.current;
  });
  return createPortal(
    (
    <div
      className={`modal-mask ${drawer ? "drawer-mask" : ""}`}
      onMouseDown={(e) => closeOnMask && e.target === e.currentTarget && onClose()}
    >
      <div
        ref={(node) => {
          box.current = node;
          if (scrollRef) scrollRef.current = node;
        }}
        onScroll={(e) => {
          scrollTop.current = e.currentTarget.scrollTop;
          onScroll?.(e);
        }}
        className={`modal ${wide ? "wide" : ""} ${drawer ? "drawer" : ""} ${className}`.trim()}
        role="dialog"
        aria-modal="true"
      >
        <div className="modal-head">
          <h3>{title}</h3>
          <div className="modal-head-actions">
            {headerActions}
            <button className="icon" title="关闭（Esc）" onClick={onClose}>
              <X />
            </button>
          </div>
        </div>
        {children}
      </div>
    </div>
    ),
    document.body,
  );
}
function ConfirmDialog({
  title,
  text,
  description = "操作后将立即生效，请确认后继续。",
  confirmText = "确认",
  danger = false,
  busy = false,
  onConfirm,
  onClose,
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <div className="confirm-body">
        <div className={danger ? "confirm-icon danger" : "confirm-icon"}>
          <Activity />
        </div>
        <div>
          <h4>{text}</h4>
          <p>{description}</p>
        </div>
      </div>
      <div className="modal-actions">
        <button className="ghost" disabled={busy} onClick={onClose}>
          取消
        </button>
        <button
          className={danger ? "danger-button" : "primary"}
          disabled={busy}
          onClick={onConfirm}
        >
          {busy && <LoaderCircle className="spin" />}
          {confirmText}
        </button>
      </div>
    </Modal>
  );
}
function DeleteDeploymentDialog({ item, busy, onConfirm, onClose }) {
  const [preview, setPreview] = useState(null),
    [error, setError] = useState("");
  useEffect(() => {
    api(`/deployments/${item.id}/delete-preview`)
      .then(setPreview)
      .catch((e) => setError(e.message));
  }, [item.id]);
  const labels = {
    containers: "容器",
    images: "应用镜像",
    registry_images: "镜像仓库版本",
    directories: "发布目录",
    gateway_files: "Nginx / 证书文件",
    records: "发布记录与日志",
  };
  return (
    <Modal title="删除本次发布" onClose={onClose} wide>
      <div className="confirm-body">
        <div className="confirm-icon danger">
          <Trash2 />
        </div>
        <div>
          <h4>
            确定删除“{item.project_name || item.id.slice(0, 8)}
            ”的这个发布版本吗？
          </h4>
          <p>
            版本 {item.release || item.id.slice(0, 8)} ·{" "}
            {item.node_name || "目标服务器"}
          </p>
        </div>
      </div>
      {!preview && !error ? (
        <div className="center delete-analysis-loading">
          <LoaderCircle className="spin" />
          <span>系统正在查询服务器，AI 正在分析本次清理范围...</span>
        </div>
      ) : (
        <>
          {preview && (
            <>
              <div className="panel security-card ai-delete-summary">
                <Bot />
                <div>
                  <h3>AI 清理分析</h3>
                  <p>{preview.ai_summary}</p>
                  <small>
                    {preview.ai?.source === "ai"
                      ? `由 ${preview.ai.model} 根据真实资源清单分析`
                      : "已按服务器真实资源清单分析"}
                  </small>
                </div>
              </div>
              <div className="delete-release-inventory">
                {Object.entries(labels).map(([key, label]) => (
                  <div key={key}>
                    <b>
                      {label}
                      <em>{preview.counts?.[key] || 0} 项</em>
                    </b>
                    {preview.resources?.[key]?.length ? (
                      <ul>
                        {preview.resources[key].map((x, i) => (
                          <li key={i}>
                            {typeof x === "string" ? x : x.name || x.path}
                            {x.node ? ` · ${x.node}` : ""}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <span>未发现可清理资源</span>
                    )}
                  </div>
                ))}
              </div>
              <div className="alert info">
                <b>明确保留：</b>
                {preview.preserved.join("、")}。
              </div>
              {preview.warnings?.map((x, i) => (
                <div className="alert warning" key={i}>
                  {x}
                </div>
              ))}
            </>
          )}
          {error && <div className="alert danger">资源分析失败：{error}</div>}
        </>
      )}
      <div className="modal-actions">
        <button className="ghost" disabled={busy} onClick={onClose}>
          取消
        </button>
        <button
          className="danger-button"
          disabled={busy || !preview}
          onClick={() => onConfirm(false)}
        >
          {busy ? <LoaderCircle className="spin" /> : <Trash2 />}
          {busy ? "正在逐项清理并复查..." : "删除清单中的本次发布资源"}
        </button>
      </div>
    </Modal>
  );
}

function BulkDeleteDeploymentDialog({ data, busy, onConfirm, onClose }) {
  const analyses = data?.analyses || [];
  const totalResources = {};
  analyses.forEach((row) => {
    Object.entries(row.preview?.resources || {}).forEach(([key, values]) => {
      if (!totalResources[key]) totalResources[key] = new Set();
      (values || []).forEach((value) => totalResources[key].add(JSON.stringify(value)));
    });
  });
  const totals = Object.fromEntries(Object.entries(totalResources).map(([key, values]) => [key, values.size]));
  const failed = analyses.filter((row) => row.error);
  return (
    <Modal title={`批量删除历史记录（${data.targets.length}）`} onClose={onClose} wide>
      <div className="confirm-body">
        <div className="confirm-icon danger"><Trash2 /></div>
        <div>
          <h4>已完成批量删除预检</h4>
          <p>当前线上、排队中和部署中的记录已自动排除；删除时核实实际资源，持久化业务数据默认保留。</p>
        </div>
      </div>
      {data.loading ? (
        <div className="center delete-analysis-loading">
          <LoaderCircle className="spin" />
          <span>正在并行扫描资源并由 AI 核对...</span>
        </div>
      ) : (
        <>
          <div className="bulk-delete-totals">
            <span>容器 <b>{totals.containers || 0}</b></span>
            <span>镜像 <b>{totals.images || 0}</b></span>
            <span>目录 <b>{totals.directories || 0}</b></span>
            <span>网关文件 <b>{totals.gateway_files || 0}</b></span>
            <span>记录 <b>{totals.records || 0}</b></span>
          </div>
          <div className="bulk-delete-analysis-list">
            {analyses.map(({ item, preview, error }) => (
              <div key={item.id} className={error ? "has-error" : ""}>
                <b>{item.release || item.id.slice(0, 8)}</b>
                <span>{error || preview?.ai_summary || "资源范围已核对"}</span>
                <em>{preview?.ai?.source === "ai" ? "AI 已分析" : error ? "无法删除" : "资源已核实"}</em>
              </div>
            ))}
          </div>
          {failed.length > 0 && <div className="alert warning">有 {failed.length} 条记录无法完成删除分析，将不会执行本次批量删除。</div>}
        </>
      )}
      <div className="modal-actions">
        <button className="ghost" disabled={busy} onClick={onClose}>取消</button>
        <button className="danger-button" disabled={busy || data.loading || failed.length > 0} onClick={onConfirm}>
          {busy && <LoaderCircle className="spin" />}
          确认清理并删除
        </button>
      </div>
    </Modal>
  );
}

function NetworkRouteDialog({ route, onClose }) {
  return (
    <Modal title="网络路由详情" onClose={onClose}>
      <div className="route-detail">
        <div className="route-code">
          <span>请求跟踪码</span>
          <code>{route.trace_code}</code>
        </div>
        <div className="route-flow">
          {route.route_steps.map((step, index) => (
            <React.Fragment key={step + index}>
              <span>{step}</span>
              {index < route.route_steps.length - 1 && <ChevronRight />}
            </React.Fragment>
          ))}
        </div>
        <div className="detail-list">
          <div>
            <span>连接方式</span>
            <b>{route.network_route === "proxy" ? "应用代理" : "服务器直连"}</b>
          </div>
          <div>
            <span>目标地址</span>
            <b>
              {route.target_host}:{route.target_port}
            </b>
          </div>
          <div>
            <span>DNS 解析</span>
            <b>{route.dns_ips?.join(", ") || "—"}</b>
          </div>
          <div>
            <span>实际连接节点</span>
            <b>{route.peer_ip || "—"}</b>
          </div>
          <div>
            <span>请求耗时</span>
            <b>{route.latency_ms} ms</b>
          </div>
        </div>
      </div>
      <div className="modal-actions">
        <button className="primary" onClick={onClose}>
          关闭
        </button>
      </div>
    </Modal>
  );
}
function Badge({ status }) {
  return (
    <span className={"badge " + (statusClass[status] || "muted")}>
      <i />
      {statusText[status] || status}
    </span>
  );
}
function Toast({ toast }) {
  const type = toast?.type || "success";
  return toast ? (
    <div className={"toast " + type}>
      <span>{type === "success" ? "✓" : type === "warning" ? "!" : "×"}</span>
      <div>
        <b>
          {type === "success"
            ? "操作成功"
            : type === "warning"
              ? "需要注意"
              : "操作失败"}
        </b>
        <p>{toast.text}</p>
      </div>
    </div>
  ) : null;
}
function Empty({ icon: Icon = Boxes, text, action }) {
  return (
    <div className="empty">
      <Icon />
      <h3>{text}</h3>
      {action}
    </div>
  );
}
function Field({ label, children, hint, className = "" }) {
  return (
    <label className={`field ${className}`.trim()}>
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}
function PortInput({ value, onChange, min = 1, max = 65535, ...props }) {
  return (
    <input
      {...props}
      type="text"
      inputMode="numeric"
      pattern="[0-9]*"
      value={value ?? ""}
      onChange={(event) => {
        const digits = event.target.value.replace(/\D/g, "").slice(0, 5);
        onChange?.(digits);
      }}
      onBlur={(event) => {
        if (!event.target.value) return;
        const normalized = Math.min(max, Math.max(min, Number(event.target.value)));
        if (String(normalized) !== event.target.value) onChange?.(String(normalized));
      }}
    />
  );
}
function validPort(value) {
  if (value === "" || value == null) return true;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}
function time(v) {
  return v ? new Date(v).toLocaleString("zh-CN") : "—";
}
async function copyText(text) {
  if (!text) throw new Error("没有可复制的内容");
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("浏览器拒绝复制");
}
function containerFileSize(bytes, type) {
  if (type === "directory") return "—";
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(value < 10240 ? 1 : 0)} KB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(value < 10 * 1024 ** 2 ? 1 : 0)} MB`;
  return `${(value / 1024 ** 3).toFixed(1)} GB`;
}
function containerFileTime(seconds) {
  if (!seconds) return "时间未知";
  return new Date(Number(seconds) * 1000).toLocaleString("zh-CN", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
  });
}
function HighlightedLogs({ text, query }) {
  if (!query) return text || "当前没有日志输出";
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matcher = new RegExp(`(${escaped})`, "ig");
  const lower = query.toLowerCase();
  const lines = String(text || "").split("\n").filter((line) => line.toLowerCase().includes(lower));
  if (!lines.length) return "没有找到匹配日志";
  return lines.map((line, lineIndex) => <React.Fragment key={`${lineIndex}-${line.slice(0, 30)}`}>{line.split(matcher).map((part, partIndex) => part.toLowerCase() === lower ? <mark key={partIndex}>{part}</mark> : part)}{lineIndex < lines.length - 1 ? "\n" : ""}</React.Fragment>);
}
function longestCommonPrefix(values) {
  if (!values.length) return "";
  let prefix = values[0];
  for (const value of values.slice(1)) {
    while (prefix && !value.startsWith(prefix)) prefix = prefix.slice(0, -1);
  }
  return prefix;
}
function deploymentDuration(item) {
  const start = item?.started_at || item?.created_at;
  if (!start) return "—";
  const terminal = ["success", "failed", "stopped"].includes(item.status);
  const end = terminal && item.finished_at ? new Date(item.finished_at) : new Date();
  const seconds = Math.max(0, Math.floor((end - new Date(start)) / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  return `${terminal ? "耗时" : "已用时"} ${hours ? `${hours}小时` : ""}${minutes ? `${minutes}分` : ""}${rest}秒`;
}

function analysisDuration(item) {
  const start = item?.started_at || item?.queued_at;
  if (!start) return "等待计时";
  const terminal = ["completed", "failed"].includes(item?.status);
  const end = terminal && item?.finished_at ? new Date(item.finished_at) : new Date();
  const seconds = Math.max(0, Math.floor((end - new Date(start)) / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  return `${terminal ? "分析耗时" : "分析已用时"} ${hours ? `${hours}小时` : ""}${minutes ? `${minutes}分` : ""}${rest}秒`;
}

function stageDuration(value) {
  if (value === null || value === undefined) return "";
  const seconds = Math.max(0, Number(value) || 0);
  if (seconds < 1) return `${Math.round(seconds * 1000)}毫秒`;
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)}秒`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes}分${rest}秒`;
}

function deploymentFileMeta(file) {
  const path = String(file?.path || "");
  const name = path.split("/").pop();
  const rules = [
    [/\.yunzhou\.ai\.compose\.ya?ml$/i, 10, "主编排"],
    [/\.yunzhou\.app\.ya?ml$/i, 20, "应用配置"],
    [/\.yunzhou\.data\.ya?ml$/i, 30, "数据服务"],
    [/\.yunzhou\.app-images\.ya?ml$/i, 40, "运行镜像"],
    [/\.yunzhou\.images\.ya?ml$/i, 50, "镜像配置"],
    [/\.yunzhou\.proxy-build\.ya?ml$/i, 60, "构建代理"],
    [/dockerfile/i, 70, "构建文件"],
    [/nginx/i, 80, "Nginx 配置"],
    [/(^|\/)\.env(?:\.|$)/i, 90, "环境配置"],
  ];
  const matched = rules.find(([pattern]) => pattern.test(path));
  return { priority: matched?.[1] ?? 100, label: matched?.[2] || "关联文件", name };
}

function shortRelease(value) {
  const text = String(value || "");
  if (/^\d{12}(?:\d{2}|-\d{2})?$/.test(text)) {
    const sequence = text.includes("-") ? ` #${Number(text.split("-")[1])}` : "";
    return text.slice(4, 6) + "-" + text.slice(6, 8) + " " + text.slice(8, 10) + ":" + text.slice(10, 12) + sequence;
  }
  return text ? "v" + (text.length > 16 ? text.slice(0, 16) + "…" : text) : "";
}

class PageErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error) {
    return { error };
  }
  componentDidCatch(error, info) {
    console.error("页面渲染失败", error, info);
  }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="empty page-error">
        <Activity />
        <h3>页面暂时没有加载成功</h3>
        <p>{this.state.error.message || "服务可能正在恢复，请稍后重试"}</p>
        <button
          className="primary"
          onClick={() => this.setState({ error: null })}
        >
          <RefreshCw />
          重新加载页面
        </button>
      </div>
    );
  }
}

function App() {
  const [me, setMe] = useState(null),
    [page, setPage] = useState("dashboard"),
    [loading, setLoading] = useState(true),
    [branding, setBranding] = useState(defaultBranding);
  const load = async () => {
    try {
      setMe(await api("/auth/me"));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    api("/branding").then(setBranding).catch(() => {});
    if (token()) load();
    else setLoading(false);
    const syncBranding = (event) => setBranding(event.detail);
    window.addEventListener("branding-updated", syncBranding);
    return () => window.removeEventListener("branding-updated", syncBranding);
  }, []);
  useEffect(() => {
    const stopNumberWheel = (event) => {
      const target = event.target;
      if (target instanceof HTMLInputElement && target.type === "number") {
        target.blur();
      }
    };
    window.addEventListener("wheel", stopNumberWheel, { capture: true, passive: true });
    return () => window.removeEventListener("wheel", stopNumberWheel, { capture: true });
  }, []);
  useEffect(() => {
    const currentAsset = [...document.scripts].map((item) => item.src).find((src) => src.includes("/assets/index-"));
    if (!currentAsset) return undefined;
    const timer = setInterval(async () => {
      if (document.hidden || document.querySelector(".modal")) return;
      try {
        const html = await fetch(`/?check=${Date.now()}`, { cache: "no-store" }).then((response) => response.text());
        const nextAsset = html.match(/src="([^"]*\/assets\/index-[^"]+\.js)"/)?.[1];
        if (nextAsset && !currentAsset.endsWith(nextAsset)) window.location.reload();
      } catch (_) {}
    }, 30000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    document.title = branding.system_name;
    let icon = document.querySelector("link[rel='icon']");
    if (!icon) {
      icon = document.createElement("link");
      icon.rel = "icon";
      document.head.appendChild(icon);
    }
    icon.href = branding.favicon_data_url || branding.logo_data_url || defaultFavicon;
  }, [branding]);
  if (loading)
    return (
      <div className="center">
        <LoaderCircle className="spin" />
      </div>
    );
  if (!me) return <Login onDone={load} branding={branding} />;
  const allowed = (item) => item[0] === "images"
    ? me.role !== "viewer"
    : !["nodes", "users", "settings"].includes(item[0]) || me.role === "admin";
  return (
    <div className="app">
      <aside>
        <div className="brand">
          <BrandLogo branding={branding} />
          <div>
            <b>{branding.short_name}</b>
            <span>{branding.system_subtitle}</span>
          </div>
        </div>
        <nav>
          {nav.filter(allowed).map(([id, label, Icon]) => (
            <button
              key={id}
              className={page === id ? "active" : ""}
              onClick={() => setPage(id)}
            >
              <Icon />
              <span>{label}</span>
              {page === id && <ChevronRight className="tail" />}
            </button>
          ))}
        </nav>
      </aside>
      <main className={page === "chat" ? "chat-page-shell" : ""}>
        <Top page={page} me={me} branding={branding} onBrandingChange={setBranding} />
        <section className="content">
          <PageErrorBoundary key={page}>
            {page === "dashboard" && <Dashboard setPage={setPage} />}{" "}
            {page === "chat" && <Chat />}{" "}
            {page === "projects" && <Projects me={me} />}{" "}
            {page === "deployments" && <Deployments />}{" "}
            {page === "images" && <ImageRepository me={me} />}{" "}
            {page === "nodes" && <Nodes />} {page === "users" && <UsersPage />}{" "}
            {page === "settings" && <SettingsPage />}
          </PageErrorBoundary>
        </section>
      </main>
    </div>
  );
}

function PasswordDialog({ onClose }) {
  const [form, setForm] = useState({
      current_password: "",
      new_password: "",
      confirm: "",
    }),
    [busy, setBusy] = useState(false),
    [err, setErr] = useState("");
  const save = async () => {
    if (form.new_password !== form.confirm) {
      setErr("两次输入的新密码不一致");
      return;
    }
    setBusy(true);
    setErr("");
    try {
      await api("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          current_password: form.current_password,
          new_password: form.new_password,
        }),
      });
      onClose(true);
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="修改登录密码" onClose={() => onClose(false)}>
      <div className="form-grid one">
        <Field label="当前密码">
          <input
            type="password"
            autoFocus
            value={form.current_password}
            onChange={(e) =>
              setForm({ ...form, current_password: e.target.value })
            }
          />
        </Field>
        <Field label="新密码" hint="至少 8 位">
          <input
            type="password"
            value={form.new_password}
            onChange={(e) => setForm({ ...form, new_password: e.target.value })}
          />
        </Field>
        <Field label="再次输入新密码">
          <input
            type="password"
            value={form.confirm}
            onChange={(e) => setForm({ ...form, confirm: e.target.value })}
          />
        </Field>
      </div>
      {err && <div className="alert danger">{err}</div>}
      <div className="modal-actions">
        <button className="ghost" onClick={() => onClose(false)}>
          取消
        </button>
        <button
          className="primary"
          disabled={
            busy ||
            !form.current_password ||
            form.new_password.length < 8 ||
            !form.confirm
          }
          onClick={save}
        >
          {busy ? <LoaderCircle className="spin" /> : <KeyRound />}确认修改
        </button>
      </div>
    </Modal>
  );
}

function BrandingDialog({ branding, onClose, onSaved }) {
  const [form, setForm] = useState(branding),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const chooseImage = (field, maxBytes) => (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (!/^image\/(png|jpeg|webp|x-icon|vnd\.microsoft\.icon)$/i.test(file.type)) {
      setError("仅支持 PNG、JPG、WebP 或 ICO 图片");
      return;
    }
    if (file.size > maxBytes) {
      setError(field === "favicon_data_url" ? "页签图标不能超过 300 KB" : "Logo 不能超过 1 MB");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => setForm((value) => ({ ...value, [field]: reader.result }));
    reader.readAsDataURL(file);
  };
  const save = async () => {
    setBusy(true);
    setError("");
    try {
      const saved = await api("/settings/branding", {
        method: "PUT",
        body: JSON.stringify(form),
      });
      onSaved(saved);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="平台外观" onClose={onClose} wide>
      <div className="branding-editor">
        <div className="branding-preview">
          <BrandLogo branding={form} large />
          <div><b>{form.system_name || "系统名称"}</b><span>{form.login_slogan || "登录页说明"}</span></div>
        </div>
        <div className="form-grid two">
          <Field label="系统名称" hint="登录页标题和浏览器页签名称">
            <input value={form.system_name} maxLength={100} onChange={(e) => setForm({ ...form, system_name: e.target.value })} />
          </Field>
          <Field label="侧边栏简称" hint="建议 2～6 个字">
            <input value={form.short_name} maxLength={40} onChange={(e) => setForm({ ...form, short_name: e.target.value })} />
          </Field>
          <Field label="侧边栏副标题">
            <input value={form.system_subtitle} maxLength={120} onChange={(e) => setForm({ ...form, system_subtitle: e.target.value })} />
          </Field>
          <Field label="登录页说明">
            <input value={form.login_slogan} maxLength={200} onChange={(e) => setForm({ ...form, login_slogan: e.target.value })} />
          </Field>
        </div>
        <div className="branding-images">
          <div>
            <b>平台 Logo</b><span>用于登录页和左侧导航，推荐正方形透明 PNG</span>
            <div className="branding-image-preview"><BrandLogo branding={form} /></div>
            <label className="ghost button"><Upload />选择图片<input type="file" accept="image/png,image/jpeg,image/webp" onChange={chooseImage("logo_data_url", 1024 * 1024)} /></label>
            {form.logo_data_url && <button className="ghost" onClick={() => setForm({ ...form, logo_data_url: "" })}>恢复默认</button>}
          </div>
          <div>
            <b>浏览器页签图标</b><span>推荐 32×32 PNG 或 ICO</span>
            <div className="branding-image-preview favicon"><img src={form.favicon_data_url || defaultFavicon} alt="页签图标预览" /></div>
            <label className="ghost button"><Upload />选择图标<input type="file" accept="image/png,image/x-icon,image/vnd.microsoft.icon" onChange={chooseImage("favicon_data_url", 300 * 1024)} /></label>
            {form.favicon_data_url && <button className="ghost" onClick={() => setForm({ ...form, favicon_data_url: "" })}>恢复默认</button>}
          </div>
        </div>
      </div>
      {error && <div className="alert danger">{error}</div>}
      <div className="modal-actions">
        <button className="ghost" disabled={busy} onClick={onClose}>取消</button>
        <button className="primary" disabled={busy || !form.system_name.trim() || !form.short_name.trim()} onClick={save}>
          {busy && <LoaderCircle className="spin" />}保存并应用
        </button>
      </div>
    </Modal>
  );
}

function Top({ page, me, branding, onBrandingChange }) {
  const item = nav.find((x) => x[0] === page),
    [open, setOpen] = useState(false),
    [password, setPassword] = useState(false),
    [brandingOpen, setBrandingOpen] = useState(false),
    [saved, setSaved] = useState(false);
  return (
    <header>
      <div>
        <h1>{item?.[1]}</h1>
        <p>
          {page === "chat"
            ? "用自然语言创建发布任务"
            : "管理你的应用与发布资源"}
        </p>
      </div>
      <div className="header-account">
        <div className="user-pill">
          <span className="online-dot" />
          系统正常
        </div>
        <button className="account-trigger" onClick={() => setOpen((x) => !x)}>
          <CircleUserRound />
          <span>
            <b>{me.display_name || me.username}</b>
            <small>{roleText[me.role]}</small>
          </span>
          <ChevronRight className={open ? "open" : ""} />
        </button>
        {open && (
          <div className="account-menu">
            <div>
              <b>{me.display_name || me.username}</b>
              <small>
                @{me.username} · {roleText[me.role]}
              </small>
            </div>
            <button
              onClick={() => {
                setOpen(false);
                setPassword(true);
              }}
            >
              <KeyRound />
              修改密码
            </button>
            {me.role === "admin" && (
              <button onClick={() => { setOpen(false); setBrandingOpen(true); }}>
                <CloudCog />
                平台外观
              </button>
            )}
            <button onClick={logout}>
              <LogOut />
              退出登录
            </button>
          </div>
        )}
        {saved && <div className="password-saved">密码修改成功</div>}
        {password && (
          <PasswordDialog
            onClose={(ok) => {
              setPassword(false);
              if (ok) {
                window.alert("密码修改成功，请重新登录");
                logout();
              }
            }}
          />
        )}
        {brandingOpen && (
          <BrandingDialog
            branding={branding}
            onClose={() => setBrandingOpen(false)}
            onSaved={(value) => {
              onBrandingChange(value);
              setBrandingOpen(false);
            }}
          />
        )}
      </div>
    </header>
  );
}

function Dashboard({ setPage }) {
  const [data, setData] = useState(null),
    [selected, setSelected] = useState(null);
  const loadDashboard = () => api("/dashboard").then(setData);
  useEffect(() => {
    loadDashboard();
  }, []);
  if (!data) return <Loader />;
  const cards = [
    ["项目总数", data.projects, FolderGit2, "violet"],
    ["服务器节点", data.nodes, Server, "cyan"],
    ["进行中的部署", data.running, LoaderCircle, "amber"],
    ["成功部署", data.success, ShieldCheck, "green"],
  ];
  return (
    <>
      <div className="hero">
        <div>
          <span className="eyebrow">
            <Bot /> AI 发布助手已就绪
          </span>
          <h2>今天要发布什么？</h2>
          <p>选择项目和服务器，或者直接告诉 AI 你的发布需求。</p>
          <button className="primary" onClick={() => setPage("chat")}>
            <MessageSquareText />
            开始 AI 发布
          </button>
        </div>
        <div className="hero-art">
          <CloudCog />
        </div>
      </div>
      <div className="stats">
        {cards.map(([t, n, I, c]) => (
          <div className="stat" key={t}>
            <div className={"stat-icon " + c}>
              <I />
            </div>
            <div>
              <span>{t}</span>
              <b>{n}</b>
            </div>
          </div>
        ))}
      </div>
      <div className="panel">
        <div className="panel-head">
          <div>
            <h3>最近部署</h3>
            <p>最新的项目发布状态</p>
          </div>
          <button className="ghost" onClick={() => setPage("deployments")}>
            查看全部
            <ChevronRight />
          </button>
        </div>
        {data.recent.length ? (
          <DeploymentTable items={data.recent} onSelect={setSelected} />
        ) : (
          <Empty text="还没有部署记录" />
        )}
      </div>
      {selected && (
        <DeploymentDetail
          item={selected}
          onClose={() => setSelected(null)}
          onChanged={loadDashboard}
        />
      )}
    </>
  );
}

function ChatMessageContent({ text }) {
  const lines = String(text || "").split("\n");
  const blocks = [];
  let plain = [];
  const flushPlain = () => {
    if (plain.length) blocks.push({ type: "text", lines: plain });
    plain = [];
  };
  for (let index = 0; index < lines.length; index += 1) {
    const fence = lines[index].trim().match(/^```(\w*)$/);
    if (!fence) {
      plain.push(lines[index]);
      continue;
    }
    flushPlain();
    const body = [];
    for (index += 1; index < lines.length && lines[index].trim() !== "```"; index += 1) body.push(lines[index]);
    blocks.push({ type: fence[1] || "code", lines: body });
  }
  flushPlain();
  const renderLine = (line, index, prefix) => {
    const value = line.trim();
    if (!value) return <div className="message-gap" key={`${prefix}-${index}`} />;
    const heading = value.match(/^(结论|当前状态|关键依据|查询结果|下一步(?:建议)?|说明)[:：]?\s*(.*)$/);
    if (heading) return <div className="message-section" key={`${prefix}-${index}`}><b>{heading[1]}</b>{heading[2] && <span>{heading[2]}</span>}</div>;
    const numbered = value.match(/^([0-9]+)[.)、]\s*(.*)$/);
    if (numbered) return <div className="message-list-line" key={`${prefix}-${index}`}><i>{numbered[1]}</i><span>{numbered[2]}</span></div>;
    return <div className="message-line" key={`${prefix}-${index}`}>{line}</div>;
  };
  return (
    <div className="message-copy">
      {blocks.map((block, blockIndex) => {
        if (block.type !== "table") return block.type === "text"
          ? block.lines.map((line, index) => renderLine(line, index, blockIndex))
          : <pre className="message-code" key={blockIndex}>{block.lines.join("\n")}</pre>;
        const rows = block.lines.filter(Boolean).map((line) => line.split("\t"));
        if (!rows.length) return <div className="query-empty" key={blockIndex}>查询成功，没有返回数据</div>;
        const width = Math.max(...rows.map((row) => row.length));
        return (
          <div className="query-result" key={blockIndex}>
            <div className="query-table-wrap">
              <table>
                <thead><tr>{Array.from({ length: width }, (_, index) => <th key={index}>{rows[0][index] || `字段 ${index + 1}`}</th>)}</tr></thead>
                <tbody>{rows.slice(1).map((row, rowIndex) => <tr key={rowIndex}>{Array.from({ length: width }, (_, index) => <td key={index} title={row[index] || ""}>{row[index] || "—"}</td>)}</tr>)}</tbody>
              </table>
            </div>
          </div>
        );
      })}
    </div>
  );
}

const MemoChatMessageContent = React.memo(ChatMessageContent);

function Chat() {
  const greeting = "你好，我是自助发布助手。你可以直接问我项目状态、故障原因，或告诉我发布要求。对话会自动保存。";
  const [projects, setProjects] = useState([]),
    [nodes, setNodes] = useState([]),
    [aiConfigs, setAiConfigs] = useState([]),
    [project, setProject] = useState(""),
    [node, setNode] = useState(""),
    [aiConfig, setAiConfig] = useState(""),
    [defaultAiConfig, setDefaultAiConfig] = useState(""),
    [text, setText] = useState(""),
    [busy, setBusy] = useState(false),
    [aiElapsed, setAiElapsed] = useState(0),
    [showUpload, setShowUpload] = useState(false),
    [sessions, setSessions] = useState([]),
    [sessionId, setSessionId] = useState(null),
    [showArchived, setShowArchived] = useState(false),
    [sessionsExpanded, setSessionsExpanded] = useState(false),
    [sessionBusy, setSessionBusy] = useState(false),
    [cleanupOpen, setCleanupOpen] = useState(false),
    [cleanupConfirm, setCleanupConfirm] = useState(""),
    [deleteTarget, setDeleteTarget] = useState(null),
    [selectedDeployment, setSelectedDeployment] = useState(null),
    [messages, setMessages] = useState([
      {
        who: "ai",
        text: greeting,
      },
    ]),
    [intent, setIntent] = useState(null);
  const messagesEndRef = useRef(null), textareaRef = useRef(null);
  useEffect(() => {
    requestAnimationFrame(() => messagesEndRef.current?.scrollIntoView({ block: "end", behavior: "smooth" }));
  }, [messages, busy, sessionId]);
  useEffect(() => {
    if (!busy) {
      setAiElapsed(0);
      return undefined;
    }
    const started = Date.now();
    const timer = setInterval(() => setAiElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(timer);
  }, [busy]);
  const loadSessions = (archived = showArchived) =>
    api(`/chat/sessions?archived=${archived}`).then(setSessions);
  useEffect(() => {
    Promise.all([
      api("/projects"),
      api("/nodes"),
      api("/settings/ai/configs"),
    ]).then(([p, n, a]) => {
      setProjects(p);
      setNodes(n);
      const enabled = a.filter((x) => x.enabled);
      const preferred = enabled.find((x) => x.is_default) || enabled[0];
      setAiConfigs(enabled);
      setDefaultAiConfig(preferred?.id || "");
      setAiConfig(preferred?.id || "");
    });
    loadSessions(false);
  }, []);
  const newConversation = () => {
    setSessionId(null);
    setMessages([{ who: "ai", text: greeting }]);
    setIntent(null);
    setAiConfig(defaultAiConfig);
  };
  const openSession = async (id) => {
    setSessionBusy(true);
    try {
      const data = await api(`/chat/sessions/${id}/messages`);
      setSessionId(id);
      setProject(data.session.project_id || "");
      setNode(data.session.node_id || "");
      const restoredModel = aiConfigs.some((item) => item.id === data.session.ai_config_id)
        ? data.session.ai_config_id
        : defaultAiConfig;
      setAiConfig(restoredModel || "");
      setIntent(null);
      setMessages(data.messages.map((item) => ({
        who: item.role === "assistant" ? "ai" : "user",
        text: item.content,
        deployment: item.deployment_id,
        action: item.action,
      })));
    } finally {
      setSessionBusy(false);
    }
  };
  const archiveCurrent = async () => {
    if (!sessionId) return;
    await api(`/chat/sessions/${sessionId}/archive`, { method: "POST" });
    newConversation();
    loadSessions();
  };
  const restoreSession = async (id) => {
    await api(`/chat/sessions/${id}/restore`, { method: "POST" });
    await loadSessions(true);
  };
  const deleteSession = async () => {
    if (!deleteTarget) return;
    const id = deleteTarget.id;
    setSessionBusy(true);
    try {
      await api(`/chat/sessions/${id}`, { method: "DELETE" });
      setDeleteTarget(null);
      if (sessionId === id) newConversation();
      await loadSessions();
    } finally {
      setSessionBusy(false);
    }
  };
  const changeArchiveView = (value) => {
    setShowArchived(value);
    setSessionsExpanded(false);
    setSessionBusy(true);
    api(`/chat/sessions?archived=${value}`).then(setSessions).finally(() => setSessionBusy(false));
  };
  const purgeArchived = async () => {
    if (cleanupConfirm !== "永久清理对话") return;
    setSessionBusy(true);
    try {
      await api("/chat/sessions/purge", {
        method: "POST",
        body: JSON.stringify({ scope: "mine", archived_only: true, confirm: cleanupConfirm }),
      });
      setCleanupOpen(false);
      setCleanupConfirm("");
      await loadSessions(true);
    } finally {
      setSessionBusy(false);
    }
  };
  const send = async () => {
    if (!text.trim() || busy) return;
    const msg = text;
    setText("");
    setMessages((x) => [...x, { who: "user", text: msg }]);
    setBusy(true);
    try {
      const r = await api("/chat", {
        method: "POST",
        body: JSON.stringify({
          message: msg,
          project_id: project || null,
          node_id: node || null,
          ai_config_id: aiConfig || null,
          intent,
          session_id: sessionId,
          history: messages.slice(-10).map((item) => ({
            role: item.who === "ai" ? "assistant" : "user",
            content: item.text,
          })),
        }),
      });
      if (r.project_id) setProject(r.project_id);
      if (r.node_id) setNode(r.node_id);
      if (r.session_id) setSessionId(r.session_id);
      setIntent(r.intent || null);
      setMessages((x) => [
        ...x,
        { who: "ai", text: r.reply, deployment: r.deployment_id, action: r.action },
      ]);
      loadSessions();
    } catch (e) {
      setMessages((x) => [...x, { who: "ai", text: e.message, error: true }]);
    } finally {
      setBusy(false);
      requestAnimationFrame(() => textareaRef.current?.focus());
    }
  };
  const openDeployment = async (id) => {
    try {
      setSelectedDeployment(await api(`/deployments/${id}`));
    } catch (error) {
      setMessages((current) => [...current, {
        who: "ai",
        text: `无法打开发布记录：${error.message || "记录可能已被删除"}`,
        error: true,
      }]);
    }
  };
  return (
    <>
      <div className="chat-layout">
        <div className="chat-main">
          <div className="chat-messages">
            {messages.map((m, i) => (
              <div
                className={"message " + m.who + (m.error ? " error" : "")}
                key={i}
              >
                {m.who === "ai" && (
                  <div className="avatar">
                    <Bot />
                  </div>
                )}
                <div>
                  <MemoChatMessageContent text={m.text} />
                  {m.deployment && (
                    <button type="button" className="chat-deployment-link" onClick={() => openDeployment(m.deployment)}>
                      <Activity />
                      {m.action === "deploy"
                        ? "任务已进入部署队列"
                        : m.action === "existing_deployment"
                          ? "查看进行中的部署任务"
                          : "查看发布记录"}
                    </button>
                  )}
                </div>
              </div>
            ))}
            {busy && (
              <div className="message ai">
                <div className="avatar">
                  <Bot />
                </div>
                <div>
                  <LoaderCircle className="spin" /> {aiElapsed < 2
                    ? "正在整理项目上下文..."
                    : aiElapsed < 8
                      ? "AI 正在分析并生成回答..."
                      : "AI 上游响应较慢，仍在等待..."}{aiElapsed > 0 ? ` · ${aiElapsed}秒` : ""}
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
          <div className="composer">
            <textarea
              ref={textareaRef}
              placeholder="例如：把这个项目部署到测试服务器"
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  send();
                }
              }}
            />
            <button className="primary" onClick={send}>
              <Play />
            </button>
            <small>AI 只能调用受控发布动作，不会执行任意服务器命令</small>
          </div>
        </div>
        <aside className="context">
          <div className="chat-history-head">
            <h3>对话记录 <span>{sessions.length}</span></h3>
            <button className="icon" title="新对话" onClick={newConversation}><Plus /></button>
          </div>
          <div className="chat-history-tabs">
            <button className={!showArchived ? "active" : ""} onClick={() => changeArchiveView(false)}>最近</button>
            <button className={showArchived ? "active" : ""} onClick={() => changeArchiveView(true)}>已归档</button>
          </div>
          <div className={`chat-session-list ${sessionsExpanded ? "expanded" : ""}`}>
            {sessionBusy && <div className="chat-session-empty"><LoaderCircle className="spin" /> 正在读取...</div>}
            {!sessionBusy && !sessions.length && <div className="chat-session-empty">{showArchived ? "没有已归档对话" : "还没有保存的对话"}</div>}
            {!sessionBusy && (sessionsExpanded ? sessions : sessions.slice(0, 5)).map((item) => (
              <div className={`chat-session-item ${sessionId === item.id ? "active" : ""}`} key={item.id}>
                <button className="chat-session-open" onClick={() => openSession(item.id)}>
                  <b>{item.title}</b>
                  <span>{item.project_name} · {item.message_count} 条</span>
                </button>
                {showArchived ? (
                  <div className="chat-session-actions">
                    <button title="恢复" onClick={() => restoreSession(item.id)}><RefreshCw /></button>
                    <button title="永久删除" onClick={() => setDeleteTarget(item)}><Trash2 /></button>
                  </div>
                ) : sessionId === item.id ? (
                  <button className="chat-session-archive" title="归档当前对话" onClick={archiveCurrent}><FileArchive /></button>
                ) : null}
              </div>
            ))}
          </div>
          {!sessionBusy && sessions.length > 5 && (
            <button className="chat-session-expand" onClick={() => setSessionsExpanded((value) => !value)}>
              {sessionsExpanded ? "收起对话" : `展开全部（${sessions.length}）`}
            </button>
          )}
          {showArchived && (
            <div className="chat-history-tools">
              <button className="ghost danger-text" disabled={!sessions.length} onClick={() => setCleanupOpen(true)}><Trash2 />清理归档</button>
            </div>
          )}
          <div className="context-divider" />
          <h3>对话设置</h3>
          <Field label="AI 模型">
            <select
              value={aiConfig}
              onChange={(e) => setAiConfig(e.target.value)}
            >
              <option value="">系统默认</option>
              {aiConfigs.map((x) => (
                <option value={x.id} key={x.id}>
                  {x.provider_name} · {x.model}{x.is_default ? "（默认）" : ""}
                </option>
              ))}
            </select>
          </Field>
          <div className="chat-context-grid">
            <Field label="关联项目">
              <select value={project} onChange={(e) => setProject(e.target.value)}>
                <option value="">请选择</option>
                {projects.map((x) => <option value={x.id} key={x.id}>{x.name}</option>)}
              </select>
            </Field>
            <Field label="目标服务器">
              <select value={node} onChange={(e) => setNode(e.target.value)}>
                <option value="">请选择</option>
                {nodes.map((x) => <option value={x.id} key={x.id}>{x.name} · {x.last_status}</option>)}
              </select>
            </Field>
          </div>
          <button className="ghost full chat-upload-project" onClick={() => setShowUpload(true)}>
            <Upload />上传新项目交给 AI
          </button>
        </aside>
      </div>
      {showUpload && (
        <ProjectModal
          deployImmediately={false}
          onClose={() => setShowUpload(false)}
          onDone={(p) => {
            setShowUpload(false);
            api("/projects").then((items) => {
              setProjects(items);
              setProject(p.id);
            });
            setMessages((x) => [
              ...x,
              {
                who: "ai",
                text: `项目“${p.name}”上传完成，已自动选中。请选择目标服务器，然后告诉我部署要求。`,
              },
            ]);
          }}
        />
      )}
      {cleanupOpen && (
        <Modal title="永久清理已归档对话" onClose={() => setCleanupOpen(false)}>
          <div className="chat-cleanup-copy">
            <p>这会永久删除你账号下全部已归档对话，无法恢复。正常对话和项目不会受影响。</p>
            <label>输入“永久清理对话”确认
              <input value={cleanupConfirm} onChange={(e) => setCleanupConfirm(e.target.value)} autoFocus />
            </label>
          </div>
          <div className="modal-actions">
            <button className="ghost" onClick={() => setCleanupOpen(false)}>取消</button>
            <button className="danger-button" disabled={cleanupConfirm !== "永久清理对话" || sessionBusy} onClick={purgeArchived}>
              {sessionBusy ? <LoaderCircle className="spin" /> : <Trash2 />}永久清理
            </button>
          </div>
        </Modal>
      )}
      {deleteTarget && (
        <ConfirmDialog
          title="永久删除对话"
          text={`确定删除“${deleteTarget.title}”？`}
          description="该对话及其中的全部消息会被永久删除，无法恢复；项目和部署记录不受影响。"
          confirmText="永久删除"
          danger
          busy={sessionBusy}
          onClose={() => setDeleteTarget(null)}
          onConfirm={deleteSession}
        />
      )}
      {selectedDeployment && (
        <DeploymentDetail
          item={selectedDeployment}
          onChanged={() => openDeployment(selectedDeployment.id)}
          onClose={() => setSelectedDeployment(null)}
        />
      )}
    </>
  );
}

function Projects({ me }) {
  const [items, setItems] = useState([]),
    [deployments, setDeployments] = useState([]),
    [projectFilter, setProjectFilter] = useState("all"),
    [show, setShow] = useState(false),
    [showCredential, setShowCredential] = useState(false),
    [selected, setSelected] = useState(null),
    [selectedDeployment, setSelectedDeployment] = useState(null),
    [detailRevision, setDetailRevision] = useState(0),
    [domainFor, setDomainFor] = useState(null),
    [startingIds, setStartingIds] = useState(() => new Set()),
    [toast, setToast] = useState(null);
  const listRefreshPendingRef = useRef(false);
  const load = () => {
    if (listRefreshPendingRef.current) return Promise.resolve();
    listRefreshPendingRef.current = true;
    return Promise.all([api("/projects"), api("/deployments")])
      .then(([projects, records]) => {
        setItems(projects);
        setDeployments(records);
      })
      .finally(() => { listRefreshPendingRef.current = false; });
  };
  useEffect(() => {
    load();
  }, []);
  const hasActiveCardWork = items.some((item) =>
    ["queued", "pulling", "analyzing", "preflight", "running"].includes(projectSourceState(item).phase),
  ) || deployments.some((item) => ["queued", "running"].includes(item.status));
  useEffect(() => {
    // Keep the project cards synchronized even while a detail modal is open.
    // Active work is refreshed quickly; idle pages use a slower interval.
    const timer = setInterval(() => {
      if (!document.hidden) load();
    }, hasActiveCardWork ? 4000 : 15000);
    return () => clearInterval(timer);
  }, [hasActiveCardWork]);
  const notify = (text, type = "success", duration = 3000) => {
    setToast({ text, type });
    setTimeout(() => setToast(null), duration);
  };
  const track = (project) => {
    setShow(false);
    notify("项目已创建，正在后台准备和分析源码", "success", 6000);
    load();
  };
  const projectStates = items.map((project) => ({ project, state: projectCardState(project, deployments, startingIds) }));
  const filterGroup = (kind) => kind === "online" ? "online" : kind === "stopped" ? "stopped" : kind === "error" ? "error" : "pending";
  const projectCounts = projectStates.reduce((counts, item) => {
    counts[filterGroup(item.state.kind)] += 1;
    return counts;
  }, { online: 0, stopped: 0, pending: 0, error: 0 });
  const visibleProjects = projectFilter === "all" ? projectStates : projectStates.filter((item) => filterGroup(item.state.kind) === projectFilter);
  return (
    <>
      <Toast toast={toast} />
      <div className="toolbar">
        <div>
          <h2>项目</h2>
          <p>先创建并分析源码，确认方案后再部署</p>
        </div>
        {me.role !== "viewer" && (
          <div className="actions">
            <button className="ghost" onClick={() => setShowCredential(true)}>
              <KeyRound />
              Git 凭据
            </button>
            <button className="primary" onClick={() => setShow(true)}>
              <Plus />
              添加项目
            </button>
          </div>
        )}
      </div>
      {items.length > 0 && (
        <div className="project-filters" aria-label="项目状态筛选">
          {[
            ["all", "全部", items.length],
            ["online", "运行中", projectCounts.online],
            ["stopped", "已停止", projectCounts.stopped],
            ["pending", "待部署", projectCounts.pending],
            ["error", "异常", projectCounts.error],
          ].map(([key, label, count]) => (
            <button key={key} className={`${key} ${projectFilter === key ? "active" : ""}`} onClick={() => setProjectFilter(key)}>
              <i />{label} <b>{count}</b>
            </button>
          ))}
        </div>
      )}
      {items.length ? (
        <div className="grid">
          {visibleProjects.map(({ project: x, state }) => {
            const facts = projectAnalysisFacts(x);
            const openPrimary = async (event) => {
              event.stopPropagation();
              if (state.kind === "online" && state.deployment?.access_url) {
                window.open(state.deployment.access_url, "_blank", "noopener,noreferrer");
                return;
              }
              if (state.kind === "stopped" && state.deployment && me.role !== "viewer") {
                const deploymentId = state.deployment.id;
                setStartingIds((current) => new Set(current).add(deploymentId));
                try {
                  notify("正在启动原来的成功版本…", "success", 5000);
                  await api(`/deployments/${deploymentId}/start`, { method: "POST" });
                  notify("服务已重新启用");
                } catch (error) {
                  notify(error.message || "重新启用失败", "error", 6000);
                } finally {
                  setStartingIds((current) => {
                    const next = new Set(current);
                    next.delete(deploymentId);
                    return next;
                  });
                  load();
                }
                return;
              }
              if (state.deployment && ["error", "working"].includes(state.kind)) {
                setSelectedDeployment(state.deployment);
                return;
              }
              setSelected(x);
            };
            return (
            <article
              className={`project-card project-card-${state.kind}`}
              key={x.id}
              onClick={() => setSelected(x)}
            >
              <div className="project-icon">
                <Code2 />
              </div>
              <div className="project-title">
                <h3>{x.name}</h3>
                <span>{x.slug}</span>
              </div>
              <div className="project-card-body">
                {facts ? (
                  <>
                    <strong>{facts.services || "已识别运行架构"}</strong>
                    <p>{facts.summary}</p>
                    <small>{facts.facts.slice(0, 3).join(" · ")}</small>
                  </>
                ) : (
                  <p>{x.description || projectSourceState(x).label}</p>
                )}
                {state.deployment?.release && <small>版本 {shortRelease(state.deployment.release)}</small>}
              </div>
              <div className="project-card-footer">
                <span className={`project-lifecycle ${state.kind}`}>
                  {state.kind === "working" ? <LoaderCircle className="spin" /> : <i />}
                  {state.label}
                  {state.secondaryLabel && <small className="project-deploying-badge"><LoaderCircle className="spin" />{state.secondaryLabel}</small>}
                </span>
                <button className={state.kind === "online" ? "primary compact" : "ghost compact"} disabled={state.label === "启动中"} onClick={openPrimary}>
                  {state.action}
                </button>
              </div>
            </article>
            );
          })}
        </div>
      ) : (
        <Empty
          icon={FolderGit2}
          text="还没有项目"
          action={
            me.role !== "viewer" && (
              <button className="primary" onClick={() => setShow(true)}>
                <Plus />
                添加第一个项目
              </button>
            )
          }
        />
      )}{" "}
      {show && (
        <ProjectModal
          notify={notify}
          onClose={() => setShow(false)}
          onDone={track}
        />
      )}{" "}
      {showCredential && (
        <CredentialModal onClose={() => setShowCredential(false)} />
      )}{" "}
      {selected && (
        <ProjectDetail
          project={selected}
          canEdit={me.role !== "viewer"}
          notify={notify}
          refreshRevision={detailRevision}
          onUpdated={(updated) => {
            setSelected(updated);
            load();
          }}
          onDeploymentCreated={(deployment) => {
            setDeployments((current) => [
              deployment,
              ...current.filter((item) => item.id !== deployment.id),
            ]);
            load();
          }}
          onDeleted={(result) => {
            setSelected(null);
            load();
            notify(result.summary || "项目及关联资源已删除", "success", 8000);
          }}
          onOpenDeployment={(deployment) => {
            setSelectedDeployment(deployment);
          }}
          onClose={() => setSelected(null)}
        />
      )}{" "}
      {selectedDeployment && (
        <DeploymentDetail
          item={selectedDeployment}
          onConfigureDomain={setDomainFor}
          onChanged={() => {
            setDetailRevision((value) => value + 1);
            load();
          }}
          onClose={() => setSelectedDeployment(null)}
        />
      )}{" "}
      {domainFor && (
        <ProjectDomainModal
          deployment={domainFor}
          notify={notify}
          onClose={() => setDomainFor(null)}
          onSaved={() => {
            setDomainFor(null);
            setSelectedDeployment(null);
            load();
          }}
        />
      )}
    </>
  );
}
function ProjectModal({ onClose, onDone, notify, deployImmediately = false }) {
  const [form, setForm] = useState({
      name: "",
      slug: "",
      description: "",
      source_type: "upload",
      git_url: "",
      git_branch: "main",
      git_repositories: [],
      build_type: "auto",
      container_port: "",
      host_port: "",
      domain: "",
      env_text: "",
      git_credential_id: "",
    }),
    [busy, setBusy] = useState(false),
    [err, setErr] = useState(""),
    [files, setFiles] = useState([]),
    [credentials, setCredentials] = useState([]),
    [nodes, setNodes] = useState([]),
    [node, setNode] = useState(""),
    [showPrivate, setShowPrivate] = useState(false),
    [credential, setCredential] = useState({
      name: "",
      auth_type: "token",
      username: "",
      secret: "",
    }),
    [credentialBusy, setCredentialBusy] = useState(false),
    [gitTesting, setGitTesting] = useState(false),
    [gitTest, setGitTest] = useState(null);
  useEffect(() => {
    Promise.all([api("/credentials").catch(() => []), api("/nodes")]).then(
      ([c, n]) => {
        setCredentials(c);
        setNodes(n);
        if (n[0]) setNode(n[0].id);
      },
    );
  }, []);
  const slugify = (name) =>
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || `project-${Date.now().toString().slice(-8)}`;
  const set = (k, v) => setForm((x) => ({ ...x, [k]: v }));
  const addGitRepository = () => setForm((value) => ({
    ...value,
    git_repositories: [...value.git_repositories, {
      git_url: "", git_branch: "main", credential_id: value.git_credential_id || "",
      role: value.git_repositories.some((row) => row.role === "frontend") ? "backend" : "frontend",
      target_dir: "",
    }],
  }));
  const updateGitRepository = (index, key, value) => setForm((current) => ({
    ...current,
    git_repositories: current.git_repositories.map((row, rowIndex) => rowIndex === index ? { ...row, [key]: value } : row),
  }));
  const removeGitRepository = (index) => setForm((current) => ({
    ...current,
    git_repositories: current.git_repositories.filter((_, rowIndex) => rowIndex !== index),
  }));
  const readEntry = (entry) =>
    new Promise((resolve, reject) => entry.file(resolve, reject));
  const readDir = (entry) =>
    new Promise((resolve, reject) => {
      const reader = entry.createReader(),
        all = [];
      const next = () =>
        reader.readEntries((batch) => {
          if (!batch.length) resolve(all);
          else {
            all.push(...batch);
            next();
          }
        }, reject);
      next();
    });
  const walk = async (entry, prefix = "") => {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isFile) return [{ file: await readEntry(entry), path }];
    const children = await readDir(entry),
      out = [];
    for (const child of children) out.push(...(await walk(child, path)));
    return out;
  };
  const acceptEntries = async (entries) => {
    const out = [];
    for (const entry of entries) out.push(...(await walk(entry)));
    setFiles(out);
    const root = entries[0]?.name?.replace(/\.[^.]+$/, "") || "新项目";
    setForm((x) => ({
      ...x,
      name: x.name || root,
      slug: x.slug || slugify(root),
    }));
  };
  const dropFolder = async (e) => {
    e.preventDefault();
    setErr("");
    try {
      await acceptEntries(
        [...e.dataTransfer.items]
          .map((x) => x.webkitGetAsEntry?.())
          .filter(Boolean),
      );
    } catch (x) {
      setErr(`读取文件夹失败：${x.message}`);
    }
  };
  const selectFiles = (e) => {
    const selected = [...e.target.files].map((file) => ({
      file,
      path: file.name,
    }));
    setFiles(selected);
    const root = selected[0]?.file?.name?.replace(/\.[^.]+$/, "") || "新项目";
    setForm((x) => ({
      ...x,
      name: x.name || root,
      slug: x.slug || slugify(root),
    }));
  };
  const selectFolder = (e) => {
    const selected = [...e.target.files].map((file) => ({
      file,
      path: file.webkitRelativePath || file.name,
    }));
    setFiles(selected);
    const root = selected[0]?.path?.split("/")[0] || "新项目";
    setForm((x) => ({
      ...x,
      name: x.name || root,
      slug: x.slug || slugify(root),
    }));
  };
  const testGit = async () => {
    setGitTesting(true);
    setGitTest(null);
    setErr("");
    try {
      const result = await api("/credentials/test-git", {
        method: "POST",
        body: JSON.stringify({
          git_url: form.git_url,
          git_branch: form.git_branch || "main",
          credential_id: form.git_credential_id || null,
        }),
      });
      setGitTest(result);
      notify?.(result.message);
    } catch (e) {
      setErr(e.message);
    } finally {
      setGitTesting(false);
    }
  };
  const saveCredential = async () => {
    setCredentialBusy(true);
    setErr("");
    try {
      const created = await api("/credentials", {
        method: "POST",
        body: JSON.stringify(credential),
      });
      setCredentials((items) => [...items, created]);
      set("git_credential_id", created.id);
      setShowPrivate(false);
      setCredential({ name: "", auth_type: "token", username: "", secret: "" });
      notify?.("私有仓库凭据已保存并自动选中");
    } catch (e) {
      setErr(e.message);
    } finally {
      setCredentialBusy(false);
    }
  };
  const submit = async () => {
    if (deployImmediately && !node) {
      setErr("请先选择部署服务器");
      return;
    }
    if (form.source_type === "upload" && !files.length) {
      setErr("请先选择源码文件或拖入项目文件夹");
      return;
    }
    setBusy(true);
    setErr("");
    try {
      const name = form.name || "新项目",
        slug = form.slug || slugify(name);
      const body = {
        ...form,
        name,
        slug,
        git_credential_id: form.git_credential_id || null,
        container_port: form.container_port
          ? Number(form.container_port)
          : null,
        host_port: form.host_port ? Number(form.host_port) : null,
      };
      if (form.source_type === "git" && form.git_repositories.length) {
        body.git_repositories = [
          {
            git_url: form.git_url,
            git_branch: form.git_branch || "main",
            credential_id: form.git_credential_id || null,
            role: "other",
            target_dir: "source",
          },
          ...form.git_repositories.map((row) => ({
            ...row,
            credential_id: row.credential_id || null,
            target_dir: row.target_dir || row.role,
          })),
        ];
      }
      const p = await api("/projects", {
        method: "POST",
        body: JSON.stringify(body),
      });
      let readyProject = p;
      if (form.source_type === "upload") {
        const batchSize = 100,
          total = Math.ceil(files.length / batchSize);
        for (let i = 0; i < total; i++) {
          notify?.(`正在上传源码：第 ${i + 1}/${total} 批`, "success", 5000);
          const batch = files.slice(i * batchSize, (i + 1) * batchSize),
            fd = new FormData();
          for (const item of batch) fd.append("files", item.file, item.path);
          const append = i > 0,
            finalize = i === total - 1;
          readyProject = await api(
            `/projects/${p.id}/upload?append=${append}&finalize=${finalize}`,
            { method: "POST", body: fd, retry: true },
          );
        }
      }
      if (deployImmediately) {
        const deployment = await api(`/projects/${p.id}/deploy`, {
          method: "POST",
          body: JSON.stringify({ node_id: node }),
        });
        onDone(deployment);
      } else {
        notify?.("项目已保存，后台 AI 已自动接管源码分析", "success", 6000);
        onDone(readyProject);
      }
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={deployImmediately ? "上传并部署项目" : "添加项目并分析源码"} onClose={onClose} wide>
      <div className="quick-deploy">
        <Field
          label="上传名称（项目名称）"
          hint="可自行修改；选择文件后仅在这里为空时自动带出文件夹或压缩包名称"
        >
          <input
            placeholder="例如：客户门户系统"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
          />
        </Field>
        <div className="quick-step">
          <span>1</span>
          <div>
            <h4>选择源码</h4>
            <p>平台会自动识别项目类型、运行端口和依赖</p>
          </div>
        </div>
        <div className="source-switch source-switch-before-picker">
          <button
            className={form.source_type === "upload" ? "on" : ""}
            onClick={() => set("source_type", "upload")}
          >
            <Upload />
            本地源码
          </button>
          <button
            className={form.source_type === "git" ? "on" : ""}
            onClick={() => set("source_type", "git")}
          >
            <FolderGit2 />
            Git 仓库
          </button>
        </div>
        {form.source_type === "upload" ? (
          <div
            className="upload-row folder-drop quick-upload whole-drop"
            onDragOver={(e) => {
              e.preventDefault();
              e.currentTarget.classList.add("dragging");
            }}
            onDragLeave={(e) => e.currentTarget.classList.remove("dragging")}
            onDrop={(e) => {
              e.currentTarget.classList.remove("dragging");
              dropFolder(e);
            }}
          >
            <div className="upload-zone">
              <div className="upload-zone-icon">
                <Upload />
              </div>
              <b>
                {files.length
                  ? `已选择 ${form.name || "未命名项目"}`
                  : "拖入源码文件或整个文件夹"}
              </b>
              <p>
                {files.length
                  ? `共 ${files.length.toLocaleString()} 个文件，目录结构将完整保留`
                  : "可将内容拖到这个区域任意位置，也可以点击下方按钮选择"}
              </p>
              <div className="upload-zone-actions">
                <label className="ghost">
                  <FolderGit2 />
                  选择文件夹
                  <input
                    type="file"
                    webkitdirectory=""
                    directory=""
                    multiple
                    hidden
                    onChange={selectFolder}
                  />
                </label>
                <label className="ghost">
                  <FileArchive />
                  选择文件 / ZIP
                  <input type="file" multiple hidden onChange={selectFiles} />
                </label>
              </div>
            </div>
          </div>
        ) : (
          <div className="form-grid one compact">
            <Field label="Git 仓库地址">
              <input
                placeholder="https://github.com/org/repo.git"
                value={form.git_url}
                onChange={(e) => set("git_url", e.target.value)}
              />
            </Field>
            <Field label="分支名称" hint="例如 main 或 master">
              <input
                value={form.git_branch}
                onChange={(e) => set("git_branch", e.target.value)}
              />
            </Field>
            <div className="multi-git-panel">
              <div className="multi-git-head">
                <div><b>多个源码仓库</b><span>前后端分开时添加；平台会分别拉取后统一分析和发布</span></div>
                <button className="ghost" type="button" onClick={addGitRepository}><Plus />添加仓库</button>
              </div>
              {form.git_repositories.map((repository, index) => (
                <div className="multi-git-row" key={index}>
                  <select value={repository.role} onChange={(e) => updateGitRepository(index, "role", e.target.value)}>
                    <option value="frontend">前端</option>
                    <option value="backend">后端</option>
                    <option value="other">其他</option>
                  </select>
                  <input placeholder="Git 仓库地址" value={repository.git_url} onChange={(e) => updateGitRepository(index, "git_url", e.target.value)} />
                  <input className="branch" placeholder="分支" value={repository.git_branch} onChange={(e) => updateGitRepository(index, "git_branch", e.target.value)} />
                  <select value={repository.credential_id} onChange={(e) => updateGitRepository(index, "credential_id", e.target.value)}>
                    <option value="">沿用主仓库凭据</option>
                    {credentials.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
                  </select>
                  <button className="icon danger" type="button" title="移除仓库" onClick={() => removeGitRepository(index)}><Trash2 /></button>
                </div>
              ))}
            </div>
            <Field label="访问凭据">
              <div className="credential-picker">
                <select
                  value={form.git_credential_id}
                  onChange={(e) => {
                    set("git_credential_id", e.target.value);
                    setGitTest(null);
                    setShowPrivate(false);
                  }}
                >
                  <option value="">无需凭据（公开仓库）</option>
                  {credentials.map((x) => (
                    <option value={x.id} key={x.id}>
                      {x.name} · {x.auth_type}
                    </option>
                  ))}
                </select>
                <button
                  className="ghost"
                  onClick={() => setShowPrivate((x) => !x)}
                >
                  <KeyRound />
                  {showPrivate ? "收起" : "添加私有仓库凭据"}
                </button>
                <button
                  className="ghost"
                  disabled={gitTesting || !form.git_url || !form.git_branch}
                  onClick={testGit}
                >
                  {gitTesting ? (
                    <LoaderCircle className="spin" />
                  ) : (
                    <Activity />
                  )}
                  测试连接
                </button>
              </div>
              {gitTest && (
                <div className="route-result">
                  <div>
                    <b>{gitTest.message}</b>
                    <span>
                      {gitTest.branch} · {gitTest.revision || "已读取仓库"} ·
                      项目目录 {gitTest.source_path || "/（仓库根目录）"} ·{" "}
                      {gitTest.network_route}
                    </span>
                  </div>
                  <ShieldCheck />
                </div>
              )}
            </Field>
            {showPrivate && (
              <div className="inline-credential">
                <div className="alert info">
                  {credential.auth_type === "ssh_key"
                    ? "SSH 仓库请粘贴完整私钥；保存后平台会加密存储。"
                    : "TFS / Azure DevOps 的 HTTP 仓库通常使用访问令牌或账号密码；令牌模式下用户名按仓库要求填写。"}
                </div>
                <div className="form-grid">
                  <Field label="凭据名称">
                    <input
                      placeholder="例如：公司 TFS"
                      value={credential.name}
                      onChange={(e) =>
                        setCredential({ ...credential, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="认证方式">
                    <select
                      value={credential.auth_type}
                      onChange={(e) =>
                        setCredential({
                          ...credential,
                          auth_type: e.target.value,
                        })
                      }
                    >
                      <option value="token">访问令牌 / PAT</option>
                      <option value="password">账号密码</option>
                      <option value="ssh_key">SSH 私钥</option>
                    </select>
                  </Field>
                  {credential.auth_type !== "ssh_key" && (
                    <Field label="用户名">
                      <input
                        placeholder="TFS 登录账号"
                        value={credential.username}
                        onChange={(e) =>
                          setCredential({
                            ...credential,
                            username: e.target.value,
                          })
                        }
                      />
                    </Field>
                  )}
                  <Field label={credential.auth_type === "ssh_key" ? "SSH 私钥" : credential.auth_type === "token" ? "访问令牌 / PAT" : "密码"}>
                    {credential.auth_type === "ssh_key" ? (
                      <textarea
                        rows="5"
                        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                        value={credential.secret}
                        onChange={(e) => setCredential({ ...credential, secret: e.target.value })}
                      />
                    ) : (
                      <input
                        type="password"
                        autoComplete="new-password"
                        placeholder={credential.auth_type === "token" ? "输入 PAT 或访问令牌" : "输入仓库登录密码"}
                        value={credential.secret}
                        onChange={(e) => setCredential({ ...credential, secret: e.target.value })}
                      />
                    )}
                  </Field>
                </div>
                <div className="inline-credential-actions">
                  <small>凭据仅用于拉取源码，不会写入项目文件。</small>
                  <button
                    className="primary"
                    disabled={credentialBusy || !credential.name || !credential.secret}
                    onClick={saveCredential}
                  >
                    {credentialBusy ? <LoaderCircle className="spin" /> : <ShieldCheck />}
                    保存并选用
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
        {deployImmediately && (
          <>
            <div className="quick-step">
              <span>2</span>
              <div>
                <h4>选择部署服务器</h4>
                <p>部署完成后会自动生成访问地址</p>
              </div>
            </div>
            <Field label="目标服务器">
              <select value={node} onChange={(e) => setNode(e.target.value)}>
                <option value="">请选择服务器</option>
                {nodes.map((x) => (
                  <option value={x.id} key={x.id}>
                    {x.name} · {x.last_status}
                  </option>
                ))}
              </select>
            </Field>
          </>
        )}
        <details className="advanced">
          <summary>
            <Settings />
            高级设置（通常不用填写）
          </summary>
          <div className="form-grid">
            <Field label="项目标识">
              <input
                placeholder="根据上传名称自动生成"
                value={form.slug}
                onChange={(e) => set("slug", e.target.value)}
              />
            </Field>
            <Field label="指定容器端口">
              <PortInput
                placeholder="自动识别"
                value={form.container_port}
                onChange={(e) => set("container_port", e.target.value)}
              />
            </Field>
            <Field label="指定内网实例端口" hint="通常留空，由系统内网端口池自动分配">
              <PortInput
                placeholder="自动分配"
                value={form.host_port}
                onChange={(e) => set("host_port", e.target.value)}
              />
            </Field>
            <Field label="域名（可选）">
              <input
                value={form.domain}
                onChange={(e) => set("domain", e.target.value)}
              />
            </Field>
            <Field label="环境变量（可选）">
              <textarea
                value={form.env_text}
                onChange={(e) => set("env_text", e.target.value)}
              />
            </Field>
          </div>
        </details>
      </div>
      {err && <div className="alert danger">{err}</div>}
      <div className="modal-actions">
        <button className="ghost" onClick={onClose}>
          取消
        </button>
        <button
          className="primary"
          disabled={busy || (deployImmediately && !node) || !form.name.trim()}
          onClick={submit}
        >
          {busy ? <LoaderCircle className="spin" /> : <Upload />}
          {busy
            ? "正在处理，请稍候"
            : deployImmediately
              ? "上传并开始部署"
              : "创建项目并分析源码"}
        </button>
      </div>
    </Modal>
  );
}
function CredentialModal({ onClose }) {
  const [items, setItems] = useState([]),
    [form, setForm] = useState({
      name: "",
      auth_type: "token",
      username: "",
      secret: "",
    }),
    [err, setErr] = useState(""),
    [busy, setBusy] = useState(false);
  const load = () => api("/credentials").then(setItems);
  useEffect(() => {
    load();
  }, []);
  const set = (k, v) => setForm({ ...form, [k]: v });
  const save = async () => {
    setBusy(true);
    setErr("");
    try {
      await api("/credentials", { method: "POST", body: JSON.stringify(form) });
      setForm({ name: "", auth_type: "token", username: "", secret: "" });
      load();
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="Git 访问凭据" onClose={onClose} wide>
      <div className="form-grid">
        <Field label="凭据名称">
          <input
            placeholder="例如：公司 GitLab"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
          />
        </Field>
        <Field label="认证方式">
          <select
            value={form.auth_type}
            onChange={(e) => set("auth_type", e.target.value)}
          >
            <option value="token">访问令牌</option>
            <option value="password">账号密码</option>
            <option value="ssh_key">SSH 私钥</option>
          </select>
        </Field>
        {form.auth_type !== "ssh_key" && (
          <Field label="用户名（可选）">
            <input
              value={form.username}
              onChange={(e) => set("username", e.target.value)}
            />
          </Field>
        )}
        <Field label={form.auth_type === "ssh_key" ? "SSH 私钥" : "密码或令牌"}>
          <textarea
            rows="5"
            value={form.secret}
            onChange={(e) => set("secret", e.target.value)}
          />
        </Field>
      </div>
      {err && <div className="alert danger">{err}</div>}
      <div className="modal-actions">
        <button className="ghost" onClick={onClose}>
          关闭
        </button>
        <button
          className="primary"
          disabled={busy || !form.name || !form.secret}
          onClick={save}
        >
          {busy && <LoaderCircle className="spin" />}保存凭据
        </button>
      </div>
      <div className="credential-list">
        <h4>已保存凭据</h4>
        {items.length ? (
          items.map((x) => (
            <div key={x.id}>
              <KeyRound />
              <span>
                <b>{x.name}</b>
                <small>
                  {x.auth_type}
                  {x.username ? ` · ${x.username}` : ""}
                </small>
              </span>
              <ShieldCheck />
            </div>
          ))
        ) : (
          <p>尚未保存 Git 凭据</p>
        )}
      </div>
    </Modal>
  );
}

function ProjectSourceManager({ project, analysis, canEdit, notify, onDone }) {
  const [files, setFiles] = useState([]),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [editingRuntime, setEditingRuntime] = useState(false),
    [runtimeRows, setRuntimeRows] = useState([]);
  const beginRuntimeEdit = () => {
    setRuntimeRows((analysis?.runtime_services || []).map((row) => ({ ...row })));
    setEditingRuntime(true);
  };
  const saveRuntimeImages = async () => {
    setBusy(true);
    try {
      const updated = await api(`/projects/${project.id}/runtime-images`, {
        method: "PUT",
        body: JSON.stringify({ items: runtimeRows.filter((row) => row.editable !== false).map(({ service, image }) => ({ service, image })) }),
      });
      setEditingRuntime(false);
      onDone?.(updated);
      notify?.("当前项目的运行服务版本已保存，仅后续部署使用");
    } catch (e) {
      notify?.(e.message, "error");
    } finally {
      setBusy(false);
    }
  };
  const selectFiles = (e) =>
    setFiles([...e.target.files].map((file) => ({ file, path: file.name })));
  const selectFolder = (e) =>
    setFiles(
      [...e.target.files].map((file) => ({
        file,
        path: file.webkitRelativePath || file.name,
      })),
    );
  const upload = async () => {
    if (!files.length) return;
    setBusy(true);
    setError("");
    try {
      const batchSize = 100,
        total = Math.ceil(files.length / batchSize);
      let updated = project;
      for (let i = 0; i < total; i++) {
        const fd = new FormData();
        for (const item of files.slice(i * batchSize, (i + 1) * batchSize))
          fd.append("files", item.file, item.path);
        updated = await api(
          `/projects/${project.id}/upload?append=${i > 0}&finalize=${i === total - 1}`,
          { method: "POST", body: fd, retry: true },
        );
      }
      setFiles([]);
      notify?.(
        "新版本源码上传完成；当前运行服务未改变，可在项目设置中发起新部署",
      );
      onDone?.(updated);
    } catch (e) {
      setError(e.message);
      notify?.(e.message, "error");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="source-manager">
      <div className="project-config-intro">
        <b>源码管理</b>
        <span>
          更新源码不会直接替换正在运行的服务；部署后才会生成新的发布版本。平台保留最近
          3 个历史源码版本。
        </span>
      </div>
      {analysis && (
        <div className={`source-process ${analysis.status || "queued"}`}>
          <div className="source-process-head">
            <div>
              {["queued", "running"].includes(analysis.status) ? <LoaderCircle className="spin" /> : analysis.status === "completed" ? <ShieldCheck /> : <Activity />}
              <span>
                <b>{projectSourceState({ source_analysis: analysis }).label}</b>
                <AnalysisSummaryDetails text={analysis.summary} />
              </span>
            </div>
            <div className="source-process-meta">
              <span>{analysisDuration(analysis)}</span>
              {analysis.revision && <code>{analysis.revision.slice(0, 12)}</code>}
            </div>
          </div>
          <div className="source-process-track">
            {["保存项目", project.source_type === "git" ? "拉取源码" : "接收源码", "分析源码", "准备完成"].map((label, index) => {
              const progress = analysis.status === "completed" ? 100 : Number(analysis.progress || 0);
              const threshold = [5, 25, 65, 100][index];
              return <span className={progress >= threshold ? "done" : ""} key={label}><i />{label}</span>;
            })}
          </div>
          {analysis.status === "failed" && <div className="source-process-error">{analysis.error || "源码处理失败，请检查仓库地址、分支或凭据后重新分析。"}</div>}
        </div>
      )}
      <div className="source-current">
        <div>
          <span>当前来源</span>
          <b>{project.source_type === "git" ? "Git 仓库" : "平台上传"}</b>
        </div>
        <div>
          <span>源码位置</span>
          <b>
            {project.source_type === "git"
              ? project.git_url || "未配置"
              : project.source_path}
          </b>
        </div>
        <div>
          <span>内部项目标识</span>
          <b>{project.slug}</b>
        </div>
      </div>
      {analysis?.status === "completed" && (
        <div className="source-build-analysis">
          <div className="source-build-analysis-head">
            <div><b>构建与运行环境</b><span>AI 从源码保存的发布依据，发布时直接使用</span></div>
            <em>{analysis.deployment_kind || "自动识别"}</em>
          </div>
          {(analysis.build_environment || []).length ? (
            <div className="source-build-analysis-list">
              {analysis.build_environment.map((row, index) => (
                <div key={`${row.module || "module"}-${index}`}>
                  <b>{row.module || `模块 ${index + 1}`}</b>
                  <span><small>技术与版本</small>{[row.language, row.runtime_version].filter(Boolean).join(" · ") || "待识别"}</span>
                  <span><small>构建工具</small>{row.package_manager || "待识别"}</span>
                  <span><small>构建镜像</small>{row.build_image || "待识别"}</span>
                  <span><small>构建命令</small><code>{row.build_command || "待识别"}</code></span>
                  <span><small>构建产物</small>{row.artifact || "待识别"}</span>
                  <span><small>运行镜像</small>{row.runtime_image || "待识别"}</span>
                  {row.evidence && <p>{row.evidence}</p>}
                </div>
              ))}
            </div>
          ) : <div className="alert info">本次旧分析未保存版本明细，点击“重新分析”后会补全。</div>}
          {!!(analysis.runtime_services || []).length && (
            <div className="source-runtime-services">
              <div className="source-runtime-services-title">
                <div><b>运行服务</b><span>源码有明确要求就采用；否则使用平台推荐</span></div>
                {canEdit && !editingRuntime && analysis.runtime_services.some((row) => row.editable !== false) && <button className="ghost compact" onClick={beginRuntimeEdit}>修改版本</button>}
              </div>
              <div className="source-runtime-services-grid">
                {(editingRuntime ? runtimeRows : analysis.runtime_services).map((row, index) => (
                  <div key={row.service}>
                    <span>{row.service}</span>
                    {row.mode === "external" ? (
                      <code title={row.endpoint}>{row.endpoint || "使用已保存的外接配置"}</code>
                    ) : editingRuntime ? (
                      <input value={row.image} onChange={(e) => setRuntimeRows(runtimeRows.map((item, itemIndex) => itemIndex === index ? { ...item, image: e.target.value } : item))} />
                    ) : <code>{row.image}</code>}
                    <em className={row.mode === "external" ? "external" : row.source === "源码识别" ? "detected" : "recommended"}>
                      {row.mode === "external" ? "源码识别 · 外部依赖" : row.source}
                    </em>
                  </div>
                ))}
              </div>
              {editingRuntime && <div className="source-runtime-actions"><button className="ghost" onClick={() => setEditingRuntime(false)}>取消</button><button className="primary" disabled={busy} onClick={saveRuntimeImages}>{busy && <LoaderCircle className="spin" />}保存版本</button></div>}
            </div>
          )}
        </div>
      )}
      {project.source_type === "upload" ? (
        <div className="source-upload">
          <div className="upload-zone">
            <div className="upload-zone-icon">
              <Upload />
            </div>
            <b>
              {files.length
                ? `已选择 ${files.length.toLocaleString()} 个文件`
                : "选择新版本源码"}
            </b>
            <p>
              支持 ZIP、多个文件或整个文件夹；确认上传后原源码归档为历史版本。
            </p>
            <div className="upload-zone-actions">
              <label className="ghost">
                <FolderGit2 />
                选择文件夹
                <input
                  type="file"
                  webkitdirectory=""
                  directory=""
                  multiple
                  hidden
                  disabled={!canEdit || busy}
                  onChange={selectFolder}
                />
              </label>
              <label className="ghost">
                <FileArchive />
                选择文件 / ZIP
                <input
                  type="file"
                  multiple
                  hidden
                  disabled={!canEdit || busy}
                  onChange={selectFiles}
                />
              </label>
            </div>
          </div>
          {error && <div className="alert danger">{error}</div>}
          <button
            className="primary"
            disabled={!canEdit || busy || !files.length}
            onClick={upload}
          >
            {busy ? <LoaderCircle className="spin" /> : <Upload />}
            {busy ? "正在上传新版本" : "上传为新源码版本"}
          </button>
        </div>
      ) : (
        <div className="alert info">
          Git 项目在下一次部署时会重新拉取配置的分支：
          {project.git_branch || "main"}。
        </div>
      )}
    </div>
  );
}

function ProjectDeleteDialog({ project, onClose, onDone, onReset }) {
  const [preview, setPreview] = useState(null),
    [error, setError] = useState(""),
    [selectedVolumes, setSelectedVolumes] = useState([]),
    [confirm, setConfirm] = useState(""),
    [copiedName, setCopiedName] = useState(false),
    [keepProject, setKeepProject] = useState(true),
    [busy, setBusy] = useState(false),
    [result, setResult] = useState(null);
  useEffect(() => {
    api(`/projects/${project.id}/delete-preview`)
      .then((result) => {
        setPreview(result);
        setSelectedVolumes((result.resources?.volumes || []).map((x) => x.name));
      })
      .catch((e) => setError(e.message));
  }, [project.id]);
  const remove = async () => {
    setBusy(true);
    setError("");
    try {
      const removed = await api(
        `/projects/${project.id}?keep_project=${keepProject ? "true" : "false"}&delete_volumes=${encodeURIComponent(JSON.stringify(selectedVolumes))}`,
        { method: "DELETE" },
      );
      setResult(removed);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const copyProjectName = async () => {
    try {
      await copyText(project.name);
      setConfirm(project.name);
      setCopiedName(true);
      setTimeout(() => setCopiedName(false), 1800);
    } catch (e) {
      setError(e.message);
    }
  };
  const labels = {
    deployments: "发布记录",
    containers: "容器",
    images: "应用镜像",
    registry_images: "镜像仓库版本",
    directories: "发布目录",
    volumes: "持久化数据卷",
    gateway_files: "Nginx/证书文件",
    source_origin: "源码来源",
    source: "平台上传源码",
  };
  if (result) {
    return (
      <Modal title={`${result.project_retained ? "项目已重置" : "项目已删除"} · ${project.name}`} onClose={() => result.project_retained ? onReset?.(result) : onDone?.(result)} wide>
        <div className="panel security-card ai-delete-summary">
          <ShieldCheck />
          <div>
            <h3>清理完成</h3>
            <p>{result.summary}</p>
            <small>以下是平台实际执行并复查通过的清理结果。</small>
          </div>
        </div>
        <div className="delete-inventory">
          {(result.details || []).map((detail, index) => (
            <div key={index}>
              <div><b>已完成</b><em>已复查</em></div>
              <span>{typeof detail === "string" ? detail : detail.summary || JSON.stringify(detail)}</span>
            </div>
          ))}
        </div>
        <h3>已删除资源清单</h3>
        <div className="delete-inventory">
          {["deployments", "containers", "images", "registry_images", "directories", "gateway_files", "source"].map((key) => (
            <div key={key}>
              <div><b>{labels[key]}</b><em>{preview?.resources?.[key]?.length || 0} 项</em></div>
              {(preview?.resources?.[key] || []).length ? (
                <ul>{preview.resources[key].map((item, index) => (
                  <li key={index}>{typeof item === "string" ? item : item.name || item.path || item.release || item.id}{item.node ? ` · ${item.node}` : ""}</li>
                ))}</ul>
              ) : <span>无</span>}
            </div>
          ))}
          <div>
            <div><b>已删除数据卷</b><em>{selectedVolumes.length} 项</em></div>
            {selectedVolumes.length ? <ul>{selectedVolumes.map((name) => <li key={name}>{name}</li>)}</ul> : <span>无（数据已保留）</span>}
          </div>
          <div>
            <div><b>保留数据卷</b><em>{(preview?.resources?.volumes || []).filter((item) => !selectedVolumes.includes(item.name)).length} 项</em></div>
            {(preview?.resources?.volumes || []).filter((item) => !selectedVolumes.includes(item.name)).length ? (
              <ul>{preview.resources.volumes.filter((item) => !selectedVolumes.includes(item.name)).map((item) => <li key={item.name}>{item.name} · {item.node}</li>)}</ul>
            ) : <span>无</span>}
          </div>
        </div>
        <div className="modal-actions">
          <button className="primary" onClick={() => result.project_retained ? onReset?.(result) : onDone?.(result)}>完成</button>
        </div>
      </Modal>
    );
  }
  return (
    <Modal title={`删除项目 · ${project.name}`} onClose={onClose} wide>
      {!preview && !error ? (
        <div className="center">
          <LoaderCircle className="spin" />
          <span>AI 正在分析项目资源...</span>
        </div>
      ) : (
        <>
          <div className="panel security-card ai-delete-summary">
            <Bot />
            <div>
              <h3>AI 清理分析</h3>
              <p>{preview?.ai_summary || "资源查询失败"}</p>
              <small>
                执行时会先停止服务，再删除项目拥有的资源，最后复查容器、节点镜像、镜像仓库版本和目录。
              </small>
            </div>
          </div>
          {preview && (
            <div className="delete-inventory">
              {Object.entries(labels).map(([key, label]) => (
                <div key={key}>
                  <div>
                    <b>{label}</b>
                    <em>
                      {preview.counts?.[key] || 0} 项
                      {key === "volumes" && (preview.counts?.volumes || 0) > 0 ? " · 勾选删除" : ""}
                    </em>
                  </div>
                  {preview.resources?.[key]?.length ? (
                    <ul>
                      {preview.resources[key].slice(0, 8).map((x, i) => (
                        <li key={i}>
                          {key === "volumes" ? (
                            <label className="inventory-volume-check">
                              <input
                                type="checkbox"
                                checked={selectedVolumes.includes(x.name)}
                                onChange={(event) => setSelectedVolumes((current) => event.target.checked
                                  ? [...new Set([...current, x.name])]
                                  : current.filter((name) => name !== x.name))}
                              />
                              <span>{x.name}{x.node ? ` · ${x.node}` : ""}</span>
                            </label>
                          ) : (
                            <>
                              {typeof x === "string" ? x : x.name || x.path || x.release || x.id}
                              {x.node ? ` · ${x.node}` : ""}
                              {x.status ? ` · ${statusText[x.status] || x.status}` : ""}
                            </>
                          )}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span>没有发现</span>
                  )}
                  {preview.resources?.[key]?.length > 8 && (
                    <small>另有 {preview.resources[key].length - 8} 项</small>
                  )}
                </div>
              ))}
            </div>
          )}
          <div className={`delete-mode-card ${keepProject ? "selected" : ""}`}>
            <label className="delete-mode-option">
              <input type="checkbox" checked={keepProject} onChange={(event) => setKeepProject(event.target.checked)} />
              <span className="delete-mode-copy">
                <b>仅清空运行资源 <em>推荐</em></b>
                <small>保留项目、源码与连接配置；清理发布记录、容器、镜像和目录后可重新发布。</small>
              </span>
            </label>
          </div>
          {(preview?.counts?.volumes || 0) > 0 ? null : (
            <div className="alert info">
              未发现该项目创建的平台托管数据卷；本次只删除清单中的项目资源。外部数据库和外部中间件不会处理。
            </div>
          )}
          <Field label="输入项目名称确认" className="delete-confirm-field">
            <div className="delete-confirm-name">
              <code>{project.name}</code>
              <button type="button" className="ghost" onClick={copyProjectName}>
                {copiedName ? <ShieldCheck /> : <Copy />}
                {copiedName ? "已复制并填入" : "复制并填入"}
              </button>
            </div>
            <input
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder={project.name}
            />
          </Field>
          {preview?.warnings?.map((x, i) => (
            <div className="alert danger" key={i}>
              {x}
            </div>
          ))}
          {error && <div className="alert danger">{error}</div>}
          <div className="modal-actions">
            <button className="ghost" disabled={busy} onClick={onClose}>
              取消
            </button>
            <button
              className="danger-button"
              disabled={busy || !preview || confirm !== project.name}
              onClick={remove}
            >
              {busy ? <LoaderCircle className="spin" /> : <Trash2 />}
              {busy
                ? "正在停止服务并清理项目资源..."
                : keepProject ? "确认清空并保留项目" : "确认删除项目及全部关联资源"}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}

function ProjectDetail({
  project,
  canEdit,
  onUpdated,
  onDeploymentCreated,
  onDeleted,
  notify,
  onClose,
  onOpenDeployment,
  refreshRevision = 0,
}) {
  const [tab, setTab] = useState("settings"),
    [showDelete, setShowDelete] = useState(false),
    [nodes, setNodes] = useState(null),
    [nodeError, setNodeError] = useState(""),
    [node, setNode] = useState(""),
    [deployments, setDeployments] = useState(null),
    [runtime, setRuntime] = useState(null),
    [runtimeRefreshing, setRuntimeRefreshing] = useState(false),
    [projectLifecycleBusy, setProjectLifecycleBusy] = useState(""),
    [projectStopConfirm, setProjectStopConfirm] = useState(false),
    [replicaStatus, setReplicaStatus] = useState(null),
    [dataResources, setDataResources] = useState(null),
    [accessConfig, setAccessConfig] = useState(null),
    [gatewaySnapshot, setGatewaySnapshot] = useState(null),
    [gatewaySnapshotLoading, setGatewaySnapshotLoading] = useState(false),
    [showGatewaySnapshot, setShowGatewaySnapshot] = useState(false),
    [showGatewaySettings, setShowGatewaySettings] = useState(false),
    [showDomainConfig, setShowDomainConfig] = useState(false),
    [deployConfirm, setDeployConfirm] = useState(false),
    [rollbackConfirm, setRollbackConfirm] = useState(null),
    [busy, setBusy] = useState(false),
    [saving, setSaving] = useState(false),
    [scaling, setScaling] = useState(false),
    [name, setName] = useState(project.name),
    [domain, setDomain] = useState(project.domain || ""),
    [containerPort, setContainerPort] = useState(project.container_port || ""),
    [hostPort, setHostPort] = useState(Number(project.host_port) > 0 ? project.host_port : ""),
    [envText, setEnvText] = useState(""),
    [managedEnvText, setManagedEnvText] = useState(""),
    [deploymentMode, setDeploymentMode] = useState(project.deployment_mode || "managed_fresh"),
    [sourceAnalysis] = useState(project.initial_analysis || null),
    [integrationAnalysis, setIntegrationAnalysis] = useState(project.source_analysis || null),
    [integrationLoading, setIntegrationLoading] = useState(false),
    [integrationTesting, setIntegrationTesting] = useState(""),
    [replicaCount, setReplicaCount] = useState(project.load_balance_enabled ? (project.replica_count || 2) : 1),
    [loadBalanceStrategy, setLoadBalanceStrategy] = useState(project.load_balance_strategy || "round_robin"),
    [msg, setMsg] = useState("");
  const runtimePendingRef = useRef(false);
  const integrationPendingRef = useRef(false);
  const envValues = useMemo(() => Object.fromEntries(
    envText.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith("#") && line.includes("="))
      .map((line) => { const index = line.indexOf("="); return [line.slice(0, index).trim(), line.slice(index + 1)]; }),
  ), [envText]);
  const setEnvValue = (key, value) => {
    const lines = envText.split(/\r?\n/).filter((line) => !line.startsWith(`${key}=`));
    if (value !== "") lines.push(`${key}=${value}`);
    setEnvText(lines.filter((line, index, all) => line.trim() || index < all.length - 1).join("\n"));
  };
  const analyzeIntegrations = async (modeOverride = deploymentMode, force = false) => {
    if (integrationPendingRef.current) return;
    if (!force && integrationAnalysis) return;
    integrationPendingRef.current = true;
    setIntegrationLoading(true);
    setMsg("");
    try {
      await api(`/projects/${project.id}`, {
        method: "PATCH",
        body: JSON.stringify({ deployment_mode: modeOverride }),
      });
      const result = await api(`/projects/${project.id}/integration-analysis/background`, { method: "POST" });
      setIntegrationAnalysis(result);
      onUpdated?.({ ...project, deployment_mode: modeOverride, source_analysis: result });
      notify?.("已转入后台分析，可以关闭项目窗口", "success");
    } catch (e) {
      setMsg(e.message);
    } finally {
      integrationPendingRef.current = false;
      setIntegrationLoading(false);
    }
  };
  const testIntegration = async (service) => {
    setIntegrationTesting(service);
    try {
      const prefix = service === "mysql" ? "YUNZHOU_MYSQL_" : "YUNZHOU_REDIS_";
      const result = await api(`/projects/${project.id}/integration-test`, {
        method: "POST",
        body: JSON.stringify({
          service,
          node_id: node,
          host: envValues[`${prefix}HOST`] || "",
          port: envValues[`${prefix}PORT`] || (service === "mysql" ? "3306" : "6379"),
          database: envValues[`${prefix}DATABASE`] || (service === "redis" ? "0" : ""),
          username: envValues[`${prefix}USERNAME`] || "",
          password: envValues[`${prefix}PASSWORD`] || "",
        }),
      });
      notify?.(result.message, "success");
    } catch (e) {
      notify?.(e.message, "error");
    } finally {
      setIntegrationTesting("");
    }
  };
  const loadNodes = (preferredNode = "") => {
    setNodeError("");
    setNodes(null);
    api("/nodes")
      .then((x) => {
        setNodes(x);
        setNode((current) =>
          x.some((item) => item.id === preferredNode)
            ? preferredNode
            : x.some((item) => item.id === current)
              ? current
              : x[0]?.id || "",
        );
      })
      .catch((e) => {
        setNodes([]);
        setNodeError(e.message);
      });
  };
  const loadDeployments = () =>
    api(`/deployments?project_id=${project.id}`)
      .then(setDeployments)
      .catch(() => setDeployments([]));
  const loadRuntime = (silent = false, force = false) => {
    if (runtimePendingRef.current) return;
    runtimePendingRef.current = true;
    if (!silent) setRuntimeRefreshing(true);
    api(`/projects/${project.id}/runtime${force ? "?refresh=true" : ""}`)
      .then(setRuntime)
      .catch((e) => {
        setRuntime((current) => current
          ? { ...current, refreshing: false, refresh_error: e.message }
          : { environments: [], error: e.message, refreshing: false });
        if (!silent) notify?.(`运行状态刷新失败：${e.message}`, "error");
      })
      .finally(() => {
        runtimePendingRef.current = false;
        if (!silent) setRuntimeRefreshing(false);
      });
  };
  const loadReplicas = () =>
    api(`/projects/${project.id}/replicas`)
      .then(setReplicaStatus)
      .catch(() => setReplicaStatus(null));
  const loadGatewaySnapshot = async () => {
    setGatewaySnapshotLoading(true);
    try {
      setGatewaySnapshot(await api(`/projects/${project.id}/gateway-preview`));
    } catch (e) {
      notify?.(e.message, "error");
    } finally {
      setGatewaySnapshotLoading(false);
    }
  };
  const openGatewaySnapshot = () => {
    setShowGatewaySnapshot(true);
    if (!gatewaySnapshot && !gatewaySnapshotLoading) loadGatewaySnapshot();
  };
  const loadDataResources = (silent = false) => {
    if (!silent && !dataResources) setDataResources(null);
    Promise.all([
      api(`/projects/${project.id}/data-resources`),
      canEdit ? api(`/projects/${project.id}/managed-credentials`).catch(() => ({ items: [] })) : Promise.resolve({ items: [] }),
      canEdit ? api(`/projects/${project.id}/data-exposures`).catch(() => ({ items: [] })) : Promise.resolve({ items: [] }),
    ])
      .then(([resources, credentials, exposures]) => setDataResources({
        ...resources,
        data_exposures: exposures.items || [],
        managed_credentials: (credentials.items || []).map((item) => ({
          ...item,
          exposure: (exposures.items || []).find((entry) => entry.service === item.service) || null,
        })),
      }))
      .catch((e) => setDataResources({ error: e.message }));
  };
  useEffect(() => {
    setNodeError("");
    setNodes(null);
    setDataResources(null);
    // Runtime inspection may involve a remote Docker/SSH refresh. Keep it in
    // flight, but do not make the project shell wait for it before rendering
    // settings, deployment history and environment data.
    runtimePendingRef.current = true;
    const runtimeRequest = api(`/projects/${project.id}/runtime`)
      .catch(() => ({ environments: [] }))
      .finally(() => { runtimePendingRef.current = false; });
    Promise.all([
      api("/nodes"),
      api(`/deployments?project_id=${project.id}`),
      canEdit ? api(`/projects/${project.id}/environment`) : Promise.resolve({ env_text: "" }),
    ])
      .then(([nodeItems, records, environment]) => {
        setNodes(nodeItems);
        setDeployments(records);
        const latestSuccessful = records.find((item) => item.status === "success");
        setHostPort((current) => current || latestSuccessful?.host_port || "");
        setContainerPort((current) => current || latestSuccessful?.deployment_plan?.container_port || "");
        setEnvText(environment.env_text || "");
        setManagedEnvText(environment.managed_env_text || "");
        setIntegrationAnalysis(environment.integration_analysis || null);
        const lastNode = records[0]?.node_id;
        setNode(
          nodeItems.some((item) => item.id === lastNode)
            ? lastNode
            : nodeItems[0]?.id || "",
        );
        runtimeRequest.then((runtimeData) => {
          setRuntime(runtimeData);
          const activeEnvironment = (runtimeData.environments || []).find(
            (item) => item.deployment_id === latestSuccessful?.id,
          );
          const mappedContainerPort = latestSuccessful?.host_port
            ? (activeEnvironment?.containers || []).map((item) => {
                const match = String(item.ports || "").match(new RegExp(`:${latestSuccessful.host_port}->(\\d+)`));
                return match?.[1] ? Number(match[1]) : null;
              }).find(Boolean)
            : null;
          setContainerPort((current) => current || mappedContainerPort || "");
        });
      })
      .catch((e) => {
        setNodeError(e.message);
        setNodes([]);
        setDeployments([]);
      });
    loadReplicas();
  }, [project.id, refreshRevision]);
  useEffect(() => {
    if (!["queued", "running"].includes(integrationAnalysis?.status)) return undefined;
    const timer = setInterval(() => {
      api(`/projects/${project.id}/environment`).then((environment) => {
        const nextAnalysis = environment.integration_analysis || null;
        setIntegrationAnalysis(nextAnalysis);
        setManagedEnvText(environment.managed_env_text || "");
        onUpdated?.({ ...project, deployment_mode: deploymentMode, source_analysis: nextAnalysis });
      }).catch(() => {});
    }, 4000);
    return () => clearInterval(timer);
  }, [project.id, integrationAnalysis?.status]);
  useEffect(() => {
    if (tab !== "deployments") return undefined;
    loadDeployments();
    const timer = setInterval(() => {
      if (!document.hidden) loadDeployments();
    }, 5000);
    return () => clearInterval(timer);
  }, [tab, project.id]);
  useEffect(() => {
    // Warm the lightweight snapshot while the user reads runtime cards. The
    // button remains immediately clickable and opens from cache instead of
    // blocking on a remote gateway SSH inspection.
    if (tab === "runtime" && !gatewaySnapshot && !gatewaySnapshotLoading) {
      loadGatewaySnapshot();
    }
  }, [tab, project.id]);
  const save = async () => {
    if (!name.trim()) return;
    if (!validPort(containerPort) || !validPort(hostPort)) {
      notify?.("端口必须是 1–65535 之间的整数", "error");
      return;
    }
    setSaving(true);
    try {
      const updated = await api(`/projects/${project.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: name.trim(),
          domain: domain.trim(),
          container_port: containerPort ? Number(containerPort) : null,
          host_port: hostPort ? Number(hostPort) : null,
          deployment_mode: deploymentMode,
        }),
      });
      await api(`/projects/${project.id}/environment`, {
        method: "PUT",
        body: JSON.stringify({ env_text: envText }),
      });
      onUpdated?.(updated);
      notify?.("项目配置已更新");
    } catch (e) {
      notify?.(e.message, "error");
    } finally {
      setSaving(false);
    }
  };
  const applyScale = async () => {
    setScaling(true);
    try {
      await api(`/projects/${project.id}`, {
        method: "PATCH",
        body: JSON.stringify({ load_balance_strategy: loadBalanceStrategy }),
      });
      const result = await api(`/projects/${project.id}/scale`, {
        method: "POST",
        body: JSON.stringify({ replicas: Number(replicaCount) }),
      });
      setReplicaStatus(result);
      onUpdated?.({
        ...project,
        load_balance_enabled: Number(replicaCount) > 1,
        replica_count: Number(replicaCount),
        load_balance_strategy: loadBalanceStrategy,
      });
      notify?.(`运行实例已调整：${result.ready}/${result.desired} 个就绪，已接入原访问入口`, "success");
      loadRuntime(true);
    } catch (e) {
      notify?.(e.message, "error");
    } finally {
      setScaling(false);
    }
  };
  const deploy = async () => {
    if (!validPort(containerPort) || !validPort(hostPort)) {
      setMsg("端口必须是 1–65535 之间的整数");
      return;
    }
    setBusy(true);
    setMsg("");
    try {
      const d = await api(`/projects/${project.id}/deploy`, {
        method: "POST",
        body: JSON.stringify({
          node_id: node,
          name: name.trim(),
          domain: domain.trim(),
          container_port: containerPort ? Number(containerPort) : null,
          host_port: hostPort ? Number(hostPort) : null,
          load_balance_enabled: false,
          replica_count: 1,
          deployment_mode: deploymentMode,
          env_text: envText,
        }),
      });
      setMsg(`部署任务已创建：${d.id.slice(0, 8)}`);
      setDeployments((current) => [
        d,
        ...(current || []).filter((item) => item.id !== d.id),
      ]);
      onDeploymentCreated?.(d);
      setDeployConfirm(false);
      loadDeployments();
    } catch (e) {
      setMsg(e.message);
    } finally {
      setBusy(false);
    }
  };
  const rollback = async () => {
    if (!rollbackConfirm) return;
    setBusy(true);
    try {
      const result = await api(`/deployments/${rollbackConfirm.id}/rollback`, { method: "POST" });
      notify?.(`已回滚到版本 ${result.release}，访问验证通过`, "success", 6000);
      setRollbackConfirm(null);
      await loadDeployments();
      loadRuntime(true);
    } catch (e) {
      notify?.(e.message || "回滚失败，原线上版本已自动恢复", "error", 8000);
    } finally {
      setBusy(false);
    }
  };
  const stopProject = async () => {
    setProjectLifecycleBusy("stop");
    setProjectStopConfirm(false);
    try {
      await api(`/projects/${project.id}/runtime/stop`, { method: "POST" });
      notify?.("项目的应用和数据服务已全部停止", "success");
      await loadDeployments();
      loadRuntime(false, true);
      loadDataResources(true);
      onUpdated?.(project);
    } catch (e) {
      notify?.(e.message, "error");
      loadRuntime(false, true);
    } finally {
      setProjectLifecycleBusy("");
    }
  };
  const startProject = async (deploymentId) => {
    if (!deploymentId) return;
    setProjectLifecycleBusy("start");
    try {
      await api(`/deployments/${deploymentId}/start`, { method: "POST" });
      notify?.("项目已重新启用", "success");
      await loadDeployments();
      loadRuntime(false, true);
      loadDataResources(true);
      onUpdated?.(project);
    } catch (e) {
      notify?.(e.message, "error");
      loadRuntime(false, true);
    } finally {
      setProjectLifecycleBusy("");
    }
  };
  const selectedNode = (nodes || []).find((item) => item.id === node);
  const latestSuccessfulDeployment = (deployments || []).find((item) => item.status === "success");
  const latestStoppedDeployment = (deployments || []).find((item) => item.status === "stopped" && item.release && item.access_url);
  const allocatedHostPort = hostPort || latestSuccessfulDeployment?.host_port || "";
  const allocatedContainerPort = containerPort || latestSuccessfulDeployment?.deployment_plan?.container_port || "";
  const normalizedDomain = String(domain || "").trim().replace(/^https?:\/\//i, "").replace(/\/$/, "");
  const configuredProtocol = accessConfig?.https_enabled ? "https" : "http";
  const configuredPort = accessConfig?.https_enabled ? accessConfig?.https_port : accessConfig?.http_port;
  const configuredDefaultPort = accessConfig?.https_enabled ? 443 : 80;
  const configuredAccessUrl = accessConfig && normalizedDomain
    ? `${configuredProtocol}://${normalizedDomain}${Number(configuredPort) && Number(configuredPort) !== configuredDefaultPort ? `:${configuredPort}` : ""}`
    : "";
  const deployedAccessUrl = configuredAccessUrl || latestSuccessfulDeployment?.access_url || latestSuccessfulDeployment?.platform_access_url || "";
  let deployedAccess = null;
  try {
    deployedAccess = deployedAccessUrl ? new URL(deployedAccessUrl) : null;
  } catch {
    deployedAccess = null;
  }
  const gatewayPort = deployedAccess?.port || (deployedAccess?.protocol === "https:" ? "443" : deployedAccess ? "80" : "自动分配");
  const accessEntry = deployedAccessUrl || (normalizedDomain
    ? `https://${normalizedDomain}`
    : `http://${window.location.hostname}:${allocatedHostPort || "自动分配"}`);
  const gatewayAddress = deployedAccess?.hostname || window.location.hostname;
  const gatewayDisplay = `${gatewayAddress}:${gatewayPort}`;
  const deploymentAddress = selectedNode?.public_address || "部署节点";
  const deploymentIsGateway = selectedNode?.public_address === gatewayAddress;
  const activeDeployment = (deployments || []).find(
    (item) => item.node_id === node && ["queued", "running"].includes(item.status),
  );
  const sourceState = projectSourceState({
    source_analysis: integrationAnalysis || project.source_analysis,
  });
  const sourceIsBusy = ["queued", "pulling", "analyzing", "running"].includes(sourceState.phase);
  const sourceFailed = sourceState.phase === "failed";
  const analysisRequired = (integrationAnalysis?.required || [])
    .filter((item, index, all) => item?.key && all.findIndex((row) => row?.key === item.key) === index);
  const analysisInferred = (integrationAnalysis?.inferred || [])
    .filter((item, index, all) => item?.key && all.findIndex((row) => row?.key === item.key) === index);
  const manualAnalysisItems = analysisRequired.filter((item) =>
    !item.key.startsWith("YUNZHOU_MYSQL_") && !item.key.startsWith("YUNZHOU_REDIS_"));
  const deployButtonText = activeDeployment
    ? "已有任务进行中"
    : sourceIsBusy
      ? sourceState.label
      : sourceFailed
        ? "源码处理失败"
        : "部署新版本";
  const hasRunningRelease = (deployments || []).some((item) => item.status === "success");
  const activeRuntimeEnvironment = (runtime?.environments || []).find(
    (item) => item.deployment_id === latestSuccessfulDeployment?.id,
  );
  const entryRuntimeContainer = (activeRuntimeEnvironment?.containers || []).find((item) =>
    latestSuccessfulDeployment?.host_port
      && String(item.ports || "").includes(`:${latestSuccessfulDeployment.host_port}->`),
  );
  const entryServiceLabel = entryRuntimeContainer?.service || entryRuntimeContainer?.name || "公网入口服务";
  const replicaControls = hasRunningRelease ? (
    <section className="runtime-mode-card runtime-scale-card">
      <div className="runtime-mode-head">
        <div>
          <b>公网入口负载</b>
          <small>流量目标：{entryServiceLabel}。这里只调整已接入平台网关的入口服务，不会误复制后端任务或数据服务。</small>
        </div>
        <div className="replica-stepper" aria-label="应用实例数">
          <button onClick={() => setReplicaCount(Math.max(1, Number(replicaCount) - 1))} disabled={!canEdit || scaling || Number(replicaCount) <= 1}>−</button>
          <span><b>{replicaCount}</b><small>个实例</small></span>
          <button onClick={() => setReplicaCount(Math.min(10, Number(replicaCount) + 1))} disabled={!canEdit || scaling || Number(replicaCount) >= 10}>＋</button>
        </div>
      </div>
      <div className="runtime-mode-summary">
        <span className={Number(replicaCount) > 1 ? "balanced" : "single"}>{Number(replicaCount) > 1 ? "负载均衡" : "单实例"}</span>
        <small>{replicaStatus
          ? `当前已就绪 ${replicaStatus.ready}/${replicaStatus.desired}；${replicaStatus.access_url || "继续使用原访问入口"}`
          : "正在读取当前实例状态"}</small>
      </div>
      {replicaStatus?.gateway && (
        <details className="runtime-gateway-status">
          <summary>
            <span className={`gateway-dot ${replicaStatus.gateway.status === "running" ? "online" : "offline"}`} />
            <b>平台网关</b>
            <span>{replicaStatus.gateway.status === "running" ? "运行中" : "异常"}</span>
            <small>{replicaStatus.gateway.access_url || replicaStatus.access_url || "尚未生成外部入口"}</small>
            <em>转发 {replicaStatus.gateway.upstream_count || replicaStatus.ready || 0} 个实例</em>
          </summary>
          <div>
            <span><small>网关节点</small><b>{replicaStatus.gateway.node || "—"}</b></span>
            <span><small>网关地址</small><b>{replicaStatus.gateway.address || "—"}</b></span>
            <span><small>转发目标</small><b>{replicaStatus.gateway.upstream || "—"}</b></span>
          </div>
        </details>
      )}
      {Number(replicaCount) > 1 && (
        <div className="runtime-mode-options">
          <Field label="流量分发策略">
            <select disabled={!canEdit || scaling} value={loadBalanceStrategy} onChange={(e) => setLoadBalanceStrategy(e.target.value)}>
              <option value="round_robin">轮询分发</option>
              <option value="least_conn">最少连接</option>
              <option value="ip_hash">同一访客固定实例</option>
            </select>
          </Field>
          <div className="stateful-service-note">
            <b>其他服务保持原样</b>
            <small>后端任务、company-sync、MySQL、Redis、MinIO 和数据卷不会被复制。内部后端如需负载，应单独配置内部网关。</small>
          </div>
        </div>
      )}
      {canEdit && (
        <div className="project-save-row">
          <button className="primary" disabled={scaling} onClick={applyScale}>
            {scaling ? <LoaderCircle className="spin" /> : <Network />}
            {scaling ? "正在调整..." : "应用实例数"}
          </button>
        </div>
      )}
    </section>
  ) : null;
  const projectRuntimeContainers = (runtime?.environments || []).flatMap((environment) => environment.containers || []);
  const projectDataContainerCount = projectRuntimeContainers.filter((container) =>
    dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`),
  ).length;
  const projectApplicationContainerCount = Math.max(0, projectRuntimeContainers.length - projectDataContainerCount);
  const projectRunningApplicationContainerCount = projectRuntimeContainers.filter((container) => {
    const isData = dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`);
    const state = `${container.state || ""} ${container.status || ""}`.toLowerCase();
    return !isData && (state.includes("running") || state.includes("up") || state.includes("healthy"));
  }).length;
  const projectRunningDataContainerCount = projectRuntimeContainers.filter((container) => {
    const isData = dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`);
    const state = `${container.state || ""} ${container.status || ""}`.toLowerCase();
    return isData && (state.includes("running") || state.includes("up") || state.includes("healthy"));
  }).length;
  const projectDataLabels = [...new Set(projectRuntimeContainers
    .filter((container) => dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`))
    .map((container) => {
      const identity = `${container.service || ""} ${container.name || ""} ${container.image || ""}`.toLowerCase();
      if (/mysql|mariadb/.test(identity)) return "MySQL";
      if (/redis/.test(identity)) return "Redis";
      if (/postgres/.test(identity)) return "PostgreSQL";
      if (/mongo/.test(identity)) return "MongoDB";
      if (/minio/.test(identity)) return "MinIO";
      return container.service || "数据服务";
    }))];
  const projectLifecycleActions = latestSuccessfulDeployment ? (
    <div className="project-lifecycle-actions">
      <span className="project-lifecycle-state running"><i />运行中{runtime && <small>应用 {projectApplicationContainerCount} · 数据 {projectDataContainerCount}</small>}</span>
      {canEdit && <button className="danger-outline" disabled={!!projectLifecycleBusy} onClick={() => setProjectStopConfirm(true)}>
        {projectLifecycleBusy === "stop" ? <LoaderCircle className="spin" /> : <Square />}
        {projectLifecycleBusy === "stop" ? "停止中" : "停止项目"}
      </button>}
    </div>
  ) : latestStoppedDeployment && projectRunningDataContainerCount > 0 ? (
    <div className="project-lifecycle-actions">
      <span className="project-lifecycle-state partial"><i /><b>应用已停</b><small>数据运行中</small></span>
      {canEdit && <button className="primary" disabled={!!projectLifecycleBusy} onClick={() => startProject(latestStoppedDeployment.id)}>
        {projectLifecycleBusy === "start" ? <LoaderCircle className="spin" /> : <Play />}
        {projectLifecycleBusy === "start" ? "启动中" : "启动应用"}
      </button>}
      {canEdit && <button className="danger-outline" disabled={!!projectLifecycleBusy} onClick={() => setProjectStopConfirm(true)}>
        {projectLifecycleBusy === "stop" ? <LoaderCircle className="spin" /> : <Square />}
        {projectLifecycleBusy === "stop" ? "停止中" : "停止项目"}
      </button>}
    </div>
  ) : latestStoppedDeployment ? (
    <div className="project-lifecycle-actions">
      <span className="project-lifecycle-state stopped"><i />已停止</span>
      {canEdit && <button className="primary" disabled={!!projectLifecycleBusy} onClick={() => startProject(latestStoppedDeployment.id)}>
        {projectLifecycleBusy === "start" ? <LoaderCircle className="spin" /> : <Play />}
        {projectLifecycleBusy === "start" ? "启动中" : "启动项目"}
      </button>}
    </div>
  ) : null;
  return (
    <Modal className="project-detail-modal" title={project.name} headerActions={projectLifecycleActions} onClose={onClose} wide>
      <div className="project-tabs">
        <button
          className={tab === "settings" ? "active" : ""}
          onClick={() => setTab("settings")}
        >
          <Settings />
          项目设置
        </button>
        <button
          className={tab === "runtime" ? "active" : ""}
          onClick={() => {
            setTab("runtime");
            if (!runtime) loadRuntime(true);
            if (!replicaStatus) loadReplicas();
          }}
        >
          <Boxes />
          运行服务 {projectRunningApplicationContainerCount > 0 && <em>{projectRunningApplicationContainerCount}</em>}
        </button>
        <button
          className={tab === "data" ? "active" : ""}
          onClick={() => {
            setTab("data");
            if (!dataResources) loadDataResources();
            if (!runtime) loadRuntime(true);
          }}
        >
          <ShieldCheck />
          数据资源 {projectRunningDataContainerCount > 0 && <em>{projectRunningDataContainerCount}</em>}
        </button>
        <button
          className={tab === "source" ? "active" : ""}
          onClick={() => setTab("source")}
        >
          <Code2 />
          源码管理
        </button>
        <button
          className={tab === "deployments" ? "active" : ""}
          onClick={() => setTab("deployments")}
        >
          <Activity />
          发布记录 <em>{deployments?.length || 0}</em>
        </button>
      </div>
      {tab === "settings" ? (
        <>
          <div className="project-config-intro">
            <div>
              <b>项目配置</b>
              <span>
                这里保存长期设置；每次发布实际使用的端口和状态请到“发布记录”查看。
              </span>
            </div>
            {canEdit && (
              <button className="ghost" disabled={integrationLoading} onClick={() => analyzeIntegrations(deploymentMode, true)}>
                {integrationLoading ? <LoaderCircle className="spin" /> : <Bot />}
                {integrationLoading ? "正在分析..." : "重新分析项目"}
              </button>
            )}
          </div>
          <div className="project-settings-grid project-settings-primary">
            <Field label="项目名称">
              <input
                disabled={!canEdit}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field label="访问配置" hint="域名、HTTP/HTTPS、端口和证书在这里统一管理">
              <div className="project-access-config-field">
                <input readOnly value={domain || "未配置自定义域名（使用平台分配地址）"} />
                {canEdit && <button type="button" className="ghost" onClick={() => setShowDomainConfig(true)}>{domain ? "修改" : "配置"}</button>}
              </div>
            </Field>
          </div>
          <details className="project-port-settings">
            <summary>
              <div className="project-port-summary">
                <span className="project-port-title"><Network /><b>访问链路</b></span>
                <span className="project-port-route">
                  <span className="project-route-step project-route-entry" title="用户实际访问的域名，或平台提供的公网 IP 与端口">
                    <small>访问入口</small>
                    <strong>{accessEntry}</strong>
                  </span>
                  <ChevronRight />
                  <span className="project-route-step project-route-gateway" title={`发布平台网关 ${gatewayDisplay}：接收公网 HTTP/HTTPS 请求并转发到部署服务器`}>
                    <small>发布平台网关</small>
                    <strong>{gatewayDisplay}</strong>
                  </span>
                  <ChevronRight />
                  <span className="project-route-step" title={`${selectedNode?.name || "部署服务器"}：Docker 在该节点上映射应用端口`}>
                    <small>{deploymentIsGateway ? "部署服务器（与平台同机）" : selectedNode?.name || "部署服务器"}</small>
                    <strong>{deploymentAddress}:{allocatedHostPort || "自动分配"}</strong>
                  </span>
                  <ChevronRight />
                  <span className="project-route-step" title="应用在容器内部实际监听的端口">
                    <small>容器应用</small>
                    <strong>内部端口 {allocatedContainerPort || "自动识别"}</strong>
                  </span>
                </span>
              </div>
              <small>修改端口</small>
            </summary>
            <div className="project-settings-grid">
            <Field
              label="部署服务器端口"
              hint="部署服务器对平台网关提供的端口；留空由系统自动分配"
            >
              <PortInput
                disabled={!canEdit}
                min="1"
                max="65535"
                placeholder="系统自动分配"
                value={hostPort}
                onChange={(e) => setHostPort(e.target.value)}
              />
            </Field>
            <Field label="容器应用端口" hint="应用在容器内部监听的端口；留空由 AI 自动识别">
              <PortInput
                disabled={!canEdit}
                min="1"
                max="65535"
                placeholder="自动识别"
                value={containerPort}
                onChange={(e) => setContainerPort(e.target.value)}
              />
            </Field>
            </div>
          </details>
          {canEdit && (
            <section className="deployment-integrations">
              <div className="integration-head">
                <div><b>部署与集成</b><small>决定 AI 如何处理旧系统依赖；部署后仍可修改。</small></div>
                <span>配置变更将在下次发布时应用</span>
              </div>
              <div className="deployment-mode-options">
                <button className={deploymentMode === "managed_fresh" ? "selected" : ""} onClick={() => setDeploymentMode("managed_fresh")}>
                  <Bot /><span><b>AI 全新托管</b><small>自动创建适合自建的 MySQL、Redis、MinIO；旧环境地址不继承，外部认证等可选集成默认关闭。</small></span>
                </button>
                <button className={deploymentMode === "preserve_integrations" ? "selected" : ""} onClick={() => {
                  setDeploymentMode("preserve_integrations");
                  if (!integrationAnalysis && !integrationLoading) analyzeIntegrations("preserve_integrations");
                }}>
                  <Network /><span><b>保留现有集成</b><small>沿用原来的对象存储、OIDC等外部系统；AI生成配置清单，由你填写地址和凭据。</small></span>
                </button>
              </div>
              {sourceAnalysis && (
                <div className="integration-analysis-summary source-analysis-summary">
                  <b>AI 源码分析完成</b>
                  <AnalysisSummaryDetails text={sourceAnalysis.summary} />
                  {!!sourceAnalysis.services?.length && <small>识别服务：{sourceAnalysis.services.join("、")}</small>}
                </div>
              )}
              {deploymentMode === "preserve_integrations" && (
                <div className="preserve-config-panel">
                  <div className="preserve-config-head">
                    <div><Settings /><span><b>现有服务连接配置</b><small>部署前先让 AI 根据源码生成所需配置项</small></span></div>
                  </div>
                  {["queued", "running"].includes(integrationAnalysis?.status) ? (
                    <div className="integration-analysis-empty">
                      <LoaderCircle className="spin" />
                      <div><b>{integrationAnalysis.status === "queued" ? "等待后台分析" : "后台正在分析源码"}</b><span>{integrationAnalysis.summary}</span></div>
                    </div>
                  ) : integrationAnalysis?.status === "failed" ? (
                    <div className="integration-analysis-empty analysis-failed">
                      <Activity />
                      <div><b>源码分析未完成</b><span>{integrationAnalysis.error || integrationAnalysis.summary}</span></div>
                    </div>
                  ) : integrationAnalysis ? (
                    <>
                      <div className="integration-analysis-summary">
                        <b>分析结果</b>
                        <span>{integrationAnalysis.summary}</span>
                        {!!integrationAnalysis.services?.length && <small>识别服务：{integrationAnalysis.services.join("、")}</small>}
                      </div>
                      <div className="service-choice-list">
                        {(integrationAnalysis.services || []).some((name) => /mysql/i.test(name)) && (
                          <div className="service-choice-card">
                            <label className="service-choice-toggle">
                              <input type="checkbox" checked={envValues.YUNZHOU_MYSQL_MODE === "external"} onChange={(event) => setEnvValue("YUNZHOU_MYSQL_MODE", event.target.checked ? "external" : "managed")} />
                              <span><b>使用现有 MySQL</b><small>勾选后填写现有数据库；不勾选由平台自动创建</small></span>
                            </label>
                            {envValues.YUNZHOU_MYSQL_MODE === "external" ? (
                              <div className="service-fields">
                                <Field label="数据库地址"><input value={envValues.YUNZHOU_MYSQL_HOST || ""} onChange={(e) => setEnvValue("YUNZHOU_MYSQL_HOST", e.target.value)} placeholder="例如 192.168.4.16" /></Field>
                                <Field label="端口"><input value={envValues.YUNZHOU_MYSQL_PORT || "3306"} onChange={(e) => setEnvValue("YUNZHOU_MYSQL_PORT", e.target.value)} placeholder="3306" /></Field>
                                <Field label="数据库名称"><input value={envValues.YUNZHOU_MYSQL_DATABASE || ""} onChange={(e) => setEnvValue("YUNZHOU_MYSQL_DATABASE", e.target.value)} placeholder="例如 wms" /></Field>
                                <Field label="用户名"><input value={envValues.YUNZHOU_MYSQL_USERNAME || ""} onChange={(e) => setEnvValue("YUNZHOU_MYSQL_USERNAME", e.target.value)} /></Field>
                                <Field label="密码"><input type="password" value={envValues.YUNZHOU_MYSQL_PASSWORD || ""} onChange={(e) => setEnvValue("YUNZHOU_MYSQL_PASSWORD", e.target.value)} /></Field>
                                <div className="service-test-row"><button className="ghost" disabled={integrationTesting === "mysql"} onClick={() => testIntegration("mysql")}>{integrationTesting === "mysql" ? <LoaderCircle className="spin" /> : <Activity />}测试 MySQL 连接</button></div>
                              </div>
                            ) : <div className="managed-service-note"><Bot />发布时由 AI 创建项目专用 MySQL，并自动生成数据库和凭据。</div>}
                          </div>
                        )}
                        {(integrationAnalysis.services || []).some((name) => /redis/i.test(name)) && (
                          <div className="service-choice-card">
                            <label className="service-choice-toggle">
                              <input type="checkbox" checked={envValues.YUNZHOU_REDIS_MODE === "external"} onChange={(event) => setEnvValue("YUNZHOU_REDIS_MODE", event.target.checked ? "external" : "managed")} />
                              <span><b>使用现有 Redis</b><small>勾选后填写现有 Redis；不勾选由平台自动创建</small></span>
                            </label>
                            {envValues.YUNZHOU_REDIS_MODE === "external" ? (
                              <div className="service-fields">
                                <Field label="Redis 地址"><input value={envValues.YUNZHOU_REDIS_HOST || ""} onChange={(e) => setEnvValue("YUNZHOU_REDIS_HOST", e.target.value)} placeholder="例如 192.168.4.16" /></Field>
                                <Field label="端口"><input value={envValues.YUNZHOU_REDIS_PORT || "6379"} onChange={(e) => setEnvValue("YUNZHOU_REDIS_PORT", e.target.value)} placeholder="6379" /></Field>
                                <Field label="库编号"><input value={envValues.YUNZHOU_REDIS_DATABASE || "0"} onChange={(e) => setEnvValue("YUNZHOU_REDIS_DATABASE", e.target.value)} placeholder="0" /></Field>
                                <Field label="密码（可不填）"><input type="password" value={envValues.YUNZHOU_REDIS_PASSWORD || ""} onChange={(e) => setEnvValue("YUNZHOU_REDIS_PASSWORD", e.target.value)} /></Field>
                                <div className="service-test-row"><button className="ghost" disabled={integrationTesting === "redis"} onClick={() => testIntegration("redis")}>{integrationTesting === "redis" ? <LoaderCircle className="spin" /> : <Activity />}测试 Redis 连接</button></div>
                              </div>
                            ) : <div className="managed-service-note"><Bot />发布时由 AI 创建项目专用 Redis，并自动完成连接配置。</div>}
                          </div>
                        )}
                      </div>
                      {!!manualAnalysisItems.length && <details className="integration-extra-fields">
                        <summary><Settings /><span><b>其他配置项</b><small>{manualAnalysisItems.length} 项 · {manualAnalysisItems.filter((item) => !envValues[item.key]).length} 项待填写</small></span></summary>
                        <div className="integration-field-list">
                          {manualAnalysisItems.map((item) => (
                              <Field key={item.key} label={item.key} hint={item.reason || item.source || (item.secret ? "敏感配置，将加密保存" : "AI 已从源码识别")}>
                                <input
                                  type={item.secret ? "password" : "text"}
                                  placeholder={item.secret && envValues[item.key] ? "已填写；重新输入可修改" : "请输入配置值"}
                                  value={envValues[item.key] || ""}
                                  onChange={(event) => setEnvValue(item.key, event.target.value)}
                                />
                              </Field>
                            ))}
                        </div>
                      </details>}
                    </>
                  ) : (
                    <div className="integration-analysis-empty">尚未分析。点击按钮后，平台会识别 MySQL、Redis、MinIO 和其他外部服务。</div>
                  )}
                  <details className="raw-environment-editor">
                    <summary>高级方式：查看或编辑原始环境变量</summary>
                    <textarea rows="12" value={envText} onChange={(event) => setEnvText(event.target.value)} placeholder="KEY=VALUE，每行一项" />
                  </details>
                </div>
              )}
              {deploymentMode === "managed_fresh" && !!managedEnvText && (
                <details className="advanced project-environment managed-environment">
                  <summary><Server />平台托管连接信息</summary>
                  <p>由平台为本项目创建，可直接用于连接 MySQL、Redis、MinIO 等服务。请只向项目维护人员开放。</p>
                  <div className="stage-log-head"><b>系统自动生成</b><button className="ghost" onClick={() => copyText(managedEnvText)}><Copy />复制全部</button></div>
                  <pre className="logs stage-log">{managedEnvText}</pre>
                </details>
              )}
            </section>
          )}
          {canEdit && (
            <div className="project-save-row">
              <button
                className="ghost save-config-button"
                disabled={saving || !name.trim()}
                onClick={save}
              >
                {saving ? <LoaderCircle className="spin" /> : <Settings />}
                仅保存配置
              </button>
            </div>
          )}
          <hr />
          <div className="deploy-project-section">
            <div>
              <b>发布新版本</b>
              <span>{sourceIsBusy
                ? "源码正在后台准备，完成后即可发布，无需停留在此页面"
                : sourceFailed
                  ? "请先到源码管理查看原因并重新分析"
                  : "选择服务器后创建一条新的发布记录"}</span>
            </div>
            {(sourceIsBusy || sourceFailed || sourceState.workspace_path) && (
              <div className={`source-deploy-readiness ${sourceFailed ? "failed" : ""}`}>
                <div>
                  {sourceIsBusy && <LoaderCircle className="spin" />}
                  <b>{sourceState.label}</b>
                  {sourceIsBusy ? <span>{sourceState.summary || "正在准备源码"}</span> : <AnalysisSummaryDetails text={sourceState.summary} />}
                  <em>{Number(sourceState.progress || 0)}%</em>
                </div>
                <progress max="100" value={Number(sourceState.progress || 0)} />
                {sourceState.repository_cache_path && <small>仓库缓存：{sourceState.repository_cache_path}</small>}
                {sourceState.workspace_path && <small>源码目录：{sourceState.workspace_path}</small>}
                {sourceState.branch && <small>分支：{sourceState.branch}{sourceState.revision ? ` · 提交 ${sourceState.revision}` : ""}</small>}
                {sourceState.error && <small className="source-error">原因：{sourceState.error}</small>}
              </div>
            )}
            <Field label="目标服务器">
              {nodes === null ? (
                <div className="alert info">
                  <LoaderCircle className="spin" />
                  正在读取服务器...
                </div>
              ) : nodeError ? (
                <div className="alert danger">
                  读取失败：{nodeError}{" "}
                  <button className="ghost" onClick={loadNodes}>
                    <RefreshCw />
                    重试
                  </button>
                </div>
              ) : (
                <select value={node} onChange={(e) => setNode(e.target.value)}>
                  <option value="">请选择服务器</option>
                  {nodes.map((x) => (
                    <option value={x.id} key={x.id}>
                      {x.name} · {x.last_status}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <button
              className="primary"
              disabled={!node || busy || !canEdit || !!activeDeployment || sourceIsBusy || sourceFailed}
              onClick={() => setDeployConfirm(true)}
            >
              {busy || sourceIsBusy ? <LoaderCircle className="spin" /> : <Play />}
              {deployButtonText}
            </button>
          </div>
          {msg && <div className="alert info">{msg}</div>}
          <div className="project-danger-zone">
            <div>
              <b>删除项目</b>
              <span>
                删除前由系统 AI
                查询并列出发布记录、容器、镜像、目录、网关配置和源码。
              </span>
            </div>
            <button
              className="danger-button"
              disabled={!canEdit}
              onClick={() => setShowDelete(true)}
            >
              <Trash2 />
              扫描并删除项目
            </button>
          </div>
        </>
      ) : tab === "runtime" ? (
        <>
          <ProjectRuntime
            projectId={project.id}
            canEdit={canEdit}
            runtime={runtime}
            refreshing={runtimeRefreshing}
            onRefresh={() => loadRuntime(false, true)}
            onGateway={openGatewaySnapshot}
            gatewayLoading={false}
            notify={notify}
            onOpen={(id) => {
              const found = deployments?.find((x) => x.id === id);
              if (found) onOpenDeployment?.(found);
            }}
            scope="application"
          />
        </>
      ) : tab === "data" ? (
        <ProjectDataResources
          project={project}
          canEdit={canEdit}
          data={dataResources}
          runtime={runtime}
          runtimeRefreshing={runtimeRefreshing}
          onRuntimeRefresh={() => loadRuntime(false, true)}
          onOpenDeployment={(id) => {
            const found = deployments?.find((x) => x.id === id);
            if (found) onOpenDeployment?.(found);
          }}
          onRefresh={loadDataResources}
          notify={notify}
        />
      ) : tab === "source" ? (
        <ProjectSourceManager
          project={project}
          analysis={integrationAnalysis || project.source_analysis}
          canEdit={canEdit}
          notify={notify}
          onDone={onUpdated}
        />
      ) : (
        <div className="project-release-list">
          {deployments === null ? (
            <div className="center">
              <LoaderCircle className="spin" />
            </div>
          ) : deployments.length ? (
            deployments.map((d) => (
              <div className="project-release-row" key={d.id} onClick={() => onOpenDeployment?.(d)}>
                <div>
                  <b>
                    {d.release
                      ? `版本 ${d.release}`
                      : `任务 ${d.id.slice(0, 8)}`}
                  </b>
                  <small>
                    {d.node_name} · {time(d.created_at)} · {deploymentDuration(d)}
                  </small>
                  {d.rollback_transition?.kind === "rollback_target" && (
                    <small className="release-transition rollback-target">
                      <RefreshCw />由版本 {d.rollback_transition.from_release} 回滚至此
                    </small>
                  )}
                  {d.rollback_transition?.kind === "rollback_source" && (
                    <small className="release-transition rollback-source">
                      <RefreshCw />已切换到版本 {d.rollback_transition.to_release}
                    </small>
                  )}
                </div>
                <div>
                  <Badge status={d.status} />
                  <span>
                    {d.status === "success"
                      ? (d.host_port ? `实际端口 ${d.host_port}` : "端口识别中")
                      : d.status === "stopped"
                        ? "启动时自动分配"
                        : d.status === "failed"
                          ? "未占用端口"
                          : "端口分配中"}
                  </span>
                  {canEdit && d.rollback_allowed && (
                    <button className="ghost rollback-button" onClick={(event) => { event.stopPropagation(); setRollbackConfirm(d); }}>
                      <RefreshCw />回滚到此版本
                    </button>
                  )}
                  <ChevronRight />
                </div>
              </div>
            ))
          ) : (
            <Empty icon={Activity} text="这个项目还没有发布记录" />
          )}
        </div>
      )}
      {showDelete && (
        <ProjectDeleteDialog
          project={project}
          onClose={() => setShowDelete(false)}
          onDone={onDeleted}
          onReset={() => {
            setShowDelete(false);
            onUpdated?.(project);
          }}
        />
      )}{" "}
      {projectStopConfirm && (
        <ConfirmDialog
          title="停止项目"
          text={`确定停止“${project.name}”的全部运行服务？`}
          description={`将停止 ${projectApplicationContainerCount} 个应用容器${projectDataLabels.length ? `以及 ${projectDataLabels.join("、")}` : ""}。数据卷、上传文件、源码和发布记录不会删除。`}
          confirmText="确认停止项目"
          danger
          busy={projectLifecycleBusy === "stop"}
          onClose={() => projectLifecycleBusy !== "stop" && setProjectStopConfirm(false)}
          onConfirm={stopProject}
        />
      )}
      {deployConfirm && (
        <ConfirmDialog
          title="确认创建部署"
          text={`发布“${project.name}”到“${selectedNode?.name || "所选服务器"}”？`}
          description="将先以 1 个应用实例完成构建、启动和访问验证。发布成功后，可到“运行服务”手动增加实例并开启负载均衡。"
          confirmText="确认并开始部署"
          busy={busy}
          onClose={() => !busy && setDeployConfirm(false)}
          onConfirm={deploy}
        />
      )}
      {rollbackConfirm && (
        <ConfirmDialog
          title="确认回滚版本"
          text={`确定回滚到版本 ${rollbackConfirm.release}？`}
          description="平台会先校验并启动目标版本；健康检查和网关切换成功后，才停止当前线上应用。MySQL、Redis 与数据卷保持不动。任何步骤失败都会清理候选版本并保留当前线上版本。"
          confirmText="确认回滚"
          busy={busy}
          onClose={() => !busy && setRollbackConfirm(null)}
          onConfirm={rollback}
        />
      )}
      {showDomainConfig && (
        <ProjectDomainModal
          deployment={{ project_id: project.id, project_name: project.name, project_domain: domain }}
          notify={notify}
          onClose={() => setShowDomainConfig(false)}
          onSaved={(result) => {
            const nextDomain = result?.domain || "";
            setDomain(nextDomain);
            setAccessConfig(result || null);
            setShowDomainConfig(false);
            loadDeployments();
            loadReplicas();
            onUpdated?.({ ...project, domain: nextDomain || null });
          }}
        />
      )}
      {showGatewaySnapshot && <GatewayGeneratedConfigModal preview={gatewaySnapshot || { routes: [], message: "正在后台读取网关配置..." }} loading={gatewaySnapshotLoading} onClose={() => setShowGatewaySnapshot(false)} onRefresh={loadGatewaySnapshot} onSettings={canEdit ? () => setShowGatewaySettings(true) : null} notify={notify} />}
      {showGatewaySettings && <GatewayPolicyModal projectId={project.id} onClose={() => setShowGatewaySettings(false)} onSaved={(preview) => { setGatewaySnapshot(preview); setShowGatewaySettings(false); notify?.("网关配置已生效", "success"); }} notify={notify} />}
    </Modal>
  );
}

function serviceScaleInfo(containers, container, servicePools = []) {
  const service = String(container.service || container.service_name || "app");
  const descriptor = `${service} ${container.name || ""} ${container.image || ""}`.toLowerCase();
  const dataService = /(^|[-_.])(mysql|mariadb|postgres|postgresql|redis|mongo|mongodb|minio|elasticsearch|rabbitmq|kafka|zookeeper|etcd)([-_.]|$)/.test(descriptor);
  const backgroundService = /(^|[-_.])(worker|job|cron|scheduler|sync|consumer|queue)([-_.]|$)/.test(descriptor);
  const explicit = typeof container.scalable === "boolean" ? container.scalable : null;
  const scalable = explicit ?? (!dataService && !backgroundService && (containers.length === 1 || /(front|web|back|api|server|app)/.test(descriptor)));
  const pool = servicePools.find((item) => String(item.service || item.name) === service);
  const counted = containers.filter((item) => String(item.service || item.service_name || "app") === service).length || 1;
  const actual = Math.max(1, Number(pool?.desired ?? pool?.replicas ?? container.desired_replicas ?? counted) || 1);
  return { service, dataService, backgroundService, scalable, actual };
}

function ServiceScaleControl({ projectId, container, containers, servicePools, enabled, notify, onDone }) {
  const info = serviceScaleInfo(containers, container, servicePools);
  const [draft, setDraft] = useState(info.actual);
  const [busy, setBusy] = useState(false);
  useEffect(() => setDraft(info.actual), [info.actual, info.service]);
  if (info.dataService) return <span className="service-singleton-badge" title="数据服务不能使用普通副本扩容">单例数据服务</span>;
  if (!info.scalable) return <span className="service-singleton-badge muted">固定服务</span>;
  const save = async (event) => {
    event.stopPropagation();
    if (!enabled || busy || Number(draft) === info.actual) return;
    setBusy(true);
    try {
      const result = await api(`/projects/${projectId}/services/${encodeURIComponent(info.service)}/scale`, {
        method: "POST",
        body: JSON.stringify({ replicas: Number(draft) }),
      });
      const desired = Number(result.desired ?? draft) || Number(draft);
      setDraft(desired);
      notify?.(`${info.service} 已调整为 ${desired} 个实例`, "success");
      await onDone?.();
    } catch (e) {
      setDraft(info.actual);
      notify?.(e.message, "error");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="service-scale-control" onClick={(event) => event.stopPropagation()}>
      <button type="button" aria-label={`${info.service} 减少一个实例`} disabled={!enabled || busy || Number(draft) <= 1} onClick={() => setDraft((value) => Math.max(1, Number(value) - 1))}>−</button>
      <span title={`${info.service} 目标实例数`}><b>{draft}</b></span>
      <button type="button" aria-label={`${info.service} 增加一个实例`} disabled={!enabled || busy || Number(draft) >= 10} onClick={() => setDraft((value) => Math.min(10, Number(value) + 1))}>＋</button>
      <button type="button" className="service-scale-save" disabled={!enabled || busy || Number(draft) === info.actual} onClick={save}>{busy ? <LoaderCircle className="spin" /> : "保存"}</button>
    </div>
  );
}

const dataContainerPattern = /mysql|mariadb|postgres|redis|mongo|oracle|sqlserver|elasticsearch|opensearch|minio|rabbitmq|kafka|zookeeper|activemq|nacos|consul|etcd/i;

function ProjectRuntime({ projectId, canEdit, runtime, refreshing, onRefresh, onGateway, gatewayLoading, onOpen, notify, scope = "application" }) {
  const [restarting, setRestarting] = useState("");
  const [logTarget, setLogTarget] = useState(null);
  const [containerLogs, setContainerLogs] = useState("");
  const [logsLoading, setLogsLoading] = useState(false);
  const [autoLogs, setAutoLogs] = useState(true);
  const [followLogs, setFollowLogs] = useState(true);
  const [logQuery, setLogQuery] = useState("");
  const [logScreenCleared, setLogScreenCleared] = useState(false);
  const [logSince, setLogSince] = useState("");
  const [restartConfirm, setRestartConfirm] = useState(null);
  const [containerTab, setContainerTab] = useState("logs");
  const [containerPath, setContainerPath] = useState("/");
  const [containerPathDraft, setContainerPathDraft] = useState("/");
  const [containerFiles, setContainerFiles] = useState([]);
  const [filesLoading, setFilesLoading] = useState(false);
  const [filesUploading, setFilesUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(null);
  const [downloadProgress, setDownloadProgress] = useState(null);
  const [fileMenu, setFileMenu] = useState(null);
  const [deleteFileConfirm, setDeleteFileConfirm] = useState(null);
  const [fileDeleting, setFileDeleting] = useState(false);
  const [terminalCommand, setTerminalCommand] = useState("");
  const [terminalOutput, setTerminalOutput] = useState("容器终端已就绪。命令将在当前目录执行并记录审计日志。\n");
  const [terminalBusy, setTerminalBusy] = useState(false);
  const [terminalConnected, setTerminalConnected] = useState(false);
  const [terminalHistory, setTerminalHistory] = useState([]);
  const [terminalSearchActive, setTerminalSearchActive] = useState(false);
  const [terminalSearchQuery, setTerminalSearchQuery] = useState("");
  const [terminalSearchMatch, setTerminalSearchMatch] = useState("");
  const terminalInputRef = useRef(null);
  const runtimeLogRef = useRef(null);
  const fileUploadRef = useRef(null);
  const uploadRequestRef = useRef(null);
  const downloadRequestRef = useRef(null);
  const fileCacheRef = useRef(new Map());
  const fileRequestRef = useRef(0);
  const terminalOutputRef = useRef(null);
  const terminalSocketRef = useRef(null);
  const terminalHoveredRef = useRef(false);
  const terminalHistoryIndexRef = useRef(-1);
  const terminalHistoryDraftRef = useRef("");
  const terminalSearchIndexRef = useRef(-1);
  const terminalSearchQueryRef = useRef("");
  const terminalSearchDraftRef = useRef("");
  const focusTerminalIfHovered = () => {
    if (terminalHoveredRef.current) terminalInputRef.current?.focus();
  };
  const loadContainerLogs = async (target, quiet = false, sinceValue = logSince) => {
    if (!target) return;
    if (!quiet) setLogsLoading(true);
    try {
      const result = await api(`/deployments/${target.deploymentId}/containers/${encodeURIComponent(target.container.name)}/logs${sinceValue ? `?since=${encodeURIComponent(sinceValue)}` : ""}`);
      if (sinceValue) {
        setContainerLogs(result.logs || "");
        setLogScreenCleared(!result.logs);
      } else {
        setContainerLogs(result.logs || "当前没有日志输出");
        setLogScreenCleared(false);
      }
    } catch (e) {
      setContainerLogs(`日志读取失败：${e.message}`);
    } finally {
      if (!quiet) setLogsLoading(false);
    }
  };
  const openContainer = (deploymentId, container) => {
    terminalSocketRef.current?.close();
    terminalSocketRef.current = null;
    setTerminalConnected(false);
    const target = { deploymentId, container };
    setLogTarget(target);
    setAutoLogs(true);
    setContainerTab("logs");
    setContainerPath("/");
    setContainerPathDraft("/");
    setContainerFiles([]);
    fileCacheRef.current.clear();
    fileRequestRef.current += 1;
    setTerminalCommand("");
    setTerminalOutput("容器终端已就绪。命令将在当前目录执行并记录审计日志。\n");
    setContainerLogs("");
    setLogQuery("");
    setFollowLogs(true);
    setLogScreenCleared(false);
    setLogSince("");
    loadContainerLogs(target, false, "");
  };
  const connectTerminal = (target = logTarget, cwd = containerPath) => {
    if (!target || [WebSocket.OPEN, WebSocket.CONNECTING].includes(terminalSocketRef.current?.readyState)) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/api/deployments/${target.deploymentId}/containers/${encodeURIComponent(target.container.name)}/terminal/ws?cwd=${encodeURIComponent(cwd || "/")}`;
    const socket = new WebSocket(url, ["yunzhou-terminal", `bearer.${token()}`]);
    terminalSocketRef.current = socket;
    socket.onopen = () => { setTerminalConnected(true); setTerminalBusy(false); setTimeout(focusTerminalIfHovered, 0); };
    socket.onmessage = (event) => setTerminalOutput((value) => `${value}${stripTerminalAnsi(event.data)}`);
    socket.onerror = () => setTerminalOutput((value) => `${value}\n[实时终端连接异常，将在重新打开时重连]\n`);
    socket.onclose = () => { if (terminalSocketRef.current === socket) terminalSocketRef.current = null; setTerminalConnected(false); setTerminalBusy(false); };
  };
  const loadContainerFiles = async (path = containerPath, options = {}) => {
    if (!logTarget) return false;
    const requested = path || "/";
    const requestId = ++fileRequestRef.current;
    const cached = fileCacheRef.current.get(requested);
    if (cached) {
      setContainerPath(requested);
      setContainerPathDraft(requested);
      setContainerFiles(cached);
    }
    setFilesLoading(!cached);
    try {
      const result = await api(`/deployments/${logTarget.deploymentId}/containers/${encodeURIComponent(logTarget.container.name)}/files?path=${encodeURIComponent(requested)}`);
      const resolved = result.path || requested;
      fileCacheRef.current.set(resolved, result.entries || []);
      if (requestId !== fileRequestRef.current) return;
      setContainerPath(resolved);
      setContainerPathDraft(resolved);
      setContainerFiles(result.entries || []);
      return true;
    } catch (e) {
      if (requestId === fileRequestRef.current) {
        notify?.(e.message, "error");
        if (options.terminal) setTerminalOutput((value) => `${value}${e.message}\n`);
      }
      return false;
    } finally {
      if (requestId === fileRequestRef.current) setFilesLoading(false);
    }
  };
  const changeContainerTab = async (tab) => {
    setContainerTab(tab);
    if (tab === "terminal") {
      // This UI is a command box rather than a full xterm emulator. Use the
      // audited command endpoint so minimal Alpine/BusyBox shells cannot leak
      // PTY control sequences into commands or corrupt the rendered output.
      terminalSocketRef.current?.close();
      terminalSocketRef.current = null;
      setTerminalConnected(false);
      const ready = containerFiles.length ? true : await loadContainerFiles("/", { terminal: true });
      setTerminalConnected(Boolean(ready));
      setTimeout(focusTerminalIfHovered, 0);
    }
  };
  const runContainerCommand = async () => {
    const command = terminalCommand.trim();
    if (!logTarget || terminalBusy) return;
    if (!command) {
      setTerminalOutput((value) => `${value}${value.endsWith("\n") ? "" : "\n"}${containerPath} # \n`);
      setTimeout(focusTerminalIfHovered, 0);
      return;
    }
    const nextHistory = [...terminalHistory, command].slice(-100);
    setTerminalHistory(nextHistory);
    terminalHistoryIndexRef.current = -1;
    terminalHistoryDraftRef.current = "";
    terminalSearchIndexRef.current = -1;
    terminalSearchQueryRef.current = "";
    if (/^(?:clear|reset)$/i.test(command)) {
      setTerminalCommand("");
      setTerminalOutput("");
      setTimeout(focusTerminalIfHovered, 0);
      return;
    }
    if (/^history$/i.test(command)) {
      setTerminalCommand("");
      setTerminalOutput((value) => `${value}${value.endsWith("\n") ? "" : "\n"}${containerPath} # ${command}\n${nextHistory.map((item, index) => `${String(index + 1).padStart(4, " ")}  ${item}`).join("\n")}\n`);
      setTimeout(focusTerminalIfHovered, 0);
      return;
    }
    setTerminalBusy(true);
    setTerminalCommand("");
    try {
      const cdMatch = command.match(/^cd(?:\s+(.+))?$/);
      setTerminalOutput((value) => `${value}${value.endsWith("\n") ? "" : "\n"}${containerPath} # ${command}\n`);
      if (cdMatch) {
        const rawPath = (cdMatch[1] || "/").trim().replace(/^['"]|['"]$/g, "");
        const parts = (rawPath.startsWith("/") ? rawPath : `${containerPath}/${rawPath}`).split("/");
        const normalized = [];
        parts.forEach((part) => { if (!part || part === ".") return; if (part === "..") normalized.pop(); else normalized.push(part); });
        await loadContainerFiles(`/${normalized.join("/")}`, { terminal: true });
        return;
      }
      const result = await api(`/deployments/${logTarget.deploymentId}/containers/${encodeURIComponent(logTarget.container.name)}/terminal`, {
        method: "POST", body: JSON.stringify({ command, cwd: containerPath }),
      });
      const cleanOutput = stripTerminalAnsi(result.output || "");
      setTerminalOutput((value) => `${value}${cleanOutput}${cleanOutput.endsWith("\n") || !cleanOutput ? "" : "\n"}${result.exit_code ? `[退出码 ${result.exit_code}]\n` : ""}`);
    } catch (e) {
      setTerminalOutput((value) => `${value}执行失败：${e.message}\n`);
    } finally {
      setTerminalBusy(false);
      setTimeout(focusTerminalIfHovered, 0);
    }
  };
  const clearTerminalScreen = () => {
    setTerminalOutput("");
    setTimeout(focusTerminalIfHovered, 0);
  };
  const findTerminalHistoryMatch = (query, beforeIndex = terminalHistory.length) => {
    const normalized = query.trim().toLowerCase();
    for (let index = Math.min(beforeIndex - 1, terminalHistory.length - 1); index >= 0; index -= 1) {
      if (!normalized || terminalHistory[index].toLowerCase().includes(normalized)) return { index, value: terminalHistory[index] };
    }
    return { index: -1, value: "" };
  };
  const updateTerminalReverseSearch = (query, beforeIndex = terminalHistory.length) => {
    const found = findTerminalHistoryMatch(query, beforeIndex);
    terminalSearchQueryRef.current = query;
    terminalSearchIndexRef.current = found.index;
    setTerminalSearchQuery(query);
    setTerminalSearchMatch(found.value);
  };
  const finishTerminalReverseSearch = (accept = true) => {
    setTerminalSearchActive(false);
    setTerminalSearchQuery("");
    setTerminalSearchMatch("");
    terminalSearchQueryRef.current = "";
    terminalSearchIndexRef.current = -1;
    setTerminalCommand(accept && terminalSearchMatch ? terminalSearchMatch : terminalSearchDraftRef.current);
    setTimeout(focusTerminalIfHovered, 0);
  };
  const handleTerminalKeyDown = (event) => {
    const clearShortcut = event.ctrlKey && !event.altKey && !event.metaKey
      && (event.key.toLowerCase() === "l" || event.key === "/");
    const reverseSearchShortcut = event.ctrlKey && !event.altKey && !event.metaKey
      && event.key.toLowerCase() === "r";
    if (clearShortcut) {
      event.preventDefault();
      event.stopPropagation();
      clearTerminalScreen();
    } else if (reverseSearchShortcut) {
      event.preventDefault();
      event.stopPropagation();
      if (!terminalHistory.length) return;
      if (!terminalSearchActive) {
        terminalSearchDraftRef.current = terminalCommand;
        setTerminalSearchActive(true);
        updateTerminalReverseSearch("", terminalHistory.length);
      } else {
        const before = terminalSearchIndexRef.current < 0 ? terminalHistory.length : terminalSearchIndexRef.current;
        const found = findTerminalHistoryMatch(terminalSearchQueryRef.current, before);
        if (found.index >= 0) {
          terminalSearchIndexRef.current = found.index;
          setTerminalSearchMatch(found.value);
        }
      }
    } else if (terminalSearchActive && event.key === "Escape") {
      event.preventDefault();
      finishTerminalReverseSearch(false);
    } else if (terminalSearchActive && event.key === "Enter") {
      event.preventDefault();
      finishTerminalReverseSearch(true);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      event.stopPropagation();
      if (!terminalHistory.length) return;
      if (terminalHistoryIndexRef.current < 0) {
        terminalHistoryDraftRef.current = terminalCommand;
        terminalHistoryIndexRef.current = terminalHistory.length - 1;
      } else if (terminalHistoryIndexRef.current > 0) {
        terminalHistoryIndexRef.current -= 1;
      }
      terminalSearchIndexRef.current = -1;
      setTerminalCommand(terminalHistory[terminalHistoryIndexRef.current]);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      event.stopPropagation();
      if (terminalHistoryIndexRef.current < 0) return;
      if (terminalHistoryIndexRef.current < terminalHistory.length - 1) {
        terminalHistoryIndexRef.current += 1;
        setTerminalCommand(terminalHistory[terminalHistoryIndexRef.current]);
      } else {
        terminalHistoryIndexRef.current = -1;
        setTerminalCommand(terminalHistoryDraftRef.current);
      }
      terminalSearchIndexRef.current = -1;
    } else if (event.key === "Tab") {
      event.preventDefault();
      event.stopPropagation();
      completeTerminalCommand();
    } else if (event.key === "Enter") {
      event.preventDefault();
      runContainerCommand();
    }
  };
  const completeTerminalCommand = async () => {
    if (!logTarget || !terminalCommand) return;
    const match = terminalCommand.match(/(^|\s)([^\s]*)$/);
    if (!match) return;
    const rawToken = match[2].replace(/^['"]|['"]$/g, "");
    const slash = rawToken.lastIndexOf("/");
    const dirPart = slash >= 0 ? rawToken.slice(0, slash + 1) : "";
    const prefix = slash >= 0 ? rawToken.slice(slash + 1) : rawToken;
    const rawParent = rawToken.startsWith("/") ? (dirPart || "/") : `${containerPath}/${dirPart}`;
    const normalized = [];
    rawParent.split("/").forEach((part) => { if (!part || part === ".") return; if (part === "..") normalized.pop(); else normalized.push(part); });
    const parent = `/${normalized.join("/")}`;
    try {
      let entries = fileCacheRef.current.get(parent);
      if (!entries) {
        const result = await api(`/deployments/${logTarget.deploymentId}/containers/${encodeURIComponent(logTarget.container.name)}/files?path=${encodeURIComponent(parent)}`);
        entries = result.entries || [];
        fileCacheRef.current.set(result.path || parent, entries);
      }
      const isCommandToken = !dirPart && terminalCommand.slice(0, (match.index || 0) + match[1].length).trim() === "";
      const commonCommands = [
        "cat", "cd", "chmod", "chown", "cp", "curl", "date", "df", "du", "echo", "env",
        "find", "grep", "head", "id", "less", "ls", "mkdir", "mv", "netstat", "ping",
        "printenv", "ps", "pwd", "redis-cli", "rm", "sed", "sh", "tail", "tar", "top",
        "touch", "uname", "vi", "wget", "which", "whoami",
      ];
      const fileMatches = entries.filter((entry) => entry.name.startsWith(prefix));
      const commandMatches = isCommandToken
        ? commonCommands.filter((name) => name.startsWith(prefix)).map((name) => ({ name, type: "command" }))
        : [];
      const matches = [...commandMatches, ...fileMatches]
        .filter((entry, index, all) => all.findIndex((candidate) => candidate.name === entry.name) === index);
      if (!matches.length) return;
      const common = longestCommonPrefix(matches.map((entry) => entry.name));
      const unique = matches.length === 1;
      const suffix = unique ? (matches[0].type === "directory" ? "/" : " ") : "";
      const replacement = `${dirPart}${common}${suffix}`;
      const tokenStart = (match.index || 0) + match[1].length;
      setTerminalCommand(`${terminalCommand.slice(0, tokenStart)}${replacement}`);
      if (!unique && common === prefix) setTerminalOutput((value) => `${value}${value.endsWith("\n") ? "" : "\n"}${matches.map((entry) => entry.name + (entry.type === "directory" ? "/" : "")).join("  ")}\n`);
    } catch (e) {
      setTerminalOutput((value) => `${value}${value.endsWith("\n") ? "" : "\n"}[补全失败] ${e.message}\n`);
    } finally {
      setTimeout(focusTerminalIfHovered, 0);
    }
  };
  useEffect(() => {
    if (containerTab === "terminal" && terminalOutputRef.current) terminalOutputRef.current.scrollTop = terminalOutputRef.current.scrollHeight;
  }, [terminalOutput, containerTab]);
  const downloadContainerPath = async (entry, archive = false) => {
    if (!logTarget || downloadProgress) return;
    const controller = new AbortController();
    downloadRequestRef.current = controller;
    const fileName = (archive || entry.type === "directory") ? `${entry.name}.tar.gz` : entry.name;
    setDownloadProgress({ name: fileName, loaded: 0, total: 0, percent: null });
    try {
      const response = await fetch(`/api/deployments/${logTarget.deploymentId}/containers/${encodeURIComponent(logTarget.container.name)}/files/download?path=${encodeURIComponent(entry.path)}&archive=${archive || entry.type === "directory"}`, { headers: { Authorization: `Bearer ${token()}` }, signal: controller.signal });
      if (!response.ok) throw new Error(`下载失败 (${response.status})`);
      const total = Number(response.headers.get("content-length")) || 0;
      let loaded = 0;
      let blob;
      if (response.body?.getReader) {
        const reader = response.body.getReader();
        const chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          loaded += value.byteLength;
          setDownloadProgress({ name: fileName, loaded, total, percent: total ? Math.min(99, Math.round((loaded / total) * 100)) : null });
        }
        blob = new Blob(chunks, { type: response.headers.get("content-type") || "application/octet-stream" });
      } else {
        blob = await response.blob();
        loaded = blob.size;
      }
      setDownloadProgress({ name: fileName, loaded, total: total || loaded, percent: 100 });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = fileName; a.click(); URL.revokeObjectURL(url);
    } catch (e) { if (e.name !== "AbortError") notify?.(e.message, "error"); }
    finally { downloadRequestRef.current = null; setTimeout(() => setDownloadProgress(null), 600); }
  };
  const uploadContainerFiles = async (fileList) => {
    const selected = Array.from(fileList || []);
    if (!logTarget || !selected.length || filesUploading) return;
    const existing = selected.filter((file) => containerFiles.some((entry) => entry.name === file.name));
    const overwrite = existing.length > 0;
    if (overwrite && !window.confirm(`${existing.map((file) => file.name).join("、")} 已存在，是否覆盖？`)) return;
    setFilesUploading(true);
    setUploadProgress({ percent: 0, name: selected.length === 1 ? selected[0].name : `${selected.length} 个文件` });
    try {
      const body = new FormData();
      body.append("path", containerPath);
      body.append("overwrite", String(overwrite));
      selected.forEach((file) => body.append("files", file));
      const result = await new Promise((resolve, reject) => {
        const request = new XMLHttpRequest();
        uploadRequestRef.current = request;
        request.open("POST", `/api/deployments/${logTarget.deploymentId}/containers/${encodeURIComponent(logTarget.container.name)}/files/upload`);
        request.setRequestHeader("Authorization", `Bearer ${token()}`);
        request.upload.onprogress = (event) => {
          if (event.lengthComputable) setUploadProgress((value) => ({ ...value, percent: Math.min(99, Math.round((event.loaded / event.total) * 100)) }));
        };
        request.onerror = () => reject(new Error("上传连接中断"));
        request.onabort = () => reject(Object.assign(new Error("上传已取消"), { name: "AbortError" }));
        request.onload = () => {
          let payload = {};
          try { payload = JSON.parse(request.responseText || "{}"); } catch { payload = {}; }
          if (request.status < 200 || request.status >= 300) reject(new Error(payload.detail || `上传失败 (${request.status})`));
          else resolve(payload);
        };
        request.send(body);
      });
      setUploadProgress((value) => ({ ...value, percent: 100 }));
      notify?.(result.message || "上传完成", "success");
      fileCacheRef.current.delete(containerPath);
      await loadContainerFiles(containerPath);
    } catch (e) { if (e.name !== "AbortError") notify?.(e.message, "error"); }
    finally { uploadRequestRef.current = null; setFilesUploading(false); setTimeout(() => setUploadProgress(null), 500); if (fileUploadRef.current) fileUploadRef.current.value = ""; }
  };
  const deleteContainerPath = async () => {
    if (!logTarget || !deleteFileConfirm || fileDeleting) return;
    setFileDeleting(true);
    try {
      const entry = deleteFileConfirm;
      const result = await api(`/deployments/${logTarget.deploymentId}/containers/${encodeURIComponent(logTarget.container.name)}/files?path=${encodeURIComponent(entry.path)}`, { method: "DELETE" });
      notify?.(result.message || "删除完成", "success");
      fileCacheRef.current.delete(containerPath);
      setDeleteFileConfirm(null);
      await loadContainerFiles(containerPath);
    } catch (e) { notify?.(e.message, "error"); }
    finally { setFileDeleting(false); }
  };
  useEffect(() => {
    if (!fileMenu) return undefined;
    const close = () => setFileMenu(null);
    const keydown = (event) => { if (event.key === "Escape") close(); };
    window.addEventListener("click", close);
    window.addEventListener("keydown", keydown);
    return () => { window.removeEventListener("click", close); window.removeEventListener("keydown", keydown); };
  }, [fileMenu]);
  useEffect(() => {
    if (!logTarget || !autoLogs) return undefined;
    const timer = setInterval(() => loadContainerLogs(logTarget, true), 5000);
    return () => clearInterval(timer);
  }, [logTarget, autoLogs, logSince]);
  const logMatchCount = logQuery ? String(containerLogs || "").split("\n").filter((line) => line.toLowerCase().includes(logQuery.toLowerCase())).length : 0;
  useEffect(() => {
    if (followLogs && runtimeLogRef.current) runtimeLogRef.current.scrollTop = runtimeLogRef.current.scrollHeight;
  }, [containerLogs, logQuery, followLogs, containerTab]);
  const restart = async (deploymentId, containerName = "") => {
    const key = containerName || deploymentId;
    setRestarting(key);
    setRestartConfirm(null);
    try {
      const result = await api(`/deployments/${deploymentId}/restart`, { method: "POST", body: JSON.stringify({ container_name: containerName || null }) });
      notify?.(result.message, "success");
      onRefresh?.(true);
    } catch (e) {
      notify?.(e.message, "error");
    } finally {
      setRestarting("");
    }
  };
  const startStopped = async (deploymentId) => {
    setRestarting(deploymentId);
    try {
      await api(`/deployments/${deploymentId}/start`, { method: "POST" });
      notify?.("服务已重新启用", "success");
      onRefresh?.(true);
    } catch (e) {
      notify?.(e.message, "error");
      onRefresh?.(true);
    } finally {
      setRestarting("");
    }
  };
  if (!runtime)
    return (
      <div className="center">
        <LoaderCircle className="spin" />
      </div>
    );
  if (runtime.error)
    return (
      <div className="empty">
        <Boxes />
        <h3>运行状态读取失败</h3>
        <button className="ghost" onClick={() => onRefresh?.()}>
          <RefreshCw />
          重试
        </button>
      </div>
    );
  if (!runtime.environments?.length)
    return <Empty icon={Boxes} text="这个项目还没有运行环境" />;
  const allRuntimeContainers = runtime.environments.flatMap((environment) => environment.containers || []);
  const allDataContainers = allRuntimeContainers.filter((container) =>
    dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`),
  );
  const allApplicationContainers = allRuntimeContainers.filter((container) => !allDataContainers.includes(container));
  const visibleEnvironments = runtime.environments
    .map((env) => ({
      ...env,
      containers: (env.containers || []).filter((container) => {
        const isData = dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`);
        return scope === "data" ? isData : !isData;
      }),
    }))
    .filter((env) => scope !== "data" || env.containers.length);
  if (!visibleEnvironments.length)
    return <Empty icon={Boxes} text={scope === "data" ? "当前版本没有数据库或中间件容器" : "当前版本没有应用容器"} />;
  return (
    <div className={`project-runtime ${scope === "data" ? "data-runtime" : "application-runtime"}`}>
      <div className="runtime-toolbar">
        <div>
          <b>{scope === "data" ? "数据容器" : "应用容器"}</b>
          <span>{scope === "data" ? "数据库、中间件及其他非应用容器集中管理" : "前端、后端及业务进程"}</span>
        </div>
        <div className="runtime-toolbar-actions">
          {scope !== "data" && <button className="ghost" disabled={gatewayLoading} onClick={onGateway}>
            {gatewayLoading ? <LoaderCircle className="spin" /> : <Code2 />}
            平台网关
          </button>}
          <button className="ghost" disabled={refreshing} onClick={onRefresh}>
            <RefreshCw className={refreshing ? "spin" : ""} />
            {refreshing ? "刷新中" : "刷新状态"}
          </button>
        </div>
      </div>
      {scope !== "data" && (
        <div className="runtime-composition">
          <span><Boxes /><b>共 {allRuntimeContainers.length} 个容器</b></span>
          <span>应用 {allApplicationContainers.length}</span>
          <span>数据资源 {allDataContainers.length}</span>
        </div>
      )}
      {runtime.refresh_error && (
        <div className="alert warning runtime-refresh-error">
          实时状态读取失败，当前展示基础信息。
          <button className="ghost" onClick={onRefresh}><RefreshCw />重新读取</button>
        </div>
      )}
      {visibleEnvironments.map((env) => (
        <div className="panel runtime-environment" key={env.deployment_id}>
          <div className="runtime-environment-head">
            <div>
              <Server />
              <span>
                <b>{env.node?.name || "未知服务器"}</b>
                <small>
                  {env.node?.address || "—"} ·{" "}
                  {env.release ? `版本 ${shortRelease(env.release)}` : "正在准备版本"}
                </small>
              </span>
            </div>
            <div>
              {restarting === env.deployment_id ? (
                <span className="badge info"><LoaderCircle className="spin" />启动中</span>
              ) : <Badge status={env.status} />}
              {scope !== "data" && env.containers?.length > 0 && <button
                className="ghost"
                disabled={!!restarting}
                onClick={() => setRestartConfirm({ deploymentId: env.deployment_id, containerName: "", label: `${env.node?.name || "当前服务器"}的全部应用服务`, risky: true })}
              >
                {restarting === env.deployment_id ? <LoaderCircle className="spin" /> : <RefreshCw />}
                {restarting === env.deployment_id ? "重启中" : "重启应用"}
              </button>}
              <button
                className="ghost"
                onClick={() => onOpen(env.deployment_id)}
              >
                查看部署详情
                <ChevronRight />
              </button>
            </div>
          </div>
          <div className="runtime-summary">
            <span>
              内网实例端口
              <b>{["success", "running"].includes(env.status) ? (env.host_port || "识别中") : "启动时自动分配"}</b>
            </span>
            <span>
              访问地址
              <b>{["success", "running"].includes(env.status) ? (env.access_url || "部署完成后生成") : "应用已停止"}</b>
            </span>
            <span>
              运行服务<b>{env.containers?.length || 0} 个</b>
            </span>
            <span>
              CPU 使用<b>{env.resources?.cpu || "0%"}</b>
            </span>
            <span>
              内存使用<b>{env.resources?.memory_usage || "0 B"}</b>
            </span>
          </div>
          {env.containers?.length ? (
            <div className="service-grid project-service-grid">
              {env.containers.map((c) => (
                <div className="service-card runtime-clickable-card" key={c.name} role="button" tabIndex={0} onClick={() => openContainer(env.deployment_id, c)} onKeyDown={(event) => { if (event.key === "Enter") openContainer(env.deployment_id, c); }}>
                  <div className="service-title">
                    <Boxes />
                    <div>
                      <b>{c.name}</b>
                      <small>{c.image || "容器"}</small>
                    </div>
                    <div className="service-title-tools">
                      {scope !== "data" && <ServiceScaleControl
                        projectId={projectId}
                        container={c}
                        containers={env.containers}
                        servicePools={env.service_pools || env.services || []}
                        enabled={canEdit && env.status === "success"}
                        notify={notify}
                        onDone={() => onRefresh?.(true)}
                      />}
                      <i
                        className={
                          String(c.state).toLowerCase().includes("running") ||
                          String(c.status).toLowerCase().includes("up")
                            ? "up"
                            : "down"
                        }
                      />
                    </div>
                  </div>
                  <div className="service-data">
                    <span>镜像</span>
                    <b>{c.image || "—"}</b>
                    <span>状态</span>
                    <b>{c.status || c.state}</b>
                    <span>端口</span>
                    <b>
                      {typeof c.ports === "string"
                        ? c.ports || "内部服务"
                        : JSON.stringify(c.ports)}
                    </b>
                    <span>CPU</span>
                    <b>{c.resources?.cpu || "0%"}</b>
                    <span>内存</span>
                    <b>
                      {c.resources
                        ? `${c.resources.memory_usage} / ${c.resources.memory_limit}`
                        : "0 B"}
                    </b>
                  </div>
                  <div className="depends">
                    <span>依赖</span>
                    {(env.dependencies?.[c.service] || []).length ? (
                      env.dependencies[c.service].map((x) => (
                        <em key={x}>{x}</em>
                      ))
                    ) : (
                      <small>无明确依赖</small>
                    )}
                  </div>
                  <div className="service-card-actions">
                    <button className="ghost" onClick={(event) => { event.stopPropagation(); openContainer(env.deployment_id, c); }}>
                      <Terminal />
                      查看日志
                    </button>
                    <button className="ghost" disabled={!!restarting} onClick={(event) => { event.stopPropagation(); setRestartConfirm({ deploymentId: env.deployment_id, containerName: c.name, label: `容器“${c.name}”`, risky: /mysql|redis|postgres|mongo/i.test(`${c.service} ${c.name} ${c.image}`) }); }}>
                      {restarting === c.name ? <LoaderCircle className="spin" /> : <RefreshCw />}
                      重启此容器
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="runtime-empty">
              {["queued", "running"].includes(env.status) ? (
                <>
                  <LoaderCircle className="spin" />
                  部署进行中，服务启动后显示
                </>
              ) : (
                <>当前发布没有运行中的容器</>
              )}
            </div>
          )}
        </div>
      ))}
      {logTarget && (
        <Modal className="container-workspace-modal" closeOnMask={false} title={`${logTarget.container.name} · 容器详情`} onClose={() => { terminalSocketRef.current?.close(); terminalSocketRef.current = null; setLogTarget(null); setAutoLogs(false); }} wide>
          <div className="container-log-summary">
            <span>容器<b>{logTarget.container.name}</b></span>
            <span>镜像<b>{logTarget.container.image || "—"}</b></span>
            <span>状态<b>{logTarget.container.status || logTarget.container.state}</b></span>
            <span>CPU<b>{logTarget.container.resources?.cpu || "0%"}</b></span>
            <span>内存<b>{logTarget.container.resources?.memory_usage || "0 B"}</b></span>
          </div>
          <div className="container-console-tabs">
            <button className={containerTab === "logs" ? "active" : ""} onClick={() => changeContainerTab("logs")}><Terminal />运行日志</button>
            {canEdit && <button className={containerTab === "terminal" ? "active" : ""} onClick={() => changeContainerTab("terminal")}><Code2 />进入终端</button>}
          </div>
          {containerTab === "logs" && <>
            <div className="container-log-toolbar">
              <div className="container-log-options">
                <button className={`ghost log-refresh-toggle ${autoLogs ? "active" : ""}`} onClick={() => setAutoLogs((value) => !value)}>{autoLogs ? <Square /> : <Play />}{autoLogs ? "暂停刷新" : "自动刷新"}</button>
                <button
                  className={`ghost log-follow-toggle ${followLogs ? "active" : ""}`}
                  onClick={() => {
                    const next = !followLogs;
                    setFollowLogs(next);
                    if (next) requestAnimationFrame(() => {
                      if (runtimeLogRef.current) runtimeLogRef.current.scrollTop = runtimeLogRef.current.scrollHeight;
                    });
                  }}
                >{followLogs ? "保持最新" : "跟随已暂停"}</button>
              </div>
              <label className="container-log-search"><Search /><input value={logQuery} onChange={(event) => setLogQuery(event.target.value)} placeholder="搜索当前日志" />{logQuery && <span>{logMatchCount} 条</span>}</label>
              <div>
                <button className="ghost" onClick={() => { setContainerLogs(""); setLogSince(new Date().toISOString()); setLogScreenCleared(true); setAutoLogs(true); setLogQuery(""); }} title="清空旧日志显示并继续等待新日志"><X />清空屏幕</button>
                <button className="ghost" disabled={logsLoading} onClick={() => loadContainerLogs(logTarget)}>{logsLoading ? <LoaderCircle className="spin" /> : <RefreshCw />}立即刷新</button>
                <button className="ghost" onClick={() => { const blob = new Blob([containerLogs], { type: "text/plain;charset=utf-8" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `${logTarget.container.name}.log`; a.click(); URL.revokeObjectURL(url); }}><Download />下载日志</button>
                <button className="ghost" disabled={!!restarting} onClick={() => setRestartConfirm({ deploymentId: logTarget.deploymentId, containerName: logTarget.container.name, label: `容器“${logTarget.container.name}”`, risky: /mysql|redis|postgres|mongo/i.test(`${logTarget.container.service} ${logTarget.container.name} ${logTarget.container.image}`) })}><RefreshCw />重启此容器</button>
              </div>
            </div>
            <pre
              ref={runtimeLogRef}
              onScroll={(event) => {
                const element = event.currentTarget;
                setFollowLogs(element.scrollHeight - element.scrollTop - element.clientHeight < 36);
              }}
              className={`logs runtime-container-log ${logScreenCleared ? "is-cleared" : ""}`}
            >{logScreenCleared ? "屏幕已清空，正在等待新日志…" : logsLoading && !containerLogs ? "正在读取容器日志..." : <HighlightedLogs text={containerLogs} query={logQuery} />}</pre>
          </>}
          {containerTab === "terminal" && <div className="container-workbench">
            <div className="container-terminal-panel" onMouseEnter={() => { terminalHoveredRef.current = true; terminalInputRef.current?.focus(); }} onMouseLeave={() => { terminalHoveredRef.current = false; terminalInputRef.current?.blur(); }} onClick={() => { terminalHoveredRef.current = true; terminalInputRef.current?.focus(); }}>
              <div className="terminal-cwd"><span><i className={terminalConnected ? "terminal-online" : "terminal-offline"} />{terminalConnected ? "已连接" : "连接中…"}</span><code>{containerPath}</code></div>
              <div className="terminal-output-shell">
                <pre ref={terminalOutputRef} className="logs container-terminal-output">{terminalOutput}{terminalSearchActive ? <span className="terminal-reverse-search"><b>(reverse-i-search)`{terminalSearchQuery}`: </b>{terminalSearchMatch || "没有匹配命令"}<i /></span> : <span className="terminal-live-prompt"><b>{containerPath} # </b>{terminalCommand}<i /></span>}</pre>
                <input className="terminal-key-capture" aria-label="容器终端命令" title="↑↓ 历史命令；Ctrl+R 搜索历史；Tab 补全；Ctrl+L 或 Ctrl+/ 清屏" ref={terminalInputRef} value={terminalSearchActive ? terminalSearchQuery : terminalCommand} disabled={terminalBusy} autoFocus onChange={(event) => { if (terminalSearchActive) updateTerminalReverseSearch(event.target.value, terminalHistory.length); else { setTerminalCommand(event.target.value); terminalHistoryIndexRef.current = -1; terminalSearchIndexRef.current = -1; terminalSearchQueryRef.current = ""; } }} onKeyDown={handleTerminalKeyDown} />
                {terminalBusy && <LoaderCircle className="spin terminal-inline-busy" />}
              </div>
            </div>
            <aside className="terminal-file-pane">
              <div className="container-pathbar">
                <button className="ghost" disabled={containerPath === "/"} onClick={() => loadContainerFiles(containerPath.split("/").slice(0, -1).join("/") || "/")}><ChevronRight className="back-chevron" /></button>
                <input className="terminal-path-input" value={containerPathDraft} spellCheck="false" aria-label="容器目录" title="输入目录后按 Enter 跳转" onChange={(event) => setContainerPathDraft(event.target.value)} onKeyDown={async (event) => { if (event.key === "Enter") { event.preventDefault(); const ok = await loadContainerFiles(containerPathDraft.trim() || "/"); if (!ok) setContainerPathDraft(containerPath); } }} />
                <input ref={fileUploadRef} className="terminal-file-upload" type="file" multiple onChange={(event) => uploadContainerFiles(event.target.files)} />
                <button className="ghost" disabled={filesUploading} title="上传到当前目录" onClick={() => fileUploadRef.current?.click()}>{filesUploading ? <LoaderCircle className="spin" /> : <Upload />}</button>
                <button className="ghost" onClick={() => loadContainerFiles(containerPath)}>{filesLoading ? <LoaderCircle className="spin" /> : <RefreshCw />}</button>
              </div>
              {uploadProgress && <div className="container-upload-progress"><span><b>{uploadProgress.name}</b><span><em>{uploadProgress.percent}%</em>{filesUploading && <button type="button" title="取消上传" onClick={() => uploadRequestRef.current?.abort()}><X />取消</button>}</span></span><i><u style={{ width: `${uploadProgress.percent}%` }} /></i></div>}
              {downloadProgress && <div className="container-upload-progress"><span><b>下载：{downloadProgress.name}</b><span><em>{downloadProgress.percent == null ? containerFileSize(downloadProgress.loaded, "file") : `${downloadProgress.percent}%`}</em>{downloadProgress.percent !== 100 && <button type="button" title="取消下载" onClick={() => downloadRequestRef.current?.abort()}><X />取消</button>}</span></span><i><u className={downloadProgress.percent == null ? "indeterminate" : ""} style={downloadProgress.percent == null ? undefined : { width: `${downloadProgress.percent}%` }} /></i></div>}
              <div className="container-file-list terminal-file-list" onDragOver={(event) => { event.preventDefault(); event.dataTransfer.dropEffect = "copy"; }} onDrop={(event) => { event.preventDefault(); uploadContainerFiles(event.dataTransfer.files); }}>
                <div className="terminal-file-header"><span>名称</span><span>大小</span><span>上次修改</span><span>所有者</span></div>
                {containerFiles.map((entry) => <div key={entry.path} className="container-file-row terminal-file-row" title="右键查看更多操作" onContextMenu={(event) => { event.preventDefault(); event.stopPropagation(); setFileMenu({ entry, x: Math.min(event.clientX, window.innerWidth - 170), y: Math.min(event.clientY, window.innerHeight - 110) }); }}>
                  <button className="container-file-name" title={entry.type === "directory" ? `进入 ${entry.name}` : `${entry.name} 是文件，不能作为目录进入`} onClick={() => entry.type === "directory" ? loadContainerFiles(entry.path) : notify?.("这是文件，不能作为目录进入；可右键下载", "error")}>
                    {entry.type === "directory" ? <FolderGit2 /> : <FileArchive />}
                    <span>{entry.name}</span>
                  </button>
                  <span>{containerFileSize(entry.size, entry.type)}</span>
                  <span>{containerFileTime(entry.modified)}</span>
                  <span>{entry.owner || "-"}</span>
                </div>)}
                {filesLoading && !containerFiles.length && <div className="center"><LoaderCircle className="spin" /></div>}
                {!filesLoading && !containerFiles.length && <Empty icon={FolderGit2} text="这个目录为空" />}
              </div>
            </aside>
          </div>}
          {fileMenu && createPortal(<div className="terminal-file-menu" style={{ left: fileMenu.x, top: fileMenu.y }} onClick={(event) => event.stopPropagation()}>
            {fileMenu.entry.type === "file" && <button onClick={() => { downloadContainerPath(fileMenu.entry, false); setFileMenu(null); }}><Download />直接下载</button>}
            <button onClick={() => { downloadContainerPath(fileMenu.entry, true); setFileMenu(null); }}><FileArchive />打包下载</button>
            <button className="danger" onClick={() => { setDeleteFileConfirm(fileMenu.entry); setFileMenu(null); }}><Trash2 />删除</button>
          </div>, document.body)}
        </Modal>
      )}
      {restartConfirm && (
        <ConfirmDialog
          title="确认重启服务"
          text={`确定重启${restartConfirm.label}？`}
          description={`${restartConfirm.risky ? "重启期间相关服务会短暂不可用。" : "服务会短暂中断。"} 本操作不会应用尚未生效的新配置，也不会重新构建镜像。`}
          confirmText="确认重启"
          busy={!!restarting}
          onClose={() => !restarting && setRestartConfirm(null)}
          onConfirm={() => restart(restartConfirm.deploymentId, restartConfirm.containerName)}
        />
      )}
      {deleteFileConfirm && (
        <ConfirmDialog
          title={`删除${deleteFileConfirm.type === "directory" ? "文件夹" : "文件"}`}
          text={`确定永久删除“${deleteFileConfirm.name}”？`}
          description={deleteFileConfirm.type === "directory" ? "该文件夹及其全部内容都会被删除，此操作无法撤销。" : "该文件会从正在运行的容器中永久删除，此操作无法撤销。"}
          confirmText="确认删除"
          danger
          busy={fileDeleting}
          onClose={() => !fileDeleting && setDeleteFileConfirm(null)}
          onConfirm={deleteContainerPath}
        />
      )}
    </div>
  );
}

function ProjectDataResources({ project, canEdit, data, runtime, runtimeRefreshing, onRuntimeRefresh, onOpenDeployment, onRefresh, notify }) {
  if (!data)
    return (
      <div className="center">
        <LoaderCircle className="spin" />
      </div>
    );
  if (data.error)
    return (
      <div className="empty">
        <ShieldCheck />
        <h3>数据资源分析失败</h3>
        <button className="ghost" onClick={onRefresh}>
          <RefreshCw />
          重试
        </button>
      </div>
    );
  const runtimeDataContainers = (runtime?.environments || [])
    .flatMap((environment) => environment.containers || [])
    .filter((container) => dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`));
  const runtimeServiceKeys = new Set();
  runtimeDataContainers.forEach((container) => {
    const identity = `${container.service || ""} ${container.name || ""} ${container.image || ""}`.toLowerCase();
    const service = String(container.service || "").toLowerCase();
    if (service) runtimeServiceKeys.add(service);
    if (/mysql|mariadb/.test(identity)) runtimeServiceKeys.add("mysql");
    if (/redis/.test(identity)) runtimeServiceKeys.add("redis");
    if (/postgres/.test(identity)) runtimeServiceKeys.add("postgres");
    if (/mongo/.test(identity)) runtimeServiceKeys.add("mongodb");
  });
  // Credentials describe services that the platform may be able to create.
  // Only expose them when the current runtime really contains that data service,
  // otherwise source-code analysis can make an unused MySQL card look "live".
  const credentialItems = (data.managed_credentials || []).filter((item) => {
    const service = String(item.service || "").toLowerCase();
    return runtimeServiceKeys.has(service)
      || runtimeDataContainers.some((container) => `${container.service || ""} ${container.name || ""} ${container.image || ""}`.toLowerCase().includes(service));
  });
  const knownRuntimeServices = {
    mysql: { label: "MySQL", port: "3306", database: "" },
    redis: { label: "Redis", port: "6379", database: "0" },
  };
  runtimeDataContainers.forEach((container) => {
    const service = String(container.service || "").toLowerCase();
    const meta = knownRuntimeServices[service];
    if (!meta || credentialItems.some((item) => item.service === service)) return;
    credentialItems.push({
      service,
      label: meta.label,
      scope: "项目内部网络",
      host: service,
      port: meta.port,
      database: meta.database,
      username: "",
      password: "",
      runtime_only: true,
      exposure: (data.data_exposures || []).find((entry) => entry.service === service) || null,
    });
  });
  return (
    <div className="project-data-resources">
      <div className="panel data-ai-summary">
        <Bot />
        <div>
          <h3>AI 数据资源分析</h3>
          <p>{data.summary}</p>
          <small>分析来源：{data.source}</small>
        </div>
        <button className="ghost" onClick={onRefresh}>
          <RefreshCw />
          重新分析
        </button>
      </div>
      {!!credentialItems.length && (
        <details className="panel managed-credential-panel">
          <summary className="managed-credential-summary">
            <div className="managed-credential-summary-icon"><ShieldCheck /></div>
            <div>
              <h3>连接凭据</h3>
              <p>默认隐藏敏感信息，仅显示当前实际运行的数据服务</p>
            </div>
            <div className="managed-credential-summary-services">
              {credentialItems.map((item) => <span key={item.service}>{item.label}</span>)}
            </div>
            <span className="badge info">{credentialItems.length} 项 · 管理员可见</span>
            <span className="managed-credential-toggle">展开查看 <ChevronRight /></span>
          </summary>
          <div className="managed-credential-grid">
            {credentialItems.map((item) => (
              <ManagedCredentialCard
                key={item.service}
                item={item}
                projectId={project.id}
                notify={notify}
                onChanged={onRefresh}
              />
            ))}
          </div>
        </details>
      )}
      {runtimeDataContainers.length ? (
        <ProjectRuntime
          projectId={project.id}
          canEdit={canEdit}
          runtime={runtime}
          refreshing={runtimeRefreshing}
          onRefresh={onRuntimeRefresh}
          onGateway={() => {}}
          gatewayLoading={false}
          onOpen={onOpenDeployment}
          notify={notify}
          scope="data"
        />
      ) : (
        <div className="data-runtime-empty">
          <Boxes />
          <div><b>没有运行中的数据容器</b><span>当前项目未创建 MySQL、Redis 等平台托管服务</span></div>
          <button className="ghost" disabled={runtimeRefreshing} onClick={onRuntimeRefresh}>
            <RefreshCw className={runtimeRefreshing ? "spin" : ""} />刷新状态
          </button>
        </div>
      )}
      {canEdit && runtimeServiceKeys.has("mysql") && <ProjectSqlConsole project={project} notify={notify} />}
      {runtimeServiceKeys.has("mysql") && (data.migrations.length ? (
        <details className="panel migration-panel compact-tool-panel">
          <summary className="compact-tool-summary">
            <Code2 />
            <div><h3>表结构与迁移脚本</h3><p>执行前必须连接数据库并完成备份</p></div>
            <span className="badge info">{data.migrations.length} 个文件</span>
            <span className="compact-tool-toggle">展开查看 <ChevronRight /></span>
          </summary>
          <div className="migration-list">
            {data.migrations.map((x) => (
              <div key={x.path}>
                <Code2 />
                <span>
                  <b>{x.path}</b>
                  <small>
                    {x.kind} · 约 {x.statements} 条语句
                  </small>
                </span>
                <em className={x.risk}>
                  {x.risk === "high" ? "需要人工确认" : "低风险待核对"}
                </em>
              </div>
            ))}
          </div>
          <div className="data-next-step"><Bot /><span>{data.next_step}</span></div>
        </details>
      ) : (
        <div className="panel migration-empty-inline">
          <Code2 /><div><b>未发现迁移脚本</b><span>当前源码中没有 SQL 文件，无需执行迁移</span></div><span className="badge info">0 个文件</span>
        </div>
      ))}
    </div>
  );
}

function ProjectSqlConsole({ project, notify }) {
  const [sql, setSql] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [pending, setPending] = useState(null);
  const run = async (confirmation = null) => {
    if (!sql.trim() || busy) return;
    setBusy(true);
    try {
      const response = await api(`/projects/${project.id}/sql-console`, {
        method: "POST",
        body: JSON.stringify({
          sql,
          confirm_token: confirmation ? pending?.confirm_token : null,
          confirmation,
        }),
      });
      if (response.requires_confirmation) {
        setPending(response);
        setResult(null);
      } else {
        setPending(null);
        setResult(response);
        notify?.(response.kind === "query" ? `查询完成，共 ${response.row_count} 行` : "数据库变更执行成功", "success");
      }
    } catch (error) {
      notify?.(error.message, "error");
    } finally {
      setBusy(false);
    }
  };
  const columns = result?.columns || [];
  return (
    <details className="panel project-sql-console compact-tool-panel">
      <summary className="compact-tool-summary">
        <Database />
        <div><h3>SQL 控制台</h3><p>仅用于当前 MySQL；写操作必须二次确认并记录审计</p></div>
        <span className="badge info">{dataLabel(project)}</span>
        <span className="compact-tool-toggle">打开控制台 <ChevronRight /></span>
      </summary>
      <div className="sql-console-body">
        <textarea
          value={sql}
          onChange={(event) => { setSql(event.target.value); setPending(null); }}
          placeholder="输入单条 SELECT、SHOW、INSERT、UPDATE 或 DELETE SQL"
          spellCheck={false}
        />
        <div className="sql-console-actions">
          <small>一次只执行一条 SQL；表结构修改请使用迁移流程。</small>
          <button className="primary" disabled={busy || !sql.trim()} onClick={() => run()}>
            {busy ? <LoaderCircle className="spin" /> : <Play />} 执行 SQL
          </button>
        </div>
      {pending && (
        <div className={`sql-confirm-card ${pending.high_risk ? "danger" : "warning"}`}>
          <ShieldCheck />
          <div>
            <b>{pending.high_risk ? "高风险数据变更" : `${pending.operation} 数据变更`}</b>
            <span>{pending.high_risk ? "语句没有 WHERE 条件，可能影响整张表。" : "请核对 SQL，确认后才会真正写入数据库。"}</span>
            <small>校验值 {pending.digest}</small>
          </div>
          <button className={pending.high_risk ? "danger-button" : "primary"} disabled={busy} onClick={() => run(pending.confirmation_phrase)}>
            {pending.confirmation_phrase}
          </button>
        </div>
      )}
      {result?.kind === "query" && (
        <div className="sql-result-panel">
          <div><b>查询结果</b><span>{result.row_count} 行 · {columns.length} 列{result.truncated ? " · 已截取前 100 行" : ""}</span></div>
          <div className="query-table-wrap"><table><thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead><tbody>{result.rows.map((row, rowIndex) => <tr key={rowIndex}>{columns.map((_, index) => <td key={index} title={row[index] || ""}>{row[index] || "—"}</td>)}</tr>)}</tbody></table></div>
        </div>
      )}
        {result?.kind === "data_change" && <div className="sql-change-success"><ShieldCheck /><div><b>执行成功</b><span>{result.result}</span></div></div>}
      </div>
    </details>
  );
}

function dataLabel(project) {
  return project?.name ? `项目：${project.name}` : "当前项目";
}

function ManagedCredentialCard({ item, projectId, notify, onChanged }) {
  const [visible, setVisible] = useState(false);
  const [copied, setCopied] = useState("");
  const [editingExposure, setEditingExposure] = useState(false);
  const [exposureBusy, setExposureBusy] = useState(false);
  const [exposureEnabled, setExposureEnabled] = useState(!!item.exposure?.enabled);
  const [externalPort, setExternalPort] = useState(item.exposure?.host_port || "");
  const [allowCidrs, setAllowCidrs] = useState((item.exposure?.allow_cidrs || ["0.0.0.0/0"]).join("\n"));
  const copyValue = async (key, value) => {
    await copyText(value || "");
    setCopied(key);
    setTimeout(() => setCopied(""), 1200);
  };
  const rows = [
    ["地址", "host", item.host], ["端口", "port", item.port],
    ["数据库", "database", item.database], ["用户名", "username", item.username],
  ].filter(([, , value]) => value !== "" && value != null);
  const savedMode = item.exposure?.mode || "direct";
  const needsAutomaticPort = !item.exposure?.enabled || savedMode !== "gateway" || !externalPort || !item.exposure?.target_port;
  useEffect(() => {
    setExposureEnabled(!!item.exposure?.enabled);
    setExternalPort(item.exposure?.host_port || "");
    setAllowCidrs((item.exposure?.allow_cidrs || ["0.0.0.0/0"]).join("\n"));
  }, [item.exposure?.enabled, item.exposure?.mode, item.exposure?.host_port, item.exposure?.updated_at]);
  const saveExposure = async (enabled = exposureEnabled) => {
    setExposureBusy(true);
    try {
      await api(`/projects/${projectId}/data-exposures/${item.service}`, {
        method: "PUT",
        body: JSON.stringify({
          enabled,
          mode: "gateway",
          host_port: enabled && !needsAutomaticPort && externalPort ? Number(externalPort) : null,
          allow_cidrs: allowCidrs.split(/[\s,]+/).filter(Boolean),
        }),
      });
      notify?.(enabled ? `${item.label} 外部访问已应用` : `${item.label} 外部访问已关闭`, "success");
      setEditingExposure(false);
      onChanged?.();
    } catch (error) {
      notify?.(error.message, "error");
    } finally {
      setExposureBusy(false);
    }
  };
  return (
    <section className="managed-credential-card">
      <div className="managed-credential-title">
        <Database /><b>{item.label}</b><small>{item.scope}</small>
        <button className="ghost managed-exposure-config" onClick={() => setEditingExposure((value) => !value)}>
          {item.exposure?.enabled ? "外部访问已开启" : "开放外部访问"}
        </button>
      </div>
      {rows.map(([label, key, value]) => (
        <div className="managed-credential-row" key={key}>
          <span>{label}</span><code title={value}>{value}</code>
          <div className="managed-credential-actions">
            <button className="ghost" onClick={() => copyValue(key, value)}><Copy />{copied === key ? "已复制" : "复制"}</button>
          </div>
        </div>
      ))}
      {item.password ? (
        <div className="managed-credential-row">
          <span>密码</span><code title={visible ? item.password : "密码已隐藏"}>{visible ? item.password : "••••••••••••"}</code>
          <div className="managed-credential-actions password-actions">
            <button className="ghost" onClick={() => setVisible((value) => !value)}>{visible ? "隐藏" : "显示"}</button>
            <button className="ghost" onClick={() => copyValue("password", item.password)}><Copy />{copied === "password" ? "已复制" : "复制"}</button>
          </div>
        </div>
      ) : (
        <div className="managed-credential-row credential-no-password">
          <span>认证</span><code>未设置密码（仅内部访问）</code><div />
        </div>
      )}
      {item.exposure?.enabled && item.exposure?.connection_address && !editingExposure && (
        <div className="managed-exposure-summary">
          <div className="managed-exposure-live">
            <div><i /><span>{item.exposure.mode === "gateway" ? "平台转发地址" : "部署服务器地址"}</span><code>{item.exposure.connection_address}</code></div>
            <button className="ghost" onClick={() => copyValue("external", item.exposure.connection_address)}><Copy />{copied === "external" ? "已复制" : "复制"}</button>
          </div>
          <div className="managed-access-chain">
            <div><small>访问入口</small><b>{item.exposure.connection_address}</b></div>
            {item.exposure.mode === "gateway" && <><ChevronRight /><div><small>平台 TCP 转发</small><b>{item.exposure.gateway_name || "平台网关"}</b></div></>}
            <ChevronRight /><div><small>部署服务器</small><b>{item.exposure.target_host}:{item.exposure.target_port}</b></div>
            <ChevronRight /><div><small>{item.label} 服务</small><b>内部端口 {item.exposure.container_port}</b></div>
          </div>
        </div>
      )}
      {editingExposure && (
        <div className="managed-exposure-editor">
          <div className="managed-exposure-editor-head">
            <div><b>外部访问</b><span>平台自动分配公网端口并转发到部署服务器</span></div>
            <label className="switch-row"><input type="checkbox" checked={exposureEnabled} onChange={(event) => setExposureEnabled(event.target.checked)} /><span /></label>
          </div>
          {exposureEnabled && <>
            <div className="managed-access-chain preview">
              <div><small>访问入口</small><b>{item.exposure?.public_host || "平台公网地址"}:{needsAutomaticPort ? "自动分配" : externalPort}</b></div>
              <ChevronRight /><div><small>平台 TCP 转发</small><b>{item.exposure?.gateway_name || "平台网关"}</b></div>
              <ChevronRight /><div><small>部署服务器</small><b>{item.exposure?.target_host || item.exposure?.node_name || "目标节点"}:{needsAutomaticPort ? "自动分配" : item.exposure?.target_port}</b></div>
              <ChevronRight /><div><small>{item.label} 服务</small><b>内部端口 {item.service === "mysql" ? 3306 : 6379}</b></div>
            </div>
            <label><span>允许访问的 IP / 网段</span><textarea rows="3" value={allowCidrs} onChange={(event) => setAllowCidrs(event.target.value)} placeholder={"例如：203.0.113.8\n或 203.0.113.0/24"} /></label>
            <div className="managed-exposure-warning">平台会建立 TCP 转发，不经过 HTTP/Nginx 路由。填写 <code>0.0.0.0/0</code> 表示允许整个公网访问，建议仅填写你本机的公网 IP。</div>
          </>}
          <div className="managed-exposure-actions">
            <button className="ghost" disabled={exposureBusy} onClick={() => setEditingExposure(false)}>取消</button>
            <button className={exposureEnabled ? "primary" : "danger-button"} disabled={exposureBusy} onClick={() => saveExposure(exposureEnabled)}>{exposureBusy ? <LoaderCircle className="spin" /> : null}{exposureEnabled ? "保存并应用" : "关闭外部访问"}</button>
          </div>
        </div>
      )}
    </section>
  );
}

function ServicePortPopover({ hostPort, ports }) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const buttonRef = useRef(null);
  const panelRef = useRef(null);
  const uniquePorts = Array.from(
    new Map((ports || []).filter((item) => item?.port).map((item) => [`${item.service || "service"}-${item.port}`, item])).values(),
  );
  const hasEntryService = uniquePorts.some((item) => Number(item.port) === Number(hostPort));
  const allPorts = (
    hasEntryService ? uniquePorts : [{ service: "服务", port: hostPort }, ...uniquePorts]
  ).map((item) => ({ ...item, entry: Number(item.port) === Number(hostPort) }));
  useLayoutEffect(() => {
    if (!open || !buttonRef.current) return undefined;
    const place = () => {
      const rect = buttonRef.current.getBoundingClientRect();
      setPosition({
        top: Math.min(window.innerHeight - 12, rect.bottom + 6),
        left: Math.max(12, Math.min(window.innerWidth - 188, rect.left)),
      });
    };
    const closeOutside = (event) => {
      if (!buttonRef.current?.contains(event.target) && !panelRef.current?.contains(event.target)) setOpen(false);
    };
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    document.addEventListener("pointerdown", closeOutside);
    return () => {
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
      document.removeEventListener("pointerdown", closeOutside);
    };
  }, [open]);
  return <>
    <button ref={buttonRef} type="button" className="service-port-trigger" title="查看服务端口" aria-label={`查看 ${allPorts.length} 个服务端口`} onClick={(event) => { event.stopPropagation(); setOpen((value) => !value); }}>
      <Network />{allPorts.length > 1 && <span>{allPorts.length}</span>}
    </button>
    {open && createPortal(
      <div ref={panelRef} className="service-port-popover" style={position} onClick={(event) => event.stopPropagation()}>
        {allPorts.map((item) => <span key={`${item.service}-${item.port}`}><b>{item.service}{item.entry && <small>入口</small>}</b><em>{item.port}</em></span>)}
      </div>,
      document.body,
    )}
  </>;
}

function DeploymentTable({ items, onSelect, onDelete, onDomain, selectedIds, onToggle, onToggleAll }) {
  const selectable = typeof onToggle === "function" && typeof onToggleAll === "function";
  const deletableIds = items.filter((item) => ["failed", "stopped"].includes(item.status)).map((item) => item.id);
  const allSelected = deletableIds.length > 0 && deletableIds.every((id) => selectedIds?.has(id));
  const addressState = (x) =>
    x.status === "stopped"
      ? "已停止，未生成映射"
      : x.status === "failed"
        ? "部署失败，未生成映射"
        : x.status === "queued"
          ? "等待部署"
          : x.status === "running"
            ? "映射将在部署完成后生成"
            : "未配置平台映射";
  return (
    <div className="table-wrap deployment-record-table">
      <table>
        <thead>
          <tr>
            {selectable && (
              <th className="select-column">
                <input
                  type="checkbox"
                  aria-label="全选可删除历史记录"
                  title="全选可删除历史记录"
                  disabled={!deletableIds.length}
                  checked={allSelected}
                  onChange={(event) => onToggleAll(deletableIds, event.target.checked)}
                />
              </th>
            )}
            <th className="deployment-project-col">项目 / 发布版本</th>
            <th className="deployment-node-col">部署服务器</th>
            <th className="deployment-state-col">状态</th>
            <th className="deployment-address-col">内网访问地址</th>
            <th className="deployment-address-col">外网访问地址</th>
            <th className="deployment-time-col">发布时间</th>
            <th className="deployment-duration-col">部署耗时</th>
            <th className="deployment-actions-col">操作</th>
          </tr>
        </thead>
        <tbody>
          {items.map((x) => {
            const canDelete = ["failed", "stopped"].includes(x.status);
            return (
              <tr key={x.id} onClick={() => onSelect?.(x)}>
                {selectable && (
                  <td className="select-column">
                    <input
                      type="checkbox"
                      disabled={!canDelete}
                      checked={selectedIds?.has(x.id) || false}
                      aria-label={`选择 ${x.release || x.id.slice(0, 8)}`}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => canDelete && onToggle(x.id)}
                    />
                  </td>
                )}
                <td className="deployment-project-col">
                  <div className="release-title">
                    <b>{x.project_name || x.id.slice(0, 8)}</b>
                    {x.display_role && (
                      <em className={`release-role ${x.display_role_type || ""}`}>
                        {x.display_role}
                      </em>
                    )}
                  </div>
                  <small>
                    {x.release
                      ? shortRelease(x.release)
                      : `任务 ${x.id.slice(0, 8)}`}{" "}
                    · {x.trigger === "ai" ? "AI 发布" : "手动发布"}
                  </small>
                </td>
                <td className="deployment-node-col">
                  <b>{x.node_name || "—"}</b>
                  <small>{x.node_address || x.node_id.slice(0, 8)}</small>
                </td>
                <td className="deployment-state-col">
                  <div className="deployment-status">
                    <Badge status={x.status} />
                    {["queued", "running"].includes(x.status) && <>
                      <div className="mini-progress"><i style={{ width: `${x.progress || 0}%` }} /></div>
                      <small>{x.progress || 0}%</small>
                    </>}
                  </div>
                </td>
                <td className="deployment-address-col">
                  {x.node_access_url &&
                  !["failed", "stopped"].includes(x.status) ? (
                    <div className="deployment-address-stack">
                      <a
                        href={x.node_access_url}
                        title={x.node_access_url}
                        target="_blank"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {x.node_access_url}
                      </a>
                      {x.host_port && <ServicePortPopover hostPort={x.host_port} ports={x.service_ports || []} />}
                    </div>
                  ) : (
                    <span className="address-muted">
                      {x.status === "stopped"
                        ? "服务已停止"
                        : x.status === "failed"
                          ? "服务未启动"
                          : "地址生成中"}
                    </span>
                  )}
                </td>
                <td className="deployment-address-col">
                  {x.platform_access_url &&
                  !["failed", "stopped"].includes(x.status) ? (
                    <a
                      href={x.platform_access_url}
                      title={x.platform_access_url}
                      target="_blank"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {x.platform_access_url}
                    </a>
                  ) : (
                    <span className="address-muted">{addressState(x)}</span>
                  )}
                </td>
                <td className="deployment-time-col" title={time(x.created_at)}>{time(x.created_at)}</td>
                <td className="deployment-duration-col">{deploymentDuration(x)}</td>
                <td className="deployment-actions-col">
                  <div className="record-actions">
                    <button
                      className="record-delete"
                      title={
                        x.project_domain
                          ? `编辑域名：${x.project_domain}`
                          : "配置访问域名"
                      }
                      onClick={(e) => {
                        e.stopPropagation();
                        onDomain?.(x);
                      }}
                    >
                      <Settings />
                    </button>
                    <button
                      className="record-delete"
                      disabled={!canDelete}
                      title={
                        canDelete
                          ? "清理并删除该发布版本"
                          : "请先停止任务或服务"
                      }
                      onClick={(e) => {
                        e.stopPropagation();
                        if (canDelete) onDelete?.(x);
                      }}
                    >
                      <Trash2 />
                    </button>
                    <ChevronRight />
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ProjectDeploymentGroup({
  items,
  onSelect,
  onDelete,
  onDomain,
  selectedIds,
  onToggle,
  onToggleAll,
}) {
  const candidate = items.find((x) => ["queued", "running"].includes(x.status));
  const active = items.find((x) => x.status === "success");
  const visibleIds = new Set([candidate?.id, active?.id].filter(Boolean));
  const history = items.filter((x) => !visibleIds.has(x.id));
  const visible = [
    candidate && {
      ...candidate,
      display_role: "候选版本",
      display_role_type: "candidate",
    },
    active && {
      ...active,
      display_role: "当前线上",
      display_role_type: "active",
    },
  ].filter(Boolean);
  const project = items[0];
  return (
    <section className="deployment-project-card">
      <div className="deployment-project-head">
        <div>
          <h3>{project.project_name || "未命名项目"}</h3>
          <p>
            {candidate
              ? "新版本正在发布；完成后更新线上版本，失败记录不会覆盖当前成功版本"
              : active
                ? "当前只有一个对外运行版本"
                : "当前没有运行中的线上版本"}
          </p>
        </div>
        <div className="project-release-state">
          {active && (
            <span className="release-state-active">
              <i />线上运行
              <b>{active.release || active.id.slice(0, 8)}</b>
            </span>
          )}
          {candidate && (
            <span className="release-state-candidate">
              <LoaderCircle className="spin" />发布中
              <b>{candidate.progress || 0}%</b>
            </span>
          )}
        </div>
      </div>
      {visible.length > 0 && (
        <DeploymentTable
          items={visible}
          onSelect={onSelect}
          onDelete={onDelete}
          onDomain={onDomain}
          selectedIds={selectedIds}
          onToggle={onToggle}
          onToggleAll={onToggleAll}
        />
      )}
      {history.length > 0 && (
        <details className="deployment-history">
          <summary>发布历史（{history.length}）</summary>
          <DeploymentTable
            items={history}
            onSelect={onSelect}
            onDelete={onDelete}
            onDomain={onDomain}
            selectedIds={selectedIds}
            onToggle={onToggle}
            onToggleAll={onToggleAll}
          />
        </details>
      )}
    </section>
  );
}

function GatewayGeneratedConfigModal({ preview, loading, onClose, onRefresh, onSettings, notify }) {
  const upstreams = [...new Set((preview.routes || []).flatMap((route) => route.targets || []))];
  const rows = [
    ["网关节点", [preview.gateway_node, preview.gateway_address].filter(Boolean).join(" · ") || "—"],
    ["接入方式", "平台 Nginx 网关 · 单实例"],
    ["配置文件", preview.config_path || "—"],
    ["内网回源", upstreams.length ? upstreams.map((value) => `http://${value}/`).join("、") : "—"],
    ["访问域名", preview.domain || "平台自动分配地址"],
    ["HTTP 端口", preview.http_port || 80],
    ["SSL / HTTPS", preview.https_enabled ? `已启用 · 端口 ${preview.https_port || 443}${preview.certificate_name ? ` · ${preview.certificate_name}` : ""}` : "未启用"],
    ["路由生成", preview.mode === "custom" ? "自定义路由" : "平台自动生成"],
    ["网关状态", preview.generated ? "运行中" : preview.message || "尚未生成"],
  ];
  return <Modal className="gateway-snapshot-modal" title="平台网关配置" onClose={onClose}>
    <div className="gateway-snapshot-rows">{rows.map(([label, value]) => <div key={label}><span>{label}</span><b>{value}</b></div>)}</div>
    <div className="gateway-config-guidance">
      <ShieldCheck /><span>{preview.config ? "配置由平台自动维护，发布时会重新生成。需要调整转发规则，请使用“网关设置”，不要直接修改服务器文件。" : (preview.message || "部署成功后，平台会自动生成并应用 Nginx 配置。")}</span>
    </div>
    <div className="gateway-snapshot-code-head"><b>{preview.config ? "自动生成的 Nginx 配置" : "配置操作"}</b><span />
      {onSettings && <button className="ghost" onClick={onSettings}><Settings />网关设置</button>}
      <button className="ghost" disabled={loading} onClick={onRefresh}>{loading ? <LoaderCircle className="spin" /> : <RefreshCw />}刷新</button>
    </div>
    {preview.config && <pre className="gateway-snapshot-code">{preview.config}</pre>}
  </Modal>;
}

function GatewayPolicyModal({ projectId, onClose, onSaved, notify }) {
  const [form, setForm] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState("");
  useEffect(() => {
    api(`/projects/${projectId}/domain-config`).then(setForm).catch((e) => setError(e.message));
  }, [projectId]);
  const set = (key, value) => setForm((current) => ({ ...current, [key]: value }));
  const selectMode = (mode) => setForm((current) => ({
    ...current,
    gateway_mode: mode,
    custom_routes: mode === "custom" && !(current.custom_routes || []).length
      ? (current.auto_routes || []).map((route) => ({ ...route }))
      : current.custom_routes,
  }));
  const restoreDetectedRoutes = () => setForm((current) => ({
    ...current,
    custom_routes: (current.auto_routes || []).map((route) => ({ ...route })),
  }));
  const routeTargetText = (route) => {
    const targets = form?.gateway_service_targets?.[route.service] || [];
    const path = route.path || "/";
    const forwarded = route.strip_prefix && path !== "/" ? "/（已去掉前缀）" : `${path}（保留前缀）`;
    return `代理到 ${targets.length ? targets.map((target) => `http://${target}`).join("、") : (route.service || "尚未选择服务")} · 后端收到 ${forwarded}`;
  };
  const save = async () => {
    setBusy(true); setError("");
    try {
      const preview = await api(`/projects/${projectId}/gateway-policy`, {
        method: "PUT",
        body: JSON.stringify({
          gateway_mode: form.gateway_mode || "auto",
          custom_routes: form.custom_routes || [],
          proxy_read_timeout: Number(form.proxy_read_timeout) || 300,
          client_max_body_mb: Number(form.client_max_body_mb) || 50,
        }),
      });
      onSaved(preview);
    } catch (e) { setError(e.message); notify?.(e.message, "error"); }
    finally { setBusy(false); }
  };
  return <Modal className="gateway-policy-modal" title="平台网关设置" onClose={onClose} closeOnMask={false}>
    {!form ? <div className="center"><LoaderCircle className="spin" /></div> : <div className="gateway-policy-body">
      <div className="alert info">平台会根据实际运行的前端、后端及接口前缀自动生成默认路由。自定义方案会单独保存，切回自动模式也不会丢失。</div>
      <Field label="路由生成方式">
        <div className="seg">
          <button className={form.gateway_mode !== "custom" ? "on" : ""} onClick={() => selectMode("auto")}>平台自动生成（推荐）</button>
          <button className={form.gateway_mode === "custom" ? "on" : ""} onClick={() => selectMode("custom")}>自定义路由</button>
        </div>
      </Field>
      <div className="gateway-policy-limits">
        <Field label="请求超时（秒）"><PortInput min="1" max="3600" value={form.proxy_read_timeout} onChange={(value) => set("proxy_read_timeout", value)} /></Field>
        <Field label="上传大小（MB）"><PortInput min="1" max="2048" value={form.client_max_body_mb} onChange={(value) => set("client_max_body_mb", value)} /></Field>
      </div>
      {form.gateway_mode === "custom" && <div className="gateway-route-editor">
        <div className="gateway-route-editor-head"><span>自定义方案（重新发布会继续使用）</span><button className="ghost" disabled={!(form.auto_routes || []).length} onClick={restoreDetectedRoutes}><RefreshCw />恢复自动识别结果</button></div>
        {(form.custom_routes || []).map((route, index) => <div className="gateway-route-item" key={index}>
          <div className="gateway-route-row">
            <input value={route.path || ""} placeholder="访问路径，如 /prod-api/" onChange={(event) => set("custom_routes", form.custom_routes.map((item, row) => row === index ? { ...item, path: event.target.value } : item))} />
            <select value={route.service || ""} onChange={(event) => set("custom_routes", form.custom_routes.map((item, row) => row === index ? { ...item, service: event.target.value } : item))}>
              <option value="">选择代理目标服务</option>{(form.gateway_services || []).map((service) => <option key={service} value={service}>{service}</option>)}
            </select>
            <label title="例如 /prod-api/ 转发到后端时，勾选后后端收到 /；不勾选则后端仍收到 /prod-api/"><input type="checkbox" checked={Boolean(route.strip_prefix)} onChange={(event) => set("custom_routes", form.custom_routes.map((item, row) => row === index ? { ...item, strip_prefix: event.target.checked } : item))} />转发时去掉此前缀</label>
            <button className="ghost danger-text" onClick={() => set("custom_routes", form.custom_routes.filter((_, row) => row !== index))}><Trash2 /></button>
          </div>
          <div className="gateway-route-target"><span>{route.path || "/"}</span><b>→</b><span>{routeTargetText(route)}</span></div>
        </div>)}
        <button className="ghost" onClick={() => set("custom_routes", [...(form.custom_routes || []), { path: "/", service: form.gateway_services?.[0] || "", strip_prefix: false }])}><Plus />添加路由</button>
      </div>}
    </div>}
    {error && <div className="alert danger">{error}</div>}
    <div className="modal-actions"><button className="ghost" onClick={onClose}>取消</button><button className="primary" disabled={!form || busy || (form.gateway_mode === "custom" && !form.custom_routes?.length)} onClick={save}>{busy ? <LoaderCircle className="spin" /> : <ShieldCheck />}保存并应用</button></div>
  </Modal>;
}

function ProjectDomainModal({ deployment, onClose, onSaved, notify }) {
  const [form, setForm] = useState({
      domain: deployment.project_domain || "",
      http_port: 80,
      https_enabled: false,
      https_port: 443,
      redirect_https: true,
      gateway_mode: "auto",
      custom_routes: [],
      proxy_read_timeout: 300,
      client_max_body_mb: 50,
      gateway_services: [],
      has_certificate: false,
      certificate_name: null,
    }),
    [certificate, setCertificate] = useState(null),
    [privateKey, setPrivateKey] = useState(null),
    [replaceCertificate, setReplaceCertificate] = useState(false),
    [certificateLibrary, setCertificateLibrary] = useState([]),
    [selectedCertificateId, setSelectedCertificateId] = useState(null),
    [loading, setLoading] = useState(true),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    Promise.all([api(`/projects/${deployment.project_id}/domain-config`), api("/certificates")])
      .then(([data, certificates]) => { setForm(data); setCertificateLibrary(certificates || []); setSelectedCertificateId(data.certificate_id || null); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [deployment.project_id]);
  const set = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));
  const domainMatches = (domain, pattern) => {
    const host = (domain || "").toLowerCase(), rule = (pattern || "").toLowerCase();
    return host === rule || (rule.startsWith("*.") && host.endsWith(rule.slice(1)) && host.split(".").length === rule.split(".").length);
  };
  const matchingCertificates = certificateLibrary.filter((item) => item.domains?.some((pattern) => domainMatches(form.domain, pattern)));
  useEffect(() => {
    if (!form.https_enabled || replaceCertificate || !form.domain) return;
    if (!matchingCertificates.some((item) => item.id === selectedCertificateId)) setSelectedCertificateId(matchingCertificates[0]?.id || null);
  }, [form.domain, form.https_enabled, replaceCertificate, certificateLibrary]);
  const save = async () => {
    if (!validPort(form.http_port) || (form.https_enabled && !validPort(form.https_port))) {
      setError("端口必须是 1–65535 之间的整数");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const body = new FormData();
      body.append("domain", form.domain.trim());
      body.append("http_port", String(form.http_port || 80));
      body.append("https_enabled", String(form.https_enabled));
      body.append("https_port", String(form.https_port || 443));
      body.append("redirect_https", String(form.redirect_https));
      body.append("gateway_mode", form.gateway_mode || "auto");
      body.append("custom_routes_json", JSON.stringify(form.custom_routes || []));
      body.append("proxy_read_timeout", String(form.proxy_read_timeout || 300));
      body.append("client_max_body_mb", String(form.client_max_body_mb || 50));
      if (!replaceCertificate && selectedCertificateId) body.append("certificate_id", selectedCertificateId);
      if (certificate) body.append("certificate", certificate);
      if (privateKey) body.append("private_key", privateKey);
      const result = await api(`/projects/${deployment.project_id}/domain-config`, {
        method: "POST",
        body,
      });
      notify?.(
        form.https_enabled
          ? "HTTPS 与证书配置已生效"
          : "域名和 HTTP 访问配置已生效",
      );
      onSaved?.(result);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const resetToDefault = async () => {
    if (!window.confirm("确定清空当前域名与 HTTPS 配置，恢复为系统自动分配的访问地址吗？\n\n证书库中的证书不会被删除。")) return;
    setBusy(true);
    setError("");
    try {
      const body = new FormData();
      body.append("domain", "");
      body.append("http_port", "80");
      body.append("https_enabled", "false");
      body.append("https_port", "443");
      body.append("redirect_https", "false");
      body.append("gateway_mode", "auto");
      body.append("custom_routes_json", "[]");
      body.append("proxy_read_timeout", "300");
      body.append("client_max_body_mb", "50");
      const result = await api(`/projects/${deployment.project_id}/domain-config`, { method: "POST", body });
      setForm((current) => ({ ...current, domain: "", http_port: 80, https_enabled: false, https_port: 443, redirect_https: false, gateway_mode: "auto", custom_routes: [], proxy_read_timeout: 300, client_max_body_mb: 50, has_certificate: false, certificate_name: null, certificate_id: null }));
      setCertificate(null);
      setPrivateKey(null);
      setSelectedCertificateId(null);
      setReplaceCertificate(false);
      notify?.("已恢复默认访问配置，证书库内容已保留");
      onSaved?.(result);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      className="domain-config-modal"
      title={`配置访问域名 · ${deployment.project_name}`}
      onClose={onClose}
      closeOnMask={false}
      wide
    >
      {loading ? (
        <div className="center">
          <LoaderCircle className="spin" />
        </div>
      ) : (
        <>
          <div className="alert info">
            域名需解析到平台公网 IP。HTTP 默认 80、HTTPS 默认
            443，也可以按实际情况修改。
          </div>
          <div className="domain-config-body">
            <section className="domain-config-section">
              <div className="domain-section-head"><div><b>访问地址</b><small>配置域名、协议和网关端口</small></div></div>
              <div className="domain-basic-grid">
            <Field label="自定义域名" hint="例如 app.example.com">
              <input
                autoFocus
                placeholder="app.example.com"
                value={form.domain}
                onChange={(e) =>
                  set(
                    "domain",
                    e.target.value.replace(/^https?:\/\//, "").split("/")[0],
                  )
                }
              />
            </Field>
            <Field label="HTTP 端口" hint="默认 80，可修改">
              <PortInput
                min="1"
                max="65535"
                value={form.http_port}
                onChange={(value) => set("http_port", value)}
              />
            </Field>
            <Field label="SSL / HTTPS">
              <div className="seg">
                <button
                  className={!form.https_enabled ? "on" : ""}
                  onClick={() => set("https_enabled", false)}
                >
                  关闭
                </button>
                <button
                  className={form.https_enabled ? "on" : ""}
                  onClick={() => set("https_enabled", true)}
                >
                  启用
                </button>
              </div>
            </Field>
            {form.https_enabled && (
              <Field label="HTTPS 端口" hint="默认 443，可修改">
                <PortInput
                  min="1"
                  max="65535"
                  value={form.https_port}
                  onChange={(value) => set("https_port", value)}
                />
              </Field>
            )}
              </div>
            </section>
            {form.https_enabled && <section className="domain-config-section certificate-section">
              <div className="domain-section-head"><div><b>SSL 证书</b><small>{matchingCertificates.length ? `已找到 ${matchingCertificates.length} 张匹配证书，选择后可直接复用` : "证书库没有匹配项，请上传新证书"}</small></div></div>
              <div className="certificate-source-row">
              <Field label="证书方式">
                <div className={`seg ${!matchingCertificates.length ? "one" : ""}`}>
                  {!!matchingCertificates.length && <button className={!replaceCertificate ? "on" : ""} onClick={() => setReplaceCertificate(false)}>从证书库选择</button>}
                  <button className={replaceCertificate || !matchingCertificates.length ? "on" : ""} onClick={() => setReplaceCertificate(true)}>上传新证书</button>
                </div>
              </Field>
              </div>
            {!replaceCertificate && !!matchingCertificates.length && <div className="certificate-library-list">{matchingCertificates.map((item) => <button key={item.id} className={`saved-certificate-card ${selectedCertificateId === item.id ? "selected" : ""}`} onClick={() => setSelectedCertificateId(item.id)}><ShieldCheck/><div><b>{item.domains.join("、")}</b><small>{item.name} · 有效期至 {new Date(item.expires_at).toLocaleDateString()}</small></div><span>{selectedCertificateId === item.id ? "已选择" : `${item.references || 0} 个项目使用`}</span></button>)}</div>}
            {(replaceCertificate || !matchingCertificates.length) && <div className="certificate-upload-grid">{(
              <Field
                label="SSL 证书"
                hint="支持 .crt、.cer 或 .pem（PEM 格式）"
              >
                <input
                  type="file"
                  accept=".crt,.pem,.cer"
                  onChange={(e) => setCertificate(e.target.files?.[0] || null)}
                />
              </Field>
            )}
            {(
              <Field
                label="证书私钥"
                hint="支持 .key 或 .pem（私钥将加密保存）"
              >
                <input
                  type="file"
                  accept=".key,.pem"
                  onChange={(e) => setPrivateKey(e.target.files?.[0] || null)}
                />
              </Field>
            )}</div>}
            </section>}
            {form.https_enabled && <section className="domain-config-section https-policy-section">
              <div className="domain-section-head"><div><b>访问策略</b><small>决定 HTTP 请求是否自动转到 HTTPS</small></div></div>
              <Field label="HTTP 访问处理">
                <div className="seg">
                  <button
                    className={form.redirect_https ? "on" : ""}
                    onClick={() => set("redirect_https", true)}
                  >
                    开启跳转
                  </button>
                  <button
                    className={!form.redirect_https ? "on" : ""}
                    onClick={() => set("redirect_https", false)}
                  >
                    保持 HTTP
                  </button>
                </div>
              </Field>
            </section>}
          </div>
          {error && <div className="alert danger">{error}</div>}
          <div className="modal-actions">
            <button className="ghost danger-text" disabled={busy} onClick={resetToDefault}>
              恢复默认配置
            </button>
            <span className="modal-action-spacer" />
            <button className="ghost" disabled={busy} onClick={onClose}>
              取消
            </button>
            <button
              className="primary"
              disabled={
                busy ||
                !form.domain ||
                (form.gateway_mode === "custom" && !(form.custom_routes || []).length) ||
                (form.https_enabled &&
                  (replaceCertificate || !selectedCertificateId) &&
                  (!certificate || !privateKey))
              }
              onClick={save}
            >
              {busy ? <LoaderCircle className="spin" /> : <ShieldCheck />}
              保存并应用配置
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}

function Deployments() {
  const [items, setItems] = useState([]),
    [selected, setSelected] = useState(null),
    [domainFor, setDomainFor] = useState(null),
    [deleting, setDeleting] = useState(null),
    [deleteBusy, setDeleteBusy] = useState(false),
    [selectedIds, setSelectedIds] = useState(new Set()),
    [bulkBusy, setBulkBusy] = useState(false),
    [bulkDialog, setBulkDialog] = useState(null),
    [toast, setToast] = useState(null);
  const load = () => api("/deployments").then((next) => {
    setItems(next);
    return next;
  });
  const notify = (text, type = "success") => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 5000);
  };
  const remove = async (removeData) => {
    setDeleteBusy(true);
    try {
      const result = await api(
        `/deployments/${deleting.id}?remove_data=${removeData}`,
        { method: "DELETE" },
      );
      setDeleting(null);
      notify(result.cleanup || "部署记录及该版本资源已删除");
      load();
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setDeleteBusy(false);
    }
  };
  const toggleSelected = (id) =>
    setSelectedIds((current) => {
      const next = new Set(current);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  const toggleAll = (ids, checked) =>
    setSelectedIds((current) => {
      const next = new Set(current);
      ids.forEach((id) => checked ? next.add(id) : next.delete(id));
      return next;
    });
  const prepareBulkDelete = async () => {
    const targets = items.filter(
      (item) => selectedIds.has(item.id) && ["failed", "stopped"].includes(item.status),
    );
    if (!targets.length) return;
    setBulkDialog({ targets, analyses: [], loading: true });
    // Inspect all selected releases concurrently, then let AI review the
    // actual server inventory.  This keeps the safety analysis without the
    // old one-record-at-a-time wait.
    const analyses = await Promise.all(targets.map(async (item) => {
      try {
        return { item, preview: await api(`/deployments/${item.id}/delete-preview`) };
      } catch (error) {
        return { item, error: error.message };
      }
    }));
    setBulkDialog({ targets, analyses, loading: false });
  };
  const bulkDelete = async () => {
    const targets = bulkDialog?.targets || [];
    setBulkBusy(true);
    let deleted = 0;
    const errors = [];
    const groups = Object.values(targets.reduce((result, item) => {
      (result[item.project_id] ||= []).push(item);
      return result;
    }, {}));
    await Promise.all(groups.map(async (group) => {
      for (const item of group) {
        try {
          await api(`/deployments/${item.id}`, { method: "DELETE" });
          deleted += 1;
        } catch (error) {
          errors.push(`${item.release || item.id.slice(0, 8)}：${error.message}`);
        }
      }
    }));
    setSelectedIds(new Set());
    setBulkDialog(null);
    setBulkBusy(false);
    await load();
    notify(
      errors.length
        ? `已删除 ${deleted} 条，${errors.length} 条未删除：${errors[0]}`
        : `已清理并删除 ${deleted} 条历史记录`,
      errors.length ? "error" : "success",
    );
  };
  useEffect(() => {
    let cancelled = false;
    let timer = null;
    const poll = async () => {
      let delay = 20000;
      if (!document.hidden) {
        try {
          const next = await load();
          if (next.some((item) => ["queued", "running"].includes(item.status))) delay = 5000;
        } catch (_error) {}
      }
      if (!cancelled) timer = setTimeout(poll, delay);
    };
    poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, []);
  const groups = Object.values(
    items.reduce((result, item) => {
      (result[item.project_id] ||= []).push(item);
      return result;
    }, {}),
  );
  return (
    <>
      <Toast toast={toast} />
      <div className="toolbar">
        <div>
          <h2>部署记录</h2>
          <p>按项目查看每次发布版本、服务器、运行状态和访问地址</p>
        </div>
        <div className="toolbar-actions">
          {selectedIds.size > 0 && (
            <button className="danger-outline" disabled={bulkBusy} onClick={prepareBulkDelete}>
              {bulkBusy ? <LoaderCircle className="spin" /> : <Trash2 />}
              删除选中（{selectedIds.size}）
            </button>
          )}
          <button className="ghost" onClick={load}>
            <RefreshCw />刷新
          </button>
        </div>
      </div>
      {items.length ? (
        <div className="deployment-project-list">
          {groups.map((group) => (
            <ProjectDeploymentGroup
              key={group[0].project_id}
              items={group}
              onSelect={setSelected}
              onDelete={setDeleting}
              onDomain={setDomainFor}
              selectedIds={selectedIds}
              onToggle={toggleSelected}
              onToggleAll={toggleAll}
            />
          ))}
        </div>
      ) : (
        <Empty icon={Activity} text="还没有部署记录" />
      )}
      {selected && (
        <DeploymentDetail
          item={selected}
          onConfigureDomain={setDomainFor}
          onChanged={load}
          onClose={() => {
            setSelected(null);
            load();
          }}
        />
      )}{" "}
      {domainFor && (
        <ProjectDomainModal
          deployment={domainFor}
          notify={notify}
          onClose={() => setDomainFor(null)}
          onSaved={() => {
            setDomainFor(null);
            load();
            setSelected(null);
          }}
        />
      )}
      {deleting && (
        <DeleteDeploymentDialog
          item={deleting}
          busy={deleteBusy}
          onClose={() => setDeleting(null)}
          onConfirm={remove}
        />
      )}
      {bulkDialog && (
        <BulkDeleteDeploymentDialog
          data={bulkDialog}
          busy={bulkBusy}
          onClose={() => !bulkBusy && setBulkDialog(null)}
          onConfirm={bulkDelete}
        />
      )}
    </>
  );
}
function DeploymentDetail({ item, onClose, onConfigureDomain, onChanged }) {
  const [data, setData] = useState(item),
    [runtime, setRuntime] = useState(null),
    [aiFollowup, setAiFollowup] = useState(null),
    [selected, setSelected] = useState(null),
    [serviceLogs, setServiceLogs] = useState(""),
    [loadingLogs, setLoadingLogs] = useState(false),
    [serviceAutoLogs, setServiceAutoLogs] = useState(true),
    [followServiceLogs, setFollowServiceLogs] = useState(true),
    [stopping, setStopping] = useState(false),
    [stopConfirm, setStopConfirm] = useState(false),
    [actionError, setActionError] = useState(null),
    [recoveryAnalysis, setRecoveryAnalysis] = useState(null),
    [recoveryLoading, setRecoveryLoading] = useState(false),
    [stageKey, setStageKey] = useState(null),
    [buildChannel, setBuildChannel] = useState("all"),
    [gatewayConfig, setGatewayConfig] = useState(null),
    [copiedConfig, setCopiedConfig] = useState(""),
    [launchConfig, setLaunchConfig] = useState(null),
    [launchFilePath, setLaunchFilePath] = useState(""),
    [revealLaunchSecrets, setRevealLaunchSecrets] = useState(false),
    [scaleNotice, setScaleNotice] = useState(""),
    [stageLoading, setStageLoading] = useState(false),
    [followStageLog, setFollowStageLog] = useState(true),
    [followDetailScroll, setFollowDetailScroll] = useState(true),
    [runtimeSection, setRuntimeSection] = useState("services"),
    [detailTab, setDetailTab] = useState("pipeline");
  const stageLogRef = useRef(null);
  const detailScrollRef = useRef(null);
  const serviceLogRef = useRef(null);
  const runtimeRefreshPendingRef = useRef(false);
  const parentSyncRef = useRef(`${item.status}|${item.access_url || ""}|${item.release || ""}`);
  const refreshDetailRuntime = (force = true) => {
    if (runtimeRefreshPendingRef.current) return Promise.resolve(null);
    runtimeRefreshPendingRef.current = true;
    return api(`/deployments/${item.id}/runtime${force ? "?refresh=true" : ""}`)
      .then((next) => {
        setRuntime(next);
        return next;
      })
      .finally(() => { runtimeRefreshPendingRef.current = false; });
  };
  const copyConfigText = async (key, value) => {
    try {
      await copyText(value);
      setCopiedConfig(key);
      setTimeout(() => setCopiedConfig(""), 1800);
    } catch (error) {
      setCopiedConfig("error");
      setTimeout(() => setCopiedConfig(""), 2500);
    }
  };
  useEffect(() => {
    let cancelled = false;
    let timer = null;
    const load = async () => {
      try {
        const next = await api(
          `/deployments/${item.id}${stageKey ? `?stage=${stageKey}` : ""}`,
        );
        if (cancelled) return;
        setData(next);
        setStageLoading(false);
        const syncKey = `${next.status}|${next.access_url || ""}|${next.release || ""}`;
        if (syncKey !== parentSyncRef.current) {
          parentSyncRef.current = syncKey;
          onChanged?.();
        }
        // A stopped/successful historical record can be started, stopped or
        // selected as a rollback target from another view. Keep the open
        // detail modal synchronized instead of requiring close-and-reopen.
        timer = setTimeout(load, ["queued", "running"].includes(next.status) ? 3000 : 5000);
      } catch (_error) {
        if (!cancelled) timer = setTimeout(load, 5000);
        setStageLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [item.id, stageKey]);
  useEffect(() => {
    setBuildChannel("all");
    setFollowStageLog(true);
  }, [stageKey]);
  useEffect(() => {
    if (["running", "success", "stopped"].includes(data.status))
      refreshDetailRuntime(true)
        .catch(() => {});
  }, [item.id, data.status, data.release]);
  useEffect(() => {
    if (!runtime || !["success", "stopped"].includes(data.status)) return undefined;
    // Runtime cards are the primary content. Defer extra SSH diagnostics until
    // live container discovery has rendered so gateway inspection cannot make
    // the modal feel blocked.
    const timer = setTimeout(() => {
      api(`/deployments/${item.id}/gateway-config`)
        .then(setGatewayConfig)
        .catch(() => setGatewayConfig(null));
    }, 500);
    return () => clearTimeout(timer);
  }, [item.id, data.status, data.access_url, !!runtime]);
  useEffect(() => {
    if (!data.release || data.status === "queued") return undefined;
    const timer = setTimeout(() => {
      api(`/deployments/${item.id}/launch-config${revealLaunchSecrets ? "?reveal_secrets=true" : ""}`)
        .then((result) => {
          setLaunchConfig(result);
          setLaunchFilePath((current) => current && result.files?.some((file) => file.path === current)
            ? current
            : (result.files?.find((file) => file.used)?.path || result.files?.[0]?.path || ""));
        })
        .catch(() => setLaunchConfig(null));
    }, 300);
    return () => clearTimeout(timer);
  }, [item.id, data.status, data.release, revealLaunchSecrets]);
  useEffect(() => {
    if (data.status !== "stopped") return;
    setRecoveryLoading(true);
    api(`/deployments/${item.id}/recovery-analysis`)
      .then(setRecoveryAnalysis)
      .catch((error) => setActionError({ summary: "恢复状态读取失败", detail: error.message }))
      .finally(() => setRecoveryLoading(false));
  }, [item.id, data.status]);
  useEffect(() => {
    if (!data.status || data.status === "queued") return;
    const load = () =>
      api(`/deployments/${item.id}/ai-followup`)
        .then(setAiFollowup)
        .catch(() => {});
    load();
    if (data.status !== "running") return undefined;
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [item.id, data.status, data.current_step]);
  const loadServiceLogs = async (service, quiet = false) => {
    if (!service) return;
    if (!quiet) setLoadingLogs(true);
    try {
      const r = await api(
        `/deployments/${item.id}/containers/${encodeURIComponent(service.name)}/logs`,
      );
      setServiceLogs(r.logs || "当前没有日志输出");
    } catch (e) {
      setServiceLogs(e.message);
    } finally {
      if (!quiet) setLoadingLogs(false);
    }
  };
  const drill = (service) => {
    setSelected(service);
    setServiceLogs("");
    setServiceAutoLogs(true);
    setFollowServiceLogs(true);
    loadServiceLogs(service);
  };
  useEffect(() => {
    if (!selected || !serviceAutoLogs) return undefined;
    const timer = setInterval(() => loadServiceLogs(selected, true), 5000);
    return () => clearInterval(timer);
  }, [selected?.name, serviceAutoLogs]);
  useEffect(() => {
    if (!followServiceLogs) return;
    requestAnimationFrame(() => {
      if (serviceLogRef.current) serviceLogRef.current.scrollTop = serviceLogRef.current.scrollHeight;
    });
  }, [serviceLogs, followServiceLogs]);
  const stop = async () => {
    setStopping(true);
    setStopConfirm(false);
    setActionError(null);
    try {
      await api(`/deployments/${item.id}/stop`, { method: "POST" });
      setData(await api(`/deployments/${item.id}`));
      await refreshDetailRuntime(true).catch(() => {});
      onChanged?.();
    } catch (e) {
      setActionError({
        summary: "服务未能完全停止",
        detail: e.message,
      });
    } finally {
      setStopping(false);
    }
  };
  const start = async () => {
    if (recoveryAnalysis && !recoveryAnalysis.recoverable) {
      return;
    }
    if (!data.access_url) {
      setActionError({
        summary: "这个记录不能直接启动",
        detail: "该记录没有生成可复用的访问映射，说明它未完整上线。平台不会再把“启动”转换成重新构建；如需发布最新代码，请从项目页点击“部署新版本”。",
      });
      return;
    }
    setStopping(true);
    setActionError(null);
    try {
        await api(`/deployments/${item.id}/start`, { method: "POST" });
        setData(await api(`/deployments/${item.id}`));
        await refreshDetailRuntime(true).catch(() => {});
        onChanged?.();
    } catch (e) {
      setActionError({
        summary: "服务未能启用",
        detail: e.message,
      });
    } finally {
      setStopping(false);
    }
  };
  const downloadFullLog = async () => {
    try {
      const response = await fetch(`/api/deployments/${item.id}/logs/download`, {
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (!response.ok) throw new Error("完整日志下载失败");
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = href;
      link.download = `${data.project_slug || "deployment"}-${data.release || item.id.slice(0, 8)}.log`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(href);
    } catch (error) {
      setServiceLogs(error.message);
    }
  };
  const fallbackSteps = [
    ["analyze", "读取方案"], ["prepare", "准备环境"], ["build", "构建应用"],
    ["start", "启动服务"], ["verify", "验证访问"],
  ].map(([key, title], index) => ({
    key, title,
    status: data.status === "failed" && index === 0 ? "failed" : data.status === "stopped" && index === 0 ? "stopped" : "waiting",
    log: index === 0 ? (data.error || "该记录暂未返回阶段明细，请下载完整日志查看。") : "",
    build_streams: [], duration_seconds: null,
  }));
  const steps = data.pipeline_steps?.length ? data.pipeline_steps : fallbackSteps,
    liveStage = steps.find((step) => step.status === "running"),
    failedStage = steps.find((step) => step.status === "failed"),
    selectedStage = steps.find((step) => step.key === stageKey),
    loggedStage = [...steps].reverse().find((step) => step.log),
    lastFinishedStage = [...steps].reverse().find((step) => step.status !== "waiting"),
    activeStage =
      // An explicit click is authoritative, including after a later stage
      // failed. Previously the failed stage always won this selection, so
      // clicking an earlier completed card kept showing the failed build card
      // (whose log payload is intentionally the only one returned per API
      // request) and made historical stage logs appear to have disappeared.
      selectedStage ||
      // With no explicit selection, a terminal failure should open directly
      // on the failed stage.
      (data.status === "failed" && failedStage) ||
      // Follow the live stage by default while the release keeps moving.
      (data.status === "running" && liveStage) ||
      // The compact detail API returns log text only for the current/default
      // stage. Select that stage on the first render; choosing the first
      // successful card used to pair an empty card with another stage's log
      // and incorrectly displayed “等待该步骤开始…”.
      loggedStage ||
      failedStage ||
      lastFinishedStage ||
      steps[0];
  const buildStreams = activeStage?.key === "build" ? (activeStage.build_streams || []) : [];
  const selectedBuildStream = buildStreams.find((stream) => stream.key === buildChannel);
  const displayedStageLog = buildChannel === "all" || !selectedBuildStream
    ? activeStage?.log
    : selectedBuildStream.log;
  const followingLatest = followStageLog && followDetailScroll;
  useEffect(() => {
    if (!followingLatest) return;
    requestAnimationFrame(() => {
      if (stageLogRef.current) stageLogRef.current.scrollTop = stageLogRef.current.scrollHeight;
      if (detailScrollRef.current) detailScrollRef.current.scrollTop = detailScrollRef.current.scrollHeight;
    });
  }, [displayedStageLog, stageLoading, followingLatest]);
  useEffect(() => {
    if (!followingLatest || detailTab !== "pipeline") return;
    requestAnimationFrame(() => {
      if (stageLogRef.current) stageLogRef.current.scrollTop = stageLogRef.current.scrollHeight;
      if (detailScrollRef.current) detailScrollRef.current.scrollTop = detailScrollRef.current.scrollHeight;
    });
  }, [activeStage?.key, detailTab, followingLatest]);
  const runtimeRefreshEnabled = ["running", "success", "stopped"].includes(data.status);
  const runtimeTabVisible = runtime?.live_runtime !== false && (runtime?.containers || []).length > 0;
  useEffect(() => {
    if (detailTab !== "runtime" || !runtimeRefreshEnabled) return undefined;
    refreshDetailRuntime(true).catch(() => {});
    const timer = setInterval(() => refreshDetailRuntime(true).catch(() => {}), 5000);
    return () => clearInterval(timer);
  }, [item.id, detailTab, runtimeRefreshEnabled]);
  const deploymentRuntimeContainers = runtime?.containers || [];
  const deploymentDataContainers = deploymentRuntimeContainers.filter((container) =>
    dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`),
  );
  const deploymentApplicationContainers = deploymentRuntimeContainers.filter((container) =>
    !dataContainerPattern.test(`${container.service || ""} ${container.name || ""} ${container.image || ""}`),
  );
  const deploymentDataContainerCount = deploymentDataContainers.length;
  const deploymentApplicationContainerCount = deploymentApplicationContainers.length;
  const visibleLaunchFiles = (launchConfig?.files || []).filter((file) => file.used);
  const filesTabVisible = visibleLaunchFiles.length > 0;
  const diagnosisTabVisible = data.status === "failed" || Boolean(
    aiFollowup?.summary || aiFollowup?.diagnosis || aiFollowup?.root_cause,
  );
  const diagnosticFixPlan = [...new Set((aiFollowup?.fix_plan || []).map((step) => String(step).trim()).filter(Boolean))];
  const diagnosticAdvice = String(aiFollowup?.advice || "").trim();
  const adviceRepeatedInPlan = diagnosticFixPlan.length === 1 && diagnosticFixPlan[0] === diagnosticAdvice;
  const detailIdentity = data.status === "success"
    ? { label: "当前运行版本", tone: "active", hint: "正在对外提供服务" }
    : ["queued", "running"].includes(data.status)
      ? { label: "发布任务", tone: "candidate", hint: "正在准备新版本" }
      : data.status === "failed"
        ? { label: "失败记录", tone: "failed", hint: "本次发布未完成" }
        : { label: "已停止版本", tone: "stopped", hint: data.release ? "可检查后重新启用" : "发布任务已停止" };
  useEffect(() => {
    if (detailTab === "runtime" && !runtimeTabVisible) setDetailTab("pipeline");
    if (detailTab === "files" && !filesTabVisible) setDetailTab("pipeline");
    if (detailTab === "diagnosis" && !diagnosisTabVisible) setDetailTab("pipeline");
  }, [detailTab, runtimeTabVisible, filesTabVisible, diagnosisTabVisible]);
  return (
    <Modal
      className="deployment-detail-modal"
      title={`${data.project_name || data.id.slice(0, 8)} · ${detailIdentity.label}`}
      onClose={onClose}
      scrollRef={detailScrollRef}
      onScroll={(event) => {
        const element = event.currentTarget;
        setFollowDetailScroll(element.scrollHeight - element.scrollTop - element.clientHeight < 36);
      }}
      wide
    >
      <div className="deploy-summary">
        <div>
          <span className={`deployment-detail-identity ${detailIdentity.tone}`}>
            {detailIdentity.label}
          </span>
          <Badge status={data.status} />
          {data.release && <span className="deploy-id">版本 {shortRelease(data.release)}</span>}
          <span className="deploy-id">任务 {data.id.slice(0, 8)}</span>
          <span className="deploy-id">{deploymentDuration(data)}</span>
          {data.rollback_transition?.kind === "rollback_target" && (
            <span className="deployment-rollback-context">
              <RefreshCw />由版本 {data.rollback_transition.from_release} 回滚至此
            </span>
          )}
          {data.rollback_transition?.kind === "rollback_source" && (
            <span className="deployment-rollback-context is-source">
              <RefreshCw />已回滚到版本 {data.rollback_transition.to_release}
            </span>
          )}
        </div>
        <div className="deploy-actions">
          <button className="ghost" onClick={onClose}>← 返回发布记录</button>
          {data.status === "success" && <button className="ghost" onClick={() => onConfigureDomain?.(data)}>
            <Settings />
            {data.project_domain ? "编辑域名" : "配置域名"}
          </button>}
          {data.status === "success" && data.access_url && (
            <a
              className="primary button"
              href={data.access_url}
              target="_blank"
            >
              访问应用
              <ExternalLink />
            </a>
          )}
            {data.status === "stopped" && (
              <button className="primary" disabled={stopping || recoveryLoading || !data.access_url || recoveryAnalysis?.recoverable === false} onClick={start}>
              {stopping || recoveryLoading ? <LoaderCircle className="spin" /> : <Play />}
                {recoveryLoading ? "正在分析" : !data.access_url || recoveryAnalysis?.recoverable === false ? "无法直接启用" : "重新启用此版本"}
            </button>
          )}
          {!["failed", "stopped"].includes(data.status) && (
            <button
              className="danger-button"
              disabled={stopping}
              onClick={() => setStopConfirm(true)}
            >
              {stopping ? <LoaderCircle className="spin" /> : <Square />}
              {data.status === "success" ? "停止应用" : "停止部署"}
            </button>
          )}
        </div>
      </div>
      {actionError && (
        <div className="inline-alert error action-error-compact">
          <div>
            <b>{actionError.summary}</b>
            <span>平台已保留技术信息，可展开查看。</span>
          </div>
          <details>
            <summary>查看详情</summary>
            <pre>{actionError.detail}</pre>
          </details>
        </div>
      )}
      {data.status === "stopped" && recoveryLoading && !recoveryAnalysis && (
        <div className="inline-alert info recovery-live-analysis">
          <LoaderCircle className="spin" />
          <div><b>AI 实时分析</b><span>正在检查发布目录、运行配置、镜像和数据卷...</span></div>
        </div>
      )}
      {data.status === "stopped" && recoveryAnalysis && (
        <div className={`recovery-status-strip ${recoveryAnalysis.recoverable ? "is-ready" : "is-warning"}`}>
          <div className="recovery-status-icon"><Bot /></div>
          <div className="recovery-status-main">
            <em>AI 恢复分析</em>
            <b>{recoveryAnalysis.recoverable ? "可以直接恢复" : "需要重新发布"}</b>
            <span title={recoveryAnalysis.summary}>{recoveryAnalysis.summary}</span>
          </div>
          {(recoveryAnalysis.advice || recoveryAnalysis.diagnostic_detail) && (
            <details>
              <summary>查看诊断</summary>
              <p>{recoveryAnalysis.advice}</p>
              {recoveryAnalysis.diagnostic_detail && <pre>{recoveryAnalysis.diagnostic_detail}</pre>}
            </details>
          )}
        </div>
      )}
      <div className="deployment-plan">
        <div className="plan-title">
          <div>
            <b>发布前分析</b>
            <span>{data.deployment_plan?.build_mode || "正在分析"}</span>
          </div>
          <em>
            {data.deployment_plan?.access_url ||
              data.deployment_plan?.port_mode}
          </em>
        </div>
        <div className="plan-ports">
          <span>
            目标服务器
            <b>
              {data.deployment_plan?.node} ·{" "}
              {data.deployment_plan?.node_address}
            </b>
          </span>
          <span>
            源码来源<b>{data.deployment_plan?.source || "—"}</b>
          </span>
          <span>
            端口规划
            <b>
              {data.deployment_plan?.host_port
                ? `${data.deployment_plan.host_port} → ${data.deployment_plan.container_port || "待识别"}`
                : data.deployment_plan?.port_mode}
            </b>
          </span>
        </div>
      </div>
      <div className="deployment-progress">
        <div>
          <b>{data.current_step || "正在读取状态"}</b>
          <span>{data.progress || 0}%</span>
        </div>
        <div>
          <i style={{ width: `${data.progress || 0}%` }} />
        </div>
      </div>
      <div className="detail-list horizontal deploy-facts">
        <div>
          <span>部署服务器</span>
          <b>{data.node_name || runtime?.node?.name || "—"}</b>
          <small>
            {data.node_address || runtime?.node?.public_address || "—"}
          </small>
        </div>
        <div>
          <span>发布目录</span>
          <b title={runtime?.release_dir}>{runtime?.release_dir || "—"}</b>
        </div>
        <div>
          <span>内网实例端口</span>
          <b>{data.host_port || "由 Compose 管理"}</b>
        </div>
        <div>
          <span>发布版本</span>
          <b>{data.release || "—"}</b>
        </div>
      </div>
      {data.login_info?.auth_mode === "default_credentials" &&
        (data.login_info.username || data.login_info.password) && (
        <div className="login-info-card">
          <div className="login-info-head">
            <KeyRound />
            <div>
              <b>应用登录信息</b>
              <span>
                {data.login_info.note || "平台 AI 已检查项目认证方式"}
              </span>
            </div>
          </div>
          <div className="login-info-grid">
            <span>
              登录地址
              <b>
                {data.login_info.login_url ? (
                  <a href={data.login_info.login_url} target="_blank">
                    {data.login_info.login_url}
                    <ExternalLink />
                  </a>
                ) : (
                  "部署完成后生成"
                )}
              </b>
            </span>
            <span>
              登录账号
              <b>
                {data.login_info.username || "未提供"}
              </b>
            </span>
            <span>
              初始密码
              <b>
                {data.login_info.password || "未提供"}
              </b>
            </span>
          </div>
          {(data.login_info.username || data.login_info.password) && (
            <small className="login-warning">
              首次登录后请立即修改初始密码。
            </small>
          )}
        </div>
      )}
      <div className="deployment-detail-tabs">
        <button className={detailTab === "pipeline" ? "active" : ""} onClick={() => setDetailTab("pipeline")}>
          <Activity />发布过程
        </button>
        {runtimeTabVisible && (
          <button className={detailTab === "runtime" ? "active" : ""} onClick={() => setDetailTab("runtime")}>
            <Boxes />运行服务
            {!!deploymentApplicationContainerCount && <em>{deploymentApplicationContainerCount}</em>}
          </button>
        )}
        {filesTabVisible && (
          <button className={detailTab === "files" ? "active" : ""} onClick={() => setDetailTab("files")}>
            <Code2 />发布文件<em>{visibleLaunchFiles.length}</em>
          </button>
        )}
        {diagnosisTabVisible && (
          <button className={detailTab === "diagnosis" ? "active" : ""} onClick={() => setDetailTab("diagnosis")}>
            <Bot />AI 诊断
            {data.status === "failed" && <i />}
          </button>
        )}
      </div>
      {detailTab === "files" && (
        <div className="advanced gateway-config launch-config runtime-config-section">
          {launchConfig ? <>
            <div className="detail-list">
              <div><span>发布目录</span><b>{launchConfig.release_dir}</b></div>
              <div><span>实际入口</span><b>{launchConfig.file}</b></div>
              <div><span>启动方式</span><b>{launchConfig.type === "compose" ? "Docker Compose" : "Dockerfile / Docker Run"}</b></div>
            </div>
            <div className="stage-log-head"><b>本次发布涉及的文件</b><span />
              {launchConfig.can_reveal_secrets && <button className="ghost" onClick={() => setRevealLaunchSecrets((value) => !value)}>{launchConfig.secrets_revealed ? "隐藏敏感值" : "显示敏感值"}</button>}
              <small>{launchConfig.secrets_revealed ? "敏感值已显示 · 只读" : "敏感值已隐藏 · 只读"}</small>
            </div>
            <div className="runtime-section-tabs deployment-file-tabs">
              {[...visibleLaunchFiles]
                .sort((left, right) => {
                  if (Boolean(left.used) !== Boolean(right.used)) return left.used ? -1 : 1;
                  return deploymentFileMeta(left).priority - deploymentFileMeta(right).priority
                    || String(left.path).localeCompare(String(right.path));
                })
                .map((file) => (
                <button className={launchFilePath === file.path ? "active" : ""} key={file.path} onClick={() => setLaunchFilePath(file.path)}>
                  {file.used ? "✓ " : ""}{deploymentFileMeta(file).label} · {deploymentFileMeta(file).name}
                </button>
              ))}
            </div>
            {(() => {
              const selectedFile = visibleLaunchFiles.find((file) => file.path === launchFilePath);
              if (!selectedFile) return <div className="runtime-empty">当前阶段尚未生成可查看的发布文件</div>;
              return <>
                <div className="stage-log-head">
                  <b>{selectedFile.path}{selectedFile.used ? " · 本次实际使用" : " · 源码/关联配置"}</b>
                  <button className="ghost" onClick={() => copyConfigText("release-file", selectedFile.content)}><Copy />{copiedConfig === "release-file" ? "已复制" : "复制"}</button>
                </div>
                <pre className="logs stage-log">{selectedFile.content}</pre>
                <small>SHA-256：{selectedFile.sha256}</small>
              </>;
            })()}
          </> : <div className="runtime-empty"><LoaderCircle className="spin" />正在读取本次发布文件...</div>}
        </div>
      )}
      {detailTab === "runtime" && <>
      <div className="runtime-section-tabs" role="tablist" aria-label="运行服务详情">
        <button className={runtimeSection === "services" ? "active" : ""} onClick={() => setRuntimeSection("services")}>
          <Boxes />应用容器{!!deploymentApplicationContainerCount && <em>{deploymentApplicationContainerCount}</em>}
        </button>
        <button className={runtimeSection === "launch" ? "active" : ""} onClick={() => setRuntimeSection("launch")}>
          <Terminal />启动配置
        </button>
        <button className={runtimeSection === "gateway" ? "active" : ""} onClick={() => setRuntimeSection("gateway")}>
          <Settings />网关配置
        </button>
      </div>
      {runtimeSection === "gateway" && gatewayConfig && (
        <div className="advanced gateway-config runtime-config-section">
          <div className="detail-list">
            <div>
              <span>网关节点</span>
              <b>
                {gatewayConfig.gateway_node} · {gatewayConfig.gateway_address}
              </b>
            </div>
            <div>
              <span>接入方式</span>
              <b>
                {gatewayConfig.configured
                  ? gatewayConfig.replica_count > 1
                    ? `平台 Nginx 网关 · ${gatewayConfig.replica_count} 个实例负载均衡`
                    : "平台 Nginx 网关 · 单实例"
                  : "服务器端口直连（当前未经过 Nginx）"}
              </b>
            </div>
            <div>
              <span>配置文件</span>
              <b>
                {gatewayConfig.config_path || "尚未生成；配置域名后自动创建"}
              </b>
            </div>
            <div>
              <span>内网回源</span>
              <b>{gatewayConfig.upstream}</b>
            </div>
            <div>
              <span>访问域名</span>
              <b>{gatewayConfig.domain || "未配置"}</b>
            </div>
            <div>
              <span>HTTP 端口</span>
              <b>{gatewayConfig.http_port || 80}</b>
            </div>
            <div>
              <span>SSL / HTTPS</span>
              <b>
                {gatewayConfig.https_enabled
                  ? `已启用 · 端口 ${gatewayConfig.https_port || 443} · ${gatewayConfig.certificate_name || "已配置证书"}`
                  : "未启用"}
              </b>
            </div>
            <div>
              <span>网关状态</span>
              <b>
                {gatewayConfig.container_status === "running"
                  ? "运行中"
                  : gatewayConfig.container_status}
              </b>
            </div>
          </div>
          <div className="stage-log-head">
            <b>自动生成的 Nginx 配置</b>
          </div>
          <pre className="logs stage-log">
            {gatewayConfig.config ||
              "当前发布直接使用服务器端口访问，尚未生成 Nginx 配置。点击顶部“配置域名”，保存后系统会创建并应用独立的 Nginx 配置。"}
          </pre>
        </div>
      )}
      {runtimeSection === "gateway" && !gatewayConfig && (
        <div className="runtime-empty"><LoaderCircle className="spin" />正在读取网关配置...</div>
      )}
      {runtimeSection === "launch" && launchConfig && (
        <div className="advanced gateway-config launch-config runtime-config-section">
          <div className="detail-list">
            <div><span>运行方式</span><b>{launchConfig.type === "compose" ? "Docker Compose" : "Dockerfile / Docker Run"}</b></div>
            <div><span>配置文件</span><b>{launchConfig.file}</b></div>
            <div><span>发布目录</span><b>{launchConfig.release_dir}</b></div>
          </div>
          <div className="stage-log-head"><b>实际启动命令</b><button className="ghost" onClick={() => copyConfigText("command", launchConfig.command)}><Copy />{copiedConfig === "command" ? "已复制" : "复制"}</button></div>
          <pre className="logs stage-log launch-command-line">{launchConfig.command}</pre>
          <div className="stage-log-head"><b>编排文件（只读）</b><button className="ghost" onClick={() => copyConfigText("compose", launchConfig.content)}><Copy />{copiedConfig === "compose" ? "已复制" : "复制"}</button></div>
          <pre className="logs stage-log">{launchConfig.content}</pre>
          {launchConfig.environment && <><div className="stage-log-head"><b>运行环境摘要（敏感值已隐藏）</b></div><pre className="logs stage-log">{launchConfig.environment}</pre></>}
        </div>
      )}
      {runtimeSection === "launch" && !launchConfig && (
        <div className="runtime-empty"><LoaderCircle className="spin" />正在读取启动配置...</div>
      )}
      {runtimeSection === "services" && <>
      <div className="runtime-head">
        <div>
          <h4>本版本运行快照</h4>
          <p>这里只显示本版本的应用容器；MySQL、Redis 等共享服务统一在项目“数据资源”中管理</p>
        </div>
        <div className="runtime-totals">
          {!!runtime?.application_instances && <span className="ready-count">应用实例 {runtime.ready_application_instances}/{runtime.application_instances}</span>}
          <span>应用容器 {deploymentApplicationContainerCount}</span>
        </div>
      </div>
      {scaleNotice && <div className="alert info service-scale-notice">{scaleNotice}</div>}
      {deploymentApplicationContainers.length ? (
        <div className="service-grid">
          {deploymentApplicationContainers.map((c) => {
            const deps = runtime.dependencies?.[c.service] || [];
            return (
              <div
                key={c.name}
                className={
                  "service-card " +
                  (selected?.name === c.name ? "selected" : "")
                }
                role="button"
                tabIndex={0}
                onClick={() => drill(c)}
                onKeyDown={(event) => { if (event.key === "Enter") drill(c); }}
              >
                <div className="service-title">
                  <Boxes />
                  <div>
                    <b>{c.name}</b>
                    <small>{c.image || "容器"}</small>
                  </div>
                  <div className="service-title-tools">
                    {c.instance_role && <em className={`instance-role ${c.instance_role}`}>
                      {c.instance_role === "primary" ? "主实例" : c.instance_role === "replica" ? "扩展实例" : "依赖服务"}
                    </em>}
                    <i
                      className={
                        String(c.state).toLowerCase().includes("running") ||
                        String(c.status).toLowerCase().includes("up")
                          ? "up"
                          : "down"
                      }
                    />
                  </div>
                </div>
                <div className="service-data">
                  <span>镜像</span>
                  <b>{c.image || "—"}</b>
                  <span>状态</span>
                  <b>{c.status || c.state}</b>
                  <span>端口</span>
                  <b>
                    {typeof c.ports === "string"
                      ? c.ports || "内部服务"
                      : JSON.stringify(c.ports)}
                  </b>
                  <span>CPU</span>
                  <b>{c.resources?.cpu || "0%"}</b>
                  <span>内存</span>
                  <b>
                    {c.resources
                      ? `${c.resources.memory_usage} / ${c.resources.memory_limit}`
                      : "0 B"}
                  </b>
                </div>
                <div className="depends">
                  <span>依赖</span>
                  {deps.length ? (
                    deps.map((d) => <em key={d}>{d}</em>)
                  ) : (
                    <small>无</small>
                  )}
                  <ChevronRight />
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="runtime-empty">
          {runtime?.live_runtime === false ? (
            <>{runtime.runtime_message || "这是历史发布记录，不显示当前版本的运行容器。"}</>
          ) : deploymentDataContainerCount > 0 ? (
            <>本版本当前没有运行中的应用容器。项目共享的 MySQL、Redis 请到“数据资源”查看。</>
          ) : data.status === "success" ? (
            <>
              <LoaderCircle className="spin" />
              正在读取服务器上的运行服务...
            </>
          ) : (
            <>暂无运行服务</>
          )}
        </div>
      )}
      {selected && (
        <Modal
          className="deployment-service-log-modal"
          title={`${selected.name} · 当前日志`}
          onClose={() => { setSelected(null); setServiceAutoLogs(false); }}
          wide
        >
          <div className="service-inspect">
            <span>
              容器 ID<b>{selected.id || "—"}</b>
            </span>
            <span>
              状态<b>{selected.status || selected.state}</b>
            </span>
            <span>
              端口
              <b>
                {typeof selected.ports === "string"
                  ? selected.ports || "内部服务"
                  : JSON.stringify(selected.ports)}
              </b>
            </span>
            <span>
              CPU<b>{selected.resources?.cpu || "0%"}</b>
            </span>
            <span>
              内存
              <b>
                {selected.resources
                  ? `${selected.resources.memory_usage} / ${selected.resources.memory_limit}`
                  : "0 B"}
              </b>
            </span>
            <span>
              网络 I/O<b>{selected.resources?.network_io || "—"}</b>
            </span>
          </div>
          <div className="service-log-toolbar">
            <button className={`ghost log-refresh-toggle ${serviceAutoLogs ? "active" : ""}`} onClick={() => setServiceAutoLogs((value) => !value)}>
              {serviceAutoLogs ? <Square /> : <Play />}{serviceAutoLogs ? "暂停刷新" : "自动刷新"}
            </button>
            <button
              className={`ghost log-follow-toggle ${followServiceLogs ? "active" : ""}`}
              onClick={() => {
                const next = !followServiceLogs;
                setFollowServiceLogs(next);
                if (next) requestAnimationFrame(() => {
                  if (serviceLogRef.current) serviceLogRef.current.scrollTop = serviceLogRef.current.scrollHeight;
                });
              }}
            >{followServiceLogs ? "保持最新" : "跟随已暂停"}</button>
            <button className="ghost" disabled={loadingLogs} onClick={() => loadServiceLogs(selected)}>
              {loadingLogs ? <LoaderCircle className="spin" /> : <RefreshCw />}立即刷新
            </button>
          </div>
          <pre
            ref={serviceLogRef}
            onScroll={(event) => {
              const element = event.currentTarget;
              setFollowServiceLogs(element.scrollHeight - element.scrollTop - element.clientHeight < 36);
            }}
            className="logs service-log"
          >
            {loadingLogs ? "正在读取日志..." : serviceLogs}
          </pre>
        </Modal>
      )}
      </>}
      </>}
      {detailTab === "diagnosis" && (
        <div className={`panel ai-followup-compact ${data.status === "failed" ? "failed" : "running"}`}>
          <Bot />
          <div className="ai-followup-main">
            <div className="ai-followup-title">
              <b>{data.status === "failed" ? "部署异常" : aiFollowup?.stage || "部署分析中"}</b>
              <span>{data.status === "failed" ? "需要处理" : "AI 实时诊断"}</span>
              {aiFollowup?.retryable && (
                <em className="ai-retrying"><LoaderCircle className="spin" />正在重试</em>
              )}
            </div>
            <p>{aiFollowup?.summary || "正在读取日志并判断当前状态..."}</p>
            {(diagnosticAdvice || diagnosticFixPlan.length) && (
              <details className="ai-diagnostic-details" open>
                <summary>处理建议</summary>
                {diagnosticAdvice && !adviceRepeatedInPlan && <div>{diagnosticAdvice}</div>}
                {diagnosticFixPlan.length > 0 && (
                  <ol>
                    {diagnosticFixPlan.map((step, index) => <li key={`${index}-${step}`}>{step}</li>)}
                  </ol>
                )}
              </details>
            )}
          </div>
        </div>
      )}
      {detailTab === "pipeline" && <div className="pipeline-workbench">
      {data.auto_repair && (
        <section className={`auto-repair-card ${data.status}`}>
          <div className="auto-repair-card-title">
            <div><Bot /><b>AI 自动修复{data.auto_repair.attempt ? ` · 第 ${data.auto_repair.attempt} 次` : ""}</b></div>
            <span>{data.status === "success" ? "验证通过" : data.status === "failed" ? "验证失败" : "正在验证"}</span>
          </div>
          <div className="auto-repair-grid">
            <div><small>具体问题</small><p>{data.auto_repair.problem}</p></div>
            <div><small>当前验证</small><p>{data.auto_repair.verification}</p></div>
          </div>
          <div className="auto-repair-changes">
            <small>平台实际修改</small>
            {data.auto_repair.changes?.length ? (
              <ul>{data.auto_repair.changes.map((change, index) => <li key={`${index}-${change}`}>{change}</li>)}</ul>
            ) : (
              <p>尚未确认构建文件发生有效变化；确认前平台不会重复执行相同构建。</p>
            )}
          </div>
        </section>
      )}
      <div className="pipeline-head">
        <div>
          <h4>发布流水线</h4>
          <p>按阶段查看状态、日志和发布结果</p>
        </div>
      </div>
      <div className="pipeline-workbench-body">
      <div className="pipeline-steps">
        {steps.map((step, index) => (
          <button
            key={step.key}
            className={
              (activeStage?.key === step.key ? "active " : "") + step.status
            }
            onClick={() => {
              if (step.key !== stageKey) setStageLoading(true);
              setStageKey(step.key);
            }}
          >
            <span>
              {step.status === "success" ? (
                "✓"
              ) : step.status === "running" ? (
                <LoaderCircle className="spin" />
              ) : step.status === "failed" ? (
                "×"
              ) : step.status === "stopped" ? (
                <Square />
              ) : (
                index + 1
              )}
            </span>
            <div>
              <b>{step.title}</b>
              <small>
                {step.status === "success"
                  ? (step.skipped ? "无需构建" : "已完成")
                  : step.status === "running"
                    ? "执行中"
                    : step.status === "failed"
                      ? "失败"
                      : step.status === "stopped"
                        ? "已停止"
                        : "等待中"}
                {!step.skipped && step.duration_seconds !== null && step.duration_seconds !== undefined
                  ? ` · ${stageDuration(step.duration_seconds)}`
                  : ""}
              </small>
            </div>
          </button>
        ))}
      </div>
      <div className="pipeline-log-pane">
      <div className="stage-log-head">
        <div className="stage-log-title">
          <b>{activeStage?.title || "部署日志"}</b>
          {activeStage?.skipped
            ? <span>处理方式：复用预构建镜像</span>
            : activeStage?.duration_seconds !== null && activeStage?.duration_seconds !== undefined && (
              <span>持续时间：{stageDuration(activeStage.duration_seconds)}</span>
            )}
        </div>
        <div className="stage-log-tools">
          <button
            className={`ghost log-follow-toggle ${followingLatest ? "active" : ""}`}
            onClick={() => {
              const next = !followingLatest;
              setFollowStageLog(next);
              setFollowDetailScroll(next);
              if (next) requestAnimationFrame(() => {
                if (stageLogRef.current) {
                  stageLogRef.current.scrollTop = stageLogRef.current.scrollHeight;
                }
                if (detailScrollRef.current) detailScrollRef.current.scrollTop = detailScrollRef.current.scrollHeight;
              });
            }}
          >{followingLatest ? "保持最新" : "跟随已暂停"}</button>
          <button className="ghost" onClick={downloadFullLog}>
            <FileArchive />下载完整日志
          </button>
        </div>
      </div>
      {buildStreams.length > 1 && (
        <div className="build-log-tabs" role="tablist" aria-label="构建服务日志">
          <button className={`build-log-all ${buildChannel === "all" ? "active" : ""}`} onClick={() => setBuildChannel("all")}><b>全部</b></button>
          {buildStreams.map((stream) => (
            <button key={stream.key} className={buildChannel === stream.key ? `active ${stream.status}` : stream.status} onClick={() => setBuildChannel(stream.key)}>
              <span>{stream.status === "running" ? <LoaderCircle className="spin" /> : stream.status === "failed" ? "×" : stream.status === "stopped" ? <Square /> : "✓"}</span>
              <div>
                <b>{stream.label}</b>
                {stream.duration_seconds !== null && stream.duration_seconds !== undefined && <small>{stageDuration(stream.duration_seconds)}</small>}
              </div>
            </button>
          ))}
        </div>
      )}
      {activeStage?.key === "pull" && data.image_items?.length > 0 && (
        <div className="image-pull-list">
          {data.image_items.map((image) => (
            <div key={image.name} className={image.status}>
              <Boxes />
              <b>{image.name}</b>
              <span>
                {image.status === "ready"
                  ? "已就绪"
                  : image.status === "pulling"
                    ? "正在拉取"
                    : image.status === "local"
                      ? "本地构建"
                      : "拉取失败"}
              </span>
            </div>
          ))}
        </div>
      )}
      <pre
        ref={stageLogRef}
        onScroll={(event) => {
          const element = event.currentTarget;
          setFollowStageLog(element.scrollHeight - element.scrollTop - element.clientHeight < 36);
        }}
        className="logs stage-log"
      >
        {stageLoading
          ? "正在读取该阶段日志..."
          : displayedStageLog || (activeStage?.status === "waiting" ? "等待该步骤开始..." : "该阶段没有产生日志")}
      </pre>
      </div>
      </div>
      </div>}
      {stopConfirm && (
        <ConfirmDialog
          title={data.status === "success" ? "停止应用" : "停止部署任务"}
          text={data.status === "success" ? "确定停止当前版本的应用？" : "确定停止这次部署任务？"}
          description={data.status === "success"
            ? `将停止${deploymentApplicationContainerCount ? ` ${deploymentApplicationContainerCount} 个` : "当前版本的"}应用容器；MySQL、Redis 等数据资源继续运行，数据不会受到影响。`
            : "将终止当前发布流程并清理本次任务产生的应用容器；现有线上版本和数据资源保持不变。"}
          confirmText={data.status === "success" ? "确认停止应用" : "确认停止部署"}
          danger
          busy={stopping}
          onClose={() => !stopping && setStopConfirm(false)}
          onConfirm={stop}
        />
      )}
    </Modal>
  );
}

function ImageRepository({ me }) {
  const [data, setData] = useState({ repositories: [], repository_count: 0, tag_count: 0, endpoint: "yunzhou.hub:5000" }),
    [loading, setLoading] = useState(true),
    [query, setQuery] = useState(""),
    [selectedProject, setSelectedProject] = useState(null),
    [selected, setSelected] = useState(null),
    [selectedRepositories, setSelectedRepositories] = useState(() => new Set()),
    [bulkDelete, setBulkDelete] = useState(null),
    [bulkBusy, setBulkBusy] = useState(false),
    [deleting, setDeleting] = useState(null),
    [busy, setBusy] = useState(""),
    [copied, setCopied] = useState(""),
    [toast, setToast] = useState(null);
  const notify = (text, type = "success") => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 5000);
  };
  const load = async (silent = false, force = false) => {
    if (!silent) setLoading(true);
    try {
      const next = await api(`/images${force ? "?refresh=true" : ""}`);
      setData(next);
      setSelectedRepositories((previous) => new Set([...previous].filter((name) => next.repositories.some((item) => item.name === name))));
      if (selected) setSelected(next.repositories.find((item) => item.name === selected.name) || null);
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load(true);
    const timer = setInterval(() => load(true), 15000);
    return () => clearInterval(timer);
  }, []);
  const remove = async () => {
    if (!deleting) return;
    const key = `${deleting.repository}:${deleting.tag}`;
    setBusy(key);
    try {
      const result = await api("/images", {
        method: "DELETE",
        body: JSON.stringify(deleting),
      });
      notify(result.message);
      setDeleting(null);
      await load(true);
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setBusy("");
    }
  };
  const repositories = data.repositories.filter((item) =>
    `${item.name} ${item.project_slug || ""} ${item.project_name || ""} ${item.service_name || ""}`
      .toLowerCase().includes(query.toLowerCase()),
  );
  const projectGroups = Object.values(repositories.reduce((groups, item) => {
    const key = item.project_slug || item.name;
    if (!groups[key]) groups[key] = {
      key,
      slug: item.project_slug || item.name,
      name: item.project_name || "未关联项目",
      repositories: [],
      tag_count: 0,
    };
    groups[key].repositories.push(item);
    groups[key].tag_count += item.tag_count;
    return groups;
  }, {}));
  const allFilteredSelected = repositories.length > 0 && repositories.every((item) => selectedRepositories.has(item.name));
  const toggleRepository = (name) => setSelectedRepositories((previous) => {
    const next = new Set(previous);
    if (next.has(name)) next.delete(name); else next.add(name);
    return next;
  });
  const toggleAllFiltered = () => setSelectedRepositories((previous) => {
    const next = new Set(previous);
    if (allFilteredSelected) repositories.forEach((item) => next.delete(item.name));
    else repositories.forEach((item) => next.add(item.name));
    return next;
  });
  const previewBulkDelete = async () => {
    if (!selectedRepositories.size) return;
    setBulkBusy(true);
    try {
      const result = await api("/images/bulk-delete", {
        method: "POST",
        body: JSON.stringify({ repositories: [...selectedRepositories], confirm: false }),
      });
      setBulkDelete(result.preview);
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setBulkBusy(false);
    }
  };
  const confirmBulkDelete = async () => {
    setBulkBusy(true);
    try {
      const result = await api("/images/bulk-delete", {
        method: "POST",
        body: JSON.stringify({ repositories: [...selectedRepositories], confirm: true }),
      });
      notify(result.message, result.ok ? "success" : "error");
      setBulkDelete(null);
      setSelectedRepositories(new Set());
      await load(true);
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setBulkBusy(false);
    }
  };
  const size = (bytes) => {
    if (!bytes) return "—";
    const units = ["B", "KB", "MB", "GB"];
    let value = bytes, unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
    return `${value.toFixed(unit > 1 ? 1 : 0)} ${units[unit]}`;
  };
  const copyPullCommand = async (key, command) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(command);
      } else {
        const input = document.createElement("textarea");
        input.value = command;
        input.style.position = "fixed";
        input.style.opacity = "0";
        document.body.appendChild(input);
        input.select();
        if (!document.execCommand("copy")) throw new Error("浏览器拒绝复制");
        input.remove();
      }
      setCopied(key);
      notify("复制成功，可以直接粘贴执行");
      setTimeout(() => setCopied(""), 1800);
    } catch (error) {
      notify("复制失败，请手动复制命令", "error");
    }
  };
  return (
    <>
      <Toast toast={toast} />
      <div className="toolbar registry-heading">
        <div><h2>镜像仓库</h2><p>集中保存平台构建产物，不包含服务器本地镜像</p></div>
        <button className="ghost" disabled={loading} onClick={() => load(false, true)}><RefreshCw className={loading ? "spin" : ""} />刷新</button>
      </div>
      <div className="registry-stats">
        <div><Boxes /><span><b>{data.project_count ?? projectGroups.length}</b><small>项目目录</small></span></div>
        <div><Tag /><span><b>{data.tag_count}</b><small>版本标签</small></span></div>
        <div><ShieldCheck /><span><b>运行中</b><small>平台私有仓库</small></span></div>
      </div>
      <div className="image-repository-filters">
        {me.role === "admin" && <label className="registry-select-all" title="选择当前筛选结果"><input type="checkbox" checked={allFilteredSelected} onChange={toggleAllFiltered} /></label>}
        <Search /><input placeholder="搜索镜像仓库" value={query} onChange={(event) => setQuery(event.target.value)} />
        {me.role === "admin" && selectedRepositories.size > 0 && <button className="danger-button registry-bulk-action" disabled={bulkBusy} onClick={previewBulkDelete}>{bulkBusy ? <LoaderCircle className="spin" /> : <Trash2 />}删除所选（{selectedRepositories.size}）</button>}
      </div>
      <div className="registry-list">
        {projectGroups.map((group) => <div key={group.key} className={`registry-row ${me.role === "admin" ? "selectable" : ""} ${group.repositories.every((item) => selectedRepositories.has(item.name)) ? "selected" : ""}`} role="button" tabIndex="0" onClick={() => setSelectedProject(group)} onKeyDown={(event) => { if (event.key === "Enter") setSelectedProject(group); }}>
          {me.role === "admin" && <input className="registry-row-checkbox" type="checkbox" checked={group.repositories.every((item) => selectedRepositories.has(item.name))} onClick={(event) => event.stopPropagation()} onChange={() => {
            const allSelected = group.repositories.every((item) => selectedRepositories.has(item.name));
            setSelectedRepositories((previous) => {
              const next = new Set(previous);
              group.repositories.forEach((item) => allSelected ? next.delete(item.name) : next.add(item.name));
              return next;
            });
          }} />}
          <span className="registry-icon"><Boxes /></span>
          <span className="registry-name"><b>{group.slug}</b><small>{group.name}</small></span>
          <span className="registry-count">{group.repositories.length} 个服务 · {group.tag_count} 个版本</span><ChevronRight />
        </div>)}
        {!loading && !projectGroups.length && <Empty icon={Boxes} text="仓库还是空的，项目构建成功后镜像会自动入库" />}
        {loading && <div className="center"><LoaderCircle className="spin" /></div>}
      </div>
      {selectedProject && <Modal onClose={() => setSelectedProject(null)} title={selectedProject.slug} wide>
        <div className="registry-detail-intro">
          <div className="registry-icon"><Boxes /></div>
          <div><b>{selectedProject.name}</b><p>{selectedProject.repositories.length} 个服务镜像，共 {selectedProject.tag_count} 个版本。</p></div>
        </div>
        <div className="registry-list">
          {selectedProject.repositories.map((item) => <div key={item.name} className="registry-row" role="button" tabIndex="0" onClick={() => { setSelectedProject(null); setSelected(item); }} onKeyDown={(event) => { if (event.key === "Enter") { setSelectedProject(null); setSelected(item); } }}>
            <span className="registry-icon"><Boxes /></span>
            <span className="registry-name"><b>{item.service_name || "app"}</b><small>{item.name}</small></span>
            <span className="registry-count">{item.tag_count} 个版本</span><ChevronRight />
          </div>)}
        </div>
      </Modal>}
      {selected && <Modal onClose={() => setSelected(null)} title={selected.name} wide>
        <div className="registry-detail-intro">
          <div className="registry-icon"><Boxes /></div>
          <div><b>镜像版本</b><p>共 {selected.tag_count} 个版本；删除仓库标签不会停止已运行的容器。</p></div>
        </div>
        <div className="registry-tags">{selected?.tags.map((tag) => {
          const key = `${selected.name}:${tag.tag}`;
          const pullCommand = `docker pull ${data.endpoint || "yunzhou.hub:5000"}/${selected.name}:${tag.tag}`;
          return <div key={tag.tag}><span><Tag /><b>{tag.tag}</b></span><code title={tag.digest}>{tag.digest ? tag.digest.slice(0, 22) + "…" : "—"}</code><span>{size(tag.size_bytes)}</span><span className="registry-time">{tag.created_at ? time(tag.created_at) : "时间未知"}</span>
            <button className={`icon copy-action ${copied === key ? "copied" : ""}`} title="复制 docker pull 命令" onClick={() => copyPullCommand(key, pullCommand)}>{copied === key ? <ShieldCheck /> : <Copy />}</button>
            {me.role === "admin" && <button className="icon danger" disabled={busy === key} onClick={() => setDeleting({ repository: selected.name, tag: tag.tag })}>{busy === key ? <LoaderCircle className="spin" /> : <Trash2 />}</button>}
          </div>})}</div>
      </Modal>}
      {deleting && <Modal onClose={() => setDeleting(null)} title="删除镜像版本">
        <div className="registry-delete-copy"><div className="confirm-icon danger"><Trash2 /></div><div><b>确认删除这个镜像版本？</b><code>{deleting.repository}:{deleting.tag}</code><p>删除后不能从仓库重新拉取，但不会影响已经运行的容器。</p></div></div>
        <div className="modal-actions"><button className="ghost" onClick={() => setDeleting(null)}>取消</button><button className="danger-button" onClick={remove}>确认删除</button></div>
      </Modal>}
      {bulkDelete && <Modal onClose={() => !bulkBusy && setBulkDelete(null)} title="批量删除镜像仓库">
        <div className="registry-delete-copy"><div className="confirm-icon danger"><Trash2 /></div><div><b>确认清理所选仓库？</b><p>已选择 {bulkDelete.repository_count} 个仓库，共 {bulkDelete.tag_count} 个版本。</p></div></div>
        <div className="registry-bulk-summary">
          <span><b>{bulkDelete.deletable_count}</b><small>可以删除</small></span>
          <span className="protected"><b>{bulkDelete.protected_count}</b><small>在线版本受保护</small></span>
        </div>
        {bulkDelete.protected_count > 0 && <p className="registry-protection-note"><ShieldCheck />平台会跳过最新在线及正在发布的版本，确保容器重启时仍能拉取。</p>}
        {!!bulkDelete.missing?.length && <p className="muted">其中 {bulkDelete.missing.length} 个仓库已经不存在，将自动跳过。</p>}
        <div className="modal-actions"><button className="ghost" disabled={bulkBusy} onClick={() => setBulkDelete(null)}>取消</button><button className="danger-button" disabled={bulkBusy || bulkDelete.deletable_count === 0} onClick={confirmBulkDelete}>{bulkBusy && <LoaderCircle className="spin" />}确认删除 {bulkDelete.deletable_count} 个版本</button></div>
      </Modal>}
    </>
  );
}

function Nodes() {
  const readCache = (key, fallback) => {
    try {
      return JSON.parse(localStorage.getItem(key)) || fallback;
    } catch {
      return fallback;
    }
  };
  const [items, setItems] = useState(() => readCache("yunzhou.nodes", [])),
    [resources, setResources] = useState(() =>
      readCache("yunzhou.nodeResources", {}),
    ),
    [show, setShow] = useState(false),
    [editing, setEditing] = useState(null),
    [toast, setToast] = useState(null),
    [deleting, setDeleting] = useState(null);
  const loadResources = () =>
    api("/nodes/resources")
      .then((next) => {
        setResources((previous) => {
          const merged = { ...previous, ...next };
          localStorage.setItem("yunzhou.nodeResources", JSON.stringify(merged));
          return merged;
        });
      })
      .catch(() => {});
  const load = () =>
    api("/nodes")
      .then((nodes) => {
        setItems(nodes);
        localStorage.setItem("yunzhou.nodes", JSON.stringify(nodes));
        loadResources();
      })
      .catch(() => loadResources());
  useEffect(() => {
    load();
    const timer = setInterval(loadResources, 30000);
    return () => clearInterval(timer);
  }, []);
  const notify = (text, type = "success") => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 3000);
  };
  const test = async (x) => {
    try {
      const r = await api(`/nodes/${x.id}/test`, { method: "POST" });
      notify(
        r.status === "online"
          ? `${x.name} 连接成功`
          : `${x.name} 连接失败：${r.detail || ""}`,
        r.status === "online" ? "success" : "error",
      );
      load();
    } catch (e) {
      notify(e.message, "error");
    }
  };
  const remove = async (x) => {
    try {
      await api(`/nodes/${x.id}`, { method: "DELETE" });
      setDeleting(null);
      notify("节点已删除");
      load();
    } catch (e) {
      setDeleting(null);
      notify(e.message, "error");
    }
  };
  const size = (n) => {
    if (!n) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = Number(n),
      i = 0;
    while (value >= 1024 && i < units.length - 1) {
      value /= 1024;
      i++;
    }
    return `${value.toFixed(i > 1 ? 1 : 0)} ${units[i]}`;
  };
  return (
    <>
      <div className="toolbar">
        <div>
          <h2>服务器节点</h2>
          <p>平台可以发布项目的 Docker 服务器；资源数据每 30 秒自动刷新</p>
        </div>
        <button className="primary" onClick={() => setShow(true)}>
          <Plus />
          添加节点
        </button>
      </div>
      <Toast toast={toast} />
      {items.length ? (
        <div className="grid node-grid">
          {items.map((x) => {
            const r = resources[x.id];
            return (
              <div className="node-card node-card-horizontal" key={x.id}>
                <div className="node-identity">
                  <div className="node-top">
                    <div className="stat-icon cyan">
                      <Server />
                    </div>
                    <Badge
                      status={
                        x.last_status === "online" ? "success" : x.last_status
                      }
                    />
                  </div>
                  <h3>{x.name}</h3>
                  <p>
                    {x.username}@
                    {x.host === "host.docker.internal"
                      ? r?.host_ips?.[0] || x.public_address
                      : x.host}
                    :{x.port}
                  </p>
                </div>
                {r?.online ? (
                  <div className="node-resources">
                    <div>
                      <span>CPU</span>
                      <b>{r.cpu_percent}%</b>
                      <i>
                        <em style={{ width: `${r.cpu_percent}%` }} />
                      </i>
                      <small>
                        {r.cores} 核 · 负载 {r.load}
                      </small>
                    </div>
                    <div>
                      <span>内存</span>
                      <b>{r.memory_percent}%</b>
                      <i>
                        <em style={{ width: `${r.memory_percent}%` }} />
                      </i>
                      <small>
                        {size(r.memory_used)} / {size(r.memory_total)}
                      </small>
                    </div>
                    <div>
                      <span>系统盘</span>
                      <b>{r.disk_percent}%</b>
                      <i>
                        <em style={{ width: `${r.disk_percent}%` }} />
                      </i>
                      <small>
                        {size(r.disk_used)} / {size(r.disk_total)}
                      </small>
                    </div>
                    <div>
                      <span>容器</span>
                      <b>{r.containers}</b>
                      <small>运行中 / 共 {r.containers_total} 个</small>
                    </div>
                  </div>
                ) : (
                  <div className="node-resource-loading">
                    {r?.error ? "资源读取失败" : "正在读取实时资源..."}
                  </div>
                )}
                <div className="node-side">
                  <div className="node-info">
                    <span>工作目录</span>
                    <b>{x.work_dir}</b>
                    <span>公网地址</span>
                    <b>{x.public_address || "未配置"}</b>
                    <span>节点类型</span>
                    <b>
                      {x.host === "host.docker.internal"
                        ? `平台宿主机${r?.host_ips?.[0] ? ` · 内网 ${r.host_ips[0]}` : ""}`
                        : `远程服务器 · ${x.host}`}
                    </b>
                  </div>
                  {x.last_error && (
                    <div className="node-error">{x.last_error}</div>
                  )}
                  <div className="node-actions">
                    <button className="ghost" onClick={() => setEditing(x)}>
                      <Settings />
                      编辑
                    </button>
                    <button className="ghost" onClick={() => test(x)}>
                      <Activity />
                      测试
                    </button>
                    <button
                      className="danger-button"
                      onClick={() => setDeleting(x)}
                    >
                      <X />
                      删除
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <Empty
          icon={Server}
          text="还没有服务器节点"
          action={
            <button className="primary" onClick={() => setShow(true)}>
              <Plus />
              添加第一台服务器
            </button>
          }
        />
      )}{" "}
      {show && (
        <NodeModal
          notify={notify}
          onClose={() => setShow(false)}
          onDone={() => {
            setShow(false);
            notify("节点添加成功");
            load();
          }}
        />
      )}
      {editing && (
        <NodeModal
          node={editing}
          notify={notify}
          onClose={() => setEditing(null)}
          onDone={() => {
            setEditing(null);
            notify("节点修改成功");
            load();
          }}
        />
      )}
      {deleting && (
        <ConfirmDialog
          danger
          title="删除服务器节点"
          text={`确定删除“${deleting.name}”吗？`}
          confirmText="删除节点"
          onClose={() => setDeleting(null)}
          onConfirm={() => remove(deleting)}
        />
      )}
    </>
  );
}
function NodeModal({ node, onClose, onDone, notify }) {
  const [form, setForm] = useState(
      node
        ? {
            name: node.name,
            host: node.host,
            port: node.port,
            username: node.username,
            auth_type: node.auth_type,
            secret: "",
            public_address: node.public_address || "",
            work_dir: node.work_dir,
            docker_proxy_enabled: !!node.docker_proxy_enabled,
          }
        : {
            name: "",
            host: "",
            port: 22,
            username: "root",
            auth_type: "password",
            secret: "",
            public_address: "",
            work_dir: "/data/yunzhou/projects",
            docker_proxy_enabled: false,
          },
    ),
    [busy, setBusy] = useState(false),
    [testing, setTesting] = useState(false),
    [stagingProxy, setStagingProxy] = useState(false),
    [proxyActual, setProxyActual] = useState(null),
    [proxyStatusError, setProxyStatusError] = useState(""),
    [err, setErr] = useState("");
  useEffect(() => {
    if (!node) return;
    api(`/nodes/${node.id}/docker-proxy-status`)
      .then((status) => {
        setProxyStatusError("");
        setProxyActual(status);
        setForm((current) => ({ ...current, docker_proxy_enabled: !!status.configured }));
      })
      .catch((error) => {
        setProxyStatusError(error.message || "读取失败");
        setProxyActual({ active: !!node.docker_proxy_enabled, configured: !!node.docker_proxy_enabled, pending_restart: false });
      });
  }, [node?.id]);
  const set = (k, v) => setForm({ ...form, [k]: v });
  const changeDockerProxy = async (enabled) => {
    if (!node) return set("docker_proxy_enabled", enabled);
    setStagingProxy(true);
    setErr("");
    try {
      const result = await api(`/nodes/${node.id}/docker-proxy-config`, {
        method: "PUT",
        body: JSON.stringify({ enabled }),
      });
      setForm((current) => ({ ...current, docker_proxy_enabled: enabled }));
      setProxyActual((current) => ({ ...(current || {}), configured: enabled, pending_restart: result.pending_restart }));
    } catch (e) {
      setErr(e.message);
    } finally {
      setStagingProxy(false);
    }
  };
  const cancelModal = async () => {
    if (node && proxyActual?.pending_restart) {
      try {
        await api(`/nodes/${node.id}/docker-proxy-config`, {
          method: "PUT",
          body: JSON.stringify({ enabled: !!proxyActual.active }),
        });
      } catch (e) {
        notify(`恢复 Docker 代理配置失败：${e.message}`, "error");
        return;
      }
    }
    onClose();
  };
  const submit = async () => {
    setBusy(true);
    setErr("");
    try {
      const saved = await api(node ? `/nodes/${node.id}` : "/nodes", {
        method: node ? "PATCH" : "POST",
        body: JSON.stringify(form),
      });
      if (saved.docker_proxy_status === "error") {
        setErr(`节点已保存，但 Docker 代理应用失败：${saved.docker_proxy_error || "请检查 Docker 服务"}`);
        return;
      }
      if (node && form.docker_proxy_enabled !== !!node.docker_proxy_enabled && node.public_address === window.location.hostname) {
        notify("配置已保存；平台本机 Docker 将重启，页面可能短暂断开后自动恢复");
      }
      onDone();
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  const testOnly = async () => {
    setTesting(true);
    try {
      const r = await api("/nodes/test-connection", {
        method: "POST",
        body: JSON.stringify({ ...form, node_id: node?.id || null }),
      });
      notify(r.message || "服务器连接成功");
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setTesting(false);
    }
  };
  return (
    <Modal title={node ? "编辑服务器节点" : "添加服务器节点"} onClose={cancelModal}>
      <div className="form-grid one">
        <Field label="节点名称">
          <input
            placeholder="例如：生产服务器"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
          />
        </Field>
        <div className="split">
          <Field label="服务器地址">
            <input
              placeholder="IP 或域名"
              value={form.host}
              onChange={(e) => set("host", e.target.value)}
            />
          </Field>
          <Field label="SSH 端口">
            <PortInput
              value={form.port}
              onChange={(e) => set("port", Number(e.target.value))}
            />
          </Field>
        </div>
        <div className="split">
          <Field label="SSH 用户">
            <input
              value={form.username}
              onChange={(e) => set("username", e.target.value)}
            />
          </Field>
          <Field label="认证方式">
            <select
              value={form.auth_type}
              onChange={(e) => set("auth_type", e.target.value)}
            >
              <option value="password">密码</option>
              <option value="ssh_key">SSH 私钥</option>
            </select>
          </Field>
        </div>
        <Field
          label={form.auth_type === "password" ? "SSH 密码" : "SSH 私钥"}
          hint={node ? "留空表示保留原凭据" : ""}
        >
          {form.auth_type === "password" ? (
            <input
              type="password"
              placeholder={node ? "无需修改可留空" : ""}
              value={form.secret}
              onChange={(e) => set("secret", e.target.value)}
            />
          ) : (
            <textarea
              rows="5"
              placeholder={node ? "无需修改可留空" : ""}
              value={form.secret}
              onChange={(e) => set("secret", e.target.value)}
            />
          )}
        </Field>
        <Field label="对外访问地址" hint="生成 IP + 端口访问地址">
          <input
            placeholder="通常填写公网 IP"
            value={form.public_address}
            onChange={(e) => set("public_address", e.target.value)}
          />
        </Field>
        <Field label="项目目录">
          <input
            value={form.work_dir}
            onChange={(e) => set("work_dir", e.target.value)}
          />
        </Field>
        <label className="node-proxy-option">
          <input type="checkbox" checked={form.docker_proxy_enabled} disabled={stagingProxy || (node && proxyActual === null && !proxyStatusError)}
            onChange={(e) => changeDockerProxy(e.target.checked)} />
          <span>
            <b>Docker 镜像拉取使用平台代理</b>
            <small>勾选立即创建配置文件，取消立即删除；点击保存修改时才会重启该节点 Docker。</small>
            {proxyActual?.active && <em>当前已生效 · {proxyActual.https_proxy || proxyActual.http_proxy}</em>}
            {proxyActual?.pending_restart && <em className="danger-text">配置文件已变更，等待保存后重启</em>}
            {node && proxyActual === null && !proxyStatusError && <em>正在读取实际状态</em>}
            {proxyStatusError && <em className="danger-text">实际状态读取失败，当前显示已保存设置</em>}
            {node?.docker_proxy_status === "error" && <em className="danger-text">上次应用失败</em>}
          </span>
        </label>
      </div>
      {err && <div className="alert danger">{err}</div>}
      <div className="modal-actions">
        <button className="ghost" onClick={cancelModal} disabled={stagingProxy}>
          取消
        </button>
        <button className="ghost" disabled={testing} onClick={testOnly}>
          {testing ? <LoaderCircle className="spin" /> : <Activity />}测试连接
        </button>
        <button
          className="primary"
          onClick={submit}
          disabled={busy || (!node && !form.secret)}
        >
          {busy && <LoaderCircle className="spin" />}
          {node ? (proxyActual?.pending_restart ? "保存并重启 Docker" : "保存修改") : "保存节点"}
        </button>
      </div>
    </Modal>
  );
}

function UsersPage() {
  const [items, setItems] = useState([]),
    [show, setShow] = useState(false),
    [editing, setEditing] = useState(null),
    [viewingUser, setViewingUser] = useState(null),
    [toast, setToast] = useState(null);
  const load = () => api("/users").then(setItems);
  const done = () => {
    setShow(false);
    setEditing(null);
    setToast({ text: "用户信息已保存", type: "success" });
    setTimeout(() => setToast(null), 3000);
    load();
  };
  const unlock = async (event, user) => {
    event.stopPropagation();
    try {
      await api(`/users/${user.id}/unlock`, { method: "POST" });
      setToast({ text: `${user.display_name || user.username} 已解除锁定`, type: "success" });
      setTimeout(() => setToast(null), 3000);
      load();
    } catch (error) {
      setToast({ text: error.message, type: "error" });
      setTimeout(() => setToast(null), 3000);
    }
  };
  useEffect(() => {
    load();
  }, []);
  return (
    <>
      <Toast toast={toast} />
      <div className="toolbar">
        <div>
          <h2>用户权限</h2>
          <p>控制谁可以配置、发布或只读查看</p>
        </div>
        <button className="primary" onClick={() => setShow(true)}>
          <Plus />
          添加用户
        </button>
      </div>
      <div className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>用户</th>
                <th>角色</th>
                <th>项目</th>
                <th>状态</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {items.map((x) => (
                <React.Fragment key={x.id}>
                <tr>
                  <td>
                    <b>{x.display_name || x.username}</b>
                    <small>@{x.username}</small>
                  </td>
                  <td>{roleText[x.role]}</td>
                  <td>
                    <button
                      className={"user-project-count " + (x.project_count ? "has-projects" : "")}
                      onClick={(event) => {
                        event.stopPropagation();
                        setViewingUser(x);
                      }}
                    >
                      {x.project_scope === "all" ? "全部" : `${x.project_count || 0} 个项目`}
                      <ChevronRight />
                    </button>
                  </td>
                  <td>
                    <span
                      className={"badge " + (!x.active ? "muted" : (x.locked_until && new Date(x.locked_until) > new Date()) ? "danger" : "success")}
                    >
                      <i />
                      {!x.active ? "停用" : (x.locked_until && new Date(x.locked_until) > new Date()) ? "已锁定" : x.failed_login_attempts ? `失败 ${x.failed_login_attempts} 次` : "正常"}
                    </span>
                  </td>
                  <td>{time(x.created_at)}</td>
                  <td>
                    {(x.failed_login_attempts > 0 || (x.locked_until && new Date(x.locked_until) > new Date())) && (
                      <button className="ghost user-edit" onClick={(event) => unlock(event, x)}>
                        <KeyRound />
                        解除锁定
                      </button>
                    )}
                    <button
                      className="ghost user-edit"
                      onClick={(e) => {
                        e.stopPropagation();
                        setEditing(x);
                      }}
                    >
                      <Settings />
                      编辑账号
                    </button>
                  </td>
                </tr>
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {show && <UserModal onClose={() => setShow(false)} onDone={done} />}{" "}
      {editing && (
        <UserModal
          user={editing}
          onClose={() => setEditing(null)}
          onDone={done}
        />
      )}
      {viewingUser && <Modal drawer closeOnMask title={`${viewingUser.display_name || viewingUser.username} · 可管理项目`} onClose={() => setViewingUser(null)}>
        <div className="drawer-summary"><span>{viewingUser.project_scope === "all" ? "拥有全部项目权限" : `共 ${viewingUser.project_count || 0} 个项目`}</span><b>{roleText[viewingUser.role]}</b></div>
        <div className="drawer-project-list">
          {(viewingUser.projects || []).map((project) => <div key={project.id}>
            <div><b>{project.name}</b><small>{project.slug}</small></div>
            <em>{project.permission}</em>
          </div>)}
          {!(viewingUser.projects || []).length && <div className="drawer-project-empty">暂未分配项目</div>}
        </div>
      </Modal>}
    </>
  );
}
function UserModal({ user, onClose, onDone }) {
  const editing = !!user;
  const [f, setF] = useState(
      editing
        ? {
            username: user.username,
            display_name: user.display_name || "",
            password: "",
            role: user.role,
            active: user.active,
          }
        : {
            username: "",
            display_name: "",
            password: "",
            role: "viewer",
            active: true,
          },
    ),
    [err, setErr] = useState(""),
    [busy, setBusy] = useState(false),
    [projects, setProjects] = useState([]),
    [projectQuery, setProjectQuery] = useState(""),
    [selectedProjects, setSelectedProjects] = useState(() => new Set((user?.projects || []).map((item) => item.id))),
    [deleteConfirm, setDeleteConfirm] = useState(false),
    [deleting, setDeleting] = useState(false);
  useEffect(() => {
    api("/projects").then(setProjects).catch((error) => setErr(error.message));
  }, []);
  const toggleProject = (projectId) => setSelectedProjects((current) => {
    const next = new Set(current);
    if (next.has(projectId)) next.delete(projectId); else next.add(projectId);
    return next;
  });
  const submit = async () => {
    setBusy(true);
    setErr("");
    try {
      const body = { ...f };
      if (editing && !body.password) delete body.password;
      const savedUser = await api(editing ? `/users/${user.id}` : "/users", {
        method: editing ? "PATCH" : "POST",
        body: JSON.stringify(body),
      });
      if (f.role !== "admin") {
        await api(`/users/${savedUser.id}/projects`, {
          method: "PUT",
          body: JSON.stringify({ project_ids: [...selectedProjects] }),
        });
      }
      onDone();
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  const removeUser = async () => {
    setDeleting(true);
    setErr("");
    try {
      await api(`/users/${user.id}`, { method: "DELETE" });
      setDeleteConfirm(false);
      onDone();
    } catch (error) {
      setDeleteConfirm(false);
      setErr(error.message);
    } finally {
      setDeleting(false);
    }
  };
  return (
    <Modal title={editing ? "编辑用户账号" : "添加用户"} onClose={onClose}>
      <div className="form-grid one">
        <Field label="登录账号">
          <input
            value={f.username}
            onChange={(e) => setF({ ...f, username: e.target.value })}
          />
        </Field>
        <Field label="显示名称">
          <input
            value={f.display_name}
            onChange={(e) => setF({ ...f, display_name: e.target.value })}
          />
        </Field>
        <Field
          label={editing ? "重置密码" : "初始密码"}
          hint={editing ? "不修改密码时留空；新密码至少 8 位" : ""}
        >
          <input
            type="password"
            placeholder={editing ? "留空保持原密码" : ""}
            value={f.password}
            onChange={(e) => setF({ ...f, password: e.target.value })}
          />
        </Field>
        <Field label="角色">
          <select
            value={f.role}
            onChange={(e) => setF({ ...f, role: e.target.value })}
          >
            <option value="viewer">只读人员</option>
            <option value="deployer">发布人员</option>
            <option value="admin">管理员</option>
          </select>
        </Field>
        {f.role !== "admin" && <Field label="可访问项目" hint={f.role === "viewer" ? "该用户只能查看勾选的项目" : "该用户可以管理和发布勾选的项目"}>
          <div className="user-project-picker">
            <label className="user-project-search"><Search /><input value={projectQuery} onChange={(event) => setProjectQuery(event.target.value)} placeholder="搜索项目名称或标识" /></label>
            <div className="user-project-options">
              {projects.filter((project) => `${project.name} ${project.slug}`.toLowerCase().includes(projectQuery.trim().toLowerCase())).map((project) => <label key={project.id} className={selectedProjects.has(project.id) ? "selected" : ""}>
                <input type="checkbox" checked={selectedProjects.has(project.id)} onChange={() => toggleProject(project.id)} />
                <span><b>{project.name}</b><small>{project.slug}</small></span>
              </label>)}
              {!projects.length && <div className="drawer-project-empty">暂无可分配项目</div>}
            </div>
            <small className="user-project-selected">已选择 {selectedProjects.size} 个项目</small>
          </div>
        </Field>}
        {editing && (
          <Field label="账号状态">
            <div className="seg">
              <button
                className={f.active ? "on" : ""}
                onClick={() => setF({ ...f, active: true })}
              >
                启用
              </button>
              <button
                className={!f.active ? "on" : ""}
                onClick={() => setF({ ...f, active: false })}
              >
                停用
              </button>
            </div>
          </Field>
        )}
      </div>
      {err && <div className="alert danger">{err}</div>}
      <div className="modal-actions">
        {editing && user.role !== "admin" && <button className="ghost danger-text" disabled={busy || deleting} onClick={() => setDeleteConfirm(true)}><Trash2 />删除账号</button>}
        <button className="ghost" onClick={onClose}>
          取消
        </button>
        <button
          className="primary"
          disabled={busy || !f.username || (!editing && f.password.length < 8)}
          onClick={submit}
        >
          {busy && <LoaderCircle className="spin" />}
          {editing ? "保存修改" : "创建用户"}
        </button>
      </div>
      {deleteConfirm && <Modal title="删除用户账号" onClose={() => setDeleteConfirm(false)}>
        <div className="delete-warning"><Trash2 /><div><b>确定删除“{user.display_name || user.username}”吗？</b><p>账号将无法登录；其创建的 {user.project_count || 0} 个项目会移交给当前管理员，项目、部署记录和运行服务不会删除。</p></div></div>
        <div className="modal-actions"><button className="ghost" onClick={() => setDeleteConfirm(false)}>取消</button><button className="danger" disabled={deleting} onClick={removeUser}>{deleting ? <LoaderCircle className="spin" /> : <Trash2 />}确认删除账号</button></div>
      </Modal>}
    </Modal>
  );
}

function SettingsPage() {
  const [tab, setTab] = useState("ai"),
    [toast, setToast] = useState(null);
  const notify = (text, type = "success") => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 5000);
  };
  const tabs = [
    ["appearance", "外观设置", Settings],
    ["ai", "AI 模型", Bot],
    ["network", "网络代理", CloudCog],
    ["deployment", "发布调度", Activity],
    ["backup", "数据备份", FileArchive],
    ["certificates", "证书管理", KeyRound],
    ["retained", "保留数据卷", Boxes],
    ["security", "安全设置", ShieldCheck],
    ["audit", "操作记录", Activity],
    ["system", "系统信息", Activity],
  ];
  return (
    <>
      <Toast toast={toast} />
      <div className="settings-shell">
        <aside className="settings-menu">
          <h3>系统设置</h3>
          {tabs.map(([id, label, Icon]) => (
            <button
              key={id}
              className={tab === id ? "active" : ""}
              onClick={() => setTab(id)}
            >
              <Icon />
              <span>{label}</span>
              <ChevronRight />
            </button>
          ))}
        </aside>
        <div className="settings-content">
          {tab === "appearance" && <AppearanceSettings notify={notify} />}
          {tab === "ai" && <AiSettingsPanel onOpenExperience={() => setTab("experience")} />}
          {tab === "network" && <ProxySettings notify={notify} />}{" "}
          {tab === "deployment" && <DeploymentSettingsPanel notify={notify} />}{" "}
          {tab === "backup" && <BackupSettings notify={notify} />}{" "}
          {tab === "certificates" && <CertificateSettings notify={notify} />}{" "}
          {tab === "retained" && <RetainedDataSettings notify={notify} />}{" "}
          {tab === "security" && <SecuritySettings />}{" "}
          {tab === "experience" && <ExperienceSettings notify={notify} />}{" "}
          {tab === "audit" && <AuditSettings />}{" "}
          {tab === "system" && <SystemInfo />}
        </div>
      </div>
    </>
  );
}

function AppearanceSettings({ notify }) {
  const [branding, setBranding] = useState(null),
    [editing, setEditing] = useState(false);
  useEffect(() => {
    api("/branding").then(setBranding).catch((error) => notify(error.message, "error"));
  }, []);
  if (!branding) return <div className="center"><LoaderCircle className="spin" /></div>;
  return (
    <>
      <div className="toolbar">
        <div><h2>外观设置</h2><p>统一管理系统名称、侧栏 Logo、登录页和浏览器图标</p></div>
        <button className="primary" onClick={() => setEditing(true)}><Settings />编辑外观</button>
      </div>
      <div className="appearance-preview-grid">
        <section className="panel appearance-sidebar-preview">
          <span>侧栏效果</span>
          <div className="appearance-brand-row">
            <BrandLogo branding={branding} />
            <div><b>{branding.short_name}</b><small>{branding.system_subtitle}</small></div>
          </div>
        </section>
        <section className="panel appearance-browser-preview">
          <span>浏览器页签</span>
          <div><img src={branding.favicon_data_url || branding.logo_data_url || defaultFavicon} alt="页签图标" /><b>{branding.system_name}</b></div>
          <small>复杂 Logo 不适合作为小图标，可单独上传 32×32 PNG 或 ICO。</small>
        </section>
        <section className="panel appearance-login-preview">
          <span>登录页文字</span>
          <b>{branding.system_name}</b>
          <small>{branding.login_slogan}</small>
        </section>
      </div>
      <div className="alert info">透明 Logo 会自动放在白色卡片中显示，避免与侧栏品牌色冲突；Logo 与页签图标相互独立。</div>
      {editing && <BrandingDialog branding={branding} onClose={() => setEditing(false)} onSaved={(value) => {
        setBranding(value);
        setEditing(false);
        window.dispatchEvent(new CustomEvent("branding-updated", { detail: value }));
        notify("平台外观已同步应用");
      }} />}
    </>
  );
}

function CertificateSettings({ notify }) {
  const [items, setItems] = useState(null);
  const [certificate, setCertificate] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(null);
  const [updating, setUpdating] = useState(null);
  const [overlap, setOverlap] = useState(null);
  const [viewingProjects, setViewingProjects] = useState(null);
  const [uploadKey, setUploadKey] = useState(0);
  const load = () => {
    setItems(null);
    api("/certificates")
      .then(setItems)
      .catch((e) => { setItems([]); notify(e.message, "error"); });
  };
  useEffect(() => { load(); }, []);
  const upload = async (choice = "check") => {
    if (!certificate || !privateKey) return notify("请选择证书文件和对应私钥", "error");
    setBusy(true);
    try {
      const body = new FormData();
      body.append("certificate", certificate);
      body.append("private_key", privateKey);
      const target = updating || (choice === "replace" ? overlap?.candidate : null);
      const path = target
        ? `/certificates/${target.id}`
        : `/certificates${choice === "add" ? "?allow_domain_overlap=true" : ""}`;
      await api(path, { method: target ? "PUT" : "POST", body });
      setCertificate(null);
      setPrivateKey(null);
      setUploadKey((value) => value + 1);
      notify(target ? `证书已更新，并同步应用到 ${target.references || 0} 个项目` : "证书已加入共享证书库，匹配的子域名将自动复用");
      setUpdating(null);
      setOverlap(null);
      load();
    } catch (e) {
      const detail = e.payload?.detail;
      if (!updating && detail?.code === "certificate_domain_overlap" && detail.candidate) {
        setOverlap(detail);
      } else {
        notify(e.message, "error");
      }
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!deleting) return;
    setBusy(true);
    try {
      await api(`/certificates/${deleting.id}`, { method: "DELETE" });
      notify("证书已删除");
      setDeleting(null);
      load();
    } catch (e) {
      notify(e.message, "error");
      setDeleting(null);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <div className="toolbar">
        <div>
          <h2>共享证书库</h2>
          <p>证书按域名自动匹配，通配符证书只需上传一次</p>
        </div>
        <button className="ghost" onClick={load}><RefreshCw />刷新</button>
      </div>
      <div className="panel certificate-upload-panel">
        <div>
          <KeyRound />
          <div><h3>{updating ? `更新证书 · ${updating.name}` : "添加证书"}</h3><p>{updating ? "证书 ID 与项目引用保持不变；校验或网关重载失败会继续使用旧证书。" : "上传 PEM/CRT 证书与对应私钥，平台会校验域名、有效期和密钥。"}</p></div>
        </div>
        <label className="compact-file-field"><span>证书文件</span><input key={`cert-${uploadKey}`} type="file" accept=".pem,.crt,.cer" onChange={(e) => setCertificate(e.target.files?.[0] || null)} /></label>
        <label className="compact-file-field"><span>私钥文件</span><input key={`key-${uploadKey}`} type="file" accept=".key,.pem" onChange={(e) => setPrivateKey(e.target.files?.[0] || null)} /></label>
        <div className="certificate-upload-actions">
          {updating && <button className="ghost" disabled={busy} onClick={() => { setUpdating(null); setCertificate(null); setPrivateKey(null); setUploadKey((value) => value + 1); }}>取消</button>}
          <button className="primary" disabled={busy || !certificate || !privateKey} onClick={upload}>{busy ? <LoaderCircle className="spin" /> : updating ? <RefreshCw /> : <Upload />}{updating ? "更新并应用" : "加入证书库"}</button>
        </div>
      </div>
      {items === null ? (
        <div className="center"><LoaderCircle className="spin" /></div>
      ) : items.length ? (
        <div className="certificate-settings-grid">
          {items.map((x) => (
            <div className="panel certificate-settings-card" key={x.id}>
              <div className="certificate-card-icon"><ShieldCheck /></div>
              <div className="certificate-card-main">
                <div className="certificate-card-title"><h3>{x.name}</h3><span className={`badge ${x.status === "expired" ? "danger" : x.status === "expiring" ? "warning" : "success"}`}><i />{x.status === "expired" ? "已过期" : x.status === "expiring" ? `${x.days_left} 天后到期` : "有效"}</span></div>
                <p title={x.domains.join("、")}>{x.domains.join("、")}</p>
                <div className="certificate-use-badges">
                  {x.references > 0 && <button type="button" className="certificate-use-badge active" onClick={() => setViewingProjects(x)}>使用中 · {x.references} 个项目 <ChevronRight /></button>}
                  {x.auto_selected && <span className="certificate-use-badge default">自动匹配</span>}
                  {!x.references && !x.auto_selected && <span className="certificate-use-badge history">历史 / 备用</span>}
                </div>
                <div className="certificate-card-meta">
                  <span>有效期至 <b>{time(x.expires_at)}</b></span>
                </div>
              </div>
              <div className="certificate-card-actions">
                <button className="ghost icon-only" disabled={busy} title="更新证书" onClick={() => { setUpdating(x); setCertificate(null); setPrivateKey(null); setUploadKey((value) => value + 1); window.scrollTo({ top: 0, behavior: "smooth" }); }}><RefreshCw /></button>
                <button className="danger-button icon-only" disabled={busy || x.references > 0} title={x.references > 0 ? "证书正在被项目使用，不能删除" : "删除证书"} onClick={() => setDeleting(x)}><Trash2 /></button>
              </div>
            </div>
          ))}
        </div>
      ) : <Empty icon={KeyRound} text="证书库为空，上传第一份证书后项目可自动匹配" />}
      {deleting && <ConfirmDialog danger title="删除证书" text={`确定删除 ${deleting.name} 吗？此操作不会影响其他证书。`} confirmText="删除证书" onClose={() => setDeleting(null)} onConfirm={remove} />}
      {overlap && <Modal title="发现同域名证书" onClose={() => setOverlap(null)}>
        <div className="confirm-body">
          <div className="confirm-icon"><RefreshCw /></div>
          <div><h4>证书库已有 {overlap.candidate.name}</h4><p>覆盖域名：{overlap.candidate.domains.join("、")}。{overlap.candidate.references > 0 ? `当前有 ${overlap.candidate.references} 个项目正在使用；` : "当前没有项目引用；"}更新当前证书会保留项目关联，另存新版本不会改变现有项目。</p></div>
        </div>
        <div className="modal-actions">
          <button className="ghost" disabled={busy} onClick={() => setOverlap(null)}>取消</button>
          <button className="ghost" disabled={busy} onClick={() => upload("add")}>另存新版本</button>
          <button className="primary" disabled={busy} onClick={() => upload("replace")}>{busy && <LoaderCircle className="spin" />}更新当前证书</button>
        </div>
      </Modal>}
      {viewingProjects && <Modal drawer closeOnMask title={`使用项目 · ${viewingProjects.name}`} onClose={() => setViewingProjects(null)}>
        <div className="drawer-summary"><span>当前实际绑定</span><b>{viewingProjects.references} 个项目</b></div>
        <div className="drawer-project-list">
          {(viewingProjects.referenced_projects || []).map((project) => <div key={project.id}>
            <div><b>{project.name}</b><small>{project.slug}</small></div>
            <span>{project.domain}</span>
          </div>)}
        </div>
      </Modal>}
    </>
  );
}

function BackupSettings({ notify }) {
  const [data, setData] = useState(null),
    [busy, setBusy] = useState(false),
    [saving, setSaving] = useState(false),
    [deleting, setDeleting] = useState(null),
    [schedule, setSchedule] = useState({
      enabled: false,
      time: "02:00",
      retention: 10,
    });
  const load = () =>
    api("/settings/backups")
      .then((x) => {
        setData(x);
        setSchedule({
          enabled: !!x.schedule?.enabled,
          time: x.schedule?.time || "02:00",
          retention: x.schedule?.retention || 10,
        });
      })
      .catch((e) => notify(e.message, "error"));
  useEffect(() => {
    load();
  }, []);
  const create = async () => {
    setBusy(true);
    try {
      await api("/settings/backups", { method: "POST" });
      notify("最小备份已创建：平台数据与项目记录已保存");
      load();
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setBusy(false);
    }
  };
  const saveSchedule = async () => {
    setSaving(true);
    try {
      await api("/settings/backups/schedule", {
        method: "PUT",
        body: JSON.stringify(schedule),
      });
      notify(schedule.enabled ? "每日自动备份设置已保存" : "自动备份已关闭");
      load();
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setSaving(false);
    }
  };
  const remove = async () => {
    try {
      await api(`/settings/backups/${encodeURIComponent(deleting.name)}`, {
        method: "DELETE",
      });
      setDeleting(null);
      notify("备份已删除");
      load();
    } catch (e) {
      notify(e.message, "error");
    }
  };
  const download = async (item) => {
    try {
      const response = await fetch(
        `/api/settings/backups/${encodeURIComponent(item.name)}/download`,
        { headers: { Authorization: `Bearer ${token()}` } },
      );
      if (!response.ok) throw new Error("备份下载失败");
      const blob = await response.blob(),
        url = URL.createObjectURL(blob),
        a = document.createElement("a");
      a.href = url;
      a.download = item.name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      notify(e.message, "error");
    }
  };
  const size = (n) =>
    n > 1073741824
      ? `${(n / 1073741824).toFixed(2)} GB`
      : n > 1048576
        ? `${(n / 1048576).toFixed(2)} MB`
        : `${(n / 1024).toFixed(1)} KB`;
  const analysis = data?.schedule?.last_analysis;
  return (
    <>
      <div className="toolbar">
        <div>
          <h2>数据备份</h2>
          <p>小体积备份平台数据、项目记录和加密配置</p>
        </div>
        <button className="primary" disabled={busy} onClick={create}>
          {busy ? <LoaderCircle className="spin" /> : <FileArchive />}
          {busy ? "AI 正在分析并备份..." : "立即创建备份"}
        </button>
      </div>
      <div className="backup-settings-grid">
        <div className="panel backup-schedule">
          <div className="backup-title">
            <FileArchive />
            <div>
              <b>自动备份</b>
              <span>按北京时间每日执行</span>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                checked={schedule.enabled}
                onChange={(e) =>
                  setSchedule({ ...schedule, enabled: e.target.checked })
                }
              />
              <span />
            </label>
          </div>
          <div className="form-grid">
            <Field label="每日执行时间">
              <input
                type="time"
                value={schedule.time}
                onChange={(e) =>
                  setSchedule({ ...schedule, time: e.target.value })
                }
              />
            </Field>
            <Field label="保留份数" hint="超出后自动删除最早的备份">
              <input
                type="number"
                min="1"
                max="100"
                value={schedule.retention}
                onChange={(e) =>
                  setSchedule({
                    ...schedule,
                    retention: Number(e.target.value),
                  })
                }
              />
            </Field>
          </div>
          <div className="settings-actions">
            <button
              className="primary"
              disabled={saving}
              onClick={saveSchedule}
            >
              {saving && <LoaderCircle className="spin" />}保存自动备份设置
            </button>
          </div>
        </div>
        <div className="panel backup-scope">
          <div className="backup-title">
            <Bot />
            <div>
              <b>AI 备份分析</b>
              <span>
                {analysis?.source === "ai"
                  ? `由 ${analysis.model} 分析`
                  : "系统安全规则"}
              </span>
            </div>
          </div>
          <p>
            {analysis?.summary ||
              "创建备份时，系统 AI 会分析源码结构并确认备份范围。"}
          </p>
          <div>
            <b>会备份</b>
            <span>平台数据库、项目/Git 记录、分析结果、配置和加密凭据</span>
          </div>
          <div>
            <b>自动排除</b>
            <span>完整源码、依赖目录、Git 历史、缓存、日志和构建产物</span>
          </div>
          <div>
            <b>暂不包含</b>
            <span>Docker 镜像、数据卷、外部数据库和部署服务器运行目录</span>
          </div>
        </div>
      </div>
      <div className="panel backup-guide">
        <ShieldCheck />
        <div>
          <b>恢复说明</b>
          <p>
            服务器密码、Git 凭据、AI Key 等保持加密状态。恢复时必须保留当前
            ENCRYPTION_KEY。Git 项目会按仓库记录重新拉取；上传项目需要重新上传原包。
          </p>
        </div>
      </div>
      {!data ? (
        <div className="center">
          <LoaderCircle className="spin" />
        </div>
      ) : data.items.length ? (
        <div className="panel">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>备份文件</th>
                  <th>创建时间</th>
                  <th>大小</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((x) => (
                  <tr key={x.name}>
                    <td>
                      <b>{x.name}</b>
                      <small>平台数据 + 项目记录（最小备份）</small>
                    </td>
                    <td>{time(x.created_at)}</td>
                    <td>{size(x.size)}</td>
                    <td>
                      <div className="record-actions">
                        <button className="ghost" onClick={() => download(x)}>
                          <FileArchive />
                          下载
                        </button>
                        <button
                          className="danger-button"
                          onClick={() => setDeleting(x)}
                        >
                          <Trash2 />
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <Empty
          icon={FileArchive}
          text="还没有备份"
          action={
            <button className="primary" onClick={create}>
              创建第一份备份
            </button>
          }
        />
      )}{" "}
      {deleting && (
        <ConfirmDialog
          danger
          title="删除备份"
          text={`确定删除 ${deleting.name} 吗？`}
          confirmText="删除备份"
          onClose={() => setDeleting(null)}
          onConfirm={remove}
        />
      )}
    </>
  );
}
function RetainedDataSettings({ notify }) {
  const [items, setItems] = useState(null),
    [deleting, setDeleting] = useState(null),
    [busy, setBusy] = useState(false);
  const load = () => {
    setItems(null);
    api("/retained-data")
      .then(setItems)
      .catch((e) => {
        setItems([]);
        notify(e.message, "error");
      });
  };
  useEffect(() => {
    load();
  }, []);
  const purge = async () => {
    setBusy(true);
    try {
      const result = await api(`/retained-data/${encodeURIComponent(deleting.id)}`, {
        method: "DELETE",
      });
      setDeleting(null);
      notify(result.summary);
      load();
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <div className="toolbar">
        <div>
          <h2>保留数据卷</h2>
          <p>查看删除项目时明确选择留下的平台 Docker 数据卷</p>
        </div>
        <button className="ghost" onClick={load}>
          <RefreshCw />
          重新核实
        </button>
      </div>
      <div className="panel security-card">
        <ShieldCheck />
        <div>
          <h3>不会包含外部数据库</h3>
          <p>
            容器、应用镜像、发布目录和网关配置会随项目删除并自动复查；这里只保留用户明确选择留下的平台
            Docker 数据卷。彻底删除前会再次连接原服务器核实。
          </p>
        </div>
      </div>
      {items === null ? (
        <div className="center">
          <LoaderCircle className="spin" />
        </div>
      ) : items.length ? (
        <div className="panel">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>原项目</th>
                  <th>服务器与数据卷</th>
                  <th>保留时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {items.map((x) => (
                  <tr key={x.id}>
                    <td>
                      <b>{x.project}</b>
                      <small>
                        {x.count} 个数据卷{x.discovered ? " · 扫描发现" : " · 删除时保留"}
                      </small>
                    </td>
                    <td>
                      {x.volumes.map((v, i) => (
                        <small key={i}>
                          {v.node} · {v.name}
                        </small>
                      ))}
                    </td>
                    <td>{x.retained_at ? time(x.retained_at) : "历史遗留"}</td>
                    <td>
                      <button
                        className="danger-button"
                        disabled={x.in_use}
                        onClick={() => setDeleting(x)}
                        title={x.in_use ? "仍被容器使用，不能删除" : ""}
                      >
                        <Trash2 />
                        {x.in_use ? "正在使用" : "彻底删除"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <Empty icon={Boxes} text="没有遗留的数据卷" />
      )}
      {deleting && (
        <ConfirmDialog
          danger
          busy={busy}
          title="彻底删除遗留数据卷"
          text={`确定删除“${deleting.project}”留下的 ${deleting.count} 个数据卷吗？`}
          description="系统会再次连接原服务器核实并删除。此操作无法恢复。"
          confirmText="核实并彻底删除"
          onClose={() => setDeleting(null)}
          onConfirm={purge}
        />
      )}
    </>
  );
}
function SecuritySettings() {
  const [settings, setSettings] = useState(null);
  const [busy, setBusy] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [editingChinaSource, setEditingChinaSource] = useState(false);
  const [notice, setNotice] = useState(null);
  const load = () => {
    setSettings(null);
    api("/settings/security")
      .then(setSettings)
      .catch((error) => setNotice({ type: "error", text: error.message }));
  };
  useEffect(load, []);
  const change = (key, value) => setSettings((current) => ({ ...current, [key]: value }));
  const save = async () => {
    setBusy(true);
    setNotice(null);
    try {
      const result = await api("/settings/security", {
        method: "PUT",
        body: JSON.stringify(settings),
      });
      setSettings(result);
      setNotice({ type: "success", text: "安全策略已保存并生效" });
    } catch (error) {
      setNotice({ type: "error", text: error.message });
      // The switch is an editable draft. If applying the gateway config fails,
      // restore the persisted value so the UI cannot claim the allowlist is
      // enabled when the backend rolled the transaction back.
      try {
        setSettings(await api("/settings/security"));
      } catch {
        // Keep the original apply error visible; a later page refresh retries.
      }
    } finally {
      setBusy(false);
    }
  };
  const updateChinaIps = async () => {
    setUpdating(true);
    setNotice(null);
    try {
      const result = await api("/settings/security/china-ip/update", { method: "POST" });
      setSettings(result);
      setNotice({ type: "success", text: `中国 IP 网段已更新，共 ${result.china_ip_count} 条` });
    } catch (error) {
      setNotice({ type: "error", text: error.message });
    } finally {
      setUpdating(false);
    }
  };
  const downloadChinaIps = async () => {
    try {
      const response = await fetch("/api/settings/security/china-ip/download", {
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (!response.ok) throw new Error("下载失败");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "blockips.conf";
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setNotice({ type: "error", text: error.message });
    }
  };
  const numberField = (key, min, max) => ({
    type: "number",
    min,
    max,
    value: settings?.[key] ?? "",
    onChange: (event) => change(key, Number(event.target.value)),
  });
  return (
    <>
      <div className="toolbar">
        <div>
          <h2>安全设置</h2>
          <p>统一管理密码、登录会话和访问来源策略</p>
        </div>
        <button className="primary" disabled={!settings || busy} onClick={save}>
          {busy ? <LoaderCircle className="spin" /> : <ShieldCheck />} 保存安全设置
        </button>
      </div>
      <div className="panel security-card security-encryption-card">
        <ShieldCheck />
        <div>
          <h3>敏感配置已加密保存</h3>
          <p>服务器密码、访问凭据、AI 密钥、环境变量和证书私钥均加密保存。恢复备份时需保留原加密密钥。</p>
        </div>
      </div>
      {notice && <div className={`settings-notice ${notice.type}`}>{notice.text}</div>}
      {!settings ? (
        <div className="panel settings-loading"><LoaderCircle className="spin" /> 正在读取安全策略…</div>
      ) : (
        <>
          <div className="security-settings-grid">
            <section className="panel security-policy-card">
              <div className="security-policy-head">
                <KeyRound />
                <div><h3>密码安全</h3><p>新建用户和修改密码时应用</p></div>
              </div>
              <div className="form-grid security-form-grid">
                <Field label="最小密码长度" hint="建议至少 10 位">
                  <input {...numberField("min_password_length", 8, 128)} />
                </Field>
                <Field label="历史密码检查" hint="0 表示不检查">
                  <input {...numberField("password_history_count", 0, 24)} />
                </Field>
                <Field label="同一字符连续次数">
                  <input {...numberField("max_repeated_chars", 1, 10)} />
                </Field>
                <Field label="密码有效期（天）" hint="0 表示长期有效">
                  <input {...numberField("password_max_age_days", 0, 3650)} />
                </Field>
              </div>
              <div className="security-check-grid">
                {[
                  ["require_lowercase", "小写字母"], ["require_uppercase", "大写字母"],
                  ["require_digit", "数字"], ["require_special", "特殊字符"],
                ].map(([key, label]) => (
                  <label className="security-check" key={key}>
                    <input type="checkbox" checked={Boolean(settings[key])} onChange={(e) => change(key, e.target.checked)} />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </section>
            <section className="panel security-policy-card">
              <div className="security-policy-head">
                <ShieldCheck />
                <div><h3>登录安全</h3><p>控制失败锁定和登录会话时长</p></div>
              </div>
              <div className="form-grid security-form-grid">
                <Field label="失败锁定次数">
                  <input {...numberField("login_max_attempts", 1, 50)} />
                </Field>
                <Field label="账号锁定时间（分钟）">
                  <input {...numberField("login_lock_minutes", 1, 1440)} />
                </Field>
                <Field label="会话超时（分钟）">
                  <input {...numberField("session_timeout_minutes", 5, 10080)} />
                </Field>
                <Field label="到期提前提醒（天）">
                  <input {...numberField("password_expiry_reminder_days", 0, 90)} />
                </Field>
              </div>
            </section>
          </div>
          <section className="panel security-policy-card audit-policy-card">
            <div className="security-policy-head">
              <Activity />
              <div><h3>审计与日志</h3><p>设置操作记录和 AI 执行记录的保存时间</p></div>
            </div>
            <div className="form-grid security-form-grid audit-policy-form">
              <Field label="审计记录保留（天）" hint="0 表示永久保留，建议保留 180 天">
                <input {...numberField("audit_retention_days", 0, 3650)} />
              </Field>
            </div>
          </section>
          <section className="panel security-policy-card china-ip-card">
            <div className="security-policy-head china-ip-head">
              <div className="security-policy-title"><Network /><div><h3>中国 IP 访问白名单</h3><p>仅允许中国公网 IP 和平台内网访问；默认关闭</p></div></div>
              <label className="toggle-row">
                <input type="checkbox" checked={Boolean(settings.china_ip_allowlist_enabled)} onChange={(e) => change("china_ip_allowlist_enabled", e.target.checked)} />
                <span>{settings.china_ip_allowlist_enabled ? "已启用" : "已停用"}</span>
              </label>
            </div>
            <div className="china-ip-content">
              <div className="china-ip-source-row">
                <div>
                  <b>网段数据源</b>
                  <p>{editingChinaSource ? "修改后保存安全设置，再更新网段" : "使用系统维护的中国公网 IP 数据源"}</p>
                </div>
                <button type="button" onClick={() => setEditingChinaSource((value) => !value)}>
                  {editingChinaSource ? "收起编辑" : "编辑数据源"}
                </button>
              </div>
              {editingChinaSource && (
                <Field label="数据源地址" hint="更新前会校验全部网段，失败不会覆盖当前网关配置">
                  <input value={settings.china_ip_source_url || ""} onChange={(e) => change("china_ip_source_url", e.target.value)} />
                </Field>
              )}
              <div className="china-ip-stats">
                <div><span>当前网段</span><b>{settings.china_ip_count || 0} 条</b></div>
                <div><span>数据更新时间</span><b>{time(settings.source_updated_at)}</b></div>
                <div><span>配置更新时间</span><b>{time(settings.updated_at)}</b></div>
              </div>
              <div className="china-ip-actions">
                <button disabled={updating} onClick={updateChinaIps}>{updating ? <LoaderCircle className="spin" /> : <RefreshCw />} 更新网段</button>
                <button onClick={downloadChinaIps}><Download /> 下载配置</button>
              </div>
            </div>
          </section>
        </>
      )}
    </>
  );
}
function AuditSettings() {
  const [items, setItems] = useState(null);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(null);
  const load = () => {
    setItems(null);
    api(`/audit${query.trim() ? `?q=${encodeURIComponent(query.trim())}` : ""}`)
      .then(setItems)
      .catch(() => setItems([]));
  };
  useEffect(() => {
    load();
  }, []);
  const labels = {
    delete_deployment: "删除发布版本",
    delete_project: "删除项目",
    delete_backup: "删除备份",
    create_backup: "创建备份",
    deploy: "创建部署",
    ai_deploy: "AI 创建部署",
    stop: "停止服务",
    start: "启动服务",
    ai_update_project_config: "AI 修改项目配置",
    scale_project: "调整运行实例",
    bulk_delete_registry_repositories: "批量清理镜像",
    delete_registry_tag: "删除镜像版本",
    cleanup_registry_now: "清理过期镜像",
    retry_deployment: "重新部署",
    restart_runtime: "重启运行服务",
    update_deployment_settings: "修改发布设置",
    update_system_proxy: "修改网络代理",
    container_file_upload: "上传容器文件",
    container_file_delete: "删除容器文件",
    container_terminal: "执行容器命令",
    configure_domain: "配置访问域名",
    update_project: "修改项目配置",
    upload_source: "更新项目源码",
    analyze_integrations: "分析服务依赖",
    ai_query_database: "AI 查询数据库",
    ai_update_database: "AI 更新数据库",
    ai_apply_migration: "AI 执行表结构",
    update_ai_experience: "调整 AI 经验",
    export_ai_experiences: "导出 AI 经验",
    update_audit_retention: "修改审计保留策略",
  };
  const targetLabels = {
    project: "项目", deployment: "发布版本", registry: "镜像仓库",
    registry_image: "镜像版本", node: "服务器", system: "系统",
    system_proxy: "网络代理", user: "用户", credential: "访问凭据",
    retained_data: "保留数据", ai_config: "AI 配置",
  };
  const detail = (x) => {
    try {
      const value = JSON.parse(x);
      if (value.sql)
        return `${value.status === "failed" ? "失败" : "成功"} · ${value.engine || "数据库"} · SQL ${value.sql}${value.error ? ` · ${value.error}` : ""}`;
      if (value.project)
        return `${value.project}${value.release ? ` · 版本 ${value.release}` : ""}${value.persistent_data ? ` · 数据${value.persistent_data === "preserved" ? "已保留" : "已删除"}` : ""}${value.managed_volumes ? ` · 托管数据卷${value.managed_volumes === "preserved" ? "已保留" : "已删除"}` : ""}`;
      return x;
    } catch {
      const raw = x || "";
      const scaled = raw.match(/replicas=(\d+)->(\d+);\s*targets=(.*)/);
      if (scaled) return `运行实例 ${scaled[1]} → ${scaled[2]} · 目标 ${scaled[3]}`;
      const cleaned = raw.match(/repositories=(\d+),removed=(\d+),protected=(\d+),failed=(\d+)/);
      if (cleaned) return `仓库 ${cleaned[1]} 个 · 删除 ${cleaned[2]} 个 · 保护 ${cleaned[3]} 个 · 失败 ${cleaned[4]} 个`;
      return raw
        .replace("current form configuration saved atomically", "当前表单配置已同步保存")
        .replace(/source updated;\s*(\d+) files;\s*kept (\d+) previous versions/, "源码已更新 · $1 个文件 · 保留 $2 个历史版本")
        || "—";
    }
  };
  return (
    <>
      <div className="toolbar">
        <div>
          <h2>操作记录</h2>
          <p>查询删除、SQL、AI 和其他关键操作；保留策略在安全设置中管理</p>
        </div>
        <button className="ghost" onClick={load}>
          <RefreshCw />
          刷新
        </button>
      </div>
      <div className="panel audit-controls">
        <div className="audit-search">
          <Search />
          <input value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} placeholder="搜索操作人、项目、动作、SQL 或结果" />
          <button className="ghost" onClick={load}>搜索</button>
        </div>
      </div>
      {items === null ? (
        <div className="center">
          <LoaderCircle className="spin" />
        </div>
      ) : (
        <div className="panel audit-panel">
          <div className="table-wrap audit-table-wrap">
            <table className="audit-table">
              <colgroup>
                <col className="audit-col-time" />
                <col className="audit-col-user" />
                <col className="audit-col-action" />
                <col className="audit-col-target" />
                <col className="audit-col-result" />
              </colgroup>
              <thead>
                <tr>
                  <th>操作时间</th>
                  <th>操作人</th>
                  <th>操作</th>
                  <th>对象</th>
                  <th>处理结果</th>
                </tr>
              </thead>
              <tbody>
                {items.map((x) => (
                  <tr key={x.id} onClick={() => setSelected(x)} className="audit-row-clickable">
                    <td className="audit-time">{time(x.created_at)}</td>
                    <td className="audit-user">
                      <b>{x.user_name}</b>
                    </td>
                    <td><span className="audit-action">{labels[x.action] || x.action}</span></td>
                    <td className="audit-target">
                      <span title={`${targetLabels[x.target_type] || x.target_type || "系统"} · ${x.target_id || "系统"}`}>
                        {targetLabels[x.target_type] || x.target_type || "系统"}
                        <small>{x.target_id?.slice(0, 8) || "系统"}</small>
                      </span>
                    </td>
                    <td>
                      <small className="audit-detail" title={detail(x.detail)}>{detail(x.detail)}</small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {selected && (
        <Modal title="操作记录详情" onClose={() => setSelected(null)} wide>
          <div className="audit-detail-modal">
            <div><b>{labels[selected.action] || selected.action}</b><span>{time(selected.created_at)} · {selected.user_name}</span></div>
            <pre>{(() => { try { return JSON.stringify(JSON.parse(selected.detail), null, 2); } catch { return selected.detail || "—"; } })()}</pre>
          </div>
        </Modal>
      )}
    </>
  );
}

function ExperienceSettings({ notify }) {
  const [data, setData] = useState(null);
  const [query, setQuery] = useState("");
  const [state, setState] = useState("");
  const [selected, setSelected] = useState(null);
  const stateLabels = { candidate: "候选", verified: "已验证", deprecated: "已停用", quarantined: "已隔离" };
  const stageLabels = { analysis: "源码分析", deployment: "构建部署", verification: "启动验证", gateway: "网关访问", data: "数据服务" };
  const categoryLabels = {
    unknown: "平台内部异常（不参与学习）",
    healthcheck: "健康检查",
    startup: "启动异常",
    network: "网络连接",
    gateway: "网关路由",
    build: "构建异常",
    dependency: "依赖安装",
    database: "数据服务",
  };
  const categoryLabel = (value) => categoryLabels[String(value || "").toLowerCase()]
    || String(value || "自动分类").replaceAll("_", " · ");
  const load = async () => {
    try {
      const params = new URLSearchParams();
      if (query.trim()) params.set("q", query.trim());
      if (state) params.set("state", state);
      setData(await api(`/ai-experiences${params.toString() ? `?${params}` : ""}`));
    } catch (error) {
      notify(error.message, "error");
      setData({ summary: {}, items: [] });
    }
  };
  useEffect(() => { load(); }, [state]);
  const exportAll = async () => {
    try {
      const response = await fetch("/api/ai-experiences/export", { headers: { Authorization: `Bearer ${token()}` } });
      if (!response.ok) throw new Error("经验导出失败");
      const link = document.createElement("a");
      link.href = URL.createObjectURL(await response.blob());
      link.download = "deployment-experiences.json";
      link.click();
      URL.revokeObjectURL(link.href);
      notify("经验包已导出");
    } catch (error) { notify(error.message, "error"); }
  };
  const summary = data?.summary || {};
  return (
    <>
      <div className="toolbar">
        <div><h2>AI 学习详情</h2><p>系统自动采集、验证、降级和隔离；这里仅用于高级审计</p></div>
        <div className="toolbar-actions"><button className="ghost" onClick={load}><RefreshCw />刷新</button><button className="primary" onClick={exportAll}><Download />导出经验包</button></div>
      </div>
      <div className="experience-summary">
        <div><span>全部经验</span><b>{summary.total ?? "—"}</b></div>
        <div className="success"><span>已验证</span><b>{summary.verified ?? "—"}</b></div>
        <div><span>候选反例</span><b>{summary.candidate ?? "—"}</b></div>
        <div className="warning"><span>停用 / 隔离</span><b>{summary.disabled ?? "—"}</b></div>
      </div>
      <div className="panel experience-controls">
        <div className="audit-search"><Search /><input value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => event.key === "Enter" && load()} placeholder="搜索错误、修复方法、技术栈或阶段" /><button className="ghost" onClick={load}>搜索</button></div>
        <select value={state} onChange={(event) => setState(event.target.value)}><option value="">全部状态</option><option value="verified">已验证</option><option value="candidate">候选</option><option value="deprecated">已停用</option><option value="quarantined">已隔离</option></select>
      </div>
      {!data ? <div className="center"><LoaderCircle className="spin" /></div> : (
        <div className="experience-list">
          {data.items.map((item) => (
            <article key={item.id} className={`panel experience-card ${!item.enabled ? "disabled" : ""}`}>
              <button className="experience-main" onClick={() => setSelected(item)}>
                <div className="experience-title"><b>{categoryLabel(item.category)}</b><span className={`experience-state ${item.state}`}>{stateLabels[item.state] || item.state}</span><span>{stageLabels[item.stage] || item.stage}</span></div>
                <p>{item.error_sample || "未记录错误样本"}</p>
                <div className="experience-meta"><span>可信度 {item.confidence}%</span><span>出现 {item.occurrences} 次</span><span>成功 {item.successful_repairs}</span><span>失败 {item.failed_repairs}</span><span>被引用 {item.use_count || 0}</span></div>
                {!!item.scope_tags?.length && <div className="experience-tags">{item.scope_tags.map((tag) => <em key={tag}>{tag}</em>)}</div>}
              </button>
            </article>
          ))}
          {!data.items.length && <div className="panel empty">没有符合条件的经验</div>}
        </div>
      )}
      {selected && <Modal title="AI 经验详情" onClose={() => setSelected(null)} wide><div className="experience-detail"><div className="experience-detail-head"><b>{categoryLabel(selected.category)}</b><span className={`experience-state ${selected.state}`}>{stateLabels[selected.state] || selected.state}</span></div><section><span>错误特征</span><pre>{selected.error_sample || "—"}</pre></section><section><span>修复与验证结论</span><pre>{selected.repair_summary || "尚未形成已验证修复结论"}</pre></section><div className="experience-meta"><span>阶段：{stageLabels[selected.stage] || selected.stage}</span><span>可信度：{selected.confidence}%</span><span>最后验证：{selected.last_verified_at ? time(selected.last_verified_at) : "未验证"}</span><span>最后引用：{selected.last_used_at ? time(selected.last_used_at) : "未引用"}</span></div></div></Modal>}
    </>
  );
}
function DeploymentSettingsPanel({ notify }) {
  const [form, setForm] = useState(null),
    [gatewayPorts, setGatewayPorts] = useState([]),
    [saving, setSaving] = useState(false),
    [registrySaving, setRegistrySaving] = useState(false);
  useEffect(() => {
    Promise.all([api("/settings/deployment"), api("/settings/deployment/gateway-ports")])
      .then(([settings, ports]) => {
        setForm(settings);
        setGatewayPorts(ports.items || []);
      })
      .catch((e) => notify(e.message, "error"));
  }, []);
  const save = async () => {
    setSaving(true);
    try {
      const data = await api("/settings/deployment", {
        method: "PUT",
        body: JSON.stringify(form),
      });
      setForm(data);
      notify("发布调度设置已保存");
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setSaving(false);
    }
  };
  const saveRegistry = async (cleanup = false) => {
    setRegistrySaving(true);
    try {
      const data = await api("/settings/deployment", {
        method: "PUT",
        body: JSON.stringify(form),
      });
      setForm(data);
      if (cleanup) {
        const result = await api("/settings/deployment/cleanup-registry", { method: "POST" });
        notify(result.message || "镜像仓库已按新策略清理");
      } else {
        notify("镜像仓库设置已保存");
      }
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setRegistrySaving(false);
    }
  };
  if (!form)
    return (
      <div className="center">
        <LoaderCircle className="spin" />
      </div>
    );
  return (
    <>
      <div className="toolbar">
        <div>
          <h2>发布调度</h2>
          <p>控制多项目同时发布，服务器离线时快速返回</p>
        </div>
      </div>
      <div className="panel deployment-settings-card">
        <div className="settings-sections">
          <section className="settings-section">
            <header>
              <div className="settings-section-icon"><Boxes /></div>
              <div>
                <h3>镜像仓库</h3>
                <p>新版本成功入库后自动清理旧标签，当前运行版本始终保留。</p>
              </div>
            </header>
            <div className="form-grid settings-fields">
              <Field label="仓库访问地址" hint="节点使用该地址推送和拉取">
                <input value={form.registry_endpoint ?? "yunzhou.hub:5000"}
                  onChange={(e) => setForm({ ...form, registry_endpoint: e.target.value })} />
              </Field>
              <Field label="资源命名空间" hint="统一命名镜像、容器、网络和数据卷">
                <input value={form.registry_namespace ?? "yunzhou"}
                  onChange={(e) => setForm({ ...form, registry_namespace: e.target.value.toLowerCase() })} />
              </Field>
              <Field label="每个仓库保留版本数" hint="默认保留最近 5 个版本">
                <input type="number" min="1" max="100" value={form.registry_retention_count ?? 5}
                  onChange={(e) => setForm({ ...form, registry_retention_count: Number(e.target.value) })} />
              </Field>
              <Field label="自动清理" hint="关闭后仓库将永久保留全部版本">
                <label className="switch-line">
                  <input type="checkbox" checked={form.registry_auto_cleanup ?? true}
                    onChange={(e) => setForm({ ...form, registry_auto_cleanup: e.target.checked })} />
                  <span>{(form.registry_auto_cleanup ?? true) ? "已开启" : "已关闭"}</span>
                </label>
              </Field>
            </div>
            <div className="settings-actions section-actions">
              <button className="ghost" disabled={registrySaving} onClick={() => saveRegistry(false)}>
                {registrySaving && <LoaderCircle className="spin" />}保存仓库设置
              </button>
              <button className="primary" disabled={registrySaving || !form.registry_auto_cleanup} onClick={() => saveRegistry(true)}>
                {registrySaving ? <LoaderCircle className="spin" /> : <Trash2 />}保存并立即清理
              </button>
            </div>
          </section>
          <section className="settings-section cache-settings-section">
            <header>
              <div className="settings-section-icon violet"><Server /></div>
              <div>
                <h3>运行服务推荐版本</h3>
                <p>源码没有明确版本时使用；外置服务和已经运行的项目不受影响。</p>
              </div>
            </header>
            <div className="form-grid settings-fields">
              <Field label="Nginx" hint="静态站点与项目内网关">
                <input value={form.default_nginx_image ?? "nginx:1.30.3-alpine"}
                  onChange={(e) => setForm({ ...form, default_nginx_image: e.target.value })} />
              </Field>
              <Field label="Redis" hint="源码未指定版本时使用">
                <input value={form.default_redis_image ?? "redis:7.4-alpine"}
                  onChange={(e) => setForm({ ...form, default_redis_image: e.target.value })} />
              </Field>
              <Field label="MySQL" hint="仅用于新建的托管数据库">
                <input value={form.default_mysql_image ?? "mysql:8.4"}
                  onChange={(e) => setForm({ ...form, default_mysql_image: e.target.value })} />
              </Field>
              <Field label="PostgreSQL" hint="仅用于新建的托管数据库">
                <input value={form.default_postgres_image ?? "postgres:16"}
                  onChange={(e) => setForm({ ...form, default_postgres_image: e.target.value })} />
              </Field>
            </div>
          </section>
          <section className="settings-section cache-settings-section">
            <header>
              <div className="settings-section-icon violet"><Database /></div>
              <div>
                <h3>构建依赖缓存</h3>
                <p>平台统一挂载这些目录；修改仅影响后续发布，不会移动或清理现有缓存。</p>
              </div>
            </header>
            <div className="form-grid settings-fields cache-settings-fields">
              <Field label="构建服务器缓存根目录" hint="各工具缓存按 maven、gradle、npm 等子目录保存">
                <input value={form.build_cache_root ?? "/data/yunzhou/builder/cache"}
                  onChange={(e) => setForm({ ...form, build_cache_root: e.target.value })} />
              </Field>
              <Field label="Maven 容器目录" hint="Maven 标准本地仓库">
                <input value={form.maven_cache_dir ?? "/root/.m2"}
                  onChange={(e) => setForm({ ...form, maven_cache_dir: e.target.value })} />
              </Field>
              <Field label="Gradle 容器目录" hint="官方 Gradle 镜像的标准用户目录">
                <input value={form.gradle_cache_dir ?? "/home/gradle/.gradle"}
                  onChange={(e) => setForm({ ...form, gradle_cache_dir: e.target.value })} />
              </Field>
              <Field label="npm 容器目录" hint="npm 下载缓存">
                <input value={form.npm_cache_dir ?? "/root/.npm"}
                  onChange={(e) => setForm({ ...form, npm_cache_dir: e.target.value })} />
              </Field>
              <Field label="pnpm 容器目录" hint="强制 pnpm 使用该 Store，防止仓库配置绕过缓存">
                <input value={form.pnpm_cache_dir ?? "/root/.local/share/pnpm/store"}
                  onChange={(e) => setForm({ ...form, pnpm_cache_dir: e.target.value })} />
              </Field>
              <Field label="Yarn 容器目录" hint="Yarn 下载缓存">
                <input value={form.yarn_cache_dir ?? "/root/.cache/yarn"}
                  onChange={(e) => setForm({ ...form, yarn_cache_dir: e.target.value })} />
              </Field>
              <Field label="pip 容器目录" hint="Python pip 下载缓存">
                <input value={form.pip_cache_dir ?? "/root/.cache/pip"}
                  onChange={(e) => setForm({ ...form, pip_cache_dir: e.target.value })} />
              </Field>
            </div>
          </section>
          <section className="settings-section">
            <header>
              <div className="settings-section-icon">
                <Activity />
              </div>
              <div>
                <h3>任务并发与连接</h3>
                <p>控制同时发布数量，以及离线服务器的快速返回时间。</p>
              </div>
            </header>
            <div className="form-grid settings-fields">
          <Field label="全局同时发布数" hint="整个平台最多同时执行的发布任务">
            <input
              type="number"
              min="1"
              max="20"
              value={form.global_concurrency}
              onChange={(e) =>
                setForm({ ...form, global_concurrency: Number(e.target.value) })
              }
            />
          </Field>
          <Field
            label="同一服务器同时发布数"
            hint="同一节点也可并发，建议 2 个"
          >
            <input
              type="number"
              min="1"
              max="10"
              value={form.per_node_concurrency}
              onChange={(e) =>
                setForm({
                  ...form,
                  per_node_concurrency: Number(e.target.value),
                })
              }
            />
          </Field>
          <Field label="源码分析并发数" hint="同时拉取并分析的项目数，建议 2 个">
            <input
              type="number"
              min="1"
              max="8"
              value={form.analysis_concurrency ?? 2}
              onChange={(e) =>
                setForm({ ...form, analysis_concurrency: Number(e.target.value) })
              }
            />
          </Field>
          <Field label="服务器连接超时（秒）" hint="连不上时不进入队列">
            <input
              type="number"
              min="2"
              max="30"
              value={form.connection_timeout_seconds}
              onChange={(e) =>
                setForm({
                  ...form,
                  connection_timeout_seconds: Number(e.target.value),
                })
              }
            />
          </Field>
            </div>
          </section>
          <section className="settings-section">
            <header>
              <div className="settings-section-icon"><Server /></div>
              <div>
                <h3>内网实例端口</h3>
                <p>仅用于目标服务器上的应用实例，由网关访问，不作为公网入口。</p>
              </div>
            </header>
            <div className="form-grid settings-fields">
              <Field label="实例端口起始值" hint="默认 30000，与公网网关端口隔离">
                <PortInput min="1024" max="65535" value={form.internal_port_start}
                  onChange={(e) => setForm({ ...form, internal_port_start: Number(e.target.value) })} />
              </Field>
              <Field label="实例端口结束值" hint="默认 39999；防火墙建议只允许平台网关访问">
                <PortInput min="1024" max="65535" value={form.internal_port_end}
                  onChange={(e) => setForm({ ...form, internal_port_end: Number(e.target.value) })} />
              </Field>
            </div>
          </section>
          <section className="settings-section">
            <header>
              <div className="settings-section-icon violet">
                <Network />
              </div>
              <div>
                <h3>公网端口与域名入口</h3>
                <p>网关端口用于无域名访问；HTTP/HTTPS 端口用于域名接入。</p>
              </div>
            </header>
            <div className="form-grid settings-fields">
          <Field
            label="Nginx 网关端口起始值"
            hint="仅用于公网入口，项目内网端口不受限制"
          >
            <PortInput
              min="1024"
              max="65535"
              value={form.external_port_start}
              onChange={(e) =>
                setForm({
                  ...form,
                  external_port_start: Number(e.target.value),
                })
              }
            />
          </Field>
          <Field
            label="Nginx 网关端口结束值"
            hint={`默认 20000–21000；${form.default_domain_http_port}/${form.default_domain_https_port} 保留给域名`}
          >
            <PortInput
              min="1024"
              max="65535"
              value={form.external_port_end}
              onChange={(e) =>
                setForm({ ...form, external_port_end: Number(e.target.value) })
              }
            />
          </Field>
          <Field label="域名默认 HTTP 端口" hint="通常为 80，可以修改">
            <PortInput
              min="1"
              max="65535"
              value={form.default_domain_http_port}
              onChange={(e) =>
                setForm({
                  ...form,
                  default_domain_http_port: Number(e.target.value),
                })
              }
            />
          </Field>
          <Field label="域名默认 HTTPS 端口" hint="通常为 443，可以修改">
            <PortInput
              min="1"
              max="65535"
              value={form.default_domain_https_port}
              onChange={(e) =>
                setForm({
                  ...form,
                  default_domain_https_port: Number(e.target.value),
                })
              }
            />
          </Field>
          <div className="gateway-port-usage">
            <div className="gateway-port-usage-head">
              <div><b>当前已使用端口</b><span>按端口从小到大排列</span></div>
              <em>{gatewayPorts.length} 个</em>
            </div>
            {gatewayPorts.length ? (
              <div className="gateway-port-usage-list">
                {gatewayPorts.map((item) => (
                  <div className="gateway-port-usage-row" key={`${item.port}-${item.project_id}`}>
                    <strong>{item.port}</strong>
                    <span title={item.project_name}>{item.project_name}</span>
                    <small>{item.node_name}</small>
                    <i className={item.status === "active" ? "active" : "reserved"}>{item.status === "active" ? "使用中" : "已预留"}</i>
                  </div>
                ))}
              </div>
            ) : <p className="gateway-port-usage-empty">当前端口范围内暂无项目占用</p>}
          </div>
            </div>
          </section>
        </div>
        <div className="settings-actions">
          <button className="primary" disabled={saving} onClick={save}>
            {saving && <LoaderCircle className="spin" />}保存发布参数
          </button>
        </div>
      </div>
      <div className="panel backup-guide">
        <Activity />
        <div>
          <b>并发安全</b>
          <p>
            每次发布使用独立版本目录、端口和 Compose
            项目名。同一服务器可并行构建；数据库和数据卷仍按项目隔离。
          </p>
        </div>
      </div>
    </>
  );
}
function SystemInfo() {
  return (
    <>
      <div className="toolbar">
        <div>
          <h2>系统信息</h2>
          <p>当前平台组件和运行方式</p>
        </div>
      </div>
      <div className="panel detail-list">
        <div>
          <span>平台名称</span>
          <b>自助发布平台</b>
        </div>
        <div>
          <span>运行组件</span>
          <b>Web、API、Worker、PostgreSQL、Nginx 网关</b>
        </div>
        <div>
          <span>备份内容</span>
          <b>数据库与上传源码</b>
        </div>
        <div>
          <span>系统状态</span>
          <b>运行正常</b>
        </div>
      </div>
    </>
  );
}

function AiSettingsPanel({ onOpenExperience }) {
  const blank = {
    provider_name: "",
    base_url: "https://api.openai.com/v1",
    model: "",
    api_key: "",
    enabled: true,
  };
  const [items, setItems] = useState(null),
    [loadError, setLoadError] = useState(""),
    [editing, setEditing] = useState(null),
    [show, setShow] = useState(false),
    [toast, setToast] = useState(null),
    [learning, setLearning] = useState(null),
    [deleting, setDeleting] = useState(null);
  const load = () => {
    setLoadError("");
    return api("/settings/ai/configs")
      .then(setItems)
      .catch((e) => setLoadError(e.message));
  };
  useEffect(() => {
    load();
    api("/ai-experiences").then((result) => setLearning(result.summary)).catch(() => setLearning({}));
  }, []);
  const notify = (text, type = "success") => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 3000);
  };
  const remove = async (x) => {
    try {
      await api(`/settings/ai/configs/${x.id}`, { method: "DELETE" });
      setDeleting(null);
      notify("AI 配置已删除");
      load();
    } catch (e) {
      setDeleting(null);
      notify(e.message, "error");
    }
  };
  const makeDefault = async (x) => {
    try {
      const selected = await api(`/settings/ai/configs/${x.id}/default`, { method: "POST" });
      setItems((current) => (current || [])
        .map((item) => ({ ...item, is_default: item.id === selected.id }))
        .sort((a, b) => Number(b.is_default) - Number(a.is_default)));
      notify(`已将“${selected.provider_name} · ${selected.model}”设为默认模型`);
      await load();
    } catch (e) {
      notify(e.message, "error");
    }
  };
  return (
    <>
      <Toast toast={toast} />
      <div className="toolbar">
        <div>
          <h2>AI 模型配置</h2>
          <p>后台分析与部署使用默认模型；每个对话仍可单独选择其他已启用模型</p>
        </div>
        <button className="primary" onClick={() => setShow(true)}>
          <Plus />
          添加 AI
        </button>
      </div>
      {items === null && !loadError ? (
        <Empty icon={LoaderCircle} text="正在读取 AI 配置..." />
      ) : loadError ? (
        <Empty
          icon={Activity}
          text={`AI 配置读取失败：${loadError}`}
          action={
            <button className="ghost" onClick={load}>
              <RefreshCw />
              重新读取
            </button>
          }
        />
      ) : (
        <>
          <div className="ai-config-grid">
            {items.map((x) => (
              <div className="panel ai-config-card" key={x.id}>
                <div className="ai-card-top">
                  <div className="stat-icon violet">
                    <Bot />
                  </div>
                  <div className="ai-card-badges">
                    {x.is_default && <span className="badge default"><Star />默认模型</span>}
                    {!x.is_default && x.enabled && (
                      <button
                        className="ai-default-action"
                        onClick={() => makeDefault(x)}
                        title="将此模型设为后台分析与部署的默认模型"
                      >
                        <Star />设为默认
                      </button>
                    )}
                    <span className={"badge " + (x.enabled ? "success" : "muted")}>
                      <i />{x.enabled ? "已启用" : "已停用"}
                    </span>
                  </div>
                </div>
                <h3>{x.provider_name}</h3>
                <p>{x.model}</p>
                <div className="ai-config-info">
                  <span>接口地址</span>
                  <b>{x.base_url}</b>
                  <span>API Key</span>
                  <b>{x.has_api_key ? "已加密保存" : "未配置"}</b>
                </div>
                <div className="node-actions">
                  <button className="ghost" onClick={() => setEditing(x)}>
                    <Settings />
                    编辑
                  </button>
                  <button
                    className="ghost"
                    onClick={() => setEditing({ ...x, testNow: true })}
                  >
                    <Activity />
                    测试
                  </button>
                  <button
                    className="danger-button"
                    disabled={x.is_default}
                    title={x.is_default ? "请先将其他模型设为默认" : "删除配置"}
                    onClick={() => setDeleting(x)}
                  >
                    <X />
                    删除
                  </button>
                </div>
              </div>
            ))}
          </div>
          {!items.length && (
            <Empty
              icon={Bot}
              text="还没有 AI 配置"
              action={
                <button className="primary" onClick={() => setShow(true)}>
                  <Plus />
                  添加第一个 AI
                </button>
              }
            />
          )}
        </>
      )}
      <div className="panel ai-learning-card">
        <div className="ai-learning-icon"><Bot /></div>
        <div className="ai-learning-copy">
          <h3>自动经验学习</h3>
          <p>平台会根据真实发布结果自动验证、降级和隔离经验，无需日常人工维护。</p>
        </div>
        <div className="ai-learning-stats">
          <span><b>{learning?.verified ?? "—"}</b>已验证</span>
          <span><b>{learning?.candidate ?? "—"}</b>观察中</span>
          <span><b>{learning?.disabled ?? "—"}</b>已隔离</span>
        </div>
        <button className="ghost" onClick={onOpenExperience}>查看学习详情 <ChevronRight /></button>
      </div>
      <div className="panel security-card multi-ai-security">
        <ShieldCheck />
        <div>
          <h3>受控执行</h3>
          <p>
            用户可以选择 AI 模型，但 AI
            仍然只能调用发布、停止和查看状态等预定义动作。
          </p>
        </div>
      </div>
      {show && (
        <AiConfigModal
          initial={blank}
          notify={notify}
          onClose={() => setShow(false)}
          onDone={() => {
            setShow(false);
            load();
          }}
        />
      )}
      {editing && (
        <AiConfigModal
          initial={editing}
          configId={editing.id}
          autoTest={editing.testNow}
          notify={notify}
          onClose={() => setEditing(null)}
          onDone={() => {
            setEditing(null);
            load();
          }}
        />
      )}
      {deleting && (
        <ConfirmDialog
          danger
          title="删除 AI 配置"
          text={`确定删除“${deleting.provider_name}”吗？`}
          confirmText="删除配置"
          onClose={() => setDeleting(null)}
          onConfirm={() => remove(deleting)}
        />
      )}
    </>
  );
}
function ProxySettings({ notify }) {
  const [f, setF] = useState(null),
    [loadError, setLoadError] = useState(""),
    [busy, setBusy] = useState(false),
    [testing, setTesting] = useState(false);
  const load = () => {
    setLoadError("");
    api("/settings/proxy")
      .then(setF)
      .catch((e) => setLoadError(e.message));
  };
  useEffect(load, []);
  const save = async () => {
    setBusy(true);
    try {
      const r = await api("/settings/proxy", {
        method: "PUT",
        body: JSON.stringify(f),
      });
      setF(r);
      notify(r.enabled ? "应用网络代理已启用" : "应用网络代理已关闭");
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setBusy(false);
    }
  };
  const test = async () => {
    setTesting(true);
    try {
      const r = await api("/settings/proxy/test", {
        method: "POST",
        body: JSON.stringify(f),
      });
      notify(
        `${r.message} · ${r.detail} · HTTP ${r.status_code} · ${r.latency_ms}ms`,
        r.severity || (r.ok ? "success" : "warning"),
      );
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setTesting(false);
    }
  };
  if (!f)
    return (
      <div className="panel proxy-settings">
        <div className="panel-head">
          <div>
            <h3>
              <CloudCog /> 应用网络代理
            </h3>
            <p>
              {loadError ? `配置读取失败：${loadError}` : "正在读取代理配置..."}
            </p>
          </div>
          {loadError ? (
            <button className="ghost" onClick={load}>
              <RefreshCw />
              重新读取
            </button>
          ) : (
            <LoaderCircle className="spin" />
          )}
        </div>
      </div>
    );
  return (
    <div className="panel proxy-settings">
      <div className="panel-head">
        <div>
          <h3>
            <CloudCog /> 应用网络代理
          </h3>
          <p>可选配置，仅用于 AI、Git 等应用请求</p>
        </div>
        <label className="switch">
          <input
            type="checkbox"
            checked={f.enabled}
            onChange={(e) => setF({ ...f, enabled: e.target.checked })}
          />
          <span />
        </label>
      </div>
      <div className="proxy-state">
        <span className={"badge " + (f.enabled ? "success" : "muted")}>
          <i />
          {f.enabled
            ? "已启用，应用请求通过代理"
            : "未启用，应用请求走服务器直连"}
        </span>
        <small>配置来源：系统数据库</small>
      </div>
      {!f.enabled && (f.http_proxy || f.https_proxy) && (
        <div className="proxy-warning">
          已填写代理地址，但开关尚未启用。下方“测试代理地址”只验证代理是否可用，不会改变启用状态。
        </div>
      )}
      <div className="form-grid proxy-form-grid">
        <Field label="HTTP 请求代理" hint="示例：http://192.168.1.10:3128">
          <input
            placeholder="未配置"
            value={f.http_proxy}
            onChange={(e) => setF({ ...f, http_proxy: e.target.value })}
          />
        </Field>
        <Field
          label="HTTPS 请求代理"
          hint="普通 HTTP CONNECT 代理也填写 http://，这是正常格式"
        >
          <input
            placeholder="未配置时自动使用 HTTP 请求代理"
            value={f.https_proxy}
            onChange={(e) => setF({ ...f, https_proxy: e.target.value })}
          />
        </Field>
        <Field label="不使用代理的地址" className="proxy-no-proxy">
          <textarea
            value={f.no_proxy}
            onChange={(e) => setF({ ...f, no_proxy: e.target.value })}
          />
        </Field>
        <div className="docker-proxy-note">
          <Boxes />
          <div>
            <b>Docker 镜像代理独立管理</b>
            <p>
              Docker 服务代理只负责拉取和构建镜像，不影响这里的应用网络代理。
            </p>
          </div>
        </div>
      </div>
      <div className="settings-actions">
        <button
          className="ghost"
          disabled={testing || !(f.http_proxy || f.https_proxy)}
          onClick={test}
        >
          {testing ? <LoaderCircle className="spin" /> : <Activity />}
          测试代理地址
        </button>
        <button className="primary" disabled={busy} onClick={save}>
          {busy && <LoaderCircle className="spin" />}
          {f.enabled ? "保存并启用代理" : "保存，保持直连"}
        </button>
      </div>
    </div>
  );
}

function AiConfigModal({
  initial,
  configId,
  autoTest,
  onClose,
  onDone,
  notify,
}) {
  const [showRoute, setShowRoute] = useState(false);
  const [f, setF] = useState({
      provider_name: initial.provider_name || "",
      base_url: initial.base_url || "",
      model: initial.model || "",
      api_key: "",
      enabled: initial.enabled !== false,
    }),
    [busy, setBusy] = useState(false),
    [testing, setTesting] = useState(false),
    [tested, setTested] = useState(false),
    [route, setRoute] = useState(null),
    [err, setErr] = useState("");
  const test = async () => {
    setTesting(true);
    setErr("");
    setRoute(null);
    try {
      const r = await api(
        `/settings/ai/test${configId ? `?config_id=${configId}` : ""}`,
        { method: "POST", body: JSON.stringify(f) },
      );
      setTested(true);
      setRoute(r);
      notify(
        `连接成功：${r.network_route === "proxy" ? "通过应用代理" : "服务器直连"} · ${r.latency_ms}ms · ${r.trace_code}`,
      );
    } catch (e) {
      setTested(false);
      notify(e.message, "error");
    } finally {
      setTesting(false);
    }
  };
  useEffect(() => {
    if (autoTest) test();
  }, []);
  const save = async () => {
    setBusy(true);
    setErr("");
    try {
      await api(
        configId ? `/settings/ai/configs/${configId}` : "/settings/ai/configs",
        { method: configId ? "PATCH" : "POST", body: JSON.stringify(f) },
      );
      notify(configId ? "AI 配置已更新" : "AI 配置已添加");
      onDone();
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Modal
        title={configId ? "编辑 AI 配置" : "添加 AI 配置"}
        onClose={onClose}
      >
        <div className="form-grid one">
          <Field label="配置名称">
            <input
              placeholder="例如：内部 GPT"
              value={f.provider_name}
              onChange={(e) => setF({ ...f, provider_name: e.target.value })}
            />
          </Field>
          <Field label="接口地址">
            <input
              placeholder="https://example.com/v1"
              value={f.base_url}
              onChange={(e) => setF({ ...f, base_url: e.target.value })}
            />
          </Field>
          <Field label="模型名称">
            <input
              placeholder="gpt-6-luna"
              value={f.model}
              onChange={(e) => setF({ ...f, model: e.target.value })}
            />
          </Field>
          <Field
            label="API Key"
            hint={configId ? "留空表示使用已保存的密钥" : "密钥将加密保存"}
          >
            <input
              type="password"
              placeholder={configId ? "无需修改可留空" : "sk-..."}
              value={f.api_key}
              onChange={(e) => setF({ ...f, api_key: e.target.value })}
            />
          </Field>
          <Field label="启用状态">
            <div className="seg">
              <button
                className={f.enabled ? "on" : ""}
                onClick={() => setF({ ...f, enabled: true })}
              >
                启用
              </button>
              <button
                className={!f.enabled ? "on" : ""}
                onClick={() => setF({ ...f, enabled: false })}
              >
                停用
              </button>
            </div>
          </Field>
        </div>
        {route && (
          <div className="route-result">
            <div>
              <b>连接测试通过</b>
              <span>
                {route.network_route === "proxy"
                  ? "通过应用代理"
                  : "服务器直连"}{" "}
                · {route.latency_ms} ms · {route.trace_code}
              </span>
            </div>
            <button className="ghost" onClick={() => setShowRoute(true)}>
              查看路由详情
              <ChevronRight />
            </button>
          </div>
        )}
        {tested && !route && <div className="alert info">连接测试已经通过</div>}
        {err && <div className="alert danger">{err}</div>}
        <div className="modal-actions">
          <button className="ghost" onClick={onClose}>
            取消
          </button>
          <button
            className="ghost"
            disabled={testing || !f.base_url || !f.model}
            onClick={test}
          >
            {testing ? <LoaderCircle className="spin" /> : <Activity />}测试连接
          </button>
          <button
            className="primary"
            disabled={
              busy ||
              !f.provider_name ||
              !f.base_url ||
              !f.model ||
              (!configId && !f.api_key)
            }
            onClick={save}
          >
            {busy && <LoaderCircle className="spin" />}保存配置
          </button>
        </div>
      </Modal>
      {showRoute && route && (
        <NetworkRouteDialog route={route} onClose={() => setShowRoute(false)} />
      )}
    </>
  );
}

function Loader() {
  return (
    <div className="center">
      <LoaderCircle className="spin" />
    </div>
  );
}
createRoot(document.getElementById("root")).render(<App />);
