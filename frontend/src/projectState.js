const sourcePhaseText = {
  queued: "等待处理",
  pulling: "正在拉取源码",
  analyzing: "正在分析源码",
  preflight: "正在预演校验",
  completed: "分析完成",
  failed: "处理失败",
  ready: "源码已保存",
};

export function projectSourceState(project) {
  const analysis = project?.source_analysis || {};
  const phase = analysis.phase || analysis.status || "ready";
  return { ...analysis, phase, label: sourcePhaseText[phase] || "准备源码" };
}

export function projectAnalysisFacts(project) {
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
      analysis.preflight?.status === "passed" ? "静态预演通过" : analysis.preflight?.status === "needs_configuration" ? "静态预演待配置" : analysis.preflight ? "静态预演失败" : "尚未预演",
    ].filter(Boolean),
    services: (analysis.services || []).join(" · "),
  };
}

export function projectCardState(project, deployments, startingIds = new Set()) {
  const source = projectSourceState(project);
  const records = deployments.filter((item) => item.project_id === project.id).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  const starting = records.find((item) => startingIds.has(item.id));
  if (starting) return { kind: "working", label: "启动中", action: "启动中", deployment: starting };
  const pending = records.find((item) => ["queued", "running"].includes(item.status));
  const active = records.find((item) => item.status === "success");
  const sourceWorking = ["queued", "pulling", "analyzing", "preflight", "running"].includes(source.phase);
  if (sourceWorking && active) return { kind: "online", label: "运行中", secondaryLabel: "新版分析中", secondaryKind: "working", action: "访问", deployment: active };
  if (source.phase === "failed" && active) return { kind: "online", label: "运行中", secondaryLabel: "新版分析失败", secondaryKind: "error", secondaryAction: "查看原因", action: "访问", deployment: active };
  if (sourceWorking) return { kind: "working", label: source.label, action: "查看进度" };
  if (pending && active) return { kind: "online", label: "运行中", secondaryLabel: pending.status === "queued" ? "新版等待" : `新版 ${Number(pending.progress || 0)}%`, secondaryKind: "working", action: "访问", deployment: active, pendingDeployment: pending };
  if (pending) return { kind: "working", label: pending.status === "queued" ? "等待部署" : `部署中 ${Number(pending.progress || 0)}%`, action: "查看进度", deployment: pending };
  if (active) return { kind: "online", label: "运行中", action: "访问", deployment: active };
  const stopped = records.find((item) => item.status === "stopped" && item.release && item.access_url);
  if (stopped) return { kind: "stopped", label: "已停止", action: "重新启用", deployment: stopped };
  const latest = records[0];
  if (latest?.status === "failed") return { kind: "error", label: "上次发布失败", action: "查看原因", deployment: latest };
  if (latest?.status === "stopped") return { kind: "ready", label: "部署已停止", action: "重新部署" };
  return { kind: source.phase === "failed" ? "error" : "ready", label: source.phase === "failed" ? "分析异常" : "分析完成", action: source.phase === "failed" ? "查看原因" : "部署" };
}
