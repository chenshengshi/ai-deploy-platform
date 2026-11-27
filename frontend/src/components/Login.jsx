import React, { useState } from "react";
import { Activity, Bot, CloudCog, Eye, EyeOff, KeyRound, LoaderCircle, Server } from "lucide-react";
import { login } from "../api";


export function BrandLogo({ branding, large = false }) {
  return (
    <div className={`logo${large ? " large" : ""}${branding?.logo_data_url ? " custom" : ""}`}>
      {branding?.logo_data_url ? <img src={branding.logo_data_url} alt="平台 Logo" /> : <CloudCog />}
    </div>
  );
}


export default function Login({ onDone, branding }) {
  const [showPassword, setShowPassword] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    const submitted = new FormData(event.currentTarget);
    const username = String(submitted.get("username") || "").trim();
    const password = String(submitted.get("password") || "");
    setBusy(true);
    setErr("");
    try {
      await login(username, password);
      onDone();
    } catch (error) {
      setErr(error.message || "登录失败，请检查账号和密码");
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
      {/* Authentication is handled by the JSON API above.  Declaring the
          form as a native POST makes Chrome re-run compromised-password
          checks after unrelated in-app tab changes.  The standard field
          names and autocomplete tokens below still allow normal autofill. */}
      <form className="login-card" autoComplete="on" onSubmit={submit}>
        <h2>欢迎回来</h2>
        <p className="sub">登录后管理项目与发布任务</p>
        <label>
          用户名
          <input id="login-username" name="username" type="text" autoComplete="username" autoCapitalize="none" spellCheck={false} aria-invalid={Boolean(err)} onInput={() => err && setErr("")} />
        </label>
        <label>
          密码
          <span className="login-password-field">
            <input id="login-password" name="password" type={showPassword ? "text" : "password"} autoComplete="current-password" aria-invalid={Boolean(err)} onInput={() => err && setErr("")} />
            <button type="button" className="login-password-toggle" aria-label={showPassword ? "隐藏密码" : "显示密码"} aria-pressed={showPassword} title={showPassword ? "隐藏密码" : "显示密码"} onClick={() => setShowPassword((current) => !current)}>
              {showPassword ? <EyeOff /> : <Eye />}
            </button>
          </span>
        </label>
        {err && <div className="login-error" role="alert">{err}</div>}
        <button type="submit" className="primary full" disabled={busy}>
          {busy ? <LoaderCircle className="spin" /> : <KeyRound />}{busy ? "登录中..." : "登录"}
        </button>
      </form>
    </div>
  );
}
