# 自助发布平台

面向非技术人员的中文 AI 应用发布平台。用户上传源码或关联 Git 仓库，通过对话或按钮将项目部署到已授权的 Docker 节点，并查看部署状态、日志、容器、端口和访问地址。

## 核心能力

- 用户登录与 RBAC：管理员、发布人员、只读人员
- OpenAI 兼容模型配置
- SSH 节点管理，支持密码和私钥
- 文件、文件夹、ZIP 上传及 Git 仓库
- Git 用户名/密码、访问令牌、SSH 私钥
- 自动识别 Docker Compose 或 Dockerfile
- 后台任务执行与持续部署日志
- 自动分配公网端口，可配置域名
- 项目、部署、运行实例和审计记录
- 中文 AI 对话触发受控部署动作

## 架构

```text
浏览器 SPA
    │
    ▼
FastAPI API ───── PostgreSQL
    │                  ▲
    ├── AI Provider    │
    │                  │
    └── Deployment Worker ── SSH/SFTP ── Docker 节点
```

AI 不直接执行任意 Shell 命令。它只能选择平台预定义的动作；真正的构建、发布、停止、日志读取由部署引擎完成。

## Docker 部署

```bash
cp .env.example .env
./deploy-classic.sh
```

访问 `http://服务器IP:7080`。首次启动使用 `.env` 中的管理员账号登录。

默认管理员：`admin`，默认密码：`Qwer1234`。正式使用前请立即修改 `.env` 中的
`ADMIN_PASSWORD`、`APP_SECRET` 和 `ENCRYPTION_KEY`。

仓库内置脱敏后的 AI 部署经验。新数据库首次启动时会自动导入这些经验，但不会包含
现网项目、发布记录、聊天、用户、节点、业务密码、证书或密钥。数据库表结构由平台
启动时自动创建，无需复制现网 PostgreSQL 数据目录。

## 支持的项目

1. 仓库或上传源码中有 `compose.yaml` / `compose.yml` / `docker-compose.yml`
2. 仓库或上传源码中有 `Dockerfile`

对于 Dockerfile 项目，需要在项目配置中填写容器端口。平台会自动选择宿主机端口，也可以手动指定。

## 域名

第一版支持记录并展示域名。将域名 DNS 指向部署节点后，可在节点上接入现有 Nginx、Caddy 或 Traefik。直接访问始终可以使用 `http://节点IP:宿主机端口`。

