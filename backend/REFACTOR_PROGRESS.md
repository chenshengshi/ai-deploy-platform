# 自助发布平台模块化进度

更新时间：2026-11-27

## 当前状态

- 线上地址：`http://36.250.234.182:7080`
- 当前已上线提交：`6f06197 refactor: split platform runtime and data modules`
- 本次待提交：AI 设置、审计模块，以及源码分析 Worker 缺失引用修复。
- 后端回归：`110 passed, 3 subtests passed`。
- 现有业务项目和数据未清除；后续测试采用重新发布，不删除项目。

## 已完成拆分

- 发布核心：构建、流水线、生命周期基础能力、日志、端口、运行快照、扩缩容、配置、网关和发布视图。
- `deployer.py` 已缩为兼容入口，核心执行位于 `deployment/`。
- 项目源码与集成分析：`project_data/integration_analysis.py`。
- 项目数据库查询、数据变更和结构迁移：`project_data/database_operations.py`。
- 项目删除预览和资源清理：`project_data/deletion.py`。
- 发布删除预览和资源清理：`deployment/deletion.py`。
- 容器日志、文件浏览、上传下载和终端：`deployment/container_access.py`。
- 镜像仓库、权限和版本保护：`deployment/registry.py`。
- 启动配置与发布文件快照：`deployment/launch_config.py`。
- AI 发布跟进诊断：`chat/deployment_followup.py`。
- AI 对话编排和对话记录路由：`chat/service.py`、`chat/routes.py`。
- 数据库初始化与兼容迁移：`bootstrap/startup.py`。
- AI 模型设置：`system_settings/ai.py`。
- 审计、经验和保留数据：`audit_routes.py`。

## 2026-11-27 收尾问题

- “数产公司网站”源码分析长期显示“等待处理”。
- 根因：Worker 入口调用 `_source_workspace_metadata`，但主入口拆分后遗漏导入，后台不断报 `name '_source_workspace_metadata' is not defined`。
- 修复：从 `project_data.integration_analysis` 显式导入，并增加回归测试，确保 Worker 入口可访问同一实现。
- 上线后必须确认该项目状态从 `queued` 进入 `running/completed`，Worker 日志不再重复报错。

## 下周继续顺序

1. 节点管理与 Docker 代理拆分。
2. Git 凭据和项目基础 CRUD 拆分。
3. 域名、证书与网关策略拆分。
4. 数据资源暴露与运行镜像配置拆分。
5. 发布停止、启动、重试、回滚和恢复分析拆分。
6. 网络代理、安全设置和发布调度设置拆分。
7. 最终清理 `main.py` 未使用导入和重复兼容代码；保持它只负责应用装配与少量路由包装。

## 每批验收规则

1. `python -m py_compile` 检查变更模块。
2. `PYTHONPATH=. pytest -q` 全量通过。
3. 检查 API 路径与方法不存在重复注册。
4. 推送 GitHub `origin/main` 和 TFS `tfs/main`。
5. 确认没有 `queued/running` 发布任务后更新平台服务。
6. 验证健康接口、AI 状态问答、历史发布配置、镜像仓库、删除预览和容器文件浏览。
7. 不清除现有项目和数据，不主动发布“设备管理系统-数转”。
