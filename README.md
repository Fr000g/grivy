## 项目简介
Grivy 是一个结合 Trivy 与 LangChain 的命令行 Agent，支持用自然语言触发容器镜像、本地目录、Git 仓库及 SBOM 的安全扫描。工具会直接调用本地 Trivy CLI，生成 JSON 报告并自动提炼摘要，避免把大体积结果传回 LLM。

## 功能特性
- 自然语言交互：在 CLI 输入中文/英文描述即可触发对应扫描。
- 覆盖 4 类目标：`image`、`fs`、`repo`、`sbom`。
- 安全摘要：自动统计 High/Critical 数量并列出 Top 风险，完整报告保存在 `data/`。
- 参数兜底：默认 `severity=HIGH,CRITICAL`、`ignore_unfixed=True`、`format=json`、`timeout=300s`。
- 流式输出：Trivy CLI 日志实时回显，避免长时间无响应。

## 环境要求
- Python 3.10+
- 已安装 Trivy 且在 `PATH` 中（`brew install trivy` 等方式）
- OpenAI 兼容 API Key，设置环境变量 `OPENAI_API_KEY`

## 安装与运行
```bash
# 推荐：使用 uv 进行环境与依赖管理
uv venv .venv
source .venv/bin/activate
uv pip install -e .

# 或使用 pip
# pip install -e .

# 启动 CLI（可指定模型，默认 gpt-5-nano）
python -m grivy.cli.main --model gpt-5-nano
```

启动后按照提示对话，例如：
- 扫描镜像：`扫描 nginx:latest 镜像的漏洞`
- 扫描目录：`帮我检查 ./src 目录，高危以上`
- 扫描仓库：`扫描 https://github.com/a/b`
- 扫描 SBOM：`扫描 sbom.json`
- 获取能力：`你能做什么` / `帮助`

扫描完成后，可在 `data/` 目录查看生成的 JSON 报告。

## 目录结构
- `src/grivy/cli/`：CLI 入口与报告摘要逻辑
- `src/grivy/tools/`：Trivy 扫描工具封装（`image/fs/repo/sbom`）
- `src/grivy/agents/`：Agent 构建与系统提示
- `data/`：扫描报告输出目录

## 配置要点
- 必填：`OPENAI_API_KEY`（或兼容环境变量）
- 常用可调：`--model` 指定 LLM，扫描时可在对话中说明 `severity`、`ignore_unfixed`、输出格式等。

## 未来规划
- 更细粒度的 `--scanners` 控制（vuln/config/secret/license）。
- 支持 `trivy k8s` 场景（集群/命名空间，含 kubeconfig 参数）。
- MCP 形态与 LangGraph/Agent Server 接入，支持远程调用与鉴权。
- 报告增强：输出 CycloneDX/SPDX/BOV，支持上传或签名链路。
- api 形式提供服务

## 开发提示
- 代码主要入口：`src/grivy/cli/main.py`（交互循环）与 `src/grivy/tools/trivy_tools.py`（实际执行 Trivy 命令并摘要）。
- 如需新增工具或参数，请在 `trivy_tools.py` 中添加并通过 `get_tools()` 统一导出。

## 致谢
- 本项目的扫描能力依赖 Aqua Security 开源的 Trivy（仓库：<https://github.com/aquasecurity/trivy>）。感谢原作者的长期维护与社区贡献。