# 安全事件调查系统（攻击图谱 POC）

基于 **Deep Agents 编排**、**专用子 Agent** 与 **Neo4j 图数据库** 的安全告警溯源与报告生成概念验证。后端将调查过程以 **SSE（Server-Sent Events）** 流式推送到前端；前端为 **React + Vite**，用 **Cytoscape / D3** 渲染攻击图谱与时间线。

---

## 核心特性

- **主控 Orchestrator + 子 Agent**：主 Agent 负责意图分级与委派；子 Agent 包括 NL→Cypher、图查询执行、攻击溯源（Tracer）、报告生成（Report）。
- **三级意图框架**：简单节点/邻居查询由主控直接调工具；中等查询走 NL2Cypher + 图查询；深度调查走 `write_todos`、Tracer、可选补充查询与 Report。
- **流式可观测性**：`/api/investigate` 推送主控与子 Agent 的 token、工具调用、待办更新、图谱增量与完成事件，便于调试与产品化展示。
- **调查产物落盘**：溯源与报告可在服务端写入 `artifacts/`（具体逻辑见 `api/sse_server.py`）。
- **Skills 知识库**：`skills/` 下各子目录的 `SKILL.md` 与模板（如 `cypher-query/cypher_templates.py`）供 Agent 通过 Deep Agents 机制加载。

---

## 架构概览

### 目录结构

```text
lab/
├── orchestrator.py       # 主控 Agent：create_deep_agent，挂载 tools + subagents + skills
├── main.py               # CLI：单轮/验证套件/交互式调试（无 HTTP）
├── api/
│   └── sse_server.py     # FastAPI + SSE 流式调查接口
├── subagents/            # 子 Agent 定义（供 orchestrator 委派）
│   ├── nl2cypher_agent.py
│   ├── graph_query_agent.py
│   ├── tracer_agent.py
│   └── report_agent.py
├── tools/                # Neo4j 与调查工具
│   ├── graph_tools.py    # 节点查询、邻居、路径追踪、Cypher 执行等
│   └── analysis_tools.py # NL→Cypher、终止评估、读写文本文件等
├── skills/               # Agent 可发现的技能与协议（Deep Agents skills 根目录）
│   ├── cypher-query/
│   ├── investigation-protocol/
│   └── graph-schema/
├── frontend/             # React + TypeScript + Vite
│   ├── src/
│   │   ├── pages/InvestigationPage.tsx
│   │   ├── components/   # 时间线、图谱、待办面板
│   │   ├── hooks/useInvestigationStream.ts
│   │   └── types/stream-events.ts
│   └── vite.config.ts    # 开发代理 /api → 后端
├── artifacts/            # 运行期生成的追踪/报告等（可纳入 .gitignore 策略）
├── seed_data.py          # 向 Neo4j 导入演示数据
├── logging_config.py     # 可选统一日志配置
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env / .env.example
└── README.md
```

### 编排与数据流（简述）

1. 用户问题进入 **Orchestrator**（`orchestrator.py`），按系统提示中的 **LEVEL-1 / 2 / 3** 选择路径。
2. **LEVEL-1**：直接调用 `get_node_by_ip`、`get_node_neighbors` 等工具，不委派子 Agent。
3. **LEVEL-2**：委派 **nl2cypher-agent** 与 **graph-query-agent** 完成查询与结果整理。
4. **LEVEL-3**：`write_todos` 规划 → **tracer-agent** 迭代溯源 → 按需 **graph-query-agent** → 默认 **report-agent** 产出结论文本。
5. HTTP 场景下，`api/sse_server.py` 将 LangGraph / Deep Agents 流中的事件转换为 SSE，前端 `useInvestigationStream` 解析后更新时间线、待办与图谱。

### 图谱与时间线

- 节点颜色与图标配置在 `api/sse_server.py` 中（与早期 `graph_utils` 约定对齐），经 `graph_update` 等事件下发到前端。
- 前端图谱基于 **Cytoscape**（及 D3 相关依赖），与时间线、待办面板共同展示一次调查的完整过程。

---

## 环境变量

| 变量 | 说明 |
|------|------|
| `OPENAI_API_KEY` | 必填。OpenAI 兼容 API 的密钥。 |
| `OPENAI_API_BASE` | 可选，默认 `https://api.openai.com/v1`。 |
| `OPENAI_MODEL` | 可选，默认 `gpt-4o`。 |
| `NEO4J_URI` | Neo4j Bolt 地址，如 `bolt://localhost:7687`。 |
| `NEO4J_USER` / `NEO4J_PASSWORD` | 数据库账号。 |
| `LOG_LEVEL` | 可选，日志级别（见 `logging_config.py`）。 |

> 根目录 `.env.example` 若仍包含其他厂商 Key，请以实际使用的 **OpenAI 兼容端点** 为准在 `.env` 中配置。

---

## 部署与启动

### 1. 本地开发（推荐：前后端分离）

**前提**：Python 3.12+（与 `Dockerfile` 一致）、Node.js ≥ 20.19、Neo4j 可访问。

```bash
cd /path/to/lab
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
# 若启动 API 时提示缺少包，请补充：
pip install fastapi uvicorn langchain-openai
```

**终端 A — 后端 SSE API**（端口可按需修改，需与前端代理一致）：

```bash
source venv/bin/activate
./venv/bin/python -m uvicorn api.sse_server:app --host 127.0.0.1 --port 8010
```

**终端 B — 前端**（默认 5173，`vite.config.ts` 将 `/api` 代理到 `http://127.0.0.1:8010`）：

```bash
cd frontend
npm install
npm run dev
```

浏览器访问 **http://127.0.0.1:5173**，在输入框提交调查语句即可。

**CLI 调试（无 SSE）**：

```bash
source venv/bin/activate
python main.py
```

将运行内置验证用例并进入交互循环。

### 2. Docker Compose

```bash
cp .env.example .env   # 编辑填入 OPENAI_* 与 NEO4J_*（或与 compose 一致的环境变量）
docker compose up -d --build
```

- 后端映射 **8000**，镜像内命令为：`uvicorn api.sse_server:app --host 0.0.0.0 --port 8000`。
- **前端不在该 compose 中**：本地仍用 `npm run dev`；或将 `frontend` 构建为静态资源后由 Nginx 等反代到同一主机的 8000 仅提供 API。

导入演示数据（Neo4j 为空时）：

```bash
docker exec -it security-agent-backend python seed_data.py
```

---

## HTTP API

### `GET /api/investigate`

- **query**（必填）：用户自然语言调查请求。
- **thread_id**（可选）：会话/线程 ID，默认 `default`。

响应为 **text/event-stream**，JSON 负载字段 `type` 与前端 `frontend/src/types/stream-events.ts` 中 `StreamEventType` 一致，例如：`orchestrator_token`、`subagent_tool_call`、`graph_update`、`todos_update`、`subagent_complete`、`done` 等。

---

## 二次开发指引

### 调整图模型与 Cypher

- 模板与说明：`skills/cypher-query/`（含 `cypher_templates.py`）。
- 图模式说明可放在 `skills/graph-schema/`，便于 Agent 对齐 Schema。

### 新增或修改子 Agent

- 在 `subagents/` 新增模块并在 `subagents/__init__.py` 中导出。
- 在 `orchestrator.py` 的 `create_deep_agent(..., subagents=[...])` 中注册，并视需要扩展 `ORCHESTRATOR_PROMPT` 中的委派规则。

### 扩展工具

- 在 `tools/graph_tools.py` 或 `analysis_tools.py` 中实现函数，导出到 `tools/__init__.py`，再在对应 Agent 的 `tools=[...]` 列表中挂载。

### 前端事件与 UI

- SSE 解析与状态归约：`frontend/src/hooks/useInvestigationStream.ts`。
- 事件类型定义：`frontend/src/types/stream-events.ts`。
- 图谱组件：`frontend/src/components/GraphPanel.tsx`。

---

## 说明与维护

- **依赖**：若从零环境安装，除 `requirements.txt` 外，运行 `api.sse_server` 需要 **FastAPI、Uvicorn**；各 Agent 使用 **langchain-openai**。建议将上述写入 `requirements.txt` 并锁定版本，便于 CI 与团队协作。
- **Docker / 纯后端**：当前 compose 仅拉起 Neo4j + API；完整 UI 需单独构建前端或自行增加静态站点服务。

---

> *"Security is a process, not a product." — Bruce Schneier*
