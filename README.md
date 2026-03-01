# 🛡️ 安全事件调查系统 (Security Investigation System)

基于 **多智能体协作 (Multi-Agent Collaboration)** 与 **Neo4j 图数据库**构建的安全事件自动分析溯源 **POC (Proof of Concept) 项目**。

本系统旨在验证利用多智能体协作模拟安全专家思维的可行性。系统假设后端已将安全告警及相关实体数据（IP、主机、进程等）写入 Neo4j 数据库，通过自动化生成查询策略、从图谱中提取关联证据，并最终输出完整的攻击链路分析报告。

---

## 📑 核心特性

- **🧠 多智能体协作架构**：系统包含四个独立但紧密协作的 Agent (Coordinator, Planner, Retriever, Analyzer)，外加一个负责总结的 Reporter。
- **🕸️ 实时攻击图谱 (Palantir Gotham Style)**：前端内置 D3.js 驱动的动态知识图谱，随后台自动提取实体（IP、域名、主机、进程）和关系，实时渲染分析过程中的攻击链路。
- **⚡ 异步流式处理 (SSE)**：基于 Server-Sent Events 实现后端推理过程的实时回显，支持“深度思考 (Deep Thinking)” 开关。
- **🔄 自主闭环迭代**：系统能根据上一步查询获取的线索，自动决定是否需要进一步深挖（迭代追踪），直到拼凑出完整的攻击面貌或达到最大深度。
- **⏸️ 随时中止**：由于安全调查耗时可能较长，系统支持在调查过程中随时中止 (Stop Investigation) 并提前生成当前进度的报告。

---

## 🏗️ 架构与原理解析

### 1. 目录结构

```text
lab/
├── agents/             # 多智能体核心逻辑
│   ├── coordinator.py  # 协调器：负责理解用户意图、提取核心实体
│   ├── planner.py      # 规划器：基于当前掌握的线索，制定下一步的查询计划
│   ├── retriever.py    # 检索器：将计划翻译为 Cypher 并在 Neo4j 执行，支持并发
│   ├── analyzer.py     # 分析器：分析检索到的数据，判断线索关联性，决定是否继续迭代
│   └── reporter.py     # 报告员：在调查全部结束后，汇总所有线索，生成最终 Markdown 报告
├── graph/              # LangGraph 状态机定义
│   ├── nodes.py        # 节点执行逻辑封装
│   ├── state.py        # 全局上下文 State 定义 (TypedDict)
│   └── workflow.py     # 有向循环图 (Cyclic Graph) 工作流编排定义
├── tools/              # 工具/驱动层
│   ├── cypher_templates.py # Cypher 查询模板
│   ├── graph_utils.py  # 负责从 Neo4j 提取 nodes/edges 用于前端 D3.js 渲染
│   └── neo4j_tools.py  # 封装 Neo4j Driver 相关操作
├── frontend/           # 前端展示层 (原生 HTML/JS/CSS)
│   ├── index.html      # 主页面，左右双栏布局 (时间线 + 攻击图谱)
│   ├── style.css       # Gotham 极夜风格主题，及图谱浮窗样式
│   ├── app.js          # SSE 事件监听，DOM 操作，状态管理
│   ├── attack_graph.js # 封装基于 D3.js (v7) 的力导向图 (Force-directed Graph) 逻辑
│   └── d3.v7.min.js    # 离线 D3.js 库
├── server.py           # FastAPI 服务出口，提供 SSE 接口 (/investigate)
├── .env                # 环境变量配置 (Neo4j, LLM Keys 等)
├── Dockerfile          # Docker 镜像构建定义
├── docker-compose.yml  # 多容器一键编排定义
├── seed_data.py        # 模拟攻击数据导入脚本
└── README.md           # 本文档
```

### 2. 多智能体处理机制与状态流转

本系统通过 **LangGraph** 实现工作流控制，其核心逻辑是一个 **循环图 (Cyclic Graph)**：

1. **`Coordinator` (起点)**：解析用户的初始输入（如：“分析 192.168.1.100 的被入侵迹象”），提取最初始的实体对象（如 IP），放入全局 State 中。
2. **进入迭代循环 (Iteration Loop)**：
   - **`Planner`**：阅读已收集的线索 (Evidences)，决定当前需要查什么。如果目前只知道 IP，可能会决定“查询该 IP 在过去24小时的网络连接”。生成一系列具体的 Action。
   - **`Retriever`**：接收 Planner 的 Action，利用 LLM 将自然语言意图翻译为 `Cypher` 查询语句，去连接 Neo4j 数据库执行查询。如果存在多个 Action，**支持并发执行**。单轮结束后，Retriever 还会执行一条**补充子图查询 (Subgraph Query)**，拉取所有已知实体间的关联边，通过 SSE 推送给前端渲染。
   - **`Analyzer`**：对 Retriever 取回的数据进行威胁研判。如果是无效数据则丢弃；如果是高价值线索（如下载了恶意载荷，又发现了该载荷对应的文件哈希），将其加入 State 的 `evidences` 中。同时 Analyzer **负责决策路由 (Routing)**：如果线索已足够拼凑出全貌，或达到了设定的迭代上限，则走向 `Reporter`；如果发现了新的衍生线索（如发现关联的新内网IP），则跳转回 `Planner` 开启下一轮。
3. **`Reporter` (终点)**：基于所有收集的 `evidences`，生成详细的人类可读的 Markdown 报告。

### 3. 攻击图谱动态生成原理

右侧的攻击图谱并不是一开始就全部加载的，而是随着智能体的调查**逐步浮现**的。
- 传统的查询方案往往是 `RETURN a, b` 得到离散的实体。
- 本项目在 `Retriever` 每轮查询结束后，会把历史上所有发现的节点 ID 汇聚起来，并向 Neo4j 发送一次子图查询：`MATCH (a)-[r]->(b) WHERE a.id IN $ids OR b.id IN $ids RETURN a, r, b LIMIT 200`
- 这保证了只要智能体摸到了线索的冰山一角，我们就能将这条链路上被牵连的节点在图谱上自动关联并点亮。

---

## 🚀 部署与启动方式

### 1. 快速开始 (推荐使用 Docker)

如果你已经安装了 [Docker](https://www.docker.com/) 和 [Docker Compose](https://docs.docker.com/compose/)，可以使用以下命令实现“一键部署”：

1. **配置环境变量**：复制 `.env.example` 为 `.env` 并填写你的 LLM API Key。
   ```bash
   cp .env.example .env
   # 编辑 .env 文件，填入 OPENAI_API_KEY 等信息
   ```

2. **启动系统**：
   ```bash
   docker compose up -d --build
   ```
   该命令会自动启动 Neo4j 数据库和后端 API 服务（包含前端静态资源）。

3. **导入模拟数据**：由于新启动的 Neo4j 是空的，我们需要导入内置的模拟攻击场景数据：
   ```bash
   # 在宿主机直接执行（需安装 neo4j 依赖）或通过容器执行：
   docker exec -it security-agent-backend python seed_data.py
   ```

4. **访问系统**：访问 **http://localhost:8000** 即可开始调查。

---

### 2. 本地手动部署 (源码运行)

#### 环境准备
- **Python**: 3.10+
- **Database**: 一个正在运行的 Neo4j 实例 (建议配合 Docker 使用)。

#### 依赖安装
建议使用虚拟环境：
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 启动服务
```bash
source venv/bin/activate
python server.py
```
默认端口为 8000（可在 `server.py` 中修改）。

---

## 🛠️ 二次开发指导

如果您希望对本项目进行扩展或定制开发，以下是一些常见的切入点：

### 1. 适配不同的图数据库结构 (Schema)
系统的 Cypher 生成高度依赖于传入 LLM 的 Database Schema。系统会自动调用 `neo4j_client.get_schema()`。如果您的 Neo4j 图谱包含特殊的命名规范（如多标签、特殊属性名），可以在 `agents/retriever.py` 中强化针对大模型的 Prompt 提示，或在 `tools/cypher_templates.py` 中补充硬编码的 Few-shot 样例。

### 2. 扩展智能体 (Adding New Agents)
如果您需要增加外部威胁情报查询 (如 VirusTotal)：
1. 在 `agents/` 下新增 `ti_lookup.py` 智能体。
2. 内部通过 Langchain 调用请求 external API 获取哈希信誉。
3. 在 `graph/nodes.py` 中将其包装为工作流节点。
4. 修改 `graph/workflow.py` 的路由逻辑，例如让 Analyzer 在发现文件哈希时，先路由给 `ti_lookup` 节点，再流回 `Planner`。

### 3. 定制化前端攻击图谱 (D3.js)
前端图谱的核心逻辑在 `frontend/attack_graph.js` 中。
- **自定义节点颜色/图标**：可以直接修改 `tools/graph_utils.py` 中的 `NODE_COLORS` 和 `NODE_ICONS` 字典，后端处理时会自动下发到前端。
- **调整力导向参数**：在 `attack_graph.js` 的 `init()` 方法中，修改 `d3.forceSimulation()` 的碰撞半径 (radius)、边距 (distance) 和电荷排斥力 (strength)，以适应大规模节点显示。
- **扩展浮游属性框**：目前 Hover 会最多截取 8 个属性，这在 `showTooltipNode()` 函数中通过 `slice(0, 8)` 控制。如果您的业务节点包含特大长文本，可能需要在该函数中额外剔除对应的字段。

### 4. 开启/配置 `Deep Thinking` 参数
默认前端 UI 提供了一个【深度思考】的 Toggle 开关。开启后，在向底层大模型（如兼容该参数的 DeepSeek r1 等模型）发送请求时，会包含相关的 thinking 激活标志。该参数经由 `server.py` 的 request body 解析传递进 `InvestigationState` 中，所有 Agent 节点在封装 LLM 调用时可通过 `state.get("deep_thinking")` 判断是否启用该特性。

---

> *"Security is a process, not a product." — Bruce Schneier*
