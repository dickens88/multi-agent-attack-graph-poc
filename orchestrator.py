import os

from dotenv import load_dotenv
from deepagents import create_deep_agent
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.store.memory import InMemoryStore

from tools import get_node_by_ip, run_cypher_query, get_node_neighbors
from subagents import (
    nl2cypher_agent,
    graph_query_agent,
    tracer_agent,
    report_agent,
)

load_dotenv()

ORCHESTRATOR_PROMPT = """
# Role: Attack Graph Investigation Orchestrator

## 职责
你是攻击图调查系统的主控协调者。
分析用户查询意图，选择最合适的执行路径，委派专用子 Agent，汇总最终结果。

## 意图分级框架（每次收到查询必须先执行此分级）

分析用户查询，分为三个复杂度等级：

### LEVEL-1：简单查询（直接处理，不使用子 Agent）

判断标准：查询涉及单一节点的存在性、属性或直接邻居

处置方式：
→ 直接调用 get_node_by_ip() 或 get_node_neighbors()
→ 立即返回结果
→ 不写 todos，不启动子 Agent

### LEVEL-2：中等查询（使用 1-2 个子 Agent，无需 todos）

判断标准：需要 Cypher 转换 or 多步查询，但不需要迭代溯源

处置方式：
→ 委派 nl2cypher-agent 转换查询
→ 委派 graph-query-agent 执行并格式化
→ 汇总返回

### LEVEL-3：深度调查（使用 write_todos + 多个子 Agent）

判断标准：需要多跳路径追踪、迭代溯源、或用户明确要求报告

处置方式：
1. 调用 write_todos() 列出调查计划
2. 委派 tracer-agent 进行迭代溯源
3. 委派 graph-query-agent 补充上下文查询（如需要）
4. 默认委派 report-agent 生成最终调查结论（即使用户未显式要求）
5. 汇总所有发现返回

## 约束（不得违反）

- 不对简单查询触发 write_todos 或子 Agent
- 不自行执行多跳 Cypher 查询（委派给专用 Agent）
- LEVEL-3 调查结束后必须委派 report-agent 产出最终结论
- 不自行编写完整报告内容（委派给 report-agent）
"""


def _build_main_model() -> ChatOpenAI:
    """Build OpenAI-compatible chat model from .env settings."""
    base_url = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
    api_key = os.getenv("OPENAI_API_KEY")
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o")

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required in .env")

    return ChatOpenAI(
        model=model_name,
        base_url=base_url,
        api_key=api_key,
        temperature=0,
    )


def create_orchestrator():
    """Create and return the configured Orchestrator agent."""
    checkpointer = MemorySaver()
    store = InMemoryStore()

    skills_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")

    orchestrator_instance = create_deep_agent(
        model=_build_main_model(),
        tools=[
            get_node_by_ip,
            run_cypher_query,
            get_node_neighbors,
        ],
        subagents=[
            nl2cypher_agent,
            graph_query_agent,
            tracer_agent,
            report_agent,
        ],
        system_prompt=ORCHESTRATOR_PROMPT,
        checkpointer=checkpointer,
        store=store,
        skills=[skills_root],
        name="attack-graph-orchestrator",
    )

    return orchestrator_instance, checkpointer


orchestrator, checkpointer = create_orchestrator()
