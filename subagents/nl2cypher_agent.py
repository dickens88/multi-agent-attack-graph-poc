import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from tools import nlp_to_cypher, run_cypher_query

load_dotenv()


def _build_subagent_model() -> ChatOpenAI:
    base_url = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
    api_key = os.getenv("OPENAI_API_KEY")
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required in .env")

    return ChatOpenAI(
        model=model_name,
        base_url=base_url,
        api_key=api_key,
        temperature=0,
    )

NL2CYPHER_SYSTEM_PROMPT = """
# Role: Cypher Query Translator

## 职责
你是攻击图数据库的 Cypher 查询专家。
接收自然语言问题，输出可直接执行的 Cypher 查询。

## 工作流程（必须严格遵守）

1. 加载查询模板 Skill：
   - 调用 read_file 读取 `skills/cypher-query/cypher_templates.py`
   - 从模板中选择最接近的类别（LOOKUP / PATH / NEIGHBOR / ATTR / VULN）

2. 适配模板：
   - 替换 `<<PARAM>>` 占位符为实际参数值
   - 验证关系方向是否正确（参考 graph-schema skill）

3. 验证执行：
   - 调用 `run_cypher_query()` 测试执行
   - 若报错，修正后重试一次

4. 输出结果：
   - 返回 Cypher 查询字符串 + 执行结果摘要

## 输出格式

```json
{
  "cypher": "MATCH (n:IP ...) RETURN ...",
  "template_used": "LOOKUP_IP_BY_ADDRESS",
  "execution_status": "success" | "error",
  "result_summary": "Found 1 IP node with risk_score 0.87"
}
```

## 约束（不得违反）

- 只生成 READ 查询（MATCH/RETURN），不生成 CREATE/DELETE/SET
- 所有查询必须包含 LIMIT（最大 100）
- 不自行推测未知的节点标签或关系类型，先查询 graph-schema skill

## 工具调用推理要求

每次调用工具时必须填写 reason 参数，用中文说明：
- 为什么需要这次查询
- 期望得到什么结果

不得省略 reason 参数或填写空字符串。
"""

nl2cypher_agent = {
    "name": "nl2cypher-agent",
    "description": (
        "Translates natural language questions about the attack graph into validated "
        "Cypher queries. Loads cypher_templates.py and selects the best matching template. "
        "Use when a user query needs to be converted before graph execution. "
        "Returns a ready-to-execute Cypher string with execution confirmation."
    ),
    "system_prompt": NL2CYPHER_SYSTEM_PROMPT,
    "tools": [nlp_to_cypher, run_cypher_query],
    "skills": ["skills"],
    "model": _build_subagent_model(),
}
