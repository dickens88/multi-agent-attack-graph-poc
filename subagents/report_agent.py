from llm_factory import build_chat_model
from tools import write_text_file

REPORT_SYSTEM_PROMPT = """
# Role: Threat Intelligence Report Writer

## 职责
根据 task() 参数中的溯源调查发现（findings），一次性生成结构化 Markdown 报告。

## 工作流程（仅一步）

1. 直接根据 task() 参数中提供的 findings 内容，生成完整 Markdown 报告并调用 write_text_file() 写入。

报告结构：
- Executive Summary（2-3句，无技术术语，面向管理层）
- Attack Timeline（按时间戳排列的事件序列）
- Attack Chain（可视化路径：Attacker → IP1 → IP2 → Target）
- Compromised Assets（列表，含风险等级）
- Vulnerability Analysis（被利用的 CVE 及影响）
- Recommendations（优先级排序的修复建议，最多5条）
- Confidence Assessment（数据质量说明 + 已知数据缺口）

写入路径：`artifacts/{timestamp}_investigation_report.md`

2. 返回 Executive Summary + report_file（真实写入路径）

## 约束（不得违反）

- 不读取文件、不查询图数据库，仅使用 task() 参数中的 findings
- 必须通过 write_text_file 实际写入文件
- 只调用一次 write_text_file，将完整报告一次写入
- Executive Summary 不超过 3 句话
- Recommendations 最多 5 条，按优先级排序
"""

report_agent = {
    "name": "report-agent",
    "description": (
        "Generates a structured threat investigation report from completed tracing findings. "
        "Receives findings directly in task() parameters, produces a formatted markdown report, "
        "and persists it to artifacts/ via a single write_text_file call. "
        "Use by default after LEVEL-3 tracing is complete, even if the user did not explicitly request a report. "
        "Do NOT invoke for simple lookups or when no tracing has been performed."
    ),
    "system_prompt": REPORT_SYSTEM_PROMPT,
    "tools": [write_text_file],
    "skills": [],
    "model": build_chat_model(),
}
