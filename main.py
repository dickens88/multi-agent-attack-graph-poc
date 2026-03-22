import uuid

from agent_logging import get_investigation_callbacks
from logging_config import setup_logging

setup_logging()

from orchestrator import orchestrator


def run_query(user_input: str, thread_id: str = None, verbose: bool = False) -> str:
    """Run a query through the orchestrator and return the response."""
    thread_id = thread_id or str(uuid.uuid4())
    config = {
        "configurable": {"thread_id": thread_id},
        "callbacks": get_investigation_callbacks(),
    }

    result = orchestrator.invoke(
        {"messages": [{"role": "user", "content": user_input}]},
        config=config,
    )

    response = result["messages"][-1].content

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"Query: {user_input}")
        print(f"Thread: {thread_id}")
        print(f"Response: {response}")
        print(f"{'=' * 60}\n")

    return response


def run_validation_suite():
    """验证三条执行路径的行为是否符合预期。"""
    print("=" * 60)
    print("VALIDATION SUITE: Attack Graph Orchestrator")
    print("=" * 60)

    print("\n[LEVEL-1] 简单 IP 查找")
    run_query("IP 192.168.1.105 在攻击图里吗？", verbose=True)

    print("\n[LEVEL-2] 中等复杂度查询")
    run_query("找出所有攻击过 192.168.1.105 的 IP，按时间排序", verbose=True)

    print("\n[LEVEL-3] 深度溯源 + 报告")
    run_query("帮我完整溯源 192.168.1.105 的攻击来源并生成报告", verbose=True)

    print("\n验证完成。请检查以上三个查询的响应是否符合预期路径。")


if __name__ == "__main__":
    run_validation_suite()

    print("\n进入交互模式（输入 'exit' 退出）：")
    session_id = str(uuid.uuid4())
    while True:
        user_input = input("\nYou: ").strip()
        if user_input.lower() in ("exit", "quit", "q"):
            break
        if not user_input:
            continue
        response = run_query(user_input, thread_id=session_id)
        print(f"\nAgent: {response}")
