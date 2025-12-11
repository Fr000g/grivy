from typing import List

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langgraph.checkpoint.memory import MemorySaver


def build_agent(llm: BaseChatModel, tools: List):
    """
    创建符合 LangChain 最佳实践的 Agent，使用 LangGraph 内置的持久化和流式支持。
    仅调用已加载的本地 Trivy 工具，缺参需追问，避免输出过长。
    """
    system_prompt = (
        "你是安全漏洞扫描助手，只能调用已加载的 Trivy 本地工具。"
        " 当用户仅咨询能力时调用 trivy_help；缺少必需参数要先追问。"
        " 优先使用工具返回的摘要信息，避免展开完整报告。"
        " 扫描结果会自动保存到 data/ 目录下。"
    )

    # 创建内存保存器用于对话历史持久化
    checkpointer = MemorySaver()

    # 使用 LangChain 1.0 的 create_agent API，直接传入 checkpointer
    agent = create_agent(
        model=llm,
        tools=tools,
        system_prompt=system_prompt,
        checkpointer=checkpointer,
    )

    return agent
