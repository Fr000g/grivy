import argparse
import sys
from typing import cast

from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI

from grivy.agents.agent import build_agent
from grivy.tools.trivy_tools import get_tools


def build_llm(model: str, temperature: float = 0):
    """构建 LLM；默认开启流式输出。"""
    return ChatOpenAI(model=model, temperature=temperature, streaming=True)


def main():
    parser = argparse.ArgumentParser(description="Trivy + LangChain CLI Agent")
    parser.add_argument(
        "--model",
        default="gpt-5-nano",
        help="LLM 模型名称，需在环境变量中配置对应 Key",
    )
    args = parser.parse_args()

    load_dotenv()

    tools = get_tools()
    llm = build_llm(args.model)
    agent = build_agent(llm, tools)

    config = cast(RunnableConfig, {"configurable": {"thread_id": "local-cli"}})

    print("欢迎使用 Trivy Agent，对话输入需求，输入 'exit' 退出。")
    print("支持的命令：")
    print("  - 扫描镜像：'扫描 nginx:latest 镜像的漏洞'")
    print("  - 扫描目录：'扫描 ./src 目录'")
    print("  - 扫描仓库：'扫描 https://github.com/example/repo'")
    print("  - 扫描 SBOM：'扫描 sbom.json 文件'")
    print("  - 获取帮助：'你能做什么？' 或 '帮助'\n")

    while True:
        try:
            user_input = input("\n你: ").strip()
            if user_input.lower() in {"exit", "quit", "q"}:
                print("\n再见！")
                break
            if not user_input:
                continue

            print("\nAgent: ", end="", flush=True)

            import asyncio

            async def run_stream():
                input_data = {"messages": [{"role": "user", "content": user_input}]}
                try:
                    async for event in agent.astream_events(
                        input_data,
                        config,
                        version="v1",
                    ):
                        if event["event"] == "on_chat_model_stream":
                            chunk = event["data"].get("chunk")
                            if chunk:
                                text = getattr(chunk, "text", None)
                                if not text:
                                    content = getattr(chunk, "content", None)
                                    text = content if isinstance(content, str) else ""
                                if text:
                                    print(text, end="", flush=True)
                    print()
                except Exception as e:
                    print(f"\n流式输出出错: {e}")

            asyncio.run(run_stream())

        except KeyboardInterrupt:
            print("\n\n再见！")
            sys.exit(0)
        except Exception as e:
            print(f"\n\n错误: {e}")
            print("请检查网络连接和 API 密钥配置。")
            continue


if __name__ == "__main__":
    main()
