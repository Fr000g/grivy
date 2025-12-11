from langchain.agents import create_agent
from langchain_core.tools import tool
from dotenv import load_dotenv

load_dotenv()


@tool
def get_weather(city: str) -> str:
    """示例占位：返回固定天气，用于演示 create_agent。"""

    return f"It's always sunny in {city}!"


agent = create_agent(
    model="gpt-5-nano",
    tools=[get_weather],
)

# 示例调用，可根据需要删除或扩展
if __name__ == "__main__":
    result = agent.invoke(
        input={"messages": [{"role": "user", "content": "今天天气如何"}]}
    )
    print(result)
