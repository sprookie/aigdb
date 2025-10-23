import os
from dotenv import load_dotenv
from typing import Optional

from langchain_openai import ChatOpenAI

# 加载环境变量
load_dotenv()

# 默认切换到 DeepSeek（OpenAI兼容）
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "deepseek-chat")


def get_llm() -> ChatOpenAI:
    """构建LLM客户端，默认使用DeepSeek。"""
    if not OPENAI_API_KEY:
        raise RuntimeError(
            "未设置OPENAI_API_KEY，请在.env或环境变量中配置。"
        )
    kwargs = {"model": OPENAI_MODEL, "temperature": 0}
    # 指定兼容的Base URL
    if OPENAI_BASE_URL:
        kwargs["base_url"] = OPENAI_BASE_URL
    return ChatOpenAI(api_key=OPENAI_API_KEY, **kwargs)