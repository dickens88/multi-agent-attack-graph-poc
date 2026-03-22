import os

from langchain_openai import ChatOpenAI


def build_chat_model(model_name: str | None = None, temperature: float | None = None) -> ChatOpenAI:
    """Build OpenAI-compatible chat model from environment settings."""
    base_url = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
    api_key = os.getenv("OPENAI_API_KEY")
    model_name = model_name or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    temperature = int(os.getenv("OPENAI_TEMPERATURE", "0"))

    return ChatOpenAI(
        model=model_name,
        base_url=base_url,
        api_key=api_key,
        temperature=temperature,
        extra_body={"thinking": {"type": "disabled"}},
    )
