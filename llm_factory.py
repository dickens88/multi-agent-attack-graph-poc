import os

from langchain_openai import ChatOpenAI


def build_chat_model(model_name: str | None = None, temperature: float | None = None) -> ChatOpenAI:
    """Build OpenAI-compatible chat model from environment settings."""
    base_url = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
    api_key = os.getenv("OPENAI_API_KEY")
    resolved_model = model_name or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required in .env")

    if temperature is None:
        temp_raw = os.getenv("OPENAI_TEMPERATURE", "0")
        try:
            resolved_temperature = float(temp_raw)
        except ValueError:
            resolved_temperature = 0.0
    else:
        resolved_temperature = float(temperature)

    return ChatOpenAI(
        model=resolved_model,
        base_url=base_url,
        api_key=api_key,
        temperature=resolved_temperature,
    )
