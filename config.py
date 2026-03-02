"""Configuration for the Security Investigation Multi-Agent System."""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # OpenAI-compatible API
    OPENAI_API_BASE: str = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")

    # Neo4j
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")

    # Investigation
    MAX_ITERATIONS: int = int(os.getenv("MAX_ITERATIONS", "10"))

    # LLM
    TEMPERATURE: float = float(os.getenv("TEMPERATURE", "0"))

    # Query
    QUERY_PARALLEL_WORKERS: int = int(os.getenv("QUERY_PARALLEL_WORKERS", "3"))

    # Model
    MAX_TOKENS: int = int(os.getenv("MAX_TOKENS", "128000"))


settings = Settings()
