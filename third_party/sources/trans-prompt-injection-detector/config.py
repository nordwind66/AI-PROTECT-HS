"""配置模块：集中管理所有配置项，支持环境变量覆盖和 .env 文件。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
    _env_file = Path(__file__).parent / ".env"
    if _env_file.exists():
        load_dotenv(_env_file)
except ImportError:
    pass


PROVIDER_ENDPOINTS: dict[str, str] = {
    "anthropic":          "https://api.anthropic.com/v1/messages",
    "openai":             "https://api.openai.com/v1",
    "openai-compatible":  "",
    "deepseek":           "https://api.deepseek.com/v1",
    "zhipu":              "https://open.bigmodel.cn/api/paas/v4",
    "qwen":               "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "ollama":             "http://localhost:11434/v1",
    "groq":               "https://api.groq.com/openai/v1",
    "moonshot":           "https://api.moonshot.cn/v1",
}

DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-haiku-4-5-20251001",
    "openai":    "gpt-4o-mini",
    "deepseek":  "deepseek-chat",
    "zhipu":     "glm-4-flash",
    "qwen":      "qwen-turbo",
    "ollama":    "llama3.2",
    "groq":      "llama-3.3-70b-versatile",
    "moonshot":  "moonshot-v1-8k",
}


@dataclass
class DetectorConfig:
    # LLM settings
    llm_api_key: str = ""
    llm_model: str = ""
    llm_endpoint: str = ""
    llm_provider: str = "anthropic"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 50

    # Detection settings
    detection_method: str = "regex"  # "regex" | "llm" | "hybrid"
    hybrid_threshold_low: int = 0    # score <= this: normal, no LLM needed
    hybrid_threshold_high: int = 5   # score >= this: attack, no LLM needed

    # Cache settings
    llm_cache_path: str = "llm_cache.json"
    llm_cache_enabled: bool = True

    # I/O settings
    data_file: str = "translation_pia_dataset_shuffled.jsonl"
    output_dir: str = "."


def load_config() -> DetectorConfig:
    config = DetectorConfig()

    env_map = {
        "DETECTOR_LLM_API_KEY": "llm_api_key",
        "DETECTOR_LLM_MODEL": "llm_model",
        "DETECTOR_LLM_ENDPOINT": "llm_endpoint",
        "DETECTOR_LLM_PROVIDER": "llm_provider",
        "DETECTOR_LLM_TEMPERATURE": "llm_temperature",
        "DETECTOR_LLM_MAX_TOKENS": "llm_max_tokens",
        "DETECTOR_DETECTION_METHOD": "detection_method",
        "DETECTOR_HYBRID_THRESHOLD_LOW": "hybrid_threshold_low",
        "DETECTOR_HYBRID_THRESHOLD_HIGH": "hybrid_threshold_high",
        "DETECTOR_LLM_CACHE_PATH": "llm_cache_path",
        "DETECTOR_LLM_CACHE_ENABLED": "llm_cache_enabled",
        "DETECTOR_DATA_FILE": "data_file",
        "DETECTOR_OUTPUT_DIR": "output_dir",
    }

    for env_var, attr in env_map.items():
        val = os.environ.get(env_var)
        if val is not None:
            field_type = type(getattr(config, attr))
            if field_type is bool:
                setattr(config, attr, val.lower() in ("1", "true", "yes"))
            elif field_type is int:
                setattr(config, attr, int(val))
            elif field_type is float:
                setattr(config, attr, float(val))
            else:
                setattr(config, attr, val)

    # Auto-fill endpoint/model from provider preset (if not explicitly set)
    provider = config.llm_provider
    if provider in PROVIDER_ENDPOINTS:
        if not config.llm_endpoint:
            endpoint = PROVIDER_ENDPOINTS[provider]
            if not endpoint:
                raise ValueError(
                    f"Provider '{provider}' requires an explicit endpoint. "
                    "Set DETECTOR_LLM_ENDPOINT or pass --endpoint."
                )
            config.llm_endpoint = endpoint
        if not config.llm_model:
            config.llm_model = DEFAULT_MODELS.get(provider, "")

    return config
