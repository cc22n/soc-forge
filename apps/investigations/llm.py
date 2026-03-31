"""
LLM provider abstraction for SOC Forge investigation summaries.

Configure via .env:
    LLM_PROVIDER=anthropic   # anthropic | openai | groq | grok | gemini
    LLM_MODEL=               # optional — overrides the provider default

Provider defaults:
    anthropic → claude-haiku-4-5-20251001
    openai    → gpt-4o-mini
    groq      → llama-3.3-70b-versatile
    grok      → grok-3-mini
    gemini    → gemini-2.0-flash

Groq, xAI (Grok), and Gemini all expose an OpenAI-compatible REST API,
so the `openai` SDK covers all three — no extra dependencies required.
"""

from django.conf import settings

# Default model for each provider
_PROVIDER_MODELS: dict[str, str] = {
    "anthropic": "claude-haiku-4-5-20251001",
    "openai":    "gpt-4o-mini",
    "groq":      "llama-3.3-70b-versatile",
    "grok":      "grok-3-mini",
    "gemini":    "gemini-2.0-flash",
}

# OpenAI-compatible base URLs for non-OpenAI providers
_OPENAI_COMPAT_URLS: dict[str, str] = {
    "groq":   "https://api.groq.com/openai/v1",
    "grok":   "https://api.x.ai/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
}

# Which settings attribute holds each provider's API key
_KEY_SETTING: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai":    "OPENAI_API_KEY",
    "groq":      "GROQ_API_KEY",
    "grok":      "GROK_API_KEY",
    "gemini":    "GEMINI_API_KEY",
}

# Human-readable labels for the UI
PROVIDER_LABELS: dict[str, str] = {
    "anthropic": "Claude Haiku (Anthropic)",
    "openai":    "GPT-4o Mini (OpenAI)",
    "groq":      "Llama 3.3 70B (Groq)",
    "grok":      "Grok 3 Mini (xAI)",
    "gemini":    "Gemini 2.0 Flash (Google)",
}


class LLMNotConfiguredError(ValueError):
    """Raised when the selected provider has no API key set."""


def get_provider_config() -> tuple[str, str, str]:
    """
    Read provider/model/key from settings.

    Returns:
        (provider, api_key, model)

    Raises:
        LLMNotConfiguredError — no API key for the selected provider
        ValueError            — unknown provider name
    """
    provider = getattr(settings, "LLM_PROVIDER", "anthropic").lower().strip()

    if provider not in _PROVIDER_MODELS:
        raise ValueError(
            f"Unknown LLM_PROVIDER '{provider}'. "
            f"Valid values: {', '.join(_PROVIDER_MODELS)}"
        )

    key_attr = _KEY_SETTING[provider]
    api_key = getattr(settings, key_attr, "").strip()
    if not api_key:
        raise LLMNotConfiguredError(
            f"Set {key_attr} (and LLM_PROVIDER={provider}) in .env to enable AI summaries."
        )

    # LLM_MODEL overrides the provider default when explicitly set
    model = (getattr(settings, "LLM_MODEL", "") or "").strip() or _PROVIDER_MODELS[provider]
    return provider, api_key, model


def call_llm(prompt: str) -> str:
    """
    Send *prompt* to the configured LLM and return the raw text response.

    Raises:
        LLMNotConfiguredError — provider not configured
        Exception             — API/network error (caller logs + returns 502)
    """
    provider, api_key, model = get_provider_config()

    if provider == "anthropic":
        return _anthropic(api_key, model, prompt)
    return _openai_compat(provider, api_key, model, prompt)


# ─── Private helpers ─────────────────────────────────────────────────────────

def _anthropic(api_key: str, model: str, prompt: str) -> str:
    import anthropic  # noqa: PLC0415
    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text.strip()


def _openai_compat(provider: str, api_key: str, model: str, prompt: str) -> str:
    """Handles openai, groq, grok, and gemini (all OpenAI-compatible)."""
    from openai import OpenAI  # noqa: PLC0415
    kwargs: dict = {"api_key": api_key}
    if provider in _OPENAI_COMPAT_URLS:
        kwargs["base_url"] = _OPENAI_COMPAT_URLS[provider]
    client = OpenAI(**kwargs)
    resp = client.chat.completions.create(
        model=model,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content.strip()
