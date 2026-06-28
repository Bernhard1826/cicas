"""
LLM 客户端工具

支持 OpenAI-compatible 后端与 Anthropic Messages API，
并提供实验代码复用的最小共享调用辅助函数。
"""
import httpx
import re
import time
import random
import logging
from typing import Optional, Dict, Any, List
import json
import asyncio

logger = logging.getLogger(__name__)

_last_request_time: float = 0.0

OPENAI_COMPATIBLE_PROVIDER = "openai_compatible"
ANTHROPIC_PROVIDER = "anthropic"
DEFAULT_ANTHROPIC_API_BASE = "https://rsxermu666.cn"


def resolve_llm_provider(provider: Optional[str] = None, api_base: Optional[str] = None) -> str:
    """Resolve the concrete LLM provider from an explicit flag or API base."""
    normalized_provider = (provider or "").strip().lower()
    if normalized_provider in {"openai", "openai-compatible", "openai_compatible", "compatible"}:
        return OPENAI_COMPATIBLE_PROVIDER
    if normalized_provider == ANTHROPIC_PROVIDER:
        return ANTHROPIC_PROVIDER

    normalized_base = (api_base or "").strip().lower()
    if "api.anthropic.com" in normalized_base or "rsxermu666.cn" in normalized_base:
        return ANTHROPIC_PROVIDER
    return OPENAI_COMPATIBLE_PROVIDER


def normalize_api_base(api_base: Optional[str], provider: Optional[str] = None) -> str:
    """Normalize provider base URLs and fill Anthropic-compatible default base when omitted."""
    resolved_provider = resolve_llm_provider(provider=provider, api_base=api_base)
    normalized_base = (api_base or "").strip().rstrip("/")

    if normalized_base:
        return normalized_base
    if resolved_provider == ANTHROPIC_PROVIDER:
        return DEFAULT_ANTHROPIC_API_BASE
    return ""


def sanitize_llm_text_response(text: str) -> str:
    """Remove provider-specific reasoning wrappers and surrounding whitespace."""
    return re.sub(r'<think>.*?</think>\s*', '', text or '', flags=re.DOTALL).strip()


def _extract_openai_content(result: Dict[str, Any]) -> str:
    choices = result.get("choices") or []
    if not choices:
        return ""

    message = (choices[0] or {}).get("message") or {}
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
                continue
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
        return "".join(parts)
    return str(content or "")


def _extract_anthropic_content(result: Dict[str, Any]) -> str:
    content = result.get("content") or []
    if isinstance(content, str):
        return content

    parts: List[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
            continue
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return "".join(parts)


def extract_text_completion_content(result: Dict[str, Any], provider: Optional[str] = None, api_base: Optional[str] = None) -> str:
    """Extract plain text content from either OpenAI-compatible or Anthropic responses."""
    resolved_provider = resolve_llm_provider(provider=provider, api_base=api_base)
    if resolved_provider == ANTHROPIC_PROVIDER:
        return sanitize_llm_text_response(_extract_anthropic_content(result))
    return sanitize_llm_text_response(_extract_openai_content(result))


def call_text_completion(
    prompt: str,
    *,
    model: str,
    api_key: str = "",
    api_base: Optional[str] = None,
    provider: Optional[str] = None,
    system_prompt: Optional[str] = None,
    temperature: float = 0,
    max_tokens: int = 4000,
    max_retries: int = 3,
    timeout: float = 120.0,
) -> str:
    """Call either an OpenAI-compatible chat endpoint or Anthropic Messages API."""
    resolved_provider = resolve_llm_provider(provider=provider, api_base=api_base)
    resolved_api_base = normalize_api_base(api_base=api_base, provider=resolved_provider)

    if resolved_provider == ANTHROPIC_PROVIDER:
        url = f"{resolved_api_base}/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if api_key and api_key.strip():
            headers["x-api-key"] = api_key

        payload: Dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if system_prompt:
            payload["system"] = system_prompt
    else:
        if not resolved_api_base:
            raise ValueError("api_base is required for openai-compatible providers")

        url = f"{resolved_api_base}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key and api_key.strip():
            headers["Authorization"] = f"Bearer {api_key}"
        if "googleapis.com" in resolved_api_base and api_key:
            headers["x-goog-api-key"] = api_key

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        else:
            # Some OpenAI-compatible gateways (e.g. ai.ailink1.com) REQUIRE a
            # system message (else HTTP 400 "Instructions are required"). When the
            # caller folded instructions into the user prompt, send a minimal one.
            messages.append({"role": "system",
                             "content": "You are a precise, controlled parser. "
                                        "Follow the user's instructions exactly."})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

    # ai.ailink1.com intermittently returns transient 5xx (503/502/500/504) and
    # 429/529 — all retryable with backoff (matches synonym_judge's _call_ailink).
    retryable_statuses = {429, 500, 502, 503, 504, 529}

    for attempt in range(max_retries + 1):
        try:
            with httpx.Client(trust_env=False, timeout=timeout) as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                result = response.json()
            return extract_text_completion_content(result, provider=resolved_provider, api_base=resolved_api_base)
        except httpx.HTTPStatusError as e:
            if e.response.status_code in retryable_statuses and attempt < max_retries:
                delay = (2 ** attempt) * 8 + random.uniform(0, 5)
                time.sleep(delay)
                continue
            try:
                error_detail = e.response.json()
            except Exception:
                error_detail = e.response.text[:500]
            raise Exception(f"HTTP {e.response.status_code}: {error_detail}") from e
        except (httpx.TimeoutException, httpx.ConnectError):
            if attempt < max_retries:
                delay = (2 ** attempt) * 2
                time.sleep(delay)
                continue
            raise


def create_async_llm_client(
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: float = 60.0,
    provider: Optional[str] = None,
) -> httpx.AsyncClient:
    """构造一个带 base_url 与鉴权头的 httpx.AsyncClient，供 OpenAI 兼容 / Anthropic 端点直接调用。"""
    resolved_base = normalize_api_base(base_url, provider=provider)
    resolved_provider = resolve_llm_provider(provider=provider, api_base=resolved_base)

    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if resolved_provider == ANTHROPIC_PROVIDER:
        headers["anthropic-version"] = "2023-06-01"
        if api_key:
            headers["x-api-key"] = api_key
    else:
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if "googleapis.com" in (resolved_base or "").lower() and api_key:
            headers["x-goog-api-key"] = api_key

    return httpx.AsyncClient(base_url=resolved_base, headers=headers, timeout=timeout)


class LLMClient:
    """LLM客户端"""

    def __init__(self, model: str, temperature: float = 0, max_tokens: int = 500):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def _resolve_runtime(self, api_key: Optional[str] = None, api_base: Optional[str] = None):
        from app.core.config import settings

        resolved_api_key = api_key if api_key is not None else settings.llm_api_key
        configured_provider = getattr(settings, "llm_provider", None)
        resolved_api_base = normalize_api_base(
            api_base if api_base is not None else settings.llm_api_base,
            provider=configured_provider,
        )
        resolved_provider = resolve_llm_provider(
            provider=configured_provider,
            api_base=resolved_api_base,
        )
        return resolved_api_key, resolved_api_base, resolved_provider

    def _build_headers(self, api_key: str, api_base: str, provider: str) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if provider == ANTHROPIC_PROVIDER:
            headers["anthropic-version"] = "2023-06-01"
            if api_key and api_key.strip():
                headers["x-api-key"] = api_key
            return headers

        if api_key and api_key.strip():
            headers["Authorization"] = f"Bearer {api_key}"
        if "googleapis.com" in (api_base or "").lower() and api_key:
            headers["x-goog-api-key"] = api_key
        return headers

    def _build_payload(
        self,
        prompt: str,
        *,
        provider: str,
        api_base: str,
        max_tokens_override: Optional[int] = None,
        response_format: Optional[Dict[str, Any]] = None,
        system_prompt: Optional[str] = None,
        stream: bool = False,
    ) -> Dict[str, Any]:
        max_tokens = max_tokens_override or self.max_tokens
        if provider == ANTHROPIC_PROVIDER:
            payload: Dict[str, Any] = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.temperature,
                "max_tokens": max_tokens,
            }
            if system_prompt:
                payload["system"] = system_prompt
            if stream:
                payload["stream"] = True
            return payload

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        else:
            # Some OpenAI-compatible gateways (e.g. ai.ailink1.com) REQUIRE a
            # system message (else HTTP 400 "Instructions are required"). When the
            # caller folded instructions into the user prompt, send a minimal one.
            messages.append({"role": "system",
                             "content": "You are a precise, controlled parser. "
                                        "Follow the user's instructions exactly."})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
            **self._get_determinism_options(api_base=api_base, response_format=response_format)
        }
        if stream:
            payload["stream"] = True
        return payload

    def _build_url(self, api_base: str, provider: str) -> str:
        if provider == ANTHROPIC_PROVIDER:
            return f"{api_base}/v1/messages"
        return f"{api_base}/chat/completions"

    def _extract_stream_chunk_text(self, chunk: Dict[str, Any], provider: str) -> str:
        if provider == ANTHROPIC_PROVIDER:
            if chunk.get("type") == "content_block_delta":
                delta = chunk.get("delta") or {}
                text = delta.get("text")
                if isinstance(text, str):
                    return text
            return ""

        # gpt-5.4/OpenAI 流会发 choices 为空 [] 的 chunk(usage/keepalive/收尾)。
        # `.get("choices",[{}])` 的默认只在 key 缺失时生效；choices=[] 时 [0] 会
        # IndexError(批量流式路径曾每个 batch 整批崩)。空 choices 安全返回 ""。
        choices = chunk.get("choices") or []
        if not choices:
            return ""
        delta = (choices[0] or {}).get("delta", {}) or {}
        content = delta.get("content")
        if isinstance(content, str):
            return content
        return ""

    def _is_stream_done_event(self, data_str: str, provider: str) -> bool:
        if data_str == "[DONE]":
            return True
        if provider != ANTHROPIC_PROVIDER:
            return False
        try:
            chunk = json.loads(data_str)
        except Exception:
            return False
        return chunk.get("type") == "message_stop"

    def _get_determinism_options(self, api_base: str, response_format: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        api_base_lower = (api_base or "").lower()
        options: Dict[str, Any] = {}
        if "googleapis.com" not in api_base_lower and any(key in api_base_lower for key in ("openai", "openrouter", "siliconflow")):
            options["seed"] = 42
        if response_format:
            options["response_format"] = response_format
        return options

    def generate(self, prompt: str, api_key: Optional[str] = None, api_base: Optional[str] = None, max_retries: int = 3, max_tokens_override: Optional[int] = None, response_format: Optional[Dict[str, Any]] = None, timeout_override: Optional[float] = None) -> str:
        resolved_api_key, resolved_api_base, resolved_provider = self._resolve_runtime(api_key=api_key, api_base=api_base)
        url = self._build_url(resolved_api_base, resolved_provider)
        headers = self._build_headers(resolved_api_key, resolved_api_base, resolved_provider)
        payload = self._build_payload(
            prompt,
            provider=resolved_provider,
            api_base=resolved_api_base,
            max_tokens_override=max_tokens_override,
            response_format=response_format,
            stream=False,
        )

        last_error = None
        for attempt in range(max_retries + 1):
            try:
                timeout = httpx.Timeout(connect=30.0, read=timeout_override or 300.0, write=30.0, pool=30.0)
                with httpx.Client(trust_env=False, timeout=timeout) as client:
                    # Non-streaming for BOTH providers. ai.ailink1.com (and some other
                    # OpenAI-compatible gateways) do not emit a usable SSE stream, so the
                    # old streaming path returned empty text → "list index out of range".
                    # generate_async already uses this non-streaming shape.
                    response = client.post(url, headers=headers, json=payload)
                    response.raise_for_status()
                    result = response.json()
                    content = extract_text_completion_content(result, provider=resolved_provider, api_base=resolved_api_base)
                # Some OpenAI-compatible gateways intermittently return HTTP 200 with
                # a BLANK body (downstream then sees "JSON 解析失败: Expecting value
                # line 1 column 1"). A 200 doesn't trip raise_for_status, so without
                # this guard the empty string was returned and recorded as a permanent
                # no_result. Treat an empty/whitespace response as a transient failure
                # and retry with backoff. Provider-agnostic — applies to any endpoint.
                if content is None or not str(content).strip():
                    raise ValueError("empty LLM response (HTTP 200, blank body) — retryable")
                return content
            except Exception as e:
                last_error = e
                if attempt < max_retries:
                    time.sleep(2 ** attempt + 1)
                    continue
                raise last_error

    async def generate_async(self, prompt: str, client: httpx.AsyncClient, api_key: Optional[str] = None, api_base: Optional[str] = None, max_tokens_override: Optional[int] = None, response_format: Optional[Dict[str, Any]] = None) -> str:
        resolved_api_key, resolved_api_base, resolved_provider = self._resolve_runtime(api_key=api_key, api_base=api_base)
        url = self._build_url(resolved_api_base, resolved_provider)
        headers = self._build_headers(resolved_api_key, resolved_api_base, resolved_provider)
        payload = self._build_payload(
            prompt,
            provider=resolved_provider,
            api_base=resolved_api_base,
            max_tokens_override=max_tokens_override,
            response_format=response_format,
        )

        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()
        return extract_text_completion_content(result, provider=resolved_provider, api_base=resolved_api_base)

    async def generate_async_stream(self, prompt: str, client: httpx.AsyncClient, system_prompt: Optional[str] = None, api_key: Optional[str] = None, api_base: Optional[str] = None, max_tokens_override: Optional[int] = None, response_format: Optional[Dict[str, Any]] = None) -> str:
        resolved_api_key, resolved_api_base, resolved_provider = self._resolve_runtime(api_key=api_key, api_base=api_base)
        url = self._build_url(resolved_api_base, resolved_provider)
        headers = self._build_headers(resolved_api_key, resolved_api_base, resolved_provider)
        payload = self._build_payload(
            prompt,
            provider=resolved_provider,
            api_base=resolved_api_base,
            max_tokens_override=max_tokens_override,
            response_format=response_format,
            system_prompt=system_prompt,
            stream=resolved_provider != ANTHROPIC_PROVIDER,
        )

        if resolved_provider == ANTHROPIC_PROVIDER:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()
            return extract_text_completion_content(result, provider=resolved_provider, api_base=resolved_api_base)

        response_text = ""
        async with client.stream("POST", url, headers=headers, json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                data_str = line[len("data: "):]
                if self._is_stream_done_event(data_str, resolved_provider):
                    break
                try:
                    chunk = json.loads(data_str)
                except Exception:
                    continue
                response_text += self._extract_stream_chunk_text(chunk, resolved_provider)

        return sanitize_llm_text_response(response_text)
