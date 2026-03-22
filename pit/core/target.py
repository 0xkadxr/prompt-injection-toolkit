"""
Target LLM wrapper supporting multiple providers.

Provides a unified interface for sending prompts to OpenAI, Anthropic,
and local model endpoints with built-in rate limiting and retry logic.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx


class Provider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


@dataclass
class LLMConfig:
    """Configuration for a target LLM."""

    provider: Provider
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 1024
    rate_limit_rpm: int = 60
    max_retries: int = 3
    retry_delay: float = 1.0
    timeout: float = 30.0
    extra_params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Message:
    """A single message in a conversation."""

    role: str  # "system", "user", "assistant"
    content: str


@dataclass
class LLMResponse:
    """Response from a target LLM."""

    content: str
    raw_response: dict[str, Any]
    latency_ms: float
    provider: Provider
    model: str
    tokens_used: Optional[int] = None


class RateLimiter:
    """Token-bucket rate limiter for API calls."""

    def __init__(self, requests_per_minute: int) -> None:
        self.rpm = requests_per_minute
        self.interval = 60.0 / requests_per_minute if requests_per_minute > 0 else 0
        self._last_request: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.interval:
                await asyncio.sleep(self.interval - elapsed)
            self._last_request = time.monotonic()

    def acquire_sync(self) -> None:
        """Synchronous version of acquire."""
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self._last_request = time.monotonic()


class TargetLLM:
    """
    Unified wrapper for target LLM endpoints.

    Supports OpenAI, Anthropic, and local model servers with a consistent
    interface for sending single prompts and multi-turn conversations.

    Example:
        >>> config = LLMConfig(provider=Provider.OPENAI, model="gpt-4", api_key="sk-...")
        >>> target = TargetLLM(config)
        >>> response = target.send("Hello, who are you?", system_prompt="You are helpful.")
        >>> print(response.content)
    """

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self._rate_limiter = RateLimiter(config.rate_limit_rpm)
        self._client: Optional[httpx.AsyncClient] = None
        self._sync_client: Optional[httpx.Client] = None

    def _get_sync_client(self) -> httpx.Client:
        """Get or create the synchronous HTTP client."""
        if self._sync_client is None:
            self._sync_client = httpx.Client(timeout=self.config.timeout)
        return self._sync_client

    async def _get_async_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.config.timeout)
        return self._client

    def send(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> LLMResponse:
        """
        Send a single prompt to the target LLM synchronously.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt to prepend.

        Returns:
            LLMResponse with the model's response.
        """
        messages = []
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        messages.append(Message(role="user", content=prompt))
        return self.send_conversation(messages)

    def send_conversation(self, messages: list[Message]) -> LLMResponse:
        """
        Send a multi-turn conversation to the target LLM synchronously.

        Args:
            messages: List of Message objects forming the conversation.

        Returns:
            LLMResponse with the model's response.
        """
        self._rate_limiter.acquire_sync()

        last_error: Optional[Exception] = None
        for attempt in range(self.config.max_retries):
            try:
                start = time.perf_counter()
                response = self._dispatch_sync(messages)
                latency = (time.perf_counter() - start) * 1000
                return self._parse_response(response, latency)
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_error = exc
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2**attempt))

        raise ConnectionError(
            f"Failed after {self.config.max_retries} retries: {last_error}"
        )

    async def async_send(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> LLMResponse:
        """
        Send a single prompt to the target LLM asynchronously.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt to prepend.

        Returns:
            LLMResponse with the model's response.
        """
        messages = []
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        messages.append(Message(role="user", content=prompt))
        return await self.async_send_conversation(messages)

    async def async_send_conversation(self, messages: list[Message]) -> LLMResponse:
        """
        Send a multi-turn conversation to the target LLM asynchronously.

        Args:
            messages: List of Message objects forming the conversation.

        Returns:
            LLMResponse with the model's response.
        """
        await self._rate_limiter.acquire()

        last_error: Optional[Exception] = None
        for attempt in range(self.config.max_retries):
            try:
                start = time.perf_counter()
                response = await self._dispatch_async(messages)
                latency = (time.perf_counter() - start) * 1000
                return self._parse_response(response, latency)
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_error = exc
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_delay * (2**attempt))

        raise ConnectionError(
            f"Failed after {self.config.max_retries} retries: {last_error}"
        )

    def _build_openai_payload(self, messages: list[Message]) -> dict[str, Any]:
        """Build request payload for OpenAI-compatible APIs."""
        return {
            "model": self.config.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            **self.config.extra_params,
        }

    def _build_anthropic_payload(self, messages: list[Message]) -> dict[str, Any]:
        """Build request payload for the Anthropic API."""
        system_text = ""
        conversation: list[dict[str, str]] = []
        for m in messages:
            if m.role == "system":
                system_text = m.content
            else:
                conversation.append({"role": m.role, "content": m.content})

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": conversation,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            **self.config.extra_params,
        }
        if system_text:
            payload["system"] = system_text
        return payload

    def _get_url_and_headers(self) -> tuple[str, dict[str, str]]:
        """Return the endpoint URL and auth headers for the configured provider."""
        if self.config.provider == Provider.OPENAI:
            url = self.config.base_url or "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }
        elif self.config.provider == Provider.ANTHROPIC:
            url = self.config.base_url or "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": self.config.api_key or "",
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
        elif self.config.provider == Provider.LOCAL:
            url = self.config.base_url or "http://localhost:8000/v1/chat/completions"
            headers = {"Content-Type": "application/json"}
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"
        else:
            raise ValueError(f"Unsupported provider: {self.config.provider}")
        return url, headers

    def _dispatch_sync(self, messages: list[Message]) -> dict[str, Any]:
        """Send the request synchronously and return the raw JSON response."""
        url, headers = self._get_url_and_headers()

        if self.config.provider == Provider.ANTHROPIC:
            payload = self._build_anthropic_payload(messages)
        else:
            payload = self._build_openai_payload(messages)

        client = self._get_sync_client()
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def _dispatch_async(self, messages: list[Message]) -> dict[str, Any]:
        """Send the request asynchronously and return the raw JSON response."""
        url, headers = self._get_url_and_headers()

        if self.config.provider == Provider.ANTHROPIC:
            payload = self._build_anthropic_payload(messages)
        else:
            payload = self._build_openai_payload(messages)

        client = await self._get_async_client()
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def _parse_response(self, raw: dict[str, Any], latency_ms: float) -> LLMResponse:
        """Parse raw API JSON into a unified LLMResponse."""
        if self.config.provider == Provider.ANTHROPIC:
            content = ""
            for block in raw.get("content", []):
                if block.get("type") == "text":
                    content += block["text"]
            tokens = raw.get("usage", {}).get("output_tokens")
        else:
            # OpenAI / local format
            choices = raw.get("choices", [])
            content = choices[0]["message"]["content"] if choices else ""
            tokens = raw.get("usage", {}).get("completion_tokens")

        return LLMResponse(
            content=content,
            raw_response=raw,
            latency_ms=latency_ms,
            provider=self.config.provider,
            model=self.config.model,
            tokens_used=tokens,
        )

    async def close(self) -> None:
        """Close underlying HTTP clients."""
        if self._client:
            await self._client.aclose()
            self._client = None
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None

    def __repr__(self) -> str:
        return (
            f"TargetLLM(provider={self.config.provider.value!r}, "
            f"model={self.config.model!r})"
        )
