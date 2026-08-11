from __future__ import annotations

import json
import socket
from urllib import error, request

from app.llm.base import LLMProvider, LLMResponseError, LLMTimeoutError, LLMUnavailableError


class OllamaProvider(LLMProvider):
    def __init__(self, *, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def health_check(self) -> bool:
        try:
            self._request_json("/api/tags", payload=None, timeout_seconds=2.0)
        except LLMUnavailableError:
            return False
        return True

    def list_models(self) -> list[str]:
        response = self._request_json("/api/tags", payload=None, timeout_seconds=5.0)
        models = response.get("models") or []
        return [str(model.get("name")) for model in models if model.get("name")]

    def generate(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        timeout_seconds: float,
    ) -> str:
        payload = {
            "model": model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
            },
        }
        response = self._request_json("/api/generate", payload=payload, timeout_seconds=timeout_seconds)
        content = str(response.get("response") or "").strip()
        if not content:
            raise LLMResponseError("ollama returned an empty response")
        return content

    def _request_json(self, path: str, payload: dict | None, timeout_seconds: float) -> dict:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        http_request = request.Request(f"{self.base_url}{path}", data=data, headers=headers, method="POST" if data else "GET")
        try:
            with request.urlopen(http_request, timeout=timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as exc:
            raise LLMUnavailableError(f"ollama request failed with status {exc.code}") from exc
        except error.URLError as exc:
            if isinstance(exc.reason, socket.timeout):
                raise LLMTimeoutError("ollama request timed out") from exc
            raise LLMUnavailableError(f"ollama unavailable: {exc.reason}") from exc
        except TimeoutError as exc:
            raise LLMTimeoutError("ollama request timed out") from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMResponseError("ollama returned invalid json") from exc
