"""
LLM 호출 통합 인터페이스.

기존 Claude/Anthropic 경로를 제거하고, 로컬/원격 Ollama HTTP API 하나만 공용
진입점으로 사용한다. 외부 호출 시그니처(`call`, `call_json`, `call_with_tools`)
는 유지해서 기존 모듈의 동작 표면은 바꾸지 않는다.
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from dataclasses import dataclass
from typing import Any
from urllib import error, request

from core import config  # noqa: F401 - import 시점에 .env를 로드함

_BASE_URL = os.getenv("PENTEST_AGENT_OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
_DEFAULT_MODEL = os.getenv("PENTEST_AGENT_OLLAMA_MODEL", "llama3.2:latest")
_TOOL_MODEL = os.getenv("PENTEST_AGENT_OLLAMA_TOOL_MODEL", _DEFAULT_MODEL)
_TIMEOUT = float(os.getenv("PENTEST_AGENT_OLLAMA_TIMEOUT_SECONDS", "120"))


class RefusalError(RuntimeError):
    """모델이 안전 정책이나 기타 이유로 응답을 거부한 경우."""


@dataclass
class TextBlock:
    type: str
    text: str


@dataclass
class ToolUseBlock:
    type: str
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class ToolMessage:
    content: list[Any]
    stop_reason: str


def _resolve_model(requested_model: str | None, *, tool_mode: bool = False) -> str:
    if tool_mode:
        return _TOOL_MODEL
    if requested_model and requested_model != "claude-sonnet-5":
        return requested_model
    return _DEFAULT_MODEL


def _print_token_usage(label: str, payload: dict[str, Any]) -> None:
    prompt_tokens = int(payload.get("prompt_eval_count") or 0)
    output_tokens = int(payload.get("eval_count") or 0)
    total_duration = int(payload.get("total_duration") or 0)
    print(
        f"[llm_client] {label} 호출: 토큰 입력 {prompt_tokens}, 출력 {output_tokens}, "
        f"총 {round(total_duration / 1_000_000, 1)}ms"
    )


def _request_json(path: str, payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    http_request = request.Request(
        f"{_BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
    except error.HTTPError as exc:
        raise RuntimeError(f"ollama request failed with status {exc.code}") from exc
    except error.URLError as exc:
        if isinstance(exc.reason, socket.timeout):
            raise RuntimeError("ollama request timed out") from exc
        raise RuntimeError(f"ollama unavailable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError("ollama request timed out") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ollama returned invalid json") from exc


def _call_generate(
    prompt: str,
    *,
    model: str,
    max_tokens: int,
    response_format: str | dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": max_tokens,
        },
    }
    if response_format is not None:
        payload["format"] = response_format
    data = _request_json("/api/generate", payload, _TIMEOUT)
    response_text = str(data.get("response") or "").strip()
    if not response_text:
        raise RuntimeError("ollama returned an empty response")
    if "cannot assist" in response_text.lower() or "can't assist" in response_text.lower():
        raise RefusalError(response_text)
    _print_token_usage("Ollama", data)
    return data


def call(prompt: str, model: str = _DEFAULT_MODEL, max_tokens: int = 1024) -> str:
    data = _call_generate(prompt, model=_resolve_model(model), max_tokens=max_tokens)
    return str(data.get("response") or "").strip()


def _tool_name_from_id(tool_use_id: str) -> str:
    return tool_use_id.split(":", 1)[0]


def _flatten_tool_result_content(items: list[dict[str, Any]]) -> tuple[str, list[str]]:
    texts: list[str] = []
    images: list[str] = []
    for item in items:
        item_type = item.get("type")
        if item_type == "text":
            texts.append(str(item.get("text") or ""))
        elif item_type == "image":
            source = item.get("source") or {}
            data = source.get("data")
            if data:
                images.append(str(data))
            texts.append("[image attached]")
    return "\n".join(t for t in texts if t).strip(), images


def _assistant_content_to_message(content: list[Any]) -> dict[str, Any]:
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in content:
        if getattr(block, "type", None) == "text":
            text_parts.append(getattr(block, "text", ""))
        elif getattr(block, "type", None) == "tool_use":
            tool_calls.append(
                {
                    "function": {
                        "name": block.name,
                        "arguments": block.input,
                    }
                }
            )
    payload: dict[str, Any] = {
        "role": "assistant",
        "content": "\n".join(part for part in text_parts if part).strip(),
    }
    if tool_calls:
        payload["tool_calls"] = tool_calls
    return payload


def _history_to_ollama_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    converted: list[dict[str, Any]] = []
    for message in messages:
        role = message["role"]
        content = message.get("content")
        if isinstance(content, str):
            converted.append({"role": role, "content": content})
            continue
        if role == "assistant" and isinstance(content, list):
            converted.append(_assistant_content_to_message(content))
            continue
        if role == "user" and isinstance(content, list):
            for item in content:
                if item.get("type") != "tool_result":
                    continue
                text, images = _flatten_tool_result_content(item.get("content") or [])
                tool_message: dict[str, Any] = {
                    "role": "tool",
                    "content": text or "(empty tool result)",
                    "tool_name": _tool_name_from_id(str(item.get("tool_use_id") or "")),
                }
                if images:
                    tool_message["images"] = images
                converted.append(tool_message)
    return converted


def _anthropic_tools_to_ollama(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    converted = []
    for tool in tools:
        converted.append(
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
                },
            }
        )
    return converted


def call_with_tools(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    model: str = _TOOL_MODEL,
    max_tokens: int = 2048,
) -> ToolMessage:
    payload = {
        "model": _resolve_model(model, tool_mode=True),
        "messages": _history_to_ollama_messages(messages),
        "tools": _anthropic_tools_to_ollama(tools),
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": max_tokens,
        },
    }
    data = _request_json("/api/chat", payload, _TIMEOUT)
    _print_token_usage("Ollama(tools)", data)
    message = data.get("message") or {}
    content: list[Any] = []
    text = str(message.get("content") or "").strip()
    if text:
        if "cannot assist" in text.lower() or "can't assist" in text.lower():
            return ToolMessage(content=[TextBlock(type="text", text=text)], stop_reason="refusal")
        content.append(TextBlock(type="text", text=text))

    for raw_call in message.get("tool_calls") or []:
        function = raw_call.get("function") or {}
        name = str(function.get("name") or "")
        args = function.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"raw": args}
        content.append(
            ToolUseBlock(
                type="tool_use",
                id=f"{name}:{uuid.uuid4().hex[:12]}",
                name=name,
                input=args,
            )
        )

    stop_reason = "tool_use" if any(getattr(block, "type", None) == "tool_use" for block in content) else "end_turn"
    return ToolMessage(content=content, stop_reason=stop_reason)


def call_json(prompt: str, model: str = _DEFAULT_MODEL, max_tokens: int = 1024) -> dict[str, Any]:
    data = _call_generate(prompt, model=_resolve_model(model), max_tokens=max_tokens, response_format="json")
    text = str(data.get("response") or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError(f"응답에서 JSON을 찾을 수 없음: {text[:200]!r}")
        return json.loads(text[start:end + 1])
