from __future__ import annotations

import abc


class LLMProviderError(RuntimeError):
    pass


class LLMUnavailableError(LLMProviderError):
    pass


class LLMTimeoutError(LLMProviderError):
    pass


class LLMResponseError(LLMProviderError):
    pass


class LLMProvider(abc.ABC):
    @abc.abstractmethod
    def health_check(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def list_models(self) -> list[str]:
        raise NotImplementedError

    @abc.abstractmethod
    def generate(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        timeout_seconds: float,
    ) -> str:
        raise NotImplementedError
