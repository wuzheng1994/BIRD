import json
from collections import defaultdict
from pathlib import Path

from langchain_core.callbacks import BaseCallbackHandler
from langchain_community.chat_models.tongyi import ChatTongyi


class TokenUsageTracer(BaseCallbackHandler):
    def __init__(self):
        self._pending = {}
        self.calls = []
        self.current_stage = "planning"

    def reset(self):
        self._pending.clear()
        self.calls.clear()
        self.current_stage = "planning"

    def set_stage(self, stage):
        self.current_stage = stage

    def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
        role_chars = defaultdict(int)

        for prompt in messages:
            for message in prompt:
                role = getattr(message, "type", message.__class__.__name__)
                role_chars[role] += len(str(message.content))

        self._pending[str(run_id)] = {
            "prompt_chars_by_role": dict(role_chars),
        }

    def on_llm_end(self, response, *, run_id, **kwargs):
        usage = {}

        if response.generations and response.generations[0]:
            message = response.generations[0][0].message
            metadata = getattr(message, "response_metadata", {}) or {}

            usage = (
                getattr(message, "usage_metadata", None)
                or metadata.get("token_usage", {})
            )

        if not usage:
            usage = (response.llm_output or {}).get("token_usage", {})

        input_tokens = usage.get(
            "input_tokens", usage.get("prompt_tokens", 0)
        )
        output_tokens = usage.get(
            "output_tokens", usage.get("completion_tokens", 0)
        )
        total_tokens = usage.get(
            "total_tokens", input_tokens + output_tokens
        )

        call = self._pending.pop(str(run_id), {})
        call.update({
            "stage": self.current_stage,
            "kind": "chat",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
        })
        self.calls.append(call)

    def record_call(
        self,
        *,
        kind: str = "embedding",
        input_tokens: int = 0,
        output_tokens: int = 0,
        total_tokens: int | None = None,
        extra: dict | None = None,
    ) -> None:
        total = (
            total_tokens
            if total_tokens is not None
            else input_tokens + output_tokens
        )
        call = {
            "stage": self.current_stage,
            "kind": kind,
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "total_tokens": int(total or 0),
        }
        if extra:
            call.update(extra)
        self.calls.append(call)

    def write_report(self, path):
        summary = {
            "input_tokens": sum(
                call["input_tokens"] for call in self.calls
            ),
            "output_tokens": sum(
                call["output_tokens"] for call in self.calls
            ),
            "total_tokens": sum(
                call["total_tokens"] for call in self.calls
            ),
        }

        by_stage = {}

        for call in self.calls:
            stage = call.get("stage", "planning")

            if stage not in by_stage:
                by_stage[stage] = {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                }

            by_stage[stage]["calls"] += 1
            by_stage[stage]["input_tokens"] += call["input_tokens"]
            by_stage[stage]["output_tokens"] += call["output_tokens"]
            by_stage[stage]["total_tokens"] += call["total_tokens"]

        report = {
            "summary": summary,
            "by_stage": by_stage,
            "calls": self.calls,
        }

        Path(path).write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


token_tracer = TokenUsageTracer()


def _configure_ca_bundle() -> None:
    import os

    bundle = Path(__file__).resolve().parent / "certs" / "ca-bundle.pem"
    if bundle.exists() and bundle.stat().st_size > 0:
        path = str(bundle)
        os.environ.setdefault("REQUESTS_CA_BUNDLE", path)
        os.environ.setdefault("SSL_CERT_FILE", path)
        os.environ.setdefault("CURL_CA_BUNDLE", path)


_configure_ca_bundle()


def get_llms():
    from config import config

    api_key = config.DASHSCOPE_API_KEY
    if not api_key:
        raise RuntimeError(
            "DASHSCOPE_API_KEY is not set. Copy .env.example to .env and add your key."
        )
    return ChatTongyi(
        model="deepseek-v4-flash-0731",
        temperature=0,
        api_key=api_key,
        callbacks=[token_tracer],
    )


def _dashscope_usage_tokens(resp) -> int:
    usage = getattr(resp, "usage", None)
    if usage is None:
        return 0
    if isinstance(usage, dict):
        return int(
            usage.get("total_tokens")
            or usage.get("input_tokens")
            or 0
        )
    return int(
        getattr(usage, "total_tokens", 0)
        or getattr(usage, "input_tokens", 0)
        or 0
    )


class _TracedEmbeddingClient:
    def __init__(self, inner):
        self._inner = inner

    def call(self, **kwargs):
        resp = self._inner.call(**kwargs)
        token_tracer.record_call(
            kind="embedding",
            input_tokens=_dashscope_usage_tokens(resp),
            output_tokens=0,
        )
        return resp


def get_embeddings():
    from langchain_community.embeddings import DashScopeEmbeddings
    from config import config

    impl = DashScopeEmbeddings(
        dashscope_api_key=config.DASHSCOPE_API_KEY,
        model="text-embedding-v4",
    )
    impl.client = _TracedEmbeddingClient(impl.client)
    return impl


llms = get_llms()