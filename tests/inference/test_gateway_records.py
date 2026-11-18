"""Output wrapper, redaction, invocation records, audit content, exception hygiene."""

from __future__ import annotations

import hashlib
import hmac
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel
from sqlalchemy import Engine, select, text
from tests.fakes.core import FakeAudit, FakeRedactor, FakeSecrets
from tests.inference.helpers import MARKER, OUTPUT_MARKER, SpyProvider

import ciso.inference.tables as tables
from ciso.common.clock import FixedClock
from ciso.common.errors import InferenceUnavailable, NotFound, ValidationFailed
from ciso.inference import (
    InferenceGateway,
    InferenceRequest,
    InvocationLog,
    Manifest,
    UntrustedModelOutput,
)

pytestmark = pytest.mark.unit

Build = Callable[..., InferenceGateway]
Req = Callable[..., InferenceRequest]
KEY_REF = "secret://inference-digest"
KEY_ONE = "digest-key-one-for-gateway-tests-0001"
KEY_TWO = "digest-key-two-for-gateway-tests-0002"


class Shape(BaseModel):
    stub: bool
    prompt_chars: int


class TestUntrustedOutput:
    def test_cannot_be_used_as_string(self, make_gateway: Build, make_request: Req) -> None:
        out = make_gateway().complete(make_request()).output
        with pytest.raises(TypeError):
            str(out)
        with pytest.raises(TypeError):
            f"{out}"
        with pytest.raises(TypeError):
            "prefix " + out  # type: ignore[operator]
        with pytest.raises(TypeError):
            out + "suffix"  # type: ignore[operator]
        with pytest.raises(TypeError):
            "%s" % out  # noqa: UP031
        assert out.unsafe_text().startswith("{")

    def test_class_is_final_and_repr_shows_no_digest(self) -> None:
        assert getattr(UntrustedModelOutput, "__final__", False) is True
        out = UntrustedModelOutput("no")
        assert not hasattr(out, "sha256")
        assert hashlib.sha256(b"no").hexdigest()[:12] not in repr(out)
        assert "no" not in repr(out).replace("UntrustedModelOutput", "")

    def test_parse_accepts_matching_and_rejects_mismatch(
        self, make_gateway: Build, make_request: Req
    ) -> None:
        good = make_gateway().complete(make_request()).output.parse(Shape)
        assert good.stub is True
        assert good.prompt_chars > 0
        bad = make_gateway(SpyProvider(text='{"stub": "LEAKY-VALUE"}')).complete(make_request())
        with pytest.raises(ValidationFailed) as info:
            bad.output.parse(Shape)
        assert "LEAKY-VALUE" not in str(info.value)
        with pytest.raises(ValidationFailed):
            UntrustedModelOutput("free text").parse(Shape)

    @pytest.mark.parametrize(
        "body",
        [f"not json {OUTPUT_MARKER}", f'{{"stub": "{OUTPUT_MARKER}", "prompt_chars": 1}}'],
        ids=["invalid-json", "bad-field-value"],
    )
    def test_parse_failure_traceback_carries_no_output(self, body: str) -> None:
        with pytest.raises(ValidationFailed) as info:
            UntrustedModelOutput(body).parse(Shape)
        formatted = "".join(traceback.format_exception(info.value))
        assert OUTPUT_MARKER not in formatted
        assert info.value.__cause__ is None
        assert info.value.__context__ is None


class TestExceptionHygiene:
    def test_provider_error_traceback_carries_no_prompt(
        self, make_gateway: Build, make_request: Req, engine: Engine, audit: FakeAudit
    ) -> None:
        spy = SpyProvider(echo_prompt_in_error=True)
        with pytest.raises(InferenceUnavailable) as info:
            make_gateway(spy).complete(make_request(inputs={"evidence": MARKER}))
        assert MARKER in spy.calls[0].prompt  # the provider really did echo it
        formatted = "".join(traceback.format_exception(info.value))
        assert MARKER not in formatted
        assert info.value.__cause__ is None
        assert info.value.__context__ is None
        rec = InvocationLog(engine).for_correlation("corr-1")[0]
        assert rec.error_type == "RuntimeError"
        assert MARKER not in repr(rec)
        assert MARKER not in repr([e.details for e in audit.events])


class TestRedactionAndRendering:
    def test_inputs_redacted_before_provider(self, make_gateway: Build, make_request: Req) -> None:
        spy = SpyProvider()
        gw = make_gateway(spy, redactor=FakeRedactor("sekret-token"))
        gw.complete(make_request(inputs={"evidence": "the key is sekret-token ok"}))
        prompt = spy.calls[0].prompt
        assert "sekret-token" not in prompt
        assert "[REDACTED]" in prompt
        assert "BEGIN EVIDENCE" in prompt

    def test_template_inputs_must_match(self, make_gateway: Build, make_request: Req) -> None:
        spy = SpyProvider()
        with pytest.raises(ValidationFailed):
            make_gateway(spy).complete(make_request(inputs={"evidence": "x", "extra": "y"}))
        assert spy.calls == []

    def test_stub_is_deterministic(self, make_gateway: Build, make_request: Req) -> None:
        gw = make_gateway()
        a = gw.complete(make_request()).output.unsafe_text()
        assert gw.complete(make_request()).output.unsafe_text() == a
        assert gw.complete(make_request(inputs={"evidence": "other"})).output.unsafe_text() != a


class TestFrozenModels:
    def test_request_inputs_cannot_be_changed_in_place(self, make_request: Req) -> None:
        source = {"evidence": "original"}
        req = make_request(inputs=source)
        with pytest.raises(TypeError):
            req.inputs["evidence"] = "changed"  # type: ignore[index]
        with pytest.raises(TypeError):
            req.inputs["new"] = "x"  # type: ignore[index]
        source["evidence"] = "mutated after construction"
        assert req.inputs["evidence"] == "original"
        assert req.model_dump()["inputs"] == {"evidence": "original"}

    def test_refs_are_a_tuple_and_models_are_frozen(self, make_request: Req) -> None:
        req = make_request()
        assert isinstance(req.context_refs, tuple)
        with pytest.raises(ValueError, match="frozen"):
            req.correlation_id = "other"  # type: ignore[misc]

    def test_record_refs_are_a_tuple(
        self, make_gateway: Build, make_request: Req, engine: Engine
    ) -> None:
        result = make_gateway().complete(make_request())
        rec = InvocationLog(engine).get(result.record_id)
        assert rec is not None
        assert isinstance(rec.context_refs, tuple)
        with pytest.raises(ValueError, match="frozen"):
            rec.status = "x"  # type: ignore[misc]


class TestInvocationRecord:
    def test_record_has_every_field(
        self, make_gateway: Build, make_request: Req, engine: Engine, clock: FixedClock
    ) -> None:
        req = make_request(
            context_refs=[
                {"ref": "evidence:ev_1", "classification": "internal"},
                {"ref": "entity:ent_2", "classification": "unknown"},
            ]
        )
        result = make_gateway(SpyProvider(text='{"a": 1}')).complete(req)
        rec = InvocationLog(engine).get(result.record_id)
        assert rec is not None
        assert rec.occurred_at == clock.now()
        assert (rec.provider_name, rec.model_id, rec.model_version) == ("spy", "stub-local", "1")
        assert (rec.prompt_template_id, rec.prompt_template_version) == ("stub", 1)
        assert len(rec.prompt_template_sha256) == 64
        assert rec.task_category == "summarise"
        assert [(r.ref, r.classification) for r in rec.context_refs] == [
            ("evidence:ev_1", "internal"),
            ("entity:ent_2", "unknown"),
        ]
        assert rec.latency_seconds is not None
        assert rec.provider_reported_seconds == 0.1
        assert (rec.input_tokens, rec.output_tokens) == (11, 7)
        assert (rec.status, rec.error_type) == ("ok", None)
        assert rec.output_size == len('{"a": 1}')
        assert rec.correlation_id == "corr-1"

    def test_prompt_version_on_each_record(
        self, make_gateway: Build, make_request: Req, engine: Engine
    ) -> None:
        gw = make_gateway()
        gw.complete(make_request(correlation_id="c-a"))
        gw.complete(make_request(correlation_id="c-b"))
        versions = [
            r.prompt_template_version
            for cid in ("c-a", "c-b")
            for r in InvocationLog(engine).for_correlation(cid)
        ]
        assert versions == [1, 1]

    def test_no_digest_is_stored_without_a_key(
        self, make_gateway: Build, make_request: Req, engine: Engine, audit: FakeAudit
    ) -> None:
        result = make_gateway(SpyProvider(text="no")).complete(make_request())
        rec = InvocationLog(engine).get(result.record_id)
        assert rec is not None
        assert rec.output_digest is None
        assert audit.events[-1].details["output_digest"] is None

    def test_digest_is_keyed_when_a_key_is_configured(
        self, make_gateway: Build, make_request: Req, engine: Engine, audit: FakeAudit
    ) -> None:
        secrets = FakeSecrets({KEY_REF: KEY_ONE})
        gw = make_gateway(SpyProvider(text="no"), secrets=secrets, digest_key_ref=KEY_REF)
        result = gw.complete(make_request())
        rec = InvocationLog(engine).get(result.record_id)
        assert rec is not None
        expected = hmac.new(KEY_ONE.encode(), b"no", "sha256").hexdigest()
        assert rec.output_digest == expected
        assert rec.output_digest != hashlib.sha256(b"no").hexdigest()
        assert audit.events[-1].details["output_digest"] == expected
        other = FakeSecrets({KEY_REF: KEY_TWO})
        second = make_gateway(SpyProvider(text="no"), secrets=other, digest_key_ref=KEY_REF)
        again = InvocationLog(engine).get(second.complete(make_request()).record_id)
        assert again is not None
        assert again.output_digest != expected

    def test_missing_digest_key_stops_before_the_provider(
        self, make_gateway: Build, make_request: Req
    ) -> None:
        spy = SpyProvider()
        gw = make_gateway(spy, secrets=FakeSecrets(), digest_key_ref=KEY_REF)
        with pytest.raises(NotFound):
            gw.complete(make_request())
        assert spy.calls == []

    def test_no_prompt_or_output_body_in_database_file(
        self,
        tmp_path: Path,
        file_engine: Engine,
        make_gateway: Build,
        make_request: Req,
        manifest: Manifest,
    ) -> None:
        spy = SpyProvider(text=f'{{"note": "{OUTPUT_MARKER}"}}')
        secrets = FakeSecrets({KEY_REF: KEY_ONE})
        gw = make_gateway(spy, engine=file_engine, secrets=secrets, digest_key_ref=KEY_REF)
        gw.complete(make_request(inputs={"evidence": MARKER}))
        assert MARKER in spy.calls[0].prompt  # the provider did see it
        with file_engine.connect() as conn:
            assert conn.execute(text("select count(*) from inference_invocation")).scalar() == 1
            dump = repr(conn.execute(select(tables.inference_invocation)).all())
        assert MARKER not in dump
        assert OUTPUT_MARKER not in dump
        file_engine.dispose()
        files = list(tmp_path.glob("ops.db*"))
        assert files
        for f in files:
            raw = f.read_bytes()
            assert MARKER.encode() not in raw
            assert OUTPUT_MARKER.encode() not in raw


class TestAuditContent:
    def test_attempt_then_result_with_metadata_only(
        self, make_gateway: Build, make_request: Req, audit: FakeAudit
    ) -> None:
        make_gateway().complete(make_request(inputs={"evidence": MARKER}))
        events = audit.find("inference.local.complete")
        assert [e.outcome.value for e in events] == ["attempt", "success"]
        assert events[0].target == events[1].target
        assert MARKER not in repr([e.details for e in events])
        assert events[1].details["prompt_template_version"] == 1
        assert events[1].details["output_size"] > 0

    def test_failure_is_audited(
        self, make_gateway: Build, make_request: Req, audit: FakeAudit
    ) -> None:
        with pytest.raises(InferenceUnavailable):
            make_gateway(SpyProvider(raises=RuntimeError("x"))).complete(make_request())
        events = audit.find("inference.local.complete")
        assert [e.outcome.value for e in events] == ["attempt", "failed"]
        assert events[1].details["status"] == "provider_error"


def test_model_identity_is_read_once(
    make_gateway: Build, make_request: Req, engine: Engine
) -> None:
    from tests.inference.helpers import FlippingProvider

    provider: Any = FlippingProvider()
    gw = make_gateway(provider)
    reads_after_build = provider.reads
    result = gw.complete(make_request())
    assert provider.reads == reads_after_build
    assert result.model_version == "1"
