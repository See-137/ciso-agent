"""Inference identifiers and pins refuse a trailing newline.

`$` also matches just before a final line feed, so `^...$` with `.match()` accepted a
sha256 pin, a label or a slug ending in `"\\n"`. Each test names the site it guards.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ciso.common.schemas import sha256_hex
from ciso.inference import InferenceRequest
from ciso.inference.manifest import ModelArtifact, PromptTemplate
from ciso.inference.records import ContextRef

pytestmark = pytest.mark.unit

TEXT = "Summarise {{finding}}."
PIN = sha256_hex(TEXT.encode("utf-8"))


def _artifact(sha256: str) -> ModelArtifact:
    return ModelArtifact(id="local-model", version="1", sha256=sha256, source="local file")


def _request(**over: Any) -> InferenceRequest:
    fields: dict[str, Any] = {
        "task_category": "triage",
        "prompt_template_id": "triage.summary",
        "prompt_template_version": 1,
        "inputs": {},
        "correlation_id": "corr-1",
        "max_output_tokens": 16,
    }
    fields.update(over)
    return InferenceRequest(**fields)


# --- manifest.py: sha256 pin ----------------------------------------------------------


def test_model_artifact_pin_with_trailing_newline_is_refused() -> None:
    assert _artifact(PIN).sha256 == PIN
    with pytest.raises(ValidationError, match="sha256 must be 64 lowercase hex"):
        _artifact(PIN + "\n")


def test_prompt_template_pin_with_trailing_newline_is_refused_by_the_shape_check() -> None:
    assert PromptTemplate(id="t", version=1, text=TEXT, sha256=PIN).sha256 == PIN
    with pytest.raises(ValidationError, match="sha256 must be 64 lowercase hex"):
        PromptTemplate(id="t", version=1, text=TEXT, sha256=PIN + "\n")


# --- records.py: label and slug -------------------------------------------------------


def test_context_ref_classification_with_trailing_newline_is_refused() -> None:
    assert ContextRef(ref="finding:f1", classification="internal").classification == "internal"
    with pytest.raises(ValidationError, match="bad classification label shape"):
        ContextRef(ref="finding:f1", classification="internal\n")


def test_context_ref_with_trailing_newline_is_refused() -> None:
    with pytest.raises(ValidationError, match="bad entity ref"):
        ContextRef(ref="finding:f1\n", classification="internal")


@pytest.mark.parametrize("field", ["task_category", "prompt_template_id"])
def test_request_slug_with_trailing_newline_is_refused(field: str) -> None:
    assert getattr(_request(**{field: "triage.v2"}), field) == "triage.v2"
    with pytest.raises(ValidationError, match="expected a short lowercase identifier"):
        _request(**{field: "triage.v2\n"})


def test_request_slug_with_embedded_newline_is_refused() -> None:
    with pytest.raises(ValidationError, match="expected a short lowercase identifier"):
        _request(task_category="triage\nv2")
