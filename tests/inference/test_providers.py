"""Providers are nominal and registered; the model pin is checked when the gateway is built."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest
from tests.inference.helpers import Impostor, RemoteProvider, RogueProvider, SpyProvider

from ciso.common.errors import IntegrityFailure
from ciso.inference import (
    DEFAULT_MANIFEST_PATH,
    InferenceGateway,
    StubLocalProvider,
    load_manifest,
)

pytestmark = [pytest.mark.unit, pytest.mark.external_inference]

Build = Callable[..., InferenceGateway]


def test_registered_provider_is_accepted(make_gateway: Build) -> None:
    assert make_gateway(StubLocalProvider()) is not None
    assert make_gateway(SpyProvider()) is not None


def test_structural_lookalike_is_refused(make_gateway: Build) -> None:
    with pytest.raises(TypeError):
        make_gateway(Impostor())


def test_unregistered_subclass_is_refused(make_gateway: Build) -> None:
    with pytest.raises(IntegrityFailure, match="not registered"):
        make_gateway(RogueProvider())


def test_subclass_of_a_registered_provider_is_refused(make_gateway: Build) -> None:
    class Sneaky(StubLocalProvider):
        pass

    with pytest.raises(IntegrityFailure, match="not registered"):
        make_gateway(Sneaky())


def test_remote_endpoint_is_refused_even_if_registered(make_gateway: Build) -> None:
    with pytest.raises(IntegrityFailure, match="in-process or loopback"):
        make_gateway(RemoteProvider())


def test_model_missing_from_manifest_is_refused(make_gateway: Build) -> None:
    with pytest.raises(IntegrityFailure, match="not listed"):
        make_gateway(SpyProvider(model_id="not-in-manifest"))


def _manifest_with_model_hash(tmp_path: Path, digest: str) -> Path:
    src = DEFAULT_MANIFEST_PATH.parent
    shutil.copy(src / "stub_v1.txt", tmp_path / "stub_v1.txt")
    data = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    data["models"][0]["sha256"] = digest
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_all_zero_model_hash_loads_but_gateway_refuses_it(
    tmp_path: Path, make_gateway: Build
) -> None:
    manifest = load_manifest(_manifest_with_model_hash(tmp_path, "0" * 64))
    with pytest.raises(IntegrityFailure, match="does not match"):
        make_gateway(StubLocalProvider(), manifest=manifest)


def test_matching_hash_in_a_copied_manifest_is_accepted(
    tmp_path: Path, make_gateway: Build
) -> None:
    real = StubLocalProvider().artifact_sha256()
    manifest = load_manifest(_manifest_with_model_hash(tmp_path, real))
    assert make_gateway(StubLocalProvider(), manifest=manifest) is not None
