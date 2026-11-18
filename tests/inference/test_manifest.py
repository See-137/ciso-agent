"""Prompt and model manifest: integrity checks at load, no write path."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import ciso.inference.manifest as manifest_module
from ciso.common.errors import IntegrityFailure, NotFound, ValidationFailed
from ciso.common.schemas import sha256_hex
from ciso.inference import PromptTemplate, StubLocalProvider, load_manifest
from ciso.inference.stub import STUB_DESCRIPTOR

pytestmark = pytest.mark.unit

BODY = "Hello {{name}}, check {{thing}}.\n"


def _write(tmp_path: Path, mutate: Any = None, body: str = BODY) -> Path:
    (tmp_path / "t_v1.txt").write_bytes(body.encode())
    data: dict[str, Any] = {
        "schema_version": 1,
        "prompts": [
            {"id": "t", "version": 1, "file": "t_v1.txt", "sha256": sha256_hex(body.encode())}
        ],
        "models": [{"id": "m", "version": "1", "sha256": "a" * 64, "source": "builtin"}],
    }
    if mutate:
        mutate(data)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_shipped_manifest_loads_and_registers_stub() -> None:
    m = load_manifest()
    prompt = m.prompt("stub", 1)
    assert prompt.placeholders() == {"evidence"}
    artifact = m.model(StubLocalProvider.model_id, StubLocalProvider.model_version)
    assert artifact.sha256 == sha256_hex(STUB_DESCRIPTOR)


def test_valid_temp_manifest_loads_and_renders(tmp_path: Path) -> None:
    m = load_manifest(_write(tmp_path))
    assert (
        m.prompt("t", 1).render({"name": "a", "thing": "{{name}}"}) == "Hello a, check {{name}}.\n"
    )


def test_crlf_checkout_does_not_change_the_pin(tmp_path: Path) -> None:
    path = _write(tmp_path)
    (tmp_path / "t_v1.txt").write_bytes(BODY.replace("\n", "\r\n").encode())
    assert load_manifest(path).prompt("t", 1).text == BODY


def test_hash_mismatch_refuses(tmp_path: Path) -> None:
    path = _write(tmp_path)
    (tmp_path / "t_v1.txt").write_bytes(b"tampered {{name}} {{thing}}\n")
    with pytest.raises(IntegrityFailure, match="mismatch"):
        load_manifest(path)


def test_missing_file_refuses(tmp_path: Path) -> None:
    path = _write(tmp_path)
    (tmp_path / "t_v1.txt").unlink()
    with pytest.raises(IntegrityFailure, match="missing"):
        load_manifest(path)


def test_missing_manifest_refuses(tmp_path: Path) -> None:
    with pytest.raises(IntegrityFailure):
        load_manifest(tmp_path / "nope.json")


def test_duplicate_prompt_refuses(tmp_path: Path) -> None:
    def dup(d: dict[str, Any]) -> None:
        d["prompts"].append(dict(d["prompts"][0]))

    with pytest.raises(IntegrityFailure, match="duplicate"):
        load_manifest(_write(tmp_path, dup))


def test_duplicate_model_refuses(tmp_path: Path) -> None:
    def dup(d: dict[str, Any]) -> None:
        d["models"].append(dict(d["models"][0]))

    with pytest.raises(IntegrityFailure, match="duplicate"):
        load_manifest(_write(tmp_path, dup))


@pytest.mark.parametrize("where", ["top", "prompt", "model"])
def test_unknown_key_refuses(tmp_path: Path, where: str) -> None:
    def add(d: dict[str, Any]) -> None:
        target = {"top": d, "prompt": d["prompts"][0], "model": d["models"][0]}[where]
        target["surprise"] = 1

    with pytest.raises(IntegrityFailure, match="unknown"):
        load_manifest(_write(tmp_path, add))


@pytest.mark.parametrize("bad", ["../escape.txt", "/abs.txt", "C:/abs.txt", "..\\escape.txt"])
def test_path_escape_refuses(tmp_path: Path, bad: str) -> None:
    def point(d: dict[str, Any]) -> None:
        d["prompts"][0]["file"] = bad

    with pytest.raises(IntegrityFailure):
        load_manifest(_write(tmp_path, point))


def test_bad_schema_version_refuses(tmp_path: Path) -> None:
    def bump(d: dict[str, Any]) -> None:
        d["schema_version"] = 2

    with pytest.raises(IntegrityFailure):
        load_manifest(_write(tmp_path, bump))


def test_template_cannot_be_built_with_wrong_hash() -> None:
    with pytest.raises(ValueError, match="sha256"):
        PromptTemplate(id="x", version=1, text="hi", sha256="b" * 64)


def test_lookup_of_unknown_entries() -> None:
    m = load_manifest()
    with pytest.raises(NotFound):
        m.prompt("stub", 2)
    with pytest.raises(NotFound):
        m.model("nope", "1")


def test_render_rejects_missing_input() -> None:
    with pytest.raises(ValidationFailed):
        load_manifest().prompt("stub", 1).render({})


def test_module_exposes_no_write_api() -> None:
    public = [n for n in dir(manifest_module) if not n.startswith("_")]
    assert "load_manifest" in public
    banned = ("write", "save", "store", "put", "set", "update", "register", "add", "dump")
    assert [n for n in public if any(b in n.lower() for b in banned)] == []
