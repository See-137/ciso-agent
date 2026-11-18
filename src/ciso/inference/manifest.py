"""Prompt template and model artifact manifest (blueprint 8.3, gap G21).

The manifest pins every prompt template and every model artifact by sha256. Loading
refuses (`IntegrityFailure`) on a hash mismatch, a missing or unreadable file, a duplicate
id plus version, a path that leaves the manifest directory, or an unknown key. The
template text a caller gets is the text that was hashed; the file is not read again.

This module only reads. Prompts and the manifest change through version control and
review, never at run time, so there is deliberately no function that writes either.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import ValidationError, field_validator, model_validator

from ciso.common.errors import IntegrityFailure, NotFound, ValidationFailed
from ciso.common.schemas import Model, sha256_hex

DEFAULT_MANIFEST_PATH = Path(__file__).parent / "prompts" / "manifest.json"
SUPPORTED_SCHEMA_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PLACEHOLDER_RE = re.compile(r"\{\{([a-z][a-z0-9_]{0,63})\}\}")


def _check_sha(value: str) -> str:
    if not _SHA256_RE.fullmatch(value):
        raise ValueError("sha256 must be 64 lowercase hex characters")
    return value


def _normalise(data: bytes) -> bytes:
    """Line endings must not change a pin: CRLF becomes LF before hashing."""
    return data.replace(b"\r\n", b"\n")


class PromptTemplate(Model):
    """A verified template. Construction itself checks that `sha256` matches `text`."""

    id: str
    version: int
    text: str
    sha256: str

    @field_validator("sha256")
    @classmethod
    def _sha(cls, value: str) -> str:
        return _check_sha(value)

    @model_validator(mode="after")
    def _hash_matches_text(self) -> PromptTemplate:
        if sha256_hex(_normalise(self.text.encode("utf-8"))) != self.sha256:
            raise ValueError("template text does not match its sha256")
        return self

    def placeholders(self) -> frozenset[str]:
        return frozenset(_PLACEHOLDER_RE.findall(self.text))

    def render(self, inputs: Mapping[str, str]) -> str:
        """Fill `{{name}}` slots. The inputs must match the placeholders exactly.

        Substitution is a single pass, so an input that itself contains `{{x}}` is not
        expanded again.
        """
        wanted = self.placeholders()
        given = frozenset(inputs)
        if wanted != given:
            missing = sorted(wanted - given)
            extra = sorted(given - wanted)
            raise ValidationFailed(f"template inputs mismatch: missing={missing} extra={extra}")
        return _PLACEHOLDER_RE.sub(lambda m: inputs[m.group(1)], self.text)


class ModelArtifact(Model):
    id: str
    version: str
    sha256: str
    source: str

    @field_validator("sha256")
    @classmethod
    def _sha(cls, value: str) -> str:
        return _check_sha(value)

    @field_validator("id", "version", "source")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class Manifest(Model):
    """Verified prompts and model artifacts. Build one with `load_manifest`."""

    prompts: tuple[PromptTemplate, ...]
    models: tuple[ModelArtifact, ...]

    def prompt(self, template_id: str, version: int) -> PromptTemplate:
        for template in self.prompts:
            if template.id == template_id and template.version == version:
                return template
        raise NotFound(f"no prompt template {template_id!r} version {version}")

    def model(self, model_id: str, version: str) -> ModelArtifact:
        for artifact in self.models:
            if artifact.id == model_id and artifact.version == version:
                return artifact
        raise NotFound(f"no model artifact {model_id!r} version {version!r}")


class _PromptEntry(Model):
    id: str
    version: int
    file: str
    sha256: str

    @field_validator("sha256")
    @classmethod
    def _sha(cls, value: str) -> str:
        return _check_sha(value)


class _ManifestFile(Model):
    schema_version: int
    prompts: tuple[_PromptEntry, ...]
    models: tuple[ModelArtifact, ...]


def _read_template(entry: _PromptEntry, base: Path) -> PromptTemplate:
    rel = PurePosixPath(entry.file.replace("\\", "/"))
    if rel.is_absolute() or ".." in rel.parts or not rel.parts or ":" in entry.file:
        raise IntegrityFailure(f"prompt file path is not inside the manifest directory: {rel}")
    target = (base / Path(*rel.parts)).resolve()
    if not target.is_relative_to(base.resolve()):
        raise IntegrityFailure(f"prompt file escapes the manifest directory: {rel}")
    try:
        data = _normalise(target.read_bytes())
    except OSError as exc:
        raise IntegrityFailure(f"prompt file missing or unreadable: {rel}") from exc
    if sha256_hex(data) != entry.sha256:
        raise IntegrityFailure(f"prompt hash mismatch for {entry.id!r} v{entry.version}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityFailure(f"prompt file is not UTF-8: {rel}") from exc
    return PromptTemplate(id=entry.id, version=entry.version, text=text, sha256=entry.sha256)


def _parse(path: Path) -> _ManifestFile:
    try:
        raw: Any = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityFailure(f"manifest missing or unreadable: {path.name}") from exc
    try:
        parsed = _ManifestFile.model_validate(raw)
    except ValidationError as exc:
        where = sorted({".".join(str(p) for p in err["loc"]) for err in exc.errors()})
        raise IntegrityFailure(f"manifest has unknown or invalid keys: {where}") from exc
    if parsed.schema_version != SUPPORTED_SCHEMA_VERSION:
        raise IntegrityFailure(f"unsupported manifest schema_version {parsed.schema_version}")
    return parsed


def load_manifest(path: Path | None = None) -> Manifest:
    """Read and verify a manifest. Anything off raises `IntegrityFailure`."""
    manifest_path = Path(path) if path is not None else DEFAULT_MANIFEST_PATH
    parsed = _parse(manifest_path)
    prompt_keys = [(p.id, p.version) for p in parsed.prompts]
    if len(set(prompt_keys)) != len(prompt_keys):
        raise IntegrityFailure("duplicate prompt id and version in manifest")
    model_keys = [(m.id, m.version) for m in parsed.models]
    if len(set(model_keys)) != len(model_keys):
        raise IntegrityFailure("duplicate model id and version in manifest")
    templates = tuple(_read_template(entry, manifest_path.parent) for entry in parsed.prompts)
    return Manifest(prompts=templates, models=parsed.models)
