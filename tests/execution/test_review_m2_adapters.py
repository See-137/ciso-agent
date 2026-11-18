"""Regression tests for the M2 review of the write-adapter contract
(`docs/reviews/m2-tools-channels-write-adapters.md`): M8.

`ciso.write_adapters` may import only `ciso.common`. The closed-schema check and the
control-plane name list it shares with the tool registry and the policy catalog live
there (`ciso.common.closed_schema`, `ciso.common.protected`); the tests here fail when
either side stops using the common one.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Annotated, Any

import pytest
from pydantic import Field

from ciso.common.enums import AuthorityLevel
from ciso.common.errors import ValidationFailed
from ciso.common.schemas import Model
from ciso.policy import catalog
from ciso.write_adapters import AdapterManifest, AdapterOperation, WriteRequest

pytestmark = pytest.mark.broker

L1 = AuthorityLevel.L1_INVESTIGATE
L3 = AuthorityLevel.L3_EXECUTE
Short = Annotated[str, Field(max_length=64)]


class Anything(Model):
    command: Any


class Buried(Model):
    options: dict[str, Any]


class Inner(Model):
    payload: object


class Outer(Model):
    inner: Inner


class Unbounded(Model):
    note: str


class TagArgs(Model):
    tag: Short
    weight: float | None = 1.0


class OtherArgs(Model):
    tag: Short
    weight: float | None = 1.0


def operation(name: str = "asset.tag", args: Any = TagArgs, **extra: Any) -> AdapterOperation:
    fields: dict[str, Any] = {
        "name": name,
        "authority_level": L3,
        "args_model": args,
        "reversible": True,
    }
    fields.update(extra)
    return AdapterOperation(**fields)


def manifest() -> AdapterManifest:
    return AdapterManifest(
        adapter_id="tagger",
        operations=(operation(), operation("asset.untag")),
        credential_refs=("secret://tagger_write",),
    )


def write_request(**overrides: Any) -> WriteRequest:
    fields: dict[str, Any] = {
        "request_id": "req_1",
        "idempotency_key": "idem-1",
        "operation": "asset.tag",
        "target_resource": "asset:a1",
        "arguments": TagArgs(tag="blue"),
    }
    fields.update(overrides)
    return WriteRequest(**fields)


# --- M8: the argument schema ------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "where"),
    [
        pytest.param(Anything, "Anything.command", id="any_field"),
        pytest.param(Buried, "Buried.options", id="dict_of_any"),
        pytest.param(Outer, "Inner.payload", id="nested_open_schema"),
        pytest.param(Unbounded, "Unbounded.note", id="unbounded_str"),
    ],
)
def test_m8_adapter_operation_refuses_an_open_argument_schema(model: Any, where: str) -> None:
    """The reviewer's sequence: `host.run` with `command: Any` was accepted."""
    with pytest.raises(ValueError, match=where):
        operation("host.run", model, reversible=False)


def test_m8_adapter_operation_accepts_a_closed_argument_schema() -> None:
    made = operation()
    assert made.args_model is TagArgs
    assert made.name == "asset.tag"


# --- M8: protected names ------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["policy.update_rule", "killswitch.release", "audit_log.purge", "finding.suppress"],
)
def test_m8_adapter_operation_refuses_a_control_plane_name(name: str) -> None:
    with pytest.raises(ValueError, match="control-plane"):
        operation(name)


def test_m8_the_adapter_side_and_the_policy_side_refuse_the_same_names() -> None:
    """One list, in `ciso.common.protected`; both sides hold that object, not a copy."""
    common = importlib.import_module("ciso.common.protected")
    protected = importlib.import_module("ciso.write_adapters.protected")
    for side in (protected, catalog):
        assert side.PROTECTED_FAMILIES is common.PROTECTED_FAMILIES
        assert side.SUPPRESSION_VERBS is common.SUPPRESSION_VERBS
        assert side.is_protected_name is common.is_protected_name
    assert len(common.PROTECTED_FAMILIES) >= 20
    assert len(common.SUPPRESSION_VERBS) == 7
    families = sorted(common.PROTECTED_FAMILIES | {"audit_log", "auditor", "asset", "host"})
    tails = ["update", "read_all", *sorted(common.SUPPRESSION_VERBS), "mute_all", "unmute"]
    names = [f"{family}.{tail}" for family in families for tail in tails]
    names += [f"asset.note.{verb}" for verb in sorted(common.SUPPRESSION_VERBS)]
    assert len(names) > 200
    refused_by_adapters, refused_by_policy = [], []
    for name in names:
        try:
            operation(name)
        except ValueError:
            refused_by_adapters.append(name)
        try:
            catalog.OperationSpec(name=name, authority_level=L3, args_model=TagArgs, writes=True)
        except ValueError:
            refused_by_policy.append(name)
    assert refused_by_adapters == refused_by_policy
    assert len(refused_by_adapters) > 150
    assert "policy.update" in refused_by_adapters
    assert "asset.update" not in refused_by_adapters


# --- M8: a request is tied to the declared operation -------------------------------------------


def test_m8_a_request_is_validated_against_the_declared_operations_args_model() -> None:
    declared = manifest()
    good = write_request()
    bound = declared.validate_request(good)
    assert bound == TagArgs(tag="blue")
    assert type(bound) is TagArgs
    assert bound is not good.arguments


@pytest.mark.parametrize(
    ("overrides", "why"),
    [
        pytest.param({"operation": "asset.delete"}, "not declared", id="undeclared_operation"),
        pytest.param({"arguments": OtherArgs(tag="blue")}, "TagArgs", id="another_model"),
        pytest.param(
            {"arguments": TagArgs.model_construct(tag=["sh", "-c", "id"], weight=1.0)},
            "schema",
            id="arguments_built_without_validation",
        ),
        pytest.param(
            {"arguments": TagArgs.model_construct(tag="t" * 65, weight=1.0)},
            "schema",
            id="over_the_declared_bound",
        ),
        pytest.param(
            {"arguments": TagArgs(tag="blue", weight=float("inf"))}, "finite", id="infinity"
        ),
    ],
)
def test_m8_a_request_that_does_not_fit_the_declared_operation_is_refused(
    overrides: dict[str, Any], why: str
) -> None:
    with pytest.raises(ValidationFailed, match=why):
        manifest().validate_request(write_request(**overrides))


def test_m8_something_that_is_not_a_write_request_is_refused() -> None:
    class Lookalike(WriteRequest):
        pass

    fields = write_request().model_dump()
    fields["arguments"] = TagArgs(tag="blue")
    with pytest.raises(ValidationFailed, match="WriteRequest"):
        manifest().validate_request(Lookalike(**fields))


# --- one schema checker, one protected-names list ----------------------------------------------

SRC = Path(__file__).resolve().parents[2] / "src" / "ciso"


def test_m8_both_packages_use_the_one_common_schema_checker() -> None:
    """The check lives once, in `ciso.common.closed_schema`. The tool registry, the
    adapter contract and the policy catalog call that function, not a copy of it."""
    common = importlib.import_module("ciso.common.closed_schema")
    users = {
        "ciso.execution.tool_models": ("schema_problem",),
        "ciso.execution.tools": ("non_finite_path",),
        "ciso.write_adapters.contract": ("schema_problem", "non_finite_path"),
        "ciso.policy.catalog": ("schema_problem",),
    }
    checked = 0
    for module_name, names in users.items():
        module = importlib.import_module(module_name)
        for name in names:
            assert getattr(module, name) is getattr(common, name), f"{module_name}.{name}"
            checked += 1
    assert checked == 5
    # Whatever is left of the two old modules defines nothing of its own.
    for old in ("execution/schema.py", "write_adapters/schema.py"):
        path = SRC / old
        if path.exists():
            text = path.read_text(encoding="utf-8")
            assert "def " not in text, old
            assert "class " not in text, old
            module = importlib.import_module("ciso." + old[:-3].replace("/", "."))
            assert module.schema_problem is common.schema_problem
            assert module.non_finite_path is common.non_finite_path


def test_m8_the_policy_catalog_refuses_what_the_tool_registry_refuses() -> None:
    """`OperationSpec` used to check only `extra="forbid"`: an unbounded or `Any` field
    passed the catalog and was caught only when a tool was registered."""
    for model, where in ((Anything, "Anything.command"), (Unbounded, "Unbounded.note")):
        with pytest.raises(ValueError, match=where):
            catalog.OperationSpec(name="host.run", authority_level=L1, args_model=model)
    made = catalog.OperationSpec(name="asset.tag", authority_level=L1, args_model=TagArgs)
    assert made.args_model is TagArgs
