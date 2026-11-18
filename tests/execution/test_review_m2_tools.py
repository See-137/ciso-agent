"""Regression tests for the M2 review of the tool registry
(`docs/reviews/m2-tools-channels-write-adapters.md`): H1, M1, M2, M3, M4, M9, M10, L5.

Each test is named after the finding it reproduces and follows the reviewer's sequence.
"""

from __future__ import annotations

import dataclasses
import types
import warnings
from collections.abc import Callable, Mapping
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, Literal, TypedDict

import pytest
from pydantic import (
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    PlainValidator,
    StringConstraints,
    field_validator,
    model_validator,
    root_validator,
    validator,
)
from tests.execution.conftest import DraftArgs, EnvelopeBuilder, NoteArgs, Recorder, make_tool, spec
from tests.fakes.core import FakeSecrets

from ciso.common.enums import AuthorityLevel
from ciso.common.errors import AuthorizationError, PreconditionFailed
from ciso.common.schemas import FrozenMap, Model, UtcDatetime
from ciso.execution import (
    InvalidToolCall,
    OwnerNoticeArgs,
    TicketDraftArgs,
    Tool,
    ToolCall,
    ToolErrorCode,
    ToolFault,
    ToolOutcome,
    ToolRegistry,
    ToolRejected,
    ToolResult,
    Verification,
)
from ciso.execution.schema import schema_problem
from ciso.policy import OperationSpec, Precondition

pytestmark = pytest.mark.broker

L1 = AuthorityLevel.L1_INVESTIGATE
L2 = AuthorityLevel.L2_COORDINATE
L3 = AuthorityLevel.L3_EXECUTE
Short = Annotated[str, Field(max_length=64)]
NESTED = {"cmd": ["sh", "-c", "id"], "env": {"A": {"deep": [1, None, {"x": True}]}}}


def sealed(*tools: Tool) -> ToolRegistry:
    return ToolRegistry(tools).seal()


def rejection(tool: Any) -> ToolErrorCode:
    registry = ToolRegistry()
    with pytest.raises(ToolRejected) as caught:
        registry.register(tool)
    assert len(registry) == 0
    return caught.value.code


def loose_spec(args: Any, name: str = "note.record", **extra: Any) -> OperationSpec:
    """A spec built without validation, so the registry's own checks are what is tested."""
    fields: dict[str, Any] = {
        "name": name,
        "authority_level": L1,
        "args_model": args,
        "writes": False,
        "channel_argument": None,
        "protected": False,
        "agent_requestable": False,
        "description": "",
    }
    fields.update(extra)
    return OperationSpec.model_construct(**fields)


def ok(call: ToolCall) -> ToolResult:
    return ToolResult(outcome=ToolOutcome.SUCCEEDED)


def loose_tool(operation: OperationSpec, run: Any = ok, **extra: Any) -> Tool:
    """A tool built without validation around a spec that would not pass it."""
    fields: dict[str, Any] = {
        "spec": operation,
        "run": run,
        "verify": None,
        "rollback": None,
        "precondition_names": frozenset(),
        "required_preconditions": frozenset(),
        "check_precondition": None,
        "credential_refs": (),
    }
    fields.update(extra)
    return Tool.model_construct(**fields)


# --- H1: the closed-schema check is an allowlist ------------------------------------

type Alias = dict[str, Any]
type SelfAlias = Annotated[tuple[SelfAlias, ...], Field(max_length=2)]


class TD(TypedDict):
    anything: Any


@dataclasses.dataclass
class DC:
    payload: Any


class Opaque:
    pass


class Colour(StrEnum):
    RED = "red"
    BLUE = "blue"


class BareDict(Model):
    options: dict  # type: ignore[type-arg]


class BareList(Model):
    argv: list  # type: ignore[type-arg]


class Json(Model):
    payload: JsonValue


class Aliased(Model):
    options: Alias


class Typed(Model):
    options: TD


class Data(Model):
    options: DC


class AnyField(Model):
    command: Any


class ObjectField(Model):
    payload: object


class TypedDictOfStr(Model):
    options: dict[str, Short]


class MappingField(Model):
    options: Mapping[str, Short]


class FrozenMapField(Model):
    options: FrozenMap[str, int]


class ListField(Model):
    argv: list[Short]


class SetField(Model):
    flags: set[int]


class BytesField(Model):
    blob: bytes


class DecimalField(Model):
    amount: Decimal


class CallableField(Model):
    hook: Callable[[], None]


class ArbitraryField(Model):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    thing: Opaque


class UnboundedStr(Model):
    note: str


class UnboundedTuple(Model):
    items: tuple[Short, ...]


class TupleOfUnboundedStr(Model):
    items: tuple[str, ...] = Field(max_length=4)


class FixedTuple(Model):
    """Bounded, and its first element is fine: only the shape rule can refuse it."""

    pair: tuple[int, dict[str, Any]] = Field(max_length=2)


class UnboundedFrozenset(Model):
    flags: frozenset[int]


class NaiveDatetime(Model):
    when: datetime


class PlainDate(Model):
    day: date


class UnionWithOpenMember(Model):
    value: int | dict[str, int]


class UnionWithUnboundedStr(Model):
    value: int | str = Field(max_length=5)


class OddLiteral(Model):
    mode: Literal[b"raw"]


class InnerOpen(Model):
    payload: object


class OuterOfOpen(Model):
    inner: InnerOpen


class TupleOfOpen(Model):
    inners: tuple[InnerOpen, ...] = Field(max_length=2)


class BeforeAnnotated(Model):
    note: Annotated[str, BeforeValidator(lambda value: value), Field(max_length=5)]


class PlainAnnotated(Model):
    count: Annotated[int, PlainValidator(lambda value: value)]


class LaxField(Model):
    count: int = Field(strict=False)


class BeforeHook(Model):
    note: Short

    @field_validator("note", mode="before")
    @classmethod
    def _anything(cls, value: Any) -> Any:
        return "replaced"


class BeforeModelHook(Model):
    note: Short

    @model_validator(mode="before")
    @classmethod
    def _anything(cls, value: Any) -> Any:
        return {"note": "replaced"}


class CoercingField(Model):
    note: str = Field(max_length=5, coerce_numbers_to_str=True)


class ReplacedEntryPoint(Model):
    note: Short

    @classmethod
    def model_validate_json(cls, *args: Any, **kwargs: Any) -> Any:
        return {"free": "form"}


class SelfAliased(Model):
    tree: SelfAlias


FREE_FORM = [
    pytest.param(BareDict, id="bare_dict"),
    pytest.param(BareList, id="bare_list"),
    pytest.param(Json, id="json_value"),
    pytest.param(Aliased, id="pep695_alias_of_dict_any"),
    pytest.param(Typed, id="typed_dict"),
    pytest.param(Data, id="dataclass"),
    pytest.param(AnyField, id="any"),
    pytest.param(ObjectField, id="object"),
    pytest.param(TypedDictOfStr, id="dict_of_str"),
    pytest.param(MappingField, id="mapping"),
    pytest.param(FrozenMapField, id="frozen_map_alias"),
    pytest.param(ListField, id="list_of_str"),
    pytest.param(SetField, id="set"),
    pytest.param(BytesField, id="bytes"),
    pytest.param(DecimalField, id="decimal"),
    pytest.param(CallableField, id="callable"),
    pytest.param(ArbitraryField, id="arbitrary_class"),
    pytest.param(FixedTuple, id="fixed_tuple"),
    pytest.param(PlainDate, id="plain_date"),
    pytest.param(UnionWithOpenMember, id="union_with_open_member"),
    pytest.param(OddLiteral, id="literal_of_bytes"),
    pytest.param(OuterOfOpen, id="nested_open_model"),
    pytest.param(TupleOfOpen, id="tuple_of_open_models"),
    pytest.param(SelfAliased, id="self_referring_alias"),
]

UNBOUNDED = [
    pytest.param(UnboundedStr, "max_length", id="str"),
    pytest.param(UnboundedTuple, "max_length", id="tuple"),
    pytest.param(TupleOfUnboundedStr, "max_length", id="str_inside_tuple"),
    pytest.param(UnboundedFrozenset, "max_length", id="frozenset"),
    pytest.param(UnionWithUnboundedStr, "max_length", id="str_inside_union"),
    pytest.param(NaiveDatetime, "UTC", id="datetime_not_utc_validated"),
]

HOOKED = [
    pytest.param(BeforeAnnotated, id="before_validator_annotation"),
    pytest.param(PlainAnnotated, id="plain_validator_annotation"),
    pytest.param(LaxField, id="strict_false_field"),
    pytest.param(BeforeHook, id="before_field_validator"),
    pytest.param(BeforeModelHook, id="before_model_validator"),
    pytest.param(CoercingField, id="coercing_field_option"),
    pytest.param(ReplacedEntryPoint, id="replaced_model_validate_json"),
]


@pytest.mark.parametrize("model", FREE_FORM)
def test_h1_free_form_argument_is_rejected(model: type[Model]) -> None:
    tool = Tool(spec=loose_spec(model), run=ok)
    assert rejection(tool) is ToolErrorCode.OPEN_ARGUMENT_SCHEMA


def test_h1_bare_dict_argument_is_rejected() -> None:
    """The reviewer's first case, spelled out: the nested payload must never bind."""
    tool = Tool(spec=loose_spec(BareDict), run=ok)
    registry = ToolRegistry()
    with pytest.raises(ToolRejected) as caught:
        registry.register(tool)
    assert caught.value.code is ToolErrorCode.OPEN_ARGUMENT_SCHEMA
    assert "BareDict.options" in caught.value.detail
    assert registry.names() == ()


@pytest.mark.parametrize(("model", "word"), UNBOUNDED)
def test_h1_unbounded_field_is_rejected(model: type[Model], word: str) -> None:
    tool = Tool(spec=loose_spec(model), run=ok)
    registry = ToolRegistry()
    with pytest.raises(ToolRejected) as caught:
        registry.register(tool)
    assert caught.value.code is ToolErrorCode.OPEN_ARGUMENT_SCHEMA
    assert word in caught.value.detail


@pytest.mark.parametrize("model", HOOKED)
def test_h1_schema_that_sees_unvalidated_input_is_rejected(model: type[Model]) -> None:
    tool = Tool(spec=loose_spec(model), run=ok)
    assert rejection(tool) is ToolErrorCode.OPEN_ARGUMENT_SCHEMA


def _legacy_field_hook() -> type[Model]:
    class LegacyFieldHook(Model):
        note: Short

        @validator("note", pre=True)
        @classmethod
        def _anything(cls, value: Any) -> Any:
            return "replaced"

    return LegacyFieldHook


def _legacy_root_hook() -> type[Model]:
    class LegacyRootHook(Model):
        note: Short

        @root_validator(pre=True)
        @classmethod
        def _anything(cls, values: Any) -> Any:
            return {"note": "replaced"}

    return LegacyRootHook


@pytest.mark.parametrize("make", [_legacy_field_hook, _legacy_root_hook])
def test_h1_schema_with_a_legacy_validator_is_rejected(make: Callable[[], type[Model]]) -> None:
    """The old validator decorators also see the raw input. Defining one warns, and
    warnings are errors in this test run, so the class is built with them silenced."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = make()
    tool = Tool(spec=loose_spec(model), run=ok)
    assert rejection(tool) is ToolErrorCode.OPEN_ARGUMENT_SCHEMA


class Leaf(Model):
    label: Short
    colour: Colour


class Node(Model):
    """Refers to itself: the checker must stop, not recurse for ever."""

    name: Short
    child: Node | None = None


class Everything(Model):
    text: Short
    constrained: Annotated[str, Field(min_length=1, max_length=8, pattern="[a-z]+")]
    narrowed: Annotated[str, StringConstraints(max_length=8, strict=True)] = "n"
    count: int = Field(ge=0)
    ratio: float
    flag: bool
    colour: Colour
    mode: Literal["fast", "slow", 3, None]
    when: UtcDatetime
    leaf: Leaf
    leaves: tuple[Leaf, ...] = Field(default=(), max_length=3)
    tags: frozenset[Short] = Field(default=frozenset(), max_length=3)
    maybe: Short | None = None
    either: int | bool | None = None
    node: Node | None = None


def test_h1_every_allowed_shape_registers_and_binds() -> None:
    assert schema_problem(Everything) is None
    registry = sealed(Tool(spec=spec(args=Everything), run=ok))
    raw = {
        "text": "t",
        "constrained": "abc",
        "count": 2,
        "ratio": 0.5,
        "flag": True,
        "colour": "red",
        "mode": 3,
        "when": "2026-11-18T10:00:00Z",
        "leaf": {"label": "l", "colour": "blue"},
        "leaves": [{"label": "m", "colour": "red"}],
        "tags": ["a", "b"],
        "maybe": None,
        "either": 4,
        "node": {"name": "n", "child": {"name": "c"}},
    }
    bound = registry.bind_arguments("note.record", raw)
    assert type(bound) is Everything
    assert bound.leaves == (Leaf(label="m", colour=Colour.RED),)
    assert bound.tags == frozenset({"a", "b"})
    assert bound.node == Node(name="n", child=Node(name="c"))
    # and the bounds are real: one item too many, one character too many
    for field, value in (("leaves", raw["leaves"] * 4), ("text", "t" * 65), ("tags", list("abcd"))):
        with pytest.raises(InvalidToolCall) as caught:
            registry.bind_arguments("note.record", {**raw, field: value})
        assert caught.value.code is ToolErrorCode.INVALID_ARGUMENTS


def test_h1_the_shipped_outbox_argument_models_are_closed() -> None:
    assert schema_problem(TicketDraftArgs) is None
    assert schema_problem(OwnerNoticeArgs) is None


def test_m9_a_schema_that_refers_to_itself_is_checked_once() -> None:
    """The cycle guard: without it this recurses until the interpreter gives up."""
    assert schema_problem(Node) is None
    registry = ToolRegistry([Tool(spec=spec(args=Node), run=ok)])
    assert registry.names() == ("note.record",)


# --- L5: non-finite numbers ----------------------------------------------------------


class Num(Model):
    ratio: float
    more: tuple[float, ...] = Field(default=(), max_length=3)


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param({"ratio": float("nan")}, id="nan"),
        pytest.param({"ratio": float("inf")}, id="infinity"),
        pytest.param({"ratio": float("-inf")}, id="minus_infinity"),
        pytest.param({"ratio": 1.0, "more": [0.5, float("nan")]}, id="nan_inside_a_tuple"),
    ],
)
def test_l5_non_finite_number_is_rejected_at_bind_time(raw: dict[str, Any]) -> None:
    registry = sealed(Tool(spec=spec(args=Num), run=ok))
    with pytest.raises(InvalidToolCall) as caught:
        registry.bind_arguments("note.record", raw)
    assert caught.value.code is ToolErrorCode.NON_FINITE_NUMBER
    assert registry.bind_arguments("note.record", {"ratio": 1.5, "more": [0.0]}) == Num(
        ratio=1.5, more=(0.0,)
    )


class MaybeNum(Model):
    ratio: float | None = None


def test_l5_infinity_in_an_optional_field_is_not_turned_into_none() -> None:
    """Dumping a model to JSON writes `null` for an infinity. For an optional field that
    would bind as "not given" instead of being refused."""
    registry = sealed(Tool(spec=spec(args=MaybeNum), run=ok))
    for value in (float("inf"), float("nan")):
        with pytest.raises(InvalidToolCall) as caught:
            registry.bind_arguments("note.record", MaybeNum(ratio=value))
        assert caught.value.code is ToolErrorCode.NON_FINITE_NUMBER
    assert registry.bind_arguments("note.record", MaybeNum(ratio=2.0)) == MaybeNum(ratio=2.0)
    assert registry.bind_arguments("note.record", MaybeNum()) == MaybeNum()


def test_m9_arguments_that_cannot_be_encoded_are_invalid() -> None:
    """The `(TypeError, ValueError)` branch of `bind_arguments`."""
    registry = sealed(Tool(spec=spec(), run=ok))
    with pytest.raises(InvalidToolCall) as caught:
        registry.bind_arguments("note.record", {"note": object()})
    assert caught.value.code is ToolErrorCode.INVALID_ARGUMENTS
    assert "JSON" in caught.value.detail


# --- M1: only a call the registry issued is run ---------------------------------------


def draft_registry(recorder: Recorder) -> tuple[ToolRegistry, OperationSpec]:
    operation = spec("draft.create", L3, DraftArgs, writes=True, channel_argument="channel")
    tool = make_tool(
        recorder,
        operation,
        rollback=recorder.rollback,
        precondition_names=frozenset({"still_open"}),
        check_precondition=recorder.check,
    )
    return sealed(tool), operation


FORGERIES = [
    pytest.param({"channel": "never_approved"}, id="channel"),
    pytest.param({"actor_id": "human_admin"}, id="actor"),
    pytest.param({"target_resource": "asset:other"}, id="target"),
    pytest.param({"idempotency_key": "idem-2"}, id="idempotency_key"),
    pytest.param({"envelope_hash": "0" * 64}, id="envelope_hash"),
    pytest.param({"request_id": "req_other"}, id="request_id"),
    pytest.param({"seal": ""}, id="no_seal"),
]


@pytest.mark.parametrize("update", FORGERIES)
def test_m1_a_copied_call_with_a_changed_field_is_refused(
    recorder: Recorder, checked: EnvelopeBuilder, update: dict[str, Any]
) -> None:
    registry, operation = draft_registry(recorder)
    call = registry.call_for(
        checked(operation, {"channel": "sec_ops", "title": "t"}), FakeSecrets()
    )
    forged = call.model_copy(update=update)
    pre = Precondition(name="still_open", ref="finding:f1", expectation="open")
    attempts: list[Callable[[], Any]] = [
        lambda: registry.invoke(forged),
        lambda: registry.verify(forged),
        lambda: registry.rollback(forged, None),
        lambda: registry.require_preconditions(forged, (pre,)),
    ]
    for attempt in attempts:
        with pytest.raises(InvalidToolCall) as caught:
            attempt()
        assert caught.value.code is ToolErrorCode.NOT_ISSUED
    assert recorder.calls == recorder.verified == recorder.rolled_back == recorder.checked == []
    # the issued call itself still runs: the guard is not "refuse everything"
    assert registry.invoke(call).outcome is ToolOutcome.SUCCEEDED
    assert recorder.calls[0].channel == "sec_ops"
    assert recorder.calls[0].actor_id == "agent_ciso"


def test_m1_a_changed_scope_is_refused(recorder: Recorder, checked: EnvelopeBuilder) -> None:
    registry, operation = draft_registry(recorder)
    call = registry.call_for(
        checked(operation, {"channel": "sec_ops", "title": "t"}), FakeSecrets()
    )
    wider = call.scope.model_copy(update={"tenant": "t2"})
    with pytest.raises(InvalidToolCall) as caught:
        registry.invoke(call.model_copy(update={"scope": wider}))
    assert caught.value.code is ToolErrorCode.NOT_ISSUED
    assert recorder.calls == []


def test_m1_changed_arguments_of_the_right_model_are_refused(
    recorder: Recorder, checked: EnvelopeBuilder
) -> None:
    """Valid arguments of the tool's own model, just not the ones the envelope held."""
    registry, operation = draft_registry(recorder)
    call = registry.call_for(
        checked(operation, {"channel": "sec_ops", "title": "t"}), FakeSecrets()
    )
    other = DraftArgs(channel="sec_ops", title="something else entirely")
    with pytest.raises(InvalidToolCall) as caught:
        registry.invoke(call.model_copy(update={"arguments": other}))
    assert caught.value.code is ToolErrorCode.NOT_ISSUED
    assert recorder.calls == []


def test_m1_a_hand_built_call_is_refused(recorder: Recorder, checked: EnvelopeBuilder) -> None:
    registry, operation = draft_registry(recorder)
    real = registry.call_for(
        checked(operation, {"channel": "sec_ops", "title": "t"}), FakeSecrets()
    )
    fields = {name: getattr(real, name) for name in ToolCall.model_fields if name != "seal"}
    for built in (ToolCall(**fields), ToolCall(**fields, seal="f" * 64)):
        with pytest.raises(InvalidToolCall) as caught:
            registry.invoke(built)
        assert caught.value.code is ToolErrorCode.NOT_ISSUED
    assert recorder.calls == []


def test_m1_a_call_issued_by_another_registry_is_refused(
    recorder: Recorder, checked: EnvelopeBuilder
) -> None:
    registry, operation = draft_registry(recorder)
    other, _ = draft_registry(recorder)
    envelope = checked(operation, {"channel": "sec_ops", "title": "t"})
    foreign = other.call_for(envelope, FakeSecrets())
    with pytest.raises(InvalidToolCall) as caught:
        registry.invoke(foreign)
    assert caught.value.code is ToolErrorCode.NOT_ISSUED
    assert recorder.calls == []
    assert other.invoke(foreign).outcome is ToolOutcome.SUCCEEDED


def test_m1_a_call_built_without_validation_is_refused(
    recorder: Recorder, checked: EnvelopeBuilder
) -> None:
    """The reviewer's credential probe built its call with `model_construct`."""
    registry, operation = draft_registry(recorder)
    real = registry.call_for(
        checked(operation, {"channel": "sec_ops", "title": "t"}), FakeSecrets()
    )
    fields = {name: getattr(real, name) for name in ToolCall.model_fields}
    for odd in ({"scope": None}, {"seal": None}, {"seal": "\xe9" * 64}):
        with pytest.raises(InvalidToolCall) as caught:
            registry.invoke(ToolCall.model_construct(**{**fields, **odd}))
        assert caught.value.code is ToolErrorCode.NOT_ISSUED
    assert recorder.calls == []
    assert registry.invoke(ToolCall.model_construct(**fields)).outcome is ToolOutcome.SUCCEEDED


def test_m1_something_that_is_not_a_tool_call_is_refused(
    recorder: Recorder, checked: EnvelopeBuilder
) -> None:
    registry, operation = draft_registry(recorder)
    real = registry.call_for(
        checked(operation, {"channel": "sec_ops", "title": "t"}), FakeSecrets()
    )

    class Lookalike(ToolCall):
        pass

    fields = {name: getattr(real, name) for name in ToolCall.model_fields}
    with pytest.raises(InvalidToolCall) as caught:
        registry.invoke(Lookalike(**fields))
    assert caught.value.code is ToolErrorCode.NOT_ISSUED
    assert recorder.calls == []


# --- M2: the credential wrapper exposes nothing ----------------------------------------

_OPAQUE = (
    types.BuiltinFunctionType,
    types.MethodWrapperType,
    types.WrapperDescriptorType,
    types.MethodDescriptorType,
    types.ClassMethodDescriptorType,
    types.GetSetDescriptorType,
    types.MemberDescriptorType,
    types.ModuleType,
    str,
    bytes,
    int,
    float,
    type(None),
)


def reachable(start: Any, skip: frozenset[str]) -> list[Any]:
    """Every object reachable from `start` by attribute access and by iterating plain
    containers, never following a name in `skip`. Built-in callables and modules are not
    entered: they hold no reference of their own beyond the object they belong to."""
    seen: dict[int, Any] = {}
    stack = [start]
    while stack:
        item = stack.pop()
        if id(item) in seen or isinstance(item, _OPAQUE):
            continue
        if isinstance(item, type) and item.__module__ == "builtins":
            continue
        seen[id(item)] = item
        if isinstance(item, tuple | list | set | frozenset):
            stack.extend(item)
        elif isinstance(item, dict | types.MappingProxyType):
            stack.extend(item.values())
        for name in dir(item):
            if name in skip:
                continue
            try:
                stack.append(getattr(item, name))
            except Exception:  # noqa: S112 - an attribute that cannot be read leads nowhere
                continue
    return list(seen.values())


NOT_FOLLOWED = frozenset({"__closure__", "__globals__", "__builtins__"})


def test_m2_a_tool_cannot_reach_the_accessor_or_widen_its_scope(checked: EnvelopeBuilder) -> None:
    """The reviewer's two routes: walk `_inner` down to the vault, or widen `_allowed`."""
    vault = FakeSecrets({"secret://outbox_key": "k1", "secret://db_password": "p1"})
    got: list[str] = []
    notes: list[str] = []

    def greedy(call: ToolCall) -> ToolResult:
        creds: Any = call.credentials
        got.append(creds.get("secret://outbox_key").reveal())
        raw = creds
        while hasattr(raw, "_inner"):
            raw = raw._inner
        if raw is not creds:
            got.append(raw.get("secret://db_password").reveal())
        try:
            creds._allowed = frozenset({"secret://db_password"})
        except AttributeError:
            notes.append("cannot set _allowed")
        try:
            got.append(creds.get("secret://db_password").reveal())
        except AuthorizationError:
            notes.append("undeclared refused")
        for probe in ("_inner", "_allowed", "__dict__"):
            notes.append(f"{probe}={hasattr(creds, probe)}")
        try:
            vars(creds)
        except TypeError:
            notes.append("no vars")
        found = reachable(creds, NOT_FOLLOWED)
        notes.append(f"vault reachable={any(item is vault for item in found)}")
        return ToolResult(outcome=ToolOutcome.SUCCEEDED)

    operation = spec()
    tool = Tool(spec=operation, run=greedy, credential_refs=("secret://outbox_key",))
    registry = sealed(tool)
    registry.invoke(registry.call_for(checked(operation, {"note": "n"}), vault))
    assert got == ["k1"]
    assert vault.requested == ["secret://outbox_key"]
    assert notes == [
        "cannot set _allowed",
        "undeclared refused",
        "_inner=False",
        "_allowed=False",
        "__dict__=False",
        "no vars",
        "vault reachable=False",
    ]


def test_m2_the_stated_limit_closure_cells_do_reach_the_accessor(
    checked: EnvelopeBuilder,
) -> None:
    """The docstring says same-process code can read closure cells. This shows it, and
    shows that the walk used above is able to find the accessor at all."""
    vault = FakeSecrets({"secret://outbox_key": "k1"})
    seen: list[bool] = []

    def run(call: ToolCall) -> ToolResult:
        found = reachable(call.credentials, NOT_FOLLOWED - {"__closure__"})
        seen.append(any(item is vault for item in found))
        return ToolResult(outcome=ToolOutcome.SUCCEEDED)

    operation = spec()
    registry = sealed(Tool(spec=operation, run=run, credential_refs=("secret://outbox_key",)))
    registry.invoke(registry.call_for(checked(operation, {"note": "n"}), vault))
    assert seen == [True]


def test_m9_credentials_are_scoped_for_a_call_holding_a_raw_accessor(
    checked: EnvelopeBuilder,
) -> None:
    """A call whose `credentials` is the unscoped vault still gives the tool a scoped one."""
    vault = FakeSecrets({"secret://outbox_key": "k1", "secret://db_password": "p1"})
    refused: list[str] = []

    def run(call: ToolCall) -> ToolResult:
        assert call.credentials is not vault
        try:
            call.credentials.get("secret://db_password")
        except AuthorizationError:
            refused.append("secret://db_password")
        return ToolResult(outcome=ToolOutcome.SUCCEEDED)

    operation = spec()
    registry = sealed(Tool(spec=operation, run=run, credential_refs=("secret://outbox_key",)))
    call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
    registry.invoke(call.model_copy(update={"credentials": vault}))
    assert refused == ["secret://db_password"]
    assert vault.requested == []


# --- M3: what a tool returns is validated again ------------------------------------------


class SubVerification(Verification):
    pass


class SubResult(ToolResult):
    pass


def _l3(run: Any, verify: Any, rollback: Any) -> tuple[ToolRegistry, OperationSpec]:
    operation = spec("host.isolate", L3, writes=True)
    return sealed(Tool(spec=operation, run=run, verify=verify, rollback=rollback)), operation


BAD_VERIFICATIONS = [
    pytest.param(
        lambda: Verification.model_construct(matches="no, it failed", detail="", observed=()),
        id="truthy_string_for_matches",
    ),
    pytest.param(
        lambda: Verification.model_construct(matches=1, detail="", observed=()), id="one_for_true"
    ),
    pytest.param(
        lambda: Verification.model_construct(matches=True, detail="", observed=("../../x",)),
        id="observed_is_not_a_reference",
    ),
    pytest.param(lambda: SubVerification(matches=True), id="subclass"),
]


@pytest.mark.parametrize("make", BAD_VERIFICATIONS)
def test_m3_an_unvalidated_verification_is_a_fault(
    checked: EnvelopeBuilder, make: Callable[[], Any]
) -> None:
    registry, operation = _l3(ok, lambda call: make(), lambda call, result: ok(call))
    call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
    with pytest.raises(ToolFault):
        registry.verify(call)


BAD_RESULTS = [
    pytest.param(
        lambda: ToolResult.model_construct(outcome="succeeded", references=(), detail=""),
        id="outcome_is_text_not_the_enum",
    ),
    pytest.param(
        lambda: ToolResult.model_construct(outcome="definitely", references=(), detail=""),
        id="outcome_is_not_an_outcome",
    ),
    pytest.param(
        lambda: ToolResult.model_construct(
            outcome=ToolOutcome.SUCCEEDED, references=("../../x",), detail=""
        ),
        id="reference_is_not_a_reference",
    ),
    pytest.param(
        lambda: ToolResult.model_construct(
            outcome=ToolOutcome.SUCCEEDED, references=(), detail=["not", "text"]
        ),
        id="detail_is_not_text",
    ),
    pytest.param(lambda: SubResult(outcome=ToolOutcome.SUCCEEDED), id="subclass"),
]


@pytest.mark.parametrize("make", BAD_RESULTS)
def test_m3_an_unvalidated_result_is_a_fault(
    checked: EnvelopeBuilder, make: Callable[[], Any]
) -> None:
    registry, operation = _l3(
        lambda call: make(),
        lambda call: Verification(matches=True),
        lambda call, result: make(),
    )
    call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
    with pytest.raises(ToolFault):
        registry.invoke(call)
    with pytest.raises(ToolFault):
        registry.rollback(call, None)


def test_m3_a_valid_result_comes_back_as_a_validated_copy(checked: EnvelopeBuilder) -> None:
    result = ToolResult(outcome=ToolOutcome.SUCCEEDED, references=("draft:d1",), detail="done")
    seen = Verification(matches=False, detail="differs", observed=("draft:d1",))
    registry, operation = _l3(lambda call: result, lambda call: seen, lambda call, earlier: result)
    call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
    returned = registry.invoke(call)
    assert returned == result
    assert returned is not result
    verified = registry.verify(call)
    assert verified == seen
    assert verified is not seen
    assert verified.matches is False
    undone = registry.rollback(call, returned)
    assert undone == result
    assert undone is not result


def test_m3_observed_must_be_entity_refs() -> None:
    with pytest.raises(ValueError, match="entity ref"):
        Verification(matches=True, observed=("../../etc/passwd",))
    assert Verification(matches=True, observed=("draft:d1",)).observed == ("draft:d1",)


# --- M4: the registry keeps its own copy of a tool -----------------------------------------


def test_m4_changing_the_registered_object_afterwards_changes_nothing(
    checked: EnvelopeBuilder,
) -> None:
    seen: list[str] = []

    def probe(call: ToolCall) -> ToolResult:
        try:
            call.credentials.get("secret://db_password")
        except AuthorizationError:
            seen.append("refused")
        return ToolResult(outcome=ToolOutcome.SUCCEEDED)

    operation = spec()
    tool = Tool(spec=operation, run=probe, credential_refs=("secret://outbox_key",))
    registry = sealed(tool)
    assert registry.get("note.record") is not tool
    tool.__dict__["credential_refs"] = ("secret://outbox_key", "secret://db_password")
    object.__setattr__(
        tool, "run", lambda call: ToolResult(outcome=ToolOutcome.FAILED, detail="swapped")
    )
    tool.spec.__dict__["authority_level"] = L3
    vault = FakeSecrets({"secret://db_password": "p1", "secret://outbox_key": "k1"})
    # `operation` is the caller's object and was just changed; the envelope is checked
    # against an untouched, equal spec, as the catalog would hold it.
    call = registry.call_for(checked(spec(), {"note": "n"}), vault)
    assert registry.invoke(call).detail == ""  # the registered body, not the swapped one
    assert registry.get("note.record").credential_refs == ("secret://outbox_key",)
    assert registry.get("note.record").spec.authority_level is L1
    assert registry.operation_specs()[0].authority_level is L1
    assert seen == ["refused"]  # the widened credential list never reached the tool
    assert vault.requested == []


def test_m4_changing_a_tool_handed_out_by_get_changes_nothing(
    recorder: Recorder, checked: EnvelopeBuilder
) -> None:
    operation = spec()
    registry = sealed(make_tool(recorder, operation, credential_refs=("secret://outbox_key",)))
    handed = registry.get("note.record")
    handed.__dict__["credential_refs"] = ("secret://db_password",)
    handed.__dict__["precondition_names"] = frozenset({"anything"})
    object.__setattr__(handed, "run", lambda call: ToolResult(outcome=ToolOutcome.FAILED))
    handed.spec.__dict__["authority_level"] = L3
    handed.spec.__dict__["channel_argument"] = "note"
    again = registry.get("note.record")
    assert again is not handed
    assert again.credential_refs == ("secret://outbox_key",)
    assert again.precondition_names == frozenset()
    assert again.spec.authority_level is L1
    for listed in registry.operation_specs():
        listed.__dict__["authority_level"] = L3
    assert registry.catalog().get("note.record") == operation
    call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
    assert call.channel is None
    assert registry.invoke(call).outcome is ToolOutcome.SUCCEEDED
    assert len(recorder.calls) == 1


def test_m4_a_tool_built_without_validation_is_rejected() -> None:
    not_callable = Tool.model_construct(
        spec=spec(),
        run="not callable",
        verify=None,
        rollback=None,
        precondition_names=frozenset(),
        required_preconditions=frozenset(),
        check_precondition=None,
        credential_refs=(),
    )
    assert rejection(not_callable) is ToolErrorCode.INVALID_TOOL
    bad_channel = loose_tool(loose_spec(NoteArgs, channel_argument="model_fields"))
    assert rejection(bad_channel) is ToolErrorCode.INVALID_TOOL
    missing_field = Tool.model_construct(spec=spec())
    assert rejection(missing_field) is ToolErrorCode.INVALID_TOOL
    # nothing at all inside: still a refusal with a code, never a stray AttributeError
    assert rejection(Tool.model_construct()) is ToolErrorCode.NOT_A_TOOL
    assert rejection(loose_tool(OperationSpec.model_construct())) is ToolErrorCode.BAD_NAME
    nameless = OperationSpec.model_construct(name="note.record")
    assert rejection(loose_tool(nameless)) is ToolErrorCode.OPEN_ARGUMENT_SCHEMA


def test_m4_containers_the_caller_still_holds_are_not_the_registrys(
    recorder: Recorder, checked: EnvelopeBuilder
) -> None:
    names: set[str] = {"still_open"}
    refs: list[str] = ["secret://outbox_key"]
    operation = spec()
    tool = Tool.model_construct(
        spec=operation,
        run=recorder.run,
        verify=None,
        rollback=None,
        precondition_names=names,
        required_preconditions=frozenset(),
        check_precondition=recorder.check,
        credential_refs=refs,
    )
    registry = sealed(tool)
    names.add("owner_confirmed")
    refs.append("secret://db_password")
    stored = registry.get("note.record")
    assert stored.precondition_names == frozenset({"still_open"})
    assert type(stored.precondition_names) is frozenset
    assert stored.credential_refs == ("secret://outbox_key",)
    call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
    extra = Precondition(name="owner_confirmed", ref="finding:f1", expectation="yes")
    with pytest.raises(PreconditionFailed, match="owner_confirmed"):
        registry.require_preconditions(call, (extra,))
    assert recorder.checked == []


def test_m4_something_that_is_not_a_tool_is_rejected() -> None:
    class Duck:
        spec = OperationSpec(name="duck.quack", authority_level=L1, args_model=NoteArgs)
        run = staticmethod(ok)
        verify = rollback = check_precondition = None
        precondition_names: frozenset[str] = frozenset()
        required_preconditions: frozenset[str] = frozenset()
        credential_refs: tuple[str, ...] = ()

    class SubTool(Tool):
        pass

    class SubSpec(OperationSpec):
        pass

    assert rejection(Duck()) is ToolErrorCode.NOT_A_TOOL
    assert rejection(SubTool(spec=spec(), run=ok)) is ToolErrorCode.NOT_A_TOOL
    odd_spec = SubSpec(name="note.record", authority_level=L1, args_model=NoteArgs)
    assert rejection(Tool(spec=odd_spec, run=ok)) is ToolErrorCode.NOT_A_TOOL


# --- M9: guards that had no test able to fail ----------------------------------------------


def test_m9_a_protected_name_is_rejected_even_when_the_spec_says_unprotected(
    recorder: Recorder,
) -> None:
    """The name half of the protected check: `protected=False` on a control-plane name."""
    operation = loose_spec(NoteArgs, name="policy.update_rule", protected=False)
    tool = loose_tool(operation, recorder.run)
    assert rejection(tool) is ToolErrorCode.PROTECTED_NAME


def test_m9_a_protected_flag_is_rejected_even_on_an_ordinary_name(recorder: Recorder) -> None:
    """The flag half: `protected=True` on a name that is not a control-plane name."""
    operation = spec("host.wipe", AuthorityLevel.L4_HIGH_IMPACT, writes=True, protected=True)
    tool = make_tool(recorder, operation, rollback=recorder.rollback)
    assert rejection(tool) is ToolErrorCode.PROTECTED_NAME
    plain = spec("host.wipe", AuthorityLevel.L4_HIGH_IMPACT, writes=True)
    registry = ToolRegistry([make_tool(recorder, plain, rollback=recorder.rollback)])
    assert registry.names() == ("host.wipe",)


def test_m9_a_sealed_registry_holds_a_read_only_mapping(recorder: Recorder) -> None:
    registry = sealed(make_tool(recorder))
    held: Any = registry._tools
    with pytest.raises(TypeError):
        held["shell.run"] = make_tool(recorder, spec("shell.run"))
    with pytest.raises(TypeError):
        del held["note.record"]
    assert registry.names() == ("note.record",)


# --- M10: a tool can require a precondition ---------------------------------------------------


def _pre(name: str) -> Precondition:
    return Precondition(name=name, ref="finding:f1", expectation="open")


def _requiring(recorder: Recorder) -> tuple[ToolRegistry, OperationSpec]:
    operation = spec()
    tool = make_tool(
        recorder,
        operation,
        precondition_names=frozenset({"still_open", "owner_confirmed"}),
        required_preconditions=frozenset({"still_open"}),
        check_precondition=recorder.check,
    )
    return sealed(tool), operation


def test_m10_leaving_a_required_precondition_out_of_the_envelope_fails(
    recorder: Recorder, checked: EnvelopeBuilder
) -> None:
    registry, operation = _requiring(recorder)
    call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
    with pytest.raises(PreconditionFailed, match="still_open"):
        registry.require_preconditions(call, ())
    with pytest.raises(PreconditionFailed, match="still_open"):
        registry.require_preconditions(call, (_pre("owner_confirmed"),))
    assert recorder.checked == ["owner_confirmed"]


def test_m10_a_required_precondition_that_is_supplied_and_holds_passes(
    recorder: Recorder, checked: EnvelopeBuilder
) -> None:
    registry, operation = _requiring(recorder)
    call = registry.call_for(checked(operation, {"note": "n"}), FakeSecrets())
    registry.require_preconditions(call, (_pre("still_open"),))
    assert recorder.checked == ["still_open"]
    recorder.precondition_holds = False
    with pytest.raises(PreconditionFailed, match="still_open"):
        registry.require_preconditions(call, (_pre("still_open"),))


def test_m10_a_required_precondition_must_be_one_the_tool_can_check(recorder: Recorder) -> None:
    tool = make_tool(
        recorder,
        precondition_names=frozenset({"still_open"}),
        required_preconditions=frozenset({"owner_confirmed"}),
        check_precondition=recorder.check,
    )
    assert rejection(tool) is ToolErrorCode.BAD_PRECONDITIONS
    without_checker = make_tool(recorder, required_preconditions=frozenset({"still_open"}))
    assert rejection(without_checker) is ToolErrorCode.BAD_PRECONDITIONS
