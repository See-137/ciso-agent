"""Blueprint 19.3 names nine test classes. Each must exist and contain tests.

A marker that collects nothing would let a whole class of safety tests be absent while the
suite stays green, so this counts them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]

REQUIRED = (
    "unit",
    "connector",
    "policy",
    "adversarial",
    "external_inference",
    "broker",
    "privacy",
    "resilience",
    "discovery_safety",
)

#: Classes whose modules are not built yet. Remove a name when its milestone lands; the
#: test then fails if the class is empty. This tuple must be empty at the M6 gate.
NOT_YET_BUILT: tuple[str, ...] = (
    "connector",
    "discovery_safety",
)


def _marker_names(node: ast.expr) -> set[str]:
    """Names in `pytest.mark.<name>` expressions, including inside lists and calls."""
    found: set[str] = set()
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Attribute)
            and isinstance(sub.value, ast.Attribute)
            and sub.value.attr == "mark"
            and isinstance(sub.value.value, ast.Name)
            and sub.value.value.id == "pytest"
        ):
            found.add(sub.attr)
    return found


def _count_tests(tree: ast.AST) -> int:
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    )


def marked_test_counts() -> dict[str, int]:
    """Tests per marker, counted from source: module `pytestmark`, class and function marks."""
    counts = dict.fromkeys(REQUIRED, 0)
    for path in sorted(TESTS.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module_marks: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "pytestmark"
                for target in node.targets
            ):
                module_marks |= _marker_names(node.value)
        for name in module_marks & set(REQUIRED):
            counts[name] += _count_tests(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                marks: set[str] = set()
                for decorator in node.decorator_list:
                    marks |= _marker_names(decorator)
                for name in (marks & set(REQUIRED)) - module_marks:
                    counts[name] += _count_tests(node) if isinstance(node, ast.ClassDef) else 1
    return counts


@pytest.mark.parametrize("marker", REQUIRED)
def test_every_required_class_has_tests(marker: str) -> None:
    count = marked_test_counts()[marker]
    if marker in NOT_YET_BUILT:
        if count == 0:
            pytest.xfail(f"'{marker}' tests arrive with a later milestone")
        pytest.fail(f"'{marker}' now has {count} tests: remove it from NOT_YET_BUILT")
    assert count > 0, f"no tests carry @pytest.mark.{marker}"


def test_counter_sees_module_class_and_function_marks(tmp_path: Path) -> None:
    """Mutation check on the counter itself."""
    sample = (
        "import pytest\n"
        "pytestmark = [pytest.mark.unit]\n"
        "def test_a(): pass\n"
        "@pytest.mark.broker\n"
        "class TestB:\n"
        "    def test_b1(self): pass\n"
        "    def test_b2(self): pass\n"
        "@pytest.mark.policy\n"
        "def test_c(): pass\n"
    )
    tree = ast.parse(sample)
    assert _count_tests(tree) == 4
    assert _marker_names(tree.body[1].value) == {"unit"}  # type: ignore[attr-defined]
