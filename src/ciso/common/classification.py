"""Data classification without a hardcoded scheme.

The company's classification labels are an open decision (blueprint OD-09), so they come
from configuration. Only one label is built in: `unknown`, which is always treated as more
sensitive than every configured label (blueprint 11.1).
"""

from __future__ import annotations

import re

from pydantic import field_validator

from ciso.common.errors import ValidationFailed
from ciso.common.schemas import Model

UNKNOWN_LABEL = "unknown"
_LABEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class ClassificationScheme(Model):
    """Ordered labels, least sensitive first."""

    labels: tuple[str, ...]

    @field_validator("labels")
    @classmethod
    def _check(cls, labels: tuple[str, ...]) -> tuple[str, ...]:
        if not labels:
            raise ValueError("a classification scheme needs at least one label")
        if len(set(labels)) != len(labels):
            raise ValueError("classification labels must be unique")
        for label in labels:
            if not _LABEL_RE.fullmatch(label):
                raise ValueError(f"bad classification label: {label!r}")
            if label == UNKNOWN_LABEL:
                raise ValueError("'unknown' is built in and cannot be configured")
        return labels

    def normalise(self, label: str | None) -> str:
        """Map a missing label to `unknown`; refuse a label nobody configured."""
        if label is None or label == "" or label == UNKNOWN_LABEL:
            return UNKNOWN_LABEL
        if label not in self.labels:
            raise ValidationFailed(f"unrecognised classification label: {label!r}")
        return label

    def rank(self, label: str | None) -> int:
        """Higher is more sensitive. `unknown` outranks every configured label."""
        normalised = self.normalise(label)
        if normalised == UNKNOWN_LABEL:
            return len(self.labels)
        return self.labels.index(normalised)

    def is_at_most(self, label: str | None, ceiling: str) -> bool:
        """True when `label` is no more sensitive than `ceiling`.

        `unknown` never passes a configured ceiling.
        """
        if ceiling == UNKNOWN_LABEL:
            raise ValidationFailed("'unknown' cannot be used as a ceiling")
        return self.rank(label) <= self.rank(ceiling)

    def most_sensitive(self, labels: list[str | None] | tuple[str | None, ...]) -> str:
        """The label that governs a mixed set. An empty set is `unknown`."""
        if not labels:
            return UNKNOWN_LABEL
        return max((self.normalise(label) for label in labels), key=self.rank)
