"""Fixed recommendation texts, supplied by the caller (spec section 4 step 7).

The text shown with a finding comes from a table a person wrote, keyed by the inspection
check id or by the decision reason code. Nothing here composes text from the action, so a
recommendation can never echo a command, a path from content or a secret. A key with no
entry gets `GENERIC_RECOMMENDATION`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from pydantic import Field, field_validator

from ciso.common.activity import clean_text
from ciso.common.schemas import FrozenMap, Model
from ciso.findings.models import MAX_RECOMMENDATION_CHARS, FindingOrigin

GENERIC_RECOMMENDATION = (
    "Review this activity with the security team before repeating it. "
    "Do not paste secrets or confidential content into the session."
)

_KEY_RE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")


def _check_texts(value: Mapping[str, str]) -> Mapping[str, str]:
    for key, text in value.items():
        if not _KEY_RE.fullmatch(key):
            raise ValueError("recommendation keys are check ids or reason codes")
        clean_text(text)
        if not text or len(text) > MAX_RECOMMENDATION_CHARS:
            raise ValueError("a recommendation must be 1-512 clean characters")
    return value


class RecommendationCatalog(Model):
    """`by_check`: inspection check id -> text. `by_reason`: decision reason code -> text."""

    by_check: FrozenMap[str, str] = Field(default_factory=dict)
    by_reason: FrozenMap[str, str] = Field(default_factory=dict)

    @field_validator("by_check", "by_reason", mode="before")
    @classmethod
    def _valid(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        if not isinstance(value, Mapping):
            raise ValueError("expected a mapping")
        return _check_texts(value)

    def text_for(self, origin: FindingOrigin, key: str) -> str:
        table = self.by_check if origin is FindingOrigin.INSPECTION else self.by_reason
        return table.get(key) or GENERIC_RECOMMENDATION
