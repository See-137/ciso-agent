"""The closed argument schema check for a write adapter (blueprint 9.4, 9.5). It lives in
`ciso.common.closed_schema`; this module only keeps the old import path working.
"""

from __future__ import annotations

from ciso.common.closed_schema import non_finite_path, schema_problem

__all__ = ["non_finite_path", "schema_problem"]
