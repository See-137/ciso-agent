"""Operation names a write adapter may never declare (blueprint 9.2, last bullet).

The list is `ciso.common.protected`, the same objects `ciso.policy.catalog` uses (this
package may not import the policy package). The broker still runs every operation
through the policy catalog before use; this check stops such an adapter from being
declared at all.
"""

from __future__ import annotations

from ciso.common.protected import PROTECTED_FAMILIES, SUPPRESSION_VERBS, is_protected_name

__all__ = ["PROTECTED_FAMILIES", "SUPPRESSION_VERBS", "is_protected_name"]
