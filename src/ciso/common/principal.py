"""Who is asking. Built by ciso.identity, read by everything else."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import Field, model_validator

from ciso.common.enums import HUMAN_ONLY_ROLES, ActorType, Role
from ciso.common.schemas import FrozenMap, Model


class RoleGrant(Model):
    """One assignment of a role, optionally narrowed to attribute values.

    `scope` maps an attribute name to the values the grant covers, for example
    `{"system": {"app:billing"}, "environment": {"staging"}}`. An empty scope means the
    grant is not narrowed. Attributes of one grant are combined with AND; separate grants
    of the same role are alternatives and never mix their attributes.
    """

    role: Role
    scope: FrozenMap[str, frozenset[str]] = Field(default_factory=dict)

    def covers(self, attributes: Mapping[str, str | None]) -> bool:
        """True when every attribute this grant narrows is present and allowed.

        An attribute the grant narrows but the caller did not supply does not match: a
        scoped grant never applies to a target whose attributes are unknown.
        """
        for name, allowed in self.scope.items():
            value = attributes.get(name)
            if value is None or value not in allowed:
                return False
        return True


class Principal(Model):
    """An authenticated actor and the roles it holds.

    `grants` carries the scope of each role assignment. A role listed in `roles` with no
    grant record is held without narrowing. Use `covers` to decide
    whether a role reaches a target.
    """

    actor_id: str
    actor_type: ActorType
    roles: frozenset[Role] = frozenset()
    grants: tuple[RoleGrant, ...] = ()
    display_name: str = ""
    #: Actor id of whoever issued the credential this principal signed in with, when
    #: known. Lets an approval refuse an approver whose token the requester minted.
    credential_issued_by: str = ""

    @model_validator(mode="after")
    def _check(self) -> Principal:
        if self.actor_type is ActorType.ANONYMOUS and self.roles:
            raise ValueError("an anonymous actor cannot hold a role")
        if self.actor_type is not ActorType.HUMAN:
            forbidden = self.roles & HUMAN_ONLY_ROLES
            if forbidden:
                names = ", ".join(sorted(r.value for r in forbidden))
                raise ValueError(f"{self.actor_type.value} actors cannot hold: {names}")
        stray = {grant.role for grant in self.grants} - self.roles
        if stray:
            names = ", ".join(sorted(r.value for r in stray))
            raise ValueError(f"grants name roles the principal does not hold: {names}")
        return self

    @property
    def is_human(self) -> bool:
        return self.actor_type is ActorType.HUMAN

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    def grants_for(self, role: Role) -> tuple[RoleGrant, ...]:
        return tuple(grant for grant in self.grants if grant.role is role)

    def covers(self, role: Role, attributes: Mapping[str, str | None]) -> bool:
        """True when the principal holds `role` in a way that reaches the given target.

        Holding the role with no grant record is unnarrowed. Otherwise at least one grant
        of that role must cover the attributes on its own.
        """
        if role not in self.roles:
            return False
        grants = self.grants_for(role)
        if not grants:
            return True
        return any(grant.covers(attributes) for grant in grants)

    def covering_roles(
        self, roles: frozenset[Role] | set[Role], attributes: Mapping[str, str | None]
    ) -> frozenset[Role]:
        """The subset of `roles` that this principal holds and that reach the target."""
        return frozenset(role for role in roles if self.covers(role, attributes))
