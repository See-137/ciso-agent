"""Who is asking. Built by ciso.identity, read by everything else."""

from __future__ import annotations

from pydantic import Field, model_validator

from ciso.common.enums import HUMAN_ONLY_ROLES, ActorType, Role
from ciso.common.schemas import Model


class Principal(Model):
    """An authenticated actor and the roles it holds.

    `scopes` narrows a role to attribute values, for example
    `{"system": ["app:billing"], "environment": ["staging"]}`. An empty mapping means the
    role is not narrowed.
    """

    actor_id: str
    actor_type: ActorType
    roles: frozenset[Role] = frozenset()
    scopes: dict[str, frozenset[str]] = Field(default_factory=dict)
    display_name: str = ""

    @model_validator(mode="after")
    def _non_humans_hold_no_human_roles(self) -> Principal:
        if self.actor_type is not ActorType.HUMAN:
            forbidden = self.roles & HUMAN_ONLY_ROLES
            if forbidden:
                names = ", ".join(sorted(r.value for r in forbidden))
                raise ValueError(f"{self.actor_type.value} actors cannot hold: {names}")
        return self

    @property
    def is_human(self) -> bool:
        return self.actor_type is ActorType.HUMAN

    def has_role(self, role: Role) -> bool:
        return role in self.roles
