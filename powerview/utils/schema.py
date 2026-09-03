#!/usr/bin/env python3
"""Helpers for features backed by optional LDAP schema extensions."""

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class SchemaFeatureVariant:
    """Describe one schema representation of an optional directory feature."""

    name: str
    marker_attribute: str
    properties: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResolvedSchemaFeature:
    """A directory feature reduced to variants supported by one server."""

    variants: tuple[SchemaFeatureVariant, ...]
    properties: tuple[str, ...]

    def __bool__(self) -> bool:
        return bool(self.variants)

    @property
    def marker_attributes(self) -> tuple[str, ...]:
        return tuple(variant.marker_attribute for variant in self.variants)

    @property
    def presence_filter(self) -> str:
        components = [f"({attribute}=*)" for attribute in self.marker_attributes]
        if len(components) == 1:
            return components[0]
        return f"(|{''.join(components)})" if components else ""


class SchemaAttributeResolver:
    """Resolve optional attributes against ldap3 server schema metadata."""

    def __init__(self, schema):
        attribute_types = getattr(schema, "attribute_types", None)
        self._attribute_names = (
            frozenset(str(name).casefold() for name in attribute_types)
            if attribute_types
            else None
        )

    @classmethod
    def from_server(cls, server):
        return cls(getattr(server, "schema", None))

    @property
    def available(self) -> bool:
        """Whether the server supplied usable schema attribute metadata."""

        return self._attribute_names is not None

    def supports(self, attribute: str) -> bool:
        """Return whether the loaded schema advertises an attribute."""

        return (
            self._attribute_names is not None
            and attribute.casefold() in self._attribute_names
        )

    def supported_attributes(self, attributes: Iterable[str]) -> tuple[str, ...]:
        """Return supported attributes in input order, without duplicates."""

        supported = []
        seen = set()
        for attribute in attributes:
            normalized = attribute.casefold()
            if normalized in seen or not self.supports(attribute):
                continue
            seen.add(normalized)
            supported.append(attribute)
        return tuple(supported)

    def resolve_feature(
        self,
        variants: Iterable[SchemaFeatureVariant],
    ) -> ResolvedSchemaFeature:
        """Resolve feature variants and their safe query properties."""

        resolved_variants = tuple(
            variant for variant in variants if self.supports(variant.marker_attribute)
        )
        requested_properties = (
            attribute
            for variant in resolved_variants
            for attribute in (variant.marker_attribute, *variant.properties)
        )
        return ResolvedSchemaFeature(
            variants=resolved_variants,
            properties=self.supported_attributes(requested_properties),
        )
