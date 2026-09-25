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


_SYNTAX_KINDS = {
    "1.3.6.1.4.1.1466.115.121.1.24": "time",
    "1.3.6.1.4.1.1466.115.121.1.53": "time",
    "1.3.6.1.4.1.1466.115.121.1.12": "dn",
    "1.3.6.1.4.1.1466.115.121.1.27": "integer",
    "1.2.840.113556.1.4.906": "integer",
    "1.3.6.1.4.1.1466.115.121.1.7": "boolean",
    "1.3.6.1.4.1.1466.115.121.1.5": "binary",
    "1.3.6.1.4.1.1466.115.121.1.40": "binary",
    "1.2.840.113556.1.4.907": "binary",
}

# Large-integer attributes that Active Directory stores as FILETIME values.
_FILETIME_ATTRIBUTES = frozenset(
    name.casefold()
    for name in (
        "accountExpires", "badPasswordTime", "lastLogoff", "lastLogon",
        "lastLogonTimestamp", "lockoutTime", "pwdLastSet",
        "msDS-LastFailedInteractiveLogonTime", "msDS-LastSuccessfulInteractiveLogonTime",
        "msDS-UserPasswordExpiryTimeComputed", "msLAPS-PasswordExpirationTime",
        "ms-Mcs-AdmPwdExpirationTime",
    )
)

# Constructed attributes are computed per object and are absent from list searches.
_CONSTRUCTED_ATTRIBUTES = frozenset(
    name.casefold()
    for name in (
        "allowedAttributes", "allowedAttributesEffective", "allowedChildClasses",
        "allowedChildClassesEffective", "canonicalName", "createTimeStamp",
        "modifyTimeStamp", "msDS-Approx-Immed-Subordinates", "msDS-KeyVersionNumber",
        "msDS-PrincipalName", "msDS-ReplAttributeMetaData", "msDS-ReplValueMetaData",
        "msDS-ResultantPSO", "msDS-User-Account-Control-Computed", "parentGUID",
        "primaryGroupToken", "sDRightsEffective", "structuralObjectClass",
        "tokenGroups", "tokenGroupsGlobalAndUniversal", "tokenGroupsNoGCAcceptable",
    )
)


@dataclass(frozen=True)
class SchemaAttribute:
    """An attribute that instances of an object class may carry."""

    name: str
    kind: str
    single_valued: bool

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "singleValued": self.single_valued}


def _names(value) -> list[str]:
    if not value:
        return []
    return [str(item) for item in (value if isinstance(value, (list, tuple)) else [value])]


class SchemaCatalog:
    """Describe the attributes available to object classes in a server schema."""

    def __init__(self, schema):
        self._attribute_types = getattr(schema, "attribute_types", None) or None
        self._object_classes = getattr(schema, "object_classes", None) or None
        self._content_rules = getattr(schema, "dit_content_rules", None) or {}

    @classmethod
    def from_server(cls, server):
        return cls(getattr(server, "schema", None))

    @property
    def available(self) -> bool:
        return self._attribute_types is not None and self._object_classes is not None

    def has_class(self, class_name: str) -> bool:
        return self.available and class_name in self._object_classes

    def canonical_class(self, class_name: str) -> str:
        return _names(self._object_classes[class_name].name)[0] if self.has_class(class_name) else class_name

    def _class_chain(self, class_name: str) -> list:
        pending = [class_name]
        seen = set()
        chain = []
        while pending:
            name = pending.pop()
            if name.casefold() in seen or name not in self._object_classes:
                continue
            seen.add(name.casefold())
            info = self._object_classes[name]
            chain.append(info)
            pending.extend(_names(info.superior))
            rule = self._content_rules.get(name)
            if rule is not None:
                pending.extend(_names(rule.auxiliary_classes))
                chain.append(rule)
        return chain

    def _describe(self, name: str) -> SchemaAttribute:
        info = self._attribute_types.get(name)
        canonical = _names(info.name)[0] if info is not None and info.name else name
        syntax = str(info.syntax) if info is not None and info.syntax else ""
        kind = _SYNTAX_KINDS.get(syntax, "text")
        if kind == "integer" and canonical.casefold() in _FILETIME_ATTRIBUTES:
            kind = "time"
        single = bool(info.single_value) if info is not None else False
        return SchemaAttribute(canonical, kind, single)

    def class_attributes(self, class_name: str) -> tuple[SchemaAttribute, ...]:
        """Return list-searchable attributes of a class, including inherited and auxiliary ones."""

        if not self.has_class(class_name):
            return ()
        names = {}
        for info in self._class_chain(class_name):
            for name in (*_names(info.must_contain), *_names(info.may_contain)):
                if name.casefold() not in _CONSTRUCTED_ATTRIBUTES:
                    names.setdefault(name.casefold(), name)
        attributes = (self._describe(name) for name in names.values())
        return tuple(sorted(attributes, key=lambda attribute: attribute.name.casefold()))
