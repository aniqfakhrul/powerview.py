import argparse
from dataclasses import dataclass, field

from ldap3 import Connection as LDAP3Connection

from powerview.lib.adws.core.connection import Connection as ADWSConnection
from powerview.lib.ldapx import (
	DEFAULT_OPERATIONS,
	OPERATIONS,
	ChainError,
	Obfuscator,
	OptionError,
	attach,
	detach,
	parse_option,
)

CHAIN_NAMES = ("filter", "basedn", "attrlist", "attrentries")
DEFAULT_CHAINS = {"filter": "CZNDR", "basedn": "CX", "attrlist": "CR", "attrentries": ""}


class ObfuscationError(ValueError):
	pass


@dataclass(frozen=True)
class ObfuscationSettings:
	filter: str = ""
	basedn: str = ""
	attrlist: str = ""
	attrentries: str = ""
	options: tuple[tuple[str, str], ...] = ()
	operations: tuple[str, ...] = DEFAULT_OPERATIONS
	obfuscator: Obfuscator = field(init=False, repr=False, compare=False)

	def __post_init__(self):
		try:
			obfuscator = Obfuscator(self.filter, self.basedn, self.attrlist, self.attrentries, dict(self.options))
		except (ChainError, OptionError) as error:
			raise ObfuscationError(str(error)) from error
		object.__setattr__(self, "obfuscator", obfuscator)

	@classmethod
	def defaults(cls) -> "ObfuscationSettings":
		return cls(**DEFAULT_CHAINS)

	@classmethod
	def from_args(cls, args) -> "ObfuscationSettings | None":
		requested = getattr(args, "obfuscate", False)
		explicit = {name: getattr(args, "obfuscate_" + name, None) for name in CHAIN_NAMES[1:]}
		if requested is False and all(chain is None for chain in explicit.values()):
			return None
		chains = dict(DEFAULT_CHAINS) if requested is not False else dict.fromkeys(CHAIN_NAMES, "")
		if isinstance(requested, str):
			chains["filter"] = requested
		chains.update({name: chain for name, chain in explicit.items() if chain is not None})
		return cls(
			**chains,
			options=tuple(getattr(args, "obfuscate_option", None) or ()),
			operations=tuple(getattr(args, "obfuscate_ops", None) or DEFAULT_OPERATIONS),
		)

	def describe(self) -> str:
		chains = " ".join("%s=%s" % (name, getattr(self, name) or "-") for name in CHAIN_NAMES)
		return "%s ops=%s" % (chains, ",".join(self.operations))


def apply_to_session(session, settings: ObfuscationSettings | None) -> None:
	if isinstance(session, LDAP3Connection):
		if settings is None:
			detach(session)
		else:
			attach(session, settings.obfuscator, settings.operations)
	elif isinstance(session, ADWSConnection):
		searches = settings is not None and "search" in settings.operations
		session.obfuscator = settings.obfuscator if searches else None


def option_argument(value: str) -> tuple[str, str]:
	try:
		return parse_option(value)
	except OptionError as error:
		raise argparse.ArgumentTypeError(str(error)) from error


def operations_argument(value: str) -> tuple[str, ...]:
	operations = tuple(dict.fromkeys(item.strip().lower() for item in value.split(",") if item.strip()))
	unknown = [operation for operation in operations if operation not in OPERATIONS]
	if unknown or not operations:
		raise argparse.ArgumentTypeError("operations must be a comma-separated subset of: %s" % ", ".join(OPERATIONS))
	return operations
