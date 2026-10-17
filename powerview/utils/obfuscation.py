import argparse
from dataclasses import dataclass, field

from powerview.lib.ldapx import (
	DEFAULT_OPERATIONS,
	OPERATIONS,
	ChainError,
	Obfuscator,
	OptionError,
	normalize_operations,
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
			operations = normalize_operations(self.operations)
			obfuscator = Obfuscator(self.filter, self.basedn, self.attrlist, self.attrentries, dict(self.options))
		except (ChainError, OptionError, ValueError) as error:
			raise ObfuscationError(str(error)) from error
		object.__setattr__(self, "operations", tuple(operation for operation in OPERATIONS if operation in operations))
		object.__setattr__(self, "obfuscator", obfuscator)

	@classmethod
	def defaults(cls) -> "ObfuscationSettings":
		return cls(**DEFAULT_CHAINS)

	@classmethod
	def from_args(cls, args: argparse.Namespace) -> "ObfuscationSettings | None":
		requested = getattr(args, "obfuscate", False)
		explicit = {name: getattr(args, "obfuscate_" + name, None) for name in CHAIN_NAMES[1:]}
		options = tuple(getattr(args, "obfuscate_option", None) or ())
		operations = getattr(args, "obfuscate_ops", None)
		if requested is False and all(chain is None for chain in explicit.values()):
			if options or operations:
				raise ObfuscationError("--obfuscate-option and --obfuscate-ops require --obfuscate or a chain flag")
			return None
		chains = dict(DEFAULT_CHAINS) if requested is not False else dict.fromkeys(CHAIN_NAMES, "")
		if isinstance(requested, str):
			chains["filter"] = requested
		chains.update({name: chain for name, chain in explicit.items() if chain is not None})
		return cls(**chains, options=options, operations=tuple(operations or DEFAULT_OPERATIONS))


def option_argument(value: str) -> tuple[str, str]:
	try:
		return parse_option(value)
	except OptionError as error:
		raise argparse.ArgumentTypeError(str(error)) from error


def operations_argument(value: str) -> tuple[str, ...]:
	operations = tuple(dict.fromkeys(item.strip().lower() for item in value.split(",") if item.strip()))
	if not operations:
		raise argparse.ArgumentTypeError("expected a comma-separated subset of: %s" % ", ".join(OPERATIONS))
	try:
		normalize_operations(operations)
	except ValueError as error:
		raise argparse.ArgumentTypeError(str(error)) from error
	return operations
