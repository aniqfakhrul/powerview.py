"""RFC 4515 escape decoding for search filters.

ldap3's development branch stopped turning \\XX escapes into bytes when it encodes a
filter (cannatag/ldap3 commit 3bf19ba3, shipped in 2.10.2rc4). An escaped "(", ")", "*"
or "\\" then reaches the server as literal text and never matches. Released ldap3
decodes them, so this restores that behaviour until upstream does.
"""
import re

from ldap3.operation import search
from ldap3.utils.conv import to_raw

_ESCAPE = re.compile(rb'\\([0-9a-fA-F]{2})')


def decode_filter_escapes(value):
	return _ESCAPE.sub(lambda match: bytes.fromhex(match.group(1).decode()), to_raw(value))


def restore_filter_escape_decoding():
	"""Install the decoder unless this ldap3 already decodes escapes itself."""
	if search.prepare_filter_for_sending(r'\28') != b'(':
		search.prepare_filter_for_sending = decode_filter_escapes
