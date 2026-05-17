#!/usr/bin/env python3
"""Single source of truth for PowerView's on-disk paths.

Every path under the PowerView home folder (normally ~/.powerview, or
%APPDATA%/powerview on Windows) is derived here, so the base directory,
the writability check and the temp-dir fallback live in one place
instead of being recomputed independently by Storage, the logger and
the web API.
"""
import os
import logging
import tempfile

_base = None


def _compute_base():
	if os.name == 'nt':
		parent = os.environ.get('APPDATA') or os.path.expanduser('~')
		name = 'powerview'
	else:
		parent = os.path.expanduser('~')
		name = '.powerview'
	if os.path.isdir(parent) and os.access(parent, os.W_OK):
		root = os.path.join(parent, name)
		try:
			os.makedirs(root, mode=0o700, exist_ok=True)
			return root
		except OSError as e:
			logging.warning("[paths] could not use %s (%s)" % (root, e))
	fallback = os.path.join(tempfile.gettempdir(), 'powerview')
	try:
		os.makedirs(fallback, mode=0o700, exist_ok=True)
		logging.warning("[paths] home not writable, using %s" % fallback)
		return fallback
	except OSError:
		root = tempfile.mkdtemp(prefix='powerview_')
		logging.warning("[paths] home not writable, using %s" % root)
		return root


def base_dir():
	"""The PowerView home folder, resolved (and created) once per process."""
	global _base
	if _base is None:
		_base = _compute_base()
	return _base


def storage_dir():
	return os.path.join(base_dir(), 'storage')


def cache_dir():
	return os.path.join(storage_dir(), 'ldap_cache')


def logs_dir(folder_name):
	return os.path.join(base_dir(), 'logs', str(folder_name or '').lower())


def vulns_file():
	return os.path.join(base_dir(), 'vulns.json')


def findings_file(domain):
	return os.path.join(base_dir(), 'findings', str(domain or 'default').lower() + '.json')
