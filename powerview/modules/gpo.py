#!/usr/bin/env python3

import re
import struct
import logging
from io import BytesIO
from xml.etree import ElementTree
from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string


class GPO:
	class Helper:
		# Registry.pol type constants
		_REG_NONE = 0
		_REG_SZ = 1
		_REG_EXPAND_SZ = 2
		_REG_BINARY = 3
		_REG_DWORD = 4
		_REG_MULTI_SZ = 7
		_REG_QWORD = 11

		@staticmethod
		def _parse_registry_pol(content):
			"""Parse Registry.pol binary files (PReg format)"""
			MAGIC = b'PReg\x01\x00\x00\x00'
			if not content.startswith(MAGIC):
				return {"raw": content.hex()}

			pos = len(MAGIC)
			registries = {}

			while pos < len(content):
				# Each entry starts with [\x00
				if pos + 2 > len(content) or content[pos:pos + 2] != b'[\x00':
					break
				pos += 2

				# Key name (UTF-16LE, terminated by ;\x00) — the decoded string
				# keeps its own trailing NUL terminator, so strip it.
				sep = content.find(b';\x00', pos)
				if sep == -1:
					break
				key = content[pos:sep].decode('utf-16-le', errors='replace').rstrip('\x00')
				pos = sep + 2

				# Value name (UTF-16LE, terminated by ;\x00)
				sep = content.find(b';\x00', pos)
				if sep == -1:
					break
				value_name = content[pos:sep].decode('utf-16-le', errors='replace').rstrip('\x00')
				pos = sep + 2

				# Type (4 bytes little-endian DWORD) + ;\x00 separator
				if pos + 4 > len(content):
					break
				reg_type = struct.unpack_from('<I', content, pos)[0]
				pos += 4
				if pos + 2 <= len(content) and content[pos:pos + 2] == b';\x00':
					pos += 2

				# Size (4 bytes little-endian DWORD) + ;\x00 separator
				if pos + 4 > len(content):
					break
				data_size = struct.unpack_from('<I', content, pos)[0]
				pos += 4
				if pos + 2 <= len(content) and content[pos:pos + 2] == b';\x00':
					pos += 2

				# Data (data_size bytes)
				if pos + data_size > len(content):
					break
				raw_data = content[pos:pos + data_size]
				pos += data_size

				# Closing ]\x00
				if pos + 2 <= len(content) and content[pos:pos + 2] == b']\x00':
					pos += 2

				# Format data based on type
				if reg_type in (GPO.Helper._REG_SZ, GPO.Helper._REG_EXPAND_SZ):
					decoded = raw_data.decode('utf-16-le', errors='replace').rstrip('\x00')
					formatted = f"REG_SZ,{decoded}"
				elif reg_type == GPO.Helper._REG_DWORD:
					val = struct.unpack('<I', raw_data[:4])[0] if len(raw_data) >= 4 else 0
					formatted = f"REG_DWORD,{val}"
				elif reg_type == GPO.Helper._REG_QWORD:
					val = struct.unpack('<Q', raw_data[:8])[0] if len(raw_data) >= 8 else 0
					formatted = f"REG_QWORD,{val}"
				elif reg_type == GPO.Helper._REG_MULTI_SZ:
					decoded = raw_data.decode('utf-16-le', errors='replace').rstrip('\x00')
					parts = [s for s in decoded.split('\x00') if s]
					formatted = f"REG_MULTI_SZ,{parts}"
				elif reg_type == GPO.Helper._REG_BINARY:
					formatted = f"REG_BINARY,{raw_data.hex()}"
				else:
					formatted = f"REG_TYPE_{reg_type},{raw_data.hex()}"

				entry_key = f"{key}\\{value_name}" if value_name else key
				registries[entry_key] = formatted

			return registries

		@staticmethod
		def _parse_inf_file(content):
			"""Parse GptTmpl.inf security settings file"""
			sections = {}
			current_section = None

			for line in content.splitlines():
				line = line.strip()
				if not line or line.startswith(';'):
					continue

				if line.startswith('[') and line.endswith(']'):
					current_section = line[1:-1]
					sections[current_section] = {}
				elif current_section and '=' in line:
					key, value = line.split('=', 1)
					sections[current_section][key.strip()] = value.strip()

			return sections

		@staticmethod
		def _parse_scripts_ini(content):
			"""Parse scripts.ini files"""
			scripts = {}
			current_section = None

			for line in content.splitlines():
				line = line.strip()
				if not line or line.startswith(';'):
					continue

				if line.startswith('[') and line.endswith(']'):
					current_section = line[1:-1]
					scripts[current_section] = []
				elif current_section and '=' in line:
					scripts[current_section].append(line)

			return scripts

		@staticmethod
		def _parse_preferences(base_path, conn, share):
			preferences = {}

			def _walk(directory):
				try:
					items = conn.listPath(share, directory + '/*')
				except Exception:
					return
				for item in items:
					name = item.get_longname()
					if name in ('.', '..'):
						continue
					child_path = f"{directory}\\{name}"
					if item.is_directory():
						_walk(child_path)
					elif name.lower().endswith('.xml'):
						_read_xml(child_path, directory)

			def _read_xml(file_path, parent_dir):
				fh = BytesIO()
				try:
					conn.getFile(share, file_path, fh.write)
					raw = fh.getvalue()
				except Exception as e:
					logging.debug(f"[Get-GPOSettings] Error reading preference file {file_path}: {e}")
					return
				finally:
					fh.close()

				# Try common encodings
				text = None
				for enc in ('utf-8-sig', 'utf-16', 'latin-1'):
					try:
						text = raw.decode(enc)
						break
					except (UnicodeDecodeError, Exception):
						continue
				if text is None:
					return

				try:
					root = ElementTree.fromstring(text)
				except ElementTree.ParseError as e:
					logging.debug(f"[Get-GPOSettings] XML parse error in {file_path}: {e}")
					return

				# Derive the preference type from parent directory name
				pref_type = parent_dir.rsplit('\\', 1)[-1]
				items = preferences.setdefault(pref_type, [])

				for child in root:
					entry = dict(child.attrib)
					# Extract Properties sub-element
					props = child.find('Properties')
					if props is not None:
						entry['Properties'] = dict(props.attrib)
					# Extract Filters sub-elements
					filters_elem = child.find('Filters')
					if filters_elem is not None:
						entry['Filters'] = [dict(f.attrib) for f in filters_elem]
					items.append(entry)

			_walk(base_path)
			return preferences
		
		def _resolve_gpo_findings(self, gpo_entries):
			for e in gpo_entries:
				if not isinstance(e, dict) or 'attributes' not in e:
					continue
				a = e['attributes']
				flags = a.get('flags')
				if isinstance(flags, list):
					flags = flags[0] if flags else 0
				try:
					flags = int(flags)
				except (TypeError, ValueError):
					flags = 0
				links = a.get('links')
				links = links if isinstance(links, list) else []
				findings = []
				if flags == 3:
					findings.append({
						'id': 'ALL_CONFIG_DISABLED', 'severity': 'low', 'label': 'disabled',
						'title': 'Both the Computer and User configuration are disabled — this GPO applies nothing.'
					})
				elif not links:
					findings.append({
						'id': 'UNLINKED', 'severity': 'medium', 'label': 'unlinked',
						'title': 'GPO is enabled but linked to no OU, site or the domain — its settings apply nowhere (orphan/leftover).'
					})
				a['findings'] = findings

		def _resolve_gpo_links(self, gpo_entries, no_cache=False):
			gpo_by_dn = {}
			for e in gpo_entries:
				if not isinstance(e, dict) or 'attributes' not in e:
					continue
				dn = e['attributes'].get('distinguishedName')
				if isinstance(dn, list):
					dn = dn[0] if dn else None
				e['attributes']['links'] = []
				if dn:
					gpo_by_dn[str(dn).lower()] = e
			if not gpo_by_dn:
				return

			soms = []
			try:
				soms += list(self.ldap_session.extend.standard.paged_search(
					self.root_dn,
					'(&(|(objectClass=organizationalUnit)(objectClass=domainDNS))(gPLink=*))',
					attributes=['distinguishedName', 'gPLink', 'objectClass', 'name'],
					paged_size=1000, generator=True, no_cache=no_cache, no_vuln_check=True))
			except Exception as e:
				logging.debug("[Get-DomainGPO] OU/domain gPLink search failed: %s" % str(e))
			try:
				soms += list(self.ldap_session.extend.standard.paged_search(
					'CN=Sites,CN=Configuration,%s' % self.root_dn,
					'(&(objectClass=site)(gPLink=*))',
					attributes=['distinguishedName', 'gPLink', 'objectClass', 'name'],
					paged_size=1000, generator=True, no_cache=no_cache, no_vuln_check=True))
			except Exception as e:
				logging.debug("[Get-DomainGPO] site gPLink search failed: %s" % str(e))

			link_re = re.compile(r'\[LDAP://([^;\]]+);(\d+)\]', re.IGNORECASE)
			for som in soms:
				if not isinstance(som, dict):
					continue
				sa = som.get('attributes', {})
				gplink = sa.get('gPLink')
				if isinstance(gplink, list):
					gplink = gplink[0] if gplink else None
				if not gplink or not str(gplink).strip():
					continue
				som_dn = sa.get('distinguishedName')
				if isinstance(som_dn, list):
					som_dn = som_dn[0] if som_dn else ''
				oc = sa.get('objectClass') or []
				som_type = 'domain' if 'domainDNS' in oc else 'site' if 'site' in oc else 'ou'
				order = 0
				for m in link_re.finditer(str(gplink)):
					order += 1
					flag = int(m.group(2))
					gpo = gpo_by_dn.get(m.group(1).strip().lower())
					if not gpo:
						continue
					gpo['attributes']['links'].append({
						'som': som_dn,
						'somType': som_type,
						'order': order,
						'enabled': (flag & 1) == 0,
						'enforced': (flag & 2) == 2,
					})

		# Apply-Group-Policy control-access right (the GPO "security filtering" right)
		_APPLY_GPO_GUID = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'

		def _resolve_gpo_security_filter(self, gpo_entries):
			DS_CONTROL_ACCESS = 0x00000100
			for e in gpo_entries:
				if not isinstance(e, dict) or 'attributes' not in e:
					continue
				a = e['attributes']
				a['securityFilter'] = []
				sd_data = a.get('nTSecurityDescriptor')
				if isinstance(sd_data, list):
					sd_data = sd_data[0] if sd_data else None
				if not sd_data:
					continue
				try:
					sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
				except Exception as ex:
					logging.debug("[Get-DomainGPO] Security descriptor parse failed: %s" % str(ex))
					continue
				if not sd['Dacl']:
					continue
				names, seen = [], set()
				for ace in sd['Dacl']['Data']:
					# only explicit allow object-ACEs carrying the Apply-Group-Policy GUID
					if ace['TypeName'] != 'ACCESS_ALLOWED_OBJECT_ACE':
						continue
					if ace['Ace']['ObjectTypeLen'] == 0:
						continue
					try:
						obj_guid = bin_to_string(ace['Ace']['ObjectType']).lower()
					except Exception:
						continue
					if obj_guid != GPO.Helper._APPLY_GPO_GUID:
						continue
					if not (ace['Ace']['Mask']['Mask'] & DS_CONTROL_ACCESS):
						continue
					try:
						sid = ace['Ace']['Sid'].formatCanonical()
					except Exception:
						continue
					if sid in seen:
						continue
					seen.add(sid)
					names.append(self.convertfrom_sid(sid) or sid)
				a['securityFilter'] = names

		# ── per-setting GPO finding classification ──────────────────────────
		# Each rule inspects one parsed setting (name + value) and, when it
		# matches a known-risky configuration, yields a finding. This is the
		# authoritative classifier — the web UI consumes these findings rather
		# than re-implementing the heuristics client-side.
		@staticmethod
		def _flatten_gpo_obj(obj, prefix, out):
			"""flatten a nested dict (e.g. a GPP preference entry) into
			'a / b / c' -> value leaf rows."""
			for k, v in (obj or {}).items():
				key = f"{prefix} / {k}" if prefix else str(k)
				if isinstance(v, dict):
					GPO.Helper._flatten_gpo_obj(v, key, out)
				else:
					out[key] = ', '.join(map(str, v)) if isinstance(v, list) else ('' if v is None else str(v))
			return out

		@staticmethod
		def _classify_gpo_setting(name, value, path):
			"""Return a finding dict for a single risky setting, else None."""
			blob = f"{name} {value}".lower()
			path_blob = ' / '.join(path).lower()
			rule = None
			if 'cpassword' in blob:
				rule = ('GPP_CPASSWORD', 'high', 'cpassword',
					'Group Policy Preferences cpassword found. The AES key is published by '
					'Microsoft (MS14-025); the credential decrypts in seconds. Extract it with '
					'Get-GPPPassword and use it directly.')
			elif ('alwaysinstallelevated' in blob) and any(t in blob for t in ('enabled', '1')):
				rule = ('ALWAYS_INSTALL_ELEVATED', 'high', 'AlwaysInstallElevated',
					'AlwaysInstallElevated is enabled — any user can install a crafted MSI as '
					'SYSTEM, a reliable local privilege-escalation primitive.')
			elif ('mrxsmb10' in blob or 'smb1' in blob or 'smbv1' in blob) and 'disable' not in blob \
					and any(t in blob for t in ('enable', 'normal', 'auto', ',1', '=1', ' 1')):
				rule = ('SMBV1_ENABLED', 'high', 'SMBv1',
					'SMBv1 is enabled on hosts this GPO applies to — exposed to EternalBlue '
					'(MS17-010) and NTLM relay; SMBv1 offers no signing or encryption.')
			elif ('disableantispyware' in blob or 'disablerealtimemonitoring' in blob
					or 'turn off microsoft defender' in blob) and any(t in blob for t in ('enabled', 'true', ',1', '=1', ' 1')):
				rule = ('DEFENDER_DISABLED', 'high', 'defender off',
					'Microsoft Defender / real-time protection is disabled by policy — payload '
					'execution on applied hosts goes uninspected.')
			elif 'defaultpassword' in blob and value:
				rule = ('AUTOLOGON_PASSWORD', 'high', 'autologon pwd',
					'A cleartext autologon password (DefaultPassword) is configured via policy — '
					'readable by anyone who can read this GPO.')
			elif 'enablefirewall' in blob and str(value).strip().lower().endswith(',0'):
				rule = ('FIREWALL_DISABLED', 'medium', 'firewall off',
					'Windows Firewall is disabled by policy for one or more network profiles on '
					'hosts this GPO applies to, widening the network attack surface.')
			elif 'lmcompatibilitylevel' in blob and any(f'{sep}{d}' in blob for sep in (',', '=', ' ') for d in '012'):
				rule = ('WEAK_NTLM', 'medium', 'weak NTLM',
					'A weak LAN Manager authentication level is set — LM / NTLMv1 responses are '
					'permitted and are crackable and relayable.')
			elif 'group membership' in path_blob and value \
					and ('544' in name or 'administrators' in name.lower()):
				rule = ('RESTRICTED_GROUPS_ADMIN', 'high', 'restricted-groups',
					'A Restricted Groups / Group Membership policy writes the local '
					'Administrators group — principals listed here gain local admin on every '
					'host this GPO applies to.')
			if not rule:
				return None
			return {'id': rule[0], 'severity': rule[1], 'label': rule[2], 'title': rule[3],
				'path': list(path), 'name': str(name)}

		@staticmethod
		def _walk_gpo_settings(node, path, findings):
			"""Walk a parsed Machine/User config tree, classifying each leaf.
			The traversal mirrors the web UI's tree builder so a finding's
			(path, name) pair lines up with the matching tree leaf."""
			if isinstance(node, dict):
				for k, v in node.items():
					if isinstance(v, (dict, list)):
						GPO.Helper._walk_gpo_settings(v, path + [str(k)], findings)
					else:
						f = GPO.Helper._classify_gpo_setting(str(k), v, path)
						if f:
							findings.append(f)
			elif isinstance(node, list):
				scalar = all(not isinstance(x, (dict, list)) for x in node)
				if scalar:
					for item in node:
						f = GPO.Helper._classify_gpo_setting(str(item), '', path)
						if f:
							findings.append(f)
				else:
					for i, item in enumerate(node):
						if not isinstance(item, dict):
							continue
						name = item.get('name') or item.get('uid') or item.get('key') \
							or item.get('subkey') or item.get('title') or f'item {i + 1}'
						flat = GPO.Helper._flatten_gpo_obj(item, '', {})
						blob = ' '.join(flat.keys()) + ' ' + ' '.join(flat.values())
						f = GPO.Helper._classify_gpo_setting(blob, blob, path)
						if f:
							f['name'] = str(name)
							findings.append(f)

		@staticmethod
		def _resolve_gposetting_findings(policy_settings):
			"""Attach a 'findings' list (risky settings) to each parsed GPO."""
			for entry in (policy_settings or []):
				if not isinstance(entry, dict) or 'attributes' not in entry:
					continue
				a = entry['attributes']
				findings = []
				for cfg_name, cfg in (('Computer Configuration', a.get('machineConfig')),
									  ('User Configuration', a.get('userConfig'))):
					if cfg:
						GPO.Helper._walk_gpo_settings(cfg, [cfg_name], findings)
				a['findings'] = findings
