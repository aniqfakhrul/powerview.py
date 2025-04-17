#!/usr/bin/env python3

class GPO:
	class Helper:
		@staticmethod
		def _parse_registry_pol(content):
			"""Parse Registry.pol files"""
			MAGIC = b'PReg\x01\x00\x00\x00'
			if not content.startswith(MAGIC):
				return {"raw": content.hex()}

			body = content[len(MAGIC):]
			registries = {}
			while len(body) > 0:
				body = body[2:]
				key, _, body = body.partition(b';\x00')
				key = key.decode('utf-16-le')[:-1]
				value, _, body = body.partition(b';\x00')
				value = value.decode('utf-16-le')[:-1]

				registries[key] = value
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
			"""Parse Group Policy Preferences"""
			# This would need XML parsing for various preference types
			# For now, return a list of available preference files
			preferences = []
			try:
				files = conn.listPath(share, base_path)
				for file in files:
					if file.get_longname() not in ['.', '..']:
						preferences.append(file.get_longname())
			except Exception as e:
				logging.debug(f"[Get-GPOPolicy] Error listing preferences: {str(e)}")
			return preferences