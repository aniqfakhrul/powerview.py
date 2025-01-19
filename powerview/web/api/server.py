#!/usr/bin/env python3
from flask import Flask, jsonify, request, render_template, Response
import logging
from contextlib import redirect_stdout, redirect_stderr
import io
import os
import sys
import threading
from datetime import date
import shlex
from argparse import Namespace
from powerview.web.api.helpers import make_serializable
from powerview.utils.parsers import powerview_arg_parse
from powerview.utils.constants import UAC_DICT
from powerview._version import __version__ as version
from powerview.lib.ldap3.extend import CustomExtendedOperationsRoot
from powerview.modules.smbclient import SMBClient
from powerview.utils.helpers import is_ipaddress, is_valid_fqdn, host2ip

class APIServer:
	def __init__(self, powerview, host="127.0.0.1", port=5000):
		self.app = Flask(__name__, static_folder='../../web/front-end/static', template_folder='../../web/front-end/templates')
		cli = sys.modules['flask.cli']
		cli.show_server_banner = lambda *x: None

		self.powerview = powerview
		self.host = host
		self.port = port
		
		components = [self.powerview.flatName.lower(), self.powerview.args.username.lower(), self.powerview.args.ldap_address.lower()]
		folder_name = '-'.join(filter(None, components)) or "default-log"
		file_name = "%s.log" % date.today()
		self.log_file_path = os.path.join(os.path.expanduser('~/.powerview/logs/'), folder_name, file_name)
		self.history_file_path = os.path.join(os.path.expanduser('~/.powerview/logs/'), folder_name, '.powerview_history')

		# Define routes
		self.app.add_url_rule('/', 'index', self.render_index, methods=['GET'])
		self.app.add_url_rule('/dashboard', 'dashboard', self.render_dashboard, methods=['GET'])
		self.app.add_url_rule('/users', 'users', self.render_users, methods=['GET'])
		self.app.add_url_rule('/computers', 'computers', self.render_computers, methods=['GET'])
		self.app.add_url_rule('/dns', 'dns', self.render_dns, methods=['GET'])
		self.app.add_url_rule('/groups', 'groups', self.render_groups, methods=['GET'])
		self.app.add_url_rule('/ca', 'ca', self.render_ca, methods=['GET'])
		self.app.add_url_rule('/ou', 'ou', self.render_ou, methods=['GET'])
		self.app.add_url_rule('/gpo', 'gpo', self.render_gpo, methods=['GET'])
		self.app.add_url_rule('/smb', 'smb', self.render_smb, methods=['GET'])
		self.app.add_url_rule('/utils', 'utils', self.render_utils, methods=['GET'])
		self.app.add_url_rule('/api/set/settings', 'set_settings', self.handle_set_settings, methods=['POST'])
		self.app.add_url_rule('/api/get/<method_name>', 'get_operation', self.handle_get_operation, methods=['GET', 'POST'])
		self.app.add_url_rule('/api/set/<method_name>', 'set_operation', self.handle_set_operation, methods=['POST'])
		self.app.add_url_rule('/api/add/<method_name>', 'add_operation', self.handle_add_operation, methods=['POST'])
		self.app.add_url_rule('/api/invoke/<method_name>', 'invoke_operation', self.handle_invoke_operation, methods=['POST'])
		self.app.add_url_rule('/api/remove/<method_name>', 'remove_operation', self.handle_remove_operation, methods=['POST'])
		self.app.add_url_rule('/api/start/<method_name>', 'start_operation', self.handle_start_operation, methods=['POST'])
		self.app.add_url_rule('/api/stop/<method_name>', 'stop_operation', self.handle_stop_operation, methods=['POST'])
		self.app.add_url_rule('/api/convertfrom/<method_name>', 'convert_from_operation', self.handle_convert_from_operation, methods=['POST'])
		self.app.add_url_rule('/api/convertto/<method_name>', 'convert_to_operation', self.handle_convert_to_operation, methods=['POST'])
		self.app.add_url_rule('/api/get/domaininfo', 'domaininfo', self.handle_domaininfo, methods=['GET'])
		self.app.add_url_rule('/health', 'health', self.handle_health, methods=['GET'])
		self.app.add_url_rule('/api/connectioninfo', 'connectioninfo', self.handle_connection_info, methods=['GET'])
		self.app.add_url_rule('/api/logs', 'logs', self.generate_log_stream, methods=['GET'])
		self.app.add_url_rule('/api/history', 'history', self.render_history, methods=['GET'])
		self.app.add_url_rule('/api/ldap/rebind', 'ldap_rebind', self.handle_ldap_rebind, methods=['GET'])
		self.app.add_url_rule('/api/ldap/close', 'ldap_close', self.handle_ldap_close, methods=['GET'])
		self.app.add_url_rule('/api/execute', 'execute_command', self.execute_command, methods=['POST'])
		self.app.add_url_rule('/api/constants', 'constants', self.handle_constants, methods=['GET'])
		self.app.add_url_rule('/api/clear-cache', 'clear_cache', self.handle_clear_cache, methods=['GET'])
		self.app.add_url_rule('/api/settings', 'settings', self.handle_settings, methods=['GET'])
		self.app.add_url_rule('/api/smb/connect', 'smb_connect', self.handle_smb_connect, methods=['POST'])
		self.app.add_url_rule('/api/smb/shares', 'smb_shares', self.handle_smb_shares, methods=['POST'])
		self.app.add_url_rule('/api/smb/ls', 'smb_ls', self.handle_smb_ls, methods=['POST'])
		self.app.add_url_rule('/api/smb/get', 'smb_get', self.handle_smb_get, methods=['POST'])
		self.app.add_url_rule('/api/smb/put', 'smb_put', self.handle_smb_put, methods=['POST'])
		self.app.add_url_rule('/api/smb/cat', 'smb_cat', self.handle_smb_cat, methods=['POST'])
		self.app.add_url_rule('/api/smb/rm', 'smb_rm', self.handle_smb_rm, methods=['POST'])
		self.app.add_url_rule('/api/smb/mkdir', 'smb_mkdir', self.handle_smb_mkdir, methods=['POST'])
		self.app.add_url_rule('/api/smb/rmdir', 'smb_rmdir', self.handle_smb_rmdir, methods=['POST'])

		self.nav_items = [
			{"name": "Explorer", "icon": "fas fa-folder-tree", "link": "/"},
			{"name": "Dashboard", "icon": "fas fa-chart-line", "link": "/dashboard"},
			{"name": "Modules", "icon": "fas fa-cubes", "subitems": [
				{"name": "Users", "icon": "far fa-user", "link": "/users"},
				{"name": "Computers", "icon": "fas fa-display", "link": "/computers"},
				{"name": "Groups", "icon": "fas fa-users", "link": "/groups"},
				{"name": "DNS", "icon": "fas fa-globe", "link": "/dns"},
				{"name": "CA", "icon": "fas fa-certificate", "link": "/ca"},
				{"name": "OUs", "icon": "fas fa-building", "link": "/ou"},
				{"name": "GPOs", "icon": "fas fa-building", "link": "/gpo"},
				{"name": "SMB Browser", "icon": "fas fa-building", "link": "/smb"},
			]},
			{"name": "Utils", "icon": "fas fa-toolbox", "link": "/utils"},
			{"name": "Logs", "icon": "far fa-file-alt", "button_id": "toggle-command-history"},
			{"name": "Settings", "icon": "fas fa-cog", "button_id": "toggle-settings"}
		]

	def render_index(self):
		context = {
			'title': 'Powerview.py',
			'version': version,
			'nav_items': self.nav_items
		}
		return render_template('explorerpage.html', **context)
	
	def render_dashboard(self):
		context = {
			'title': 'Powerview.py - Dashboard',
			'version': version,
			'nav_items': self.nav_items
		}
		return render_template('dashboardpage.html', **context)

	def render_users(self):
		context = {
			'title': 'Powerview.py - Users',
			'nav_items': self.nav_items,
			'version': version,
			'ldap_properties': [
				{'id': 'all-toggle', 'name': 'All', 'active': 'false', 'attribute': '*'},
				{'id': 'samaccountname-toggle', 'name': 'sAMAccountname', 'active': 'true', 'attribute': 'sAMAccountName'},
				{'id': 'cn-toggle', 'name': 'cn', 'active': 'true', 'attribute': 'cn'},
				{'id': 'mail-toggle', 'name': 'mail', 'active': 'true', 'attribute': 'mail'},
				{'id': 'admincount-toggle', 'name': 'adminCount', 'active': 'true', 'attribute': 'adminCount'},
				{'id': 'userprincipalname-toggle', 'name': 'userPrincipalName', 'active': 'false', 'attribute': 'userPrincipalName'},
				{'id': 'useraccountcontrol-toggle', 'name': 'userAccountControl', 'active': 'false', 'attribute': 'userAccountControl'},
				{'id': 'objectclass-toggle', 'name': 'objectClass', 'active': 'false', 'attribute': 'objectClass'},
				{'id': 'description-toggle', 'name': 'description', 'active': 'false', 'attribute': 'description'},
				{'id': 'distinguishedname-toggle', 'name': 'distinguishedName', 'active': 'false', 'attribute': 'distinguishedName'},
				{'id': 'name-toggle', 'name': 'name', 'active': 'false', 'attribute': 'name'},
				{'id': 'objectguid-toggle', 'name': 'objectGUID', 'active': 'false', 'attribute': 'objectGUID'},
				{'id': 'objectsid-toggle', 'name': 'objectSid', 'active': 'false', 'attribute': 'objectSid'},
				{'id': 'title-toggle', 'name': 'title', 'active': 'false', 'attribute': 'title'},
				{'id': 'department-toggle', 'name': 'department', 'active': 'false', 'attribute': 'department'},
				{'id': 'company-toggle', 'name': 'company', 'active': 'false', 'attribute': 'company'},
				{'id': 'serviceprincipalname-toggle', 'name': 'servicePrincipalName', 'active': 'false', 'attribute': 'servicePrincipalName'},
				{'id': 'memberof-toggle', 'name': 'memberOf', 'active': 'false', 'attribute': 'memberOf'},
				{'id': 'accountexpires-toggle', 'name': 'accountExpires', 'active': 'false', 'attribute': 'accountExpires'}
			],
			'powerview_flags': [
				{'id': 'spn-toggle', 'name': 'SPN', 'active': 'false', 'attribute': 'servicePrincipalName'},
				{'id': 'trusted-to-auth-toggle', 'name': 'TrustedToAuth', 'active': 'false', 'attribute': 'trustedToAuth'},
				{'id': 'enabled-users-toggle', 'name': 'Enabled', 'active': 'false', 'attribute': 'enabled'},
				{'id': 'preauth-not-required-toggle', 'name': 'PreauthNotReq', 'active': 'false', 'attribute': 'preauthNotRequired'},
				{'id': 'pass-not-required-toggle', 'name': 'PasswdNotReq', 'active': 'false', 'attribute': 'passwordNotRequired'},
				{'id': 'admin-count-toggle', 'name': 'AdminCount', 'active': 'false', 'attribute': 'adminCount'},
				{'id': 'lockout-toggle', 'name': 'Lockout', 'active': 'false', 'attribute': 'lockout'},
				{'id': 'rbcd-toggle', 'name': 'RBCD', 'active': 'false', 'attribute': 'rbcd'},
				{'id': 'shadow-cred-toggle', 'name': 'Shadow Cred', 'active': 'false', 'attribute': 'shadowCred'},
				{'id': 'unconstrained-delegation-toggle', 'name': 'Unconstrained', 'active': 'false', 'attribute': 'unconstrainedDelegation'},
				{'id': 'disabled-users-toggle', 'name': 'Disabled', 'active': 'false', 'attribute': 'disabled'},
				{'id': 'password-expired-toggle', 'name': 'Password Expired', 'active': 'false', 'attribute': 'passwordExpired'}
			]
		}
		return render_template('userspage.html', **context)

	def render_computers(self):
		context = {
			'title': 'Powerview.py - Computers',
			'nav_items': self.nav_items,
			'version': version,
			'ldap_properties': [
				{'id': 'all-toggle', 'name': 'All', 'active': 'false', 'attribute': '*'},
				{'id': 'samaccountname-toggle', 'name': 'sAMAccountname', 'active': 'true', 'attribute': 'sAMAccountName'},
				{'id': 'cn-toggle', 'name': 'cn', 'active': 'true', 'attribute': 'cn'},
				{'id': 'operatingsystem-toggle', 'name': 'operatingSystem', 'active': 'true', 'attribute': 'operatingSystem'},
				{'id': 'description-toggle', 'name': 'description', 'active': 'false', 'attribute': 'description'},
				{'id': 'useraccountcontrol-toggle', 'name': 'userAccountControl', 'active': 'false', 'attribute': 'userAccountControl'},
				{'id': 'serviceprincipalname-toggle', 'name': 'servicePrincipalName', 'active': 'false', 'attribute': 'servicePrincipalName'},
				{'id': 'memberof-toggle', 'name': 'memberOf', 'active': 'false', 'attribute': 'memberOf'}
			],
			'powerview_flags': [
				{'id': 'spn-toggle', 'name': 'SPN', 'active': 'false', 'attribute': 'servicePrincipalName'},
				{'id': 'trusted-to-auth-toggle', 'name': 'Trusted To Auth', 'active': 'false', 'attribute': 'trustedToAuth'},
				{'id': 'enabled-computers-toggle', 'name': 'Enabled', 'active': 'false', 'attribute': 'enabled'},
				{'id': 'rbcd-toggle', 'name': 'RBCD', 'active': 'false', 'attribute': 'rbcd'},
				{'id': 'shadow-cred-toggle', 'name': 'Shadow Cred', 'active': 'false', 'attribute': 'shadowCred'},
				{'id': 'unconstrained-delegation-toggle', 'name': 'Unconstrained', 'active': 'false', 'attribute': 'unconstrainedDelegation'},
				{'id': 'disabled-computers-toggle', 'name': 'Disabled', 'active': 'false', 'attribute': 'disabled'},
				{'id': 'laps-toggle', 'name': 'LAPS', 'active': 'false', 'attribute': 'laps'},
				{'id': 'printers-toggle', 'name': 'Printers', 'active': 'false', 'attribute': 'printers'},
				{'id': 'bitlocker-toggle', 'name': 'Bitlocker', 'active': 'false', 'attribute': 'bitlocker'},
				{'id': 'gmsapassword-toggle', 'name': 'GMSA Password', 'active': 'false', 'attribute': 'gmsaPassword'},
				{'id': 'pre2k-toggle', 'name': 'Pre-2k', 'active': 'false', 'attribute': 'pre2k'},
				{'id': 'excludedcs-toggle', 'name': 'Exclude DC', 'active': 'false', 'attribute': 'excludeDC'}
			]
		}
		return render_template('computerpage.html', **context)

	def render_dns(self):
		context = {
			'title': 'Powerview.py - DNS',
			'nav_items': self.nav_items,
			'version': version,
		}
		return render_template('dnspage.html', **context)

	def render_groups(self):
		context = {
			'title': 'Powerview.py - Groups',
			'nav_items': self.nav_items,
			'version': version,
		}
		return render_template('grouppage.html', **context)

	def render_ca(self):
		context = {
			'title': 'Powerview.py - CA',
			'nav_items': self.nav_items,
			'version': version,
		}
		return render_template('capage.html', **context)

	def render_ou(self):
		context = {
			'title': 'Powerview.py - OUs',
			'nav_items': self.nav_items,
			'version': version,
		}
		return render_template('oupage.html', **context)

	def render_gpo(self):
		context = {
			'title': 'Powerview.py - GPOs',
			'nav_items': self.nav_items,
			'version': version,
		}
		return render_template('gpopage.html', **context)

	def render_smb(self):
		context = {
			'title': 'Powerview.py - SMB',
			'nav_items': self.nav_items,
			'version': version,
		}
		return render_template('smbpage.html', **context)

	def render_utils(self):
		context = {
			'title': 'Powerview.py - Utils',
			'nav_items': self.nav_items,
			'version': version,
		}
		return render_template('utilspage.html', **context)

	def handle_get_operation(self, method_name):
		return self.handle_operation(f"get_{method_name}")

	def handle_set_operation(self, method_name):
		return self.handle_operation(f"set_{method_name}")

	def handle_add_operation(self, method_name):
		return self.handle_operation(f"add_{method_name}")

	def handle_invoke_operation(self, method_name):
		return self.handle_operation(f"invoke_{method_name}")

	def handle_remove_operation(self, method_name):
		return self.handle_operation(f"remove_{method_name}")

	def handle_convert_from_operation(self, method_name):
		return self.handle_operation(f"convertfrom_{method_name}")

	def handle_convert_to_operation(self, method_name):
		return self.handle_operation(f"convertto_{method_name}")

	def handle_start_operation(self, method_name):
		return self.handle_operation(f"start_{method_name}")

	def handle_stop_operation(self, method_name):
		return self.handle_operation(f"stop_{method_name}")

	def handle_constants(self):
		get_param = request.args.get('get', '')
		if get_param.lower() == 'uac':
			return jsonify(UAC_DICT)
		return jsonify({})

	def handle_domaininfo(self):
		domain_info = {
			'domain': self.powerview.domain,
			'root_dn': self.powerview.root_dn,
			'dc_dnshostname': self.powerview.dc_dnshostname,
			'flatName': self.powerview.flatName,
		}
		return jsonify(domain_info)
	
	def handle_clear_cache(self):
		success = self.powerview.clear_cache()
		return jsonify({'status': 'OK' if success else 'KO'}), 200 if success else 400
	
	def handle_settings(self):
		# return all self.powerview.args in json
		return jsonify(vars(self.powerview.args))
	
	def handle_set_settings(self):
		try:
			obfuscate = request.json.get('obfuscate', False)
			no_cache = request.json.get('no_cache', False)
			logging.info(f"obfuscate: {obfuscate}, no_cache: {no_cache}")
			
			# Update powerview args
			self.powerview.args.obfuscate = obfuscate
			self.powerview.args.no_cache = no_cache
			
			# Create new CustomExtendedOperationsRoot instance with updated settings
			self.powerview.custom_paged_search = CustomExtendedOperationsRoot(self.powerview.ldap_session, obfuscate=obfuscate, no_cache=no_cache)
			self.powerview.ldap_session.extend.standard = self.powerview.custom_paged_search.standard
			
			return jsonify({'status': 'OK'})
		except Exception as e:
			logging.error(f"Error setting settings: {str(e)}")
			return jsonify({'error': str(e)}), 400

	def handle_connection_info(self):
		return jsonify({
			'domain': self.powerview.domain,
			'username': self.powerview.conn.get_username(),
			'sid': self.powerview.current_user_sid,
			'is_admin': self.powerview.is_admin,
			'status': 'OK' if self.powerview.is_connection_alive() else 'KO',
			'protocol': self.powerview.conn.get_proto(),
			'ldap_address': self.powerview.conn.get_ldap_address(),
			'nameserver': self.powerview.conn.get_nameserver(),
		})

	def execute_command(self):
		properties = [
			''
		]
		try:
			# Get the command from the request
			command = request.json.get('command', '')
			if not command:
				return jsonify({'error': 'No command provided'}), 400

			# Parse the command using shlex
			try:
				cmd = shlex.split(command)
			except ValueError as e:
				logging.error(f"Command parsing error: {str(e)}")
				return jsonify({'error': f'Command parsing error: {str(e)}'}), 400

			# Parse the command arguments using PowerView's argument parser
			pv_args = powerview_arg_parse(cmd)

			# Check if the command was parsed successfully
			if pv_args is None:
				return jsonify({'error': 'Invalid command or arguments'}), 400

			# Check if the module is specified
			if not pv_args.module:
				return jsonify({'error': 'No module specified in the command'}), 400

			# Execute the command using PowerView
			result = self.powerview.execute(pv_args)

			# Make the result serializable
			serializable_result = make_serializable(result)

			# Return the result along with pv_args
			return jsonify({'result': serializable_result, 'pv_args': vars(pv_args)}), 200

		except Exception as e:
			logging.error(f"Error executing command: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_health(self):
		return jsonify({'status': 'ok'})

	def handle_ldap_rebind(self):
		success = self.powerview.conn.reset_connection()
		return jsonify({'status': 'OK' if success else 'KO'}), 200 if success else 400

	def handle_ldap_close(self):
		success = self.powerview.conn.close()
		return jsonify({'status': 'OK' if success else 'KO'}), 200 if success else 400

	def render_history(self):
		try:
			with open(self.history_file_path, 'r') as history_file:
				history_lines = history_file.readlines()
				last_50_lines = history_lines[-50:]
				history = [line.strip() for line in last_50_lines]
			return jsonify({'result': history})
		except Exception as e:
			return jsonify({'error': str(e)}), 500

	def generate_log_stream(self):
		try:
			page = int(request.args.get('page', 1))
			limit = int(request.args.get('limit', 10))

			max_limit = 100
			if limit > max_limit:
				raise ValueError(f"Limit of {limit} exceeds the maximum allowed value of {max_limit}")

			with open(self.log_file_path, 'r') as log_file:
				all_logs = log_file.readlines()

			total_logs = len(all_logs)
			start = total_logs - (page * limit)
			end = start + limit

			if start < 0:
				start = 0

			paginated_logs = all_logs[start:end][::-1]  # Reverse the order to get the most recent logs first

			formatted_logs = []
			for log in paginated_logs:
				parts = log.split(' ', 3)
				if len(parts) >= 4:
					timestamp = parts[0] + ' ' + parts[1]
					user = parts[2]
					log_type = parts[3].split(' ', 1)[0]
					debug_message = parts[3].split(' ', 1)[1].strip() if len(parts[3].split(' ', 1)) > 1 else ''
					formatted_logs.append({
						'timestamp': timestamp.strip('[]'),
						'user': user,
						'log_type': log_type,
						'debug_message': debug_message
					})

			return jsonify({'logs': formatted_logs, 'total': total_logs, 'page': page, 'limit': limit})
		except Exception as e:
			return jsonify({'error': str(e)}), 500

	def handle_operation(self, full_method_name):
		method = getattr(self.powerview, full_method_name, None)
		
		if not method:
			return jsonify({'error': f'Method {full_method_name} not found'}), 404

		params = request.args.to_dict() if request.method == 'GET' else request.json or {}

		if 'args' in params:
			params['args'] = Namespace(**params['args'])
		
		try:
			result = method(**params)
			serializable_result = make_serializable(result)
			return jsonify(serializable_result)
		except Exception as e:
			if self.powerview.args.stack_trace:
				raise e
			else:
				logging.error(f"Powerview API Error: {full_method_name}: {str(e)}")
			return jsonify({'error': str(e)}), 400

	def start(self):
		log = logging.getLogger('werkzeug')
		log.disabled = True

		with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
			self.api_server_thread = threading.Thread(
				target=self.app.run,
				kwargs={'host': self.host, 'port': self.port, 'debug': False},
				daemon=True
			)
			logging.info(f"Powerview web listening on {self.host}:{self.port}")
			self.api_server_thread.start()

	def handle_smb_connect(self):
		try:
			data = request.json
			computer = data.get('computer').lower()
			# Add optional credential parameters
			username = data.get('username')
			password = data.get('password')
			nthash = data.get('nthash')
			lmhash = data.get('lmhash')
			domain = data.get('domain')

			# Parse domain from username if in Windows format
			if username and ('/' in username or '\\' in username):
				domain, username = username.replace('/', '\\').split('\\')
			
			if not computer:
				return jsonify({'error': 'Computer name/IP is required'}), 400

			# Reuse get_netshare logic for connection
			is_fqdn = False
			host = ""

			if not is_ipaddress(computer):
				is_fqdn = True
				if not is_valid_fqdn(computer):
					host = f"{computer}.{self.powerview.domain}"
				else:
					host = computer
				logging.debug(f"[SMB Connect] Using FQDN: {host}")
			else:
				host = computer

			if self.powerview.use_kerberos:
				if is_ipaddress(computer):
					return jsonify({'error': 'FQDN must be used for kerberos authentication'}), 400
			else:
				if is_fqdn:
					host = host2ip(host, self.powerview.nameserver, 3, True, 
												use_system_ns=self.powerview.use_system_nameserver)

			if not host:
				return jsonify({'error': 'Host not found'}), 404

			# Pass optional credentials to init_smb_session
			client = self.powerview.conn.init_smb_session(
				host,
				username=username,
				password=password,
				nthash=nthash,
				lmhash=lmhash,
				domain=domain
			)
			
			if not client:
				return jsonify({'error': f'Failed to connect to {host}'}), 400

			# Store SMB client in session
			if not hasattr(self, 'smb_sessions'):
				self.smb_sessions = {}
			self.smb_sessions[host] = client

			return jsonify({
				'status': 'connected',
				'host': host
			})

		except Exception as e:
			logging.error(f"SMB Connect Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_shares(self):
		try:
			data = request.json
			host = data.get('computer').lower()
			
			if not host:
				return jsonify({'error': 'Computer name/IP is required'}), 400

			if not hasattr(self, 'smb_sessions') or host not in self.smb_sessions:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			client = self.smb_sessions[host]
			smb_client = SMBClient(client)
			shares = smb_client.shares()

			# Format shares similar to get_netshare
			formatted_shares = []
			for share in shares:
				entry = {
					"Name": share['shi1_netname'][:-1],
					"Remark": share['shi1_remark'][:-1],
					"Address": host
				}
				formatted_shares.append({"attributes": entry})

			return jsonify(formatted_shares)

		except Exception as e:
			logging.error(f"SMB Shares Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_ls(self):
		try:
			data = request.json
			host = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path', '')
			
			if not host or not share:
				return jsonify({'error': 'Computer name/IP and share name are required'}), 400

			if not hasattr(self, 'smb_sessions') or host not in self.smb_sessions:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400
			
			client = self.smb_sessions[host]
			smb_client = SMBClient(client)
			
			files = smb_client.ls(share, path)
			logging.debug(f"[SMB LS] Listing {path} on {host} with share {share}")
			
			# Format file listing and filter out . and ..
			file_list = []
			for f in files:
				name = f.get_longname()
				# Skip . and .. entries
				if name in ['.', '..']:
					continue
				
				file_info = {
					"name": name,
					"size": f.get_filesize(),
					"is_directory": f.is_directory(),
					"created": str(f.get_ctime()),
					"modified": str(f.get_mtime()),
					"accessed": str(f.get_atime())
				}
				file_list.append(file_info)

			return jsonify(file_list)

		except Exception as e:
			logging.error(f"[SMB LS] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_get(self):
		try:
			data = request.json
			host = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path')
			
			if not host or not share or not path:
				return jsonify({'error': 'Computer name/IP, share name, and file path are required'}), 400

			if not hasattr(self, 'smb_sessions') or host not in self.smb_sessions:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			client = self.smb_sessions[host]
			smb_client = SMBClient(client)
			
			try:
				file_content = smb_client.get(share, path)
				
				# Get the filename from the path
				filename = os.path.basename(path)
				
				# Create a response with the file content
				response = Response(
					file_content,
					mimetype='application/octet-stream',
					headers={
						'Content-Disposition': f'attachment; filename="{filename}"',
						'Content-Length': len(file_content)
					}
				)
				
				return response

			except Exception as e:
				logging.error(f"[SMB GET] Error reading file {path}: {str(e)}")
				return jsonify({'error': f'Failed to read file: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB GET] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_put(self):
		try:
			if 'file' not in request.files:
				return jsonify({'error': 'No file provided'}), 400
			
			file = request.files['file']
			if file.filename == '':
				return jsonify({'error': 'No file selected'}), 400

			computer = request.form.get('computer').lower()
			share = request.form.get('share')
			current_path = request.form.get('path', '')
			
			if not computer or not share:
				return jsonify({'error': 'Computer name/IP and share name are required'}), 400

			if not hasattr(self, 'smb_sessions') or computer not in self.smb_sessions:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			client = self.smb_sessions[computer]
			smb_client = SMBClient(client)
			
			# Save file temporarily
			temp_path = os.path.join('/tmp', file.filename)
			file.save(temp_path)
			
			try:
				# Upload file to SMB share
				upload_path = os.path.join(current_path, file.filename).replace('/', '\\')
				smb_client.put(share, temp_path)
				return jsonify({'message': 'File uploaded successfully'})
			finally:
				# Clean up temporary file
				if os.path.exists(temp_path):
					os.remove(temp_path)

		except Exception as e:
			logging.error(f"[SMB PUT] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_cat(self):
		try:
			data = request.json
			computer = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path')

			if not all([computer, share, path]):
				return jsonify({'error': 'Missing required parameters'}), 400

			client = self.smb_sessions[computer]
			smb_client = SMBClient(client)
			content = smb_client.cat(share, path)
			if content is None:
				return jsonify({'error': 'Failed to read file content'}), 500

			return content, 200

		except Exception as e:
			logging.error(f"Error reading file content: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_rm(self):
		try:
			data = request.json
			computer = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path')

			if not all([computer, share, path]):
				return jsonify({'error': 'Missing required parameters'}), 400

			if not hasattr(self, 'smb_sessions') or computer not in self.smb_sessions:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			client = self.smb_sessions[computer]
			smb_client = SMBClient(client)
			
			try:
				# Delete file over SMB
				smb_client.rm(share, path)
				return jsonify({'message': 'File deleted successfully'})
			except Exception as e:
				return jsonify({'error': f'Failed to delete file: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB RM] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_mkdir(self):
		try:
			data = request.json
			computer = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path')

			if not all([computer, share, path]):
				return jsonify({'error': 'Missing required parameters'}), 400

			if not hasattr(self, 'smb_sessions') or computer not in self.smb_sessions:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			client = self.smb_sessions[computer]
			smb_client = SMBClient(client)
			
			try:
				# Create directory over SMB
				smb_client.mkdir(share, path)
				return jsonify({'message': 'Directory created successfully'})
			except Exception as e:
				return jsonify({'error': f'Failed to create directory: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB MKDIR] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_rmdir(self):
		try:
			data = request.json
			computer = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path')

			if not all([computer, share, path]):
				return jsonify({'error': 'Missing required parameters'}), 400

			if not hasattr(self, 'smb_sessions') or computer not in self.smb_sessions:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			client = self.smb_sessions[computer]
			smb_client = SMBClient(client)
			
			try:
				# Delete directory over SMB
				smb_client.rmdir(share, path)
				return jsonify({'message': 'Directory deleted successfully'})
			except Exception as e:
				return jsonify({'error': f'Failed to delete directory: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB RMDIR] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500