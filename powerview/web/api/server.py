#!/usr/bin/env python3
from flask import Flask, jsonify, request, render_template, Response, stream_with_context
import logging
from contextlib import redirect_stdout, redirect_stderr
import io
import os
import sys
import threading
from datetime import date,datetime
import shlex
import fnmatch
from argparse import Namespace
from powerview.web.api.helpers import make_serializable
from powerview.utils.parsers import powerview_arg_parse
from powerview.utils.constants import UAC_DICT
from powerview._version import __version__ as version
from powerview.lib.ldap3.extend import CustomExtendedOperationsRoot
from powerview.modules.smbclient import SMBClient
from powerview.lib.tsts import TSHandler
from powerview.utils.helpers import is_ipaddress, is_valid_fqdn, host2ip, is_valid_sid
import json

class APIServer:
	def __init__(self, powerview, host="127.0.0.1", port=5000):
		self.app = Flask(__name__, static_folder='../../web/front-end/static', template_folder='../../web/front-end/templates')
		
		self.basic_auth = None
		self.web_auth_user = powerview.args.web_auth['web_auth_user'] if powerview.args.web_auth else None
		self.web_auth_password = powerview.args.web_auth['web_auth_password'] if powerview.args.web_auth else None
		if self.web_auth_user and self.web_auth_password:
			try:
				from flask_basicauth import BasicAuth
				self.app.config['BASIC_AUTH_USERNAME'] = self.web_auth_user
				self.app.config['BASIC_AUTH_PASSWORD'] = self.web_auth_password
				self.basic_auth = BasicAuth(self.app)
			except ImportError:
				logging.error("flask_basicauth is not installed. Please install it using 'pip install flask-basicauth'")
				sys.exit(1)
		
		cli = sys.modules['flask.cli']
		cli.show_server_banner = lambda *x: None

		self.powerview = powerview
		self.host = host
		self.port = port
		self.status = False
		self.smb_session_params = {}
		
		components = [self.powerview.flatName.lower(), self.powerview.args.username.lower(), self.powerview.args.ldap_address.lower()]
		folder_name = '-'.join(filter(None, components)) or "default-log"
		file_name = "%s.log" % datetime.now().strftime("%Y-%m-%d")
		self.log_file_path = os.path.join(os.path.expanduser('~/.powerview/logs/'), folder_name, file_name)
		self.history_file_path = os.path.join(os.path.expanduser('~/.powerview/logs/'), folder_name, '.powerview_history')

		self._register_routes()

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

	def _register_routes(self):
		def add_route_with_auth(rule, endpoint, view_func, **options):
			decorated_view = view_func
			if self.basic_auth:
				decorated_view = self.basic_auth.required(view_func)
			self.app.add_url_rule(rule, endpoint, decorated_view, **options)

		add_route_with_auth('/', 'index', self.render_index, methods=['GET'])
		add_route_with_auth('/dashboard', 'dashboard', self.render_dashboard, methods=['GET'])
		add_route_with_auth('/users', 'users', self.render_users, methods=['GET'])
		add_route_with_auth('/computers', 'computers', self.render_computers, methods=['GET'])
		add_route_with_auth('/dns', 'dns', self.render_dns, methods=['GET'])
		add_route_with_auth('/groups', 'groups', self.render_groups, methods=['GET'])
		add_route_with_auth('/ca', 'ca', self.render_ca, methods=['GET'])
		add_route_with_auth('/ou', 'ou', self.render_ou, methods=['GET'])
		add_route_with_auth('/gpo', 'gpo', self.render_gpo, methods=['GET'])
		add_route_with_auth('/smb', 'smb', self.render_smb, methods=['GET'])
		add_route_with_auth('/utils', 'utils', self.render_utils, methods=['GET'])
		add_route_with_auth('/api/server/info', 'server_info', self.handle_server_info, methods=['GET'])
		add_route_with_auth('/api/server/schema', 'schema_info', self.handle_schema_info, methods=['GET'])
		add_route_with_auth('/api/set/settings', 'set_settings', self.handle_set_settings, methods=['POST'])
		add_route_with_auth('/api/get/<method_name>', 'get_operation', self.handle_get_operation, methods=['GET', 'POST'])
		add_route_with_auth('/api/set/<method_name>', 'set_operation', self.handle_set_operation, methods=['POST'])
		add_route_with_auth('/api/add/<method_name>', 'add_operation', self.handle_add_operation, methods=['POST'])
		add_route_with_auth('/api/invoke/<method_name>', 'invoke_operation', self.handle_invoke_operation, methods=['POST'])
		add_route_with_auth('/api/remove/<method_name>', 'remove_operation', self.handle_remove_operation, methods=['POST'])
		add_route_with_auth('/api/start/<method_name>', 'start_operation', self.handle_start_operation, methods=['POST'])
		add_route_with_auth('/api/stop/<method_name>', 'stop_operation', self.handle_stop_operation, methods=['POST'])
		add_route_with_auth('/api/convertfrom/<method_name>', 'convert_from_operation', self.handle_convert_from_operation, methods=['POST'])
		add_route_with_auth('/api/convertto/<method_name>', 'convert_to_operation', self.handle_convert_to_operation, methods=['POST'])
		add_route_with_auth('/api/get/domaininfo', 'domaininfo', self.handle_domaininfo, methods=['GET'])
		add_route_with_auth('/health', 'health', self.handle_health, methods=['GET'])
		add_route_with_auth('/api/connectioninfo', 'connectioninfo', self.handle_connection_info, methods=['GET'])
		add_route_with_auth('/api/logs', 'logs', self.generate_log_stream, methods=['GET'])
		add_route_with_auth('/api/history', 'history', self.render_history, methods=['GET'])
		add_route_with_auth('/api/ldap/rebind', 'ldap_rebind', self.handle_ldap_rebind, methods=['GET'])
		add_route_with_auth('/api/ldap/close', 'ldap_close', self.handle_ldap_close, methods=['GET'])
		add_route_with_auth('/api/execute', 'execute_command', self.execute_command, methods=['POST'])
		add_route_with_auth('/api/constants', 'constants', self.handle_constants, methods=['GET'])
		add_route_with_auth('/api/clear-cache', 'clear_cache', self.handle_clear_cache, methods=['GET'])
		add_route_with_auth('/api/settings', 'settings', self.handle_settings, methods=['GET'])
		add_route_with_auth('/api/smb/connect', 'smb_connect', self.handle_smb_connect, methods=['POST'])
		add_route_with_auth('/api/smb/reconnect', 'smb_reconnect', self.handle_smb_reconnect, methods=['POST'])
		add_route_with_auth('/api/smb/disconnect', 'smb_disconnect', self.handle_smb_disconnect, methods=['POST'])
		add_route_with_auth('/api/smb/shares', 'smb_shares', self.handle_smb_shares, methods=['POST'])
		add_route_with_auth('/api/smb/add-share', 'smb_add_share', self.handle_smb_add_share, methods=['POST'])
		add_route_with_auth('/api/smb/delete-share', 'smb_delete_share', self.handle_smb_delete_share, methods=['POST'])
		add_route_with_auth('/api/smb/ls', 'smb_ls', self.handle_smb_ls, methods=['POST'])
		add_route_with_auth('/api/smb/mv', 'smb_mv', self.handle_smb_mv, methods=['POST'])
		add_route_with_auth('/api/smb/get', 'smb_get', self.handle_smb_get, methods=['POST'])
		add_route_with_auth('/api/smb/put', 'smb_put', self.handle_smb_put, methods=['POST'])
		add_route_with_auth('/api/smb/cat', 'smb_cat', self.handle_smb_cat, methods=['POST'])
		add_route_with_auth('/api/smb/rm', 'smb_rm', self.handle_smb_rm, methods=['POST'])
		add_route_with_auth('/api/smb/mkdir', 'smb_mkdir', self.handle_smb_mkdir, methods=['POST'])
		add_route_with_auth('/api/smb/rmdir', 'smb_rmdir', self.handle_smb_rmdir, methods=['POST'])
		add_route_with_auth('/api/smb/search', 'smb_search', self.handle_smb_search, methods=['POST'])
		add_route_with_auth('/api/smb/search-stream', 'smb_search_stream', self.handle_smb_search_stream, methods=['GET'])
		add_route_with_auth('/api/smb/sessions', 'smb_sessions', self.handle_smb_sessions, methods=['GET'])
		add_route_with_auth('/api/login_as', 'login_as', self.handle_login_as, methods=['POST'])
		add_route_with_auth('/api/smb/properties', 'smb_properties', self.handle_smb_properties, methods=['POST'])
		add_route_with_auth('/api/smb/set-security', 'smb_set_security', self.handle_smb_set_security, methods=['POST'])
		add_route_with_auth('/api/smb/remove-security', 'smb_remove_security', self.handle_smb_remove_security, methods=['POST'])
		add_route_with_auth('/api/smb/set-share-security', 'smb_set_share_security', self.handle_smb_set_share_security, methods=['POST'])
		add_route_with_auth('/api/smb/remove-share-security', 'smb_remove_share_security', self.handle_smb_remove_share_security, methods=['POST'])
		add_route_with_auth('/api/computer/restart', 'computer_restart', self.handle_computer_restart, methods=['POST'])
		add_route_with_auth('/api/computer/shutdown', 'computer_shutdown', self.handle_computer_shutdown, methods=['POST'])
		add_route_with_auth('/api/computer/tasklist', 'computer_tasklist', self.handle_computer_tasklist, methods=['POST'])

	def set_status(self, status):
		self.status = status

	def get_status(self):
		return self.status

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
		return jsonify(vars(self.powerview.args))
	
	def handle_server_info(self):
		server_info = self.powerview.conn.get_server_info()
		return jsonify(server_info)

	def handle_schema_info(self):
		schema_info = self.powerview.conn.get_schema_info()
		return jsonify(schema_info)
		
	def handle_set_settings(self):
		try:
			obfuscate = request.json.get('obfuscate', False)
			no_cache = request.json.get('no_cache', False)
			no_vuln_check = request.json.get('no_vuln_check', False)
			logging.info(f"obfuscate: {obfuscate}, no_cache: {no_cache}, no_vuln_check: {no_vuln_check}")
			
			# Update powerview args
			self.powerview.args.obfuscate = obfuscate
			self.powerview.args.no_cache = no_cache
			self.powerview.args.no_vuln_check = no_vuln_check
			
			# Create new CustomExtendedOperationsRoot instance with updated settings
			self.powerview.custom_paged_search = CustomExtendedOperationsRoot(self.powerview.ldap_session, obfuscate=obfuscate, no_cache=no_cache, no_vuln_check=no_vuln_check)
			self.powerview.ldap_session.extend.standard = self.powerview.custom_paged_search.standard
			
			return jsonify({'status': 'OK'})
		except Exception as e:
			logging.error(f"Error setting settings: {str(e)}")
			return jsonify({'error': str(e)}), 400

	def handle_connection_info(self):
		return jsonify({
			'domain': self.powerview.domain,
			'username': self.powerview.conn.get_username(),
			'is_admin': self.powerview.is_admin,
			'status': 'OK' if self.powerview.conn.is_connection_alive() else 'KO',
			'protocol': self.powerview.conn.get_proto(),
			'ldap_address': self.powerview.conn.get_ldap_address(),
			'nameserver': self.powerview.conn.get_nameserver(),
		})

	def execute_command(self):
		properties = [
			''
		]
		try:
			command = request.json.get('command', '')
			if not command:
				return jsonify({'error': 'No command provided'}), 400

			try:
				cmd = shlex.split(command)
			except ValueError as e:
				logging.error(f"Command parsing error: {str(e)}")
				return jsonify({'error': f'Command parsing error: {str(e)}'}), 400

			pv_args = powerview_arg_parse(cmd)

			if pv_args is None:
				return jsonify({'error': 'Invalid command or arguments'}), 400

			if not pv_args.module:
				return jsonify({'error': 'No module specified in the command'}), 400

			result = self.powerview.execute(pv_args)

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
		debug_enabled = bool(getattr(self.powerview.args, 'debug', False))
		request_handler = None
		try:
			from werkzeug.serving import WSGIRequestHandler
			class _SilentRequestHandler(WSGIRequestHandler):
				def log_request(self, *args, **kwargs):
					return
			request_handler = _SilentRequestHandler
		except Exception:
			request_handler = None
		log = logging.getLogger('werkzeug')
		log.setLevel(logging.CRITICAL)
		log.propagate = False
		try:
			self.app.logger.disabled = True
		except Exception:
			pass

		run_kwargs = {'host': self.host, 'port': self.port, 'debug': False}
		if request_handler is not None:
			run_kwargs['request_handler'] = request_handler

		if debug_enabled:
			self.api_server_thread = threading.Thread(
				target=self.app.run,
				kwargs=run_kwargs,
				daemon=True
			)
		else:
			with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
				self.api_server_thread = threading.Thread(
					target=self.app.run,
					kwargs=run_kwargs,
					daemon=True
				)

		self.set_status(True)
		logging.info(f"Powerview web listening on {self.host}:{self.port}")
		self.api_server_thread.start()

	def handle_smb_connect(self):
		try:
			data = request.json
			computer_input = data.get('computer')
			if not computer_input:
				return jsonify({'error': 'Computer name/IP is required'}), 400

			computer = computer_input.lower()
			username = data.get('username')
			password = data.get('password')
			nthash = data.get('nthash')
			lmhash = data.get('lmhash')
			aesKey = data.get('aesKey')
			domain = data.get('domain')

			if username and ('/' in username or '\\' in username):
				domain, username = username.replace('/', '\\').split('\\')
			
			resolved_host = self.powerview._resolve_host(computer)
			if resolved_host is None:
				return jsonify({'error': 'FQDN must be used for kerberos authentication'}), 400

			host = resolved_host
			logging.debug(f"[SMB Connect] Using resolved host: {host}")

			client = self.powerview.conn.init_smb_session(
				host,
				username=username,
				password=password,
				nthash=nthash,
				lmhash=lmhash,
				aesKey=aesKey,
				domain=domain
			)

			if not client:
				return jsonify({'error': f'Failed to connect to {host}'}), 400

			params = {
				'host': host,
				'input': computer,
				'username': username,
				'password': password,
				'nthash': nthash,
				'lmhash': lmhash,
				'aesKey': aesKey,
				'domain': domain,
			}
			self.smb_session_params[computer] = params
			self.smb_session_params[host.lower()] = params

			return jsonify({'status': 'connected', 'host': host})

		except Exception as e:
			logging.error(f"SMB Connect Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_reconnect(self):
		try:
			data = request.json
			computer_input = data.get('computer')
			if not computer_input:
				return jsonify({'error': 'Computer name/IP is required'}), 400
			computer = computer_input.lower()

			stored = self.smb_session_params.get(computer)
			resolved_host = self.powerview._resolve_host(computer)
			if not stored and resolved_host:
				stored = self.smb_session_params.get(str(resolved_host).lower())

			if resolved_host is None and self.powerview.conn.use_kerberos:
				host = (stored or {}).get('host')
				if not host:
					return jsonify({'error': 'FQDN must be used for kerberos authentication'}), 400
			else:
				host = resolved_host or computer

			kwargs = {}
			if stored:
				kwargs = {
					'username': stored.get('username'),
					'password': stored.get('password'),
					'nthash': stored.get('nthash'),
					'lmhash': stored.get('lmhash'),
					'aesKey': stored.get('aesKey'),
					'domain': stored.get('domain'),
				}

			client = self.powerview.conn.init_smb_session(host, force_new=True, **kwargs)
			logging.debug(f"SMB Reconnect: Successfully reconnected to {host}")
			return jsonify({'status': 'reconnected', 'host': host, 'used_stored_creds': bool(stored)})
		except Exception as e:
			logging.error(f"SMB Reconnect: Failed to reconnect: {str(e)}")
			return jsonify({'error': 'Failed to reconnect'}), 500

	def handle_smb_disconnect(self):
		try:
			data = request.json
			computer = data.get('computer').lower()
			
			if not computer:
				return jsonify({'error': 'Computer name/IP is required'}), 400

			self.powerview.conn.remove_smb_connection(computer)
			return jsonify({'status': 'disconnected'})
		except Exception as e:
			logging.error(f"SMB Disconnect Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_shares(self):
		try:
			data = request.json
			host = data.get('computer').lower()
			
			if not host:
				return jsonify({'error': 'Computer name/IP is required'}), 400

			try:
				client = self.powerview.conn.init_smb_session(host)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

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

	def handle_smb_add_share(self):
		try:
			data = request.json
			computer = data.get('computer', '').lower()
			share_name = data.get('share_name')
			share_path = data.get('share_path')
			
			if not all([computer, share_name, share_path]):
				return jsonify({'error': 'Computer name/IP, share name, and share path are required'}), 400

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			smb_client = SMBClient(client)
			
			try:
				result = smb_client.add_share(share_name, share_path)
				if result:
					return jsonify({
						'status': 'success', 
						'message': f'Share "{share_name}" created successfully at path "{share_path}"'
					}), 200
				else:
					return jsonify({'error': 'Failed to create share'}), 500
			except Exception as e:
				return jsonify({'error': f'Failed to create share: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB ADD SHARE] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_delete_share(self):
		try:
			data = request.json
			computer = data.get('computer', '').lower()
			share = data.get('share')
			
			if not all([computer, share]):
				return jsonify({'error': 'Computer name/IP and share name are required'}), 400

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			smb_client = SMBClient(client)
			
			try:
				result = smb_client.delete_share(share)
				if result:
					return jsonify({'status': 'success', 'message': 'Share deleted successfully'}), 200
				else:
					return jsonify({'error': 'Failed to delete share'}), 500
			except Exception as e:
				return jsonify({'error': f'Failed to delete share: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB DELETE SHARE] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_ls(self):
		try:
			data = request.json
			host = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path', '')
			
			if not host or not share:
				return jsonify({'error': 'Computer name/IP and share name are required'}), 400

			try:
				client = self.powerview.conn.init_smb_session(host)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400
			
			smb_client = SMBClient(client)
			
			files = smb_client.ls(share, path)
			logging.debug(f"[SMB LS] Listing {path} on {host} with share {share}")
			
			file_list = []
			for f in files:
				name = f.get_longname()
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

	def handle_smb_mv(self):
		try:
			data = request.json
			computer = data.get('computer').lower()
			share = data.get('share')
			source = data.get('source')
			destination = data.get('destination')

			if not all([computer, share, source, destination]):
				return jsonify({'error': 'Missing required parameters'}), 400
				
			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			smb_client = SMBClient(client)

			smb_client.mv(share, source, destination)	
			return jsonify({'message': 'File moved successfully'})
	
		except Exception as e:
			logging.error(f"[SMB MV] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_get(self):
		try:
			data = request.json
			host = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path')
			
			if not host or not share or not path:
				return jsonify({'error': 'Computer name/IP, share name, and file path are required'}), 400

			try:
				client = self.powerview.conn.init_smb_session(host)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

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
			computer = request.form.get('computer').lower()
			share = request.form.get('share')
			file = request.files.get('file')
			current_path = request.form.get('path', '')
			
			if not computer or not share:
				return jsonify({'error': 'Computer name/IP and share name are required'}), 400

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			smb_client = SMBClient(client)
			
			# Save file temporarily
			temp_path = os.path.join('/tmp', file.filename)
			file.save(temp_path)
			
			try:
				# Construct the remote path correctly
				# current_path might be like "/FolderA" or "" for root
				# file.filename is the original filename
				clean_dest_dir = current_path.strip('/').replace('/', '\\')
				remote_target_path = os.path.join(clean_dest_dir, file.filename).replace('/', '\\')
				
				logging.debug(f"[SMB PUT] Uploading {temp_path} to share '{share}', path: '{remote_target_path}'")
				
				# Reverting to the 3-argument call based on [Errno 2] indicating the path was likely accessed
				# without the correct share context.
				# Assumed signature: put(self, share_name, remote_path_in_share, local_path)
				smb_client.put(share, remote_target_path, temp_path)
				
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

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			smb_client = SMBClient(client)
			content = smb_client.cat(share, path)
			if content is None or len(content) == 0:
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

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

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

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

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

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

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

	def handle_smb_search(self):
		try:
			data = request.json
			host = data.get('computer', '').lower()
			share = data.get('share')
			query = data.get('query')
			depth = int(data.get('depth', 3))
			start_path = data.get('start_path', '')
			use_regex = data.get('use_regex', False)
			content_search = data.get('content_search', False)
			case_sensitive = data.get('case_sensitive', False)
			cred_hunt = data.get('cred_hunt', False)
			item_type = data.get('item_type', 'all')
			max_file_size = int(data.get('max_file_size', 5 * 1024 * 1024))  # Default 5MB
			file_extensions = data.get('file_extensions', ['.txt', '.cfg', '.conf', '.config', '.xml', '.json', '.ini', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.html', '.htm', '.log', '.sql', '.yml', '.yaml'])
			
			# If cred_hunt mode is enabled, set predefined patterns and options
			if cred_hunt:
				content_search = True
				use_regex = True
				if not query:
					query = r"(?i)(password|passwd|pwd|pass|cred|credential|secret|key|token|api[-_]?key|admin|root|adm)[=:].*"
				credential_file_patterns = [
					"id_rsa", "id_dsa", ".npmrc", ".pypirc", "credentials.json", "credentials.xml", "creds.txt", 
					"password", "passwd", "htpasswd", ".rdp", ".pgpass", ".git-credentials", "debug.log", 
					"web.config", ".env", "oauth", "wallet.dat", "*.pfx", "*.p12", "*.pkcs12", "*.key"
				]
				special_files = [".bash_history", ".zsh_history", ".netrc", "hosts", "authorized_keys", "known_hosts"]
			
			# Sanitize and normalize paths to prevent traversal attacks
			if '..' in start_path:
				start_path = start_path.replace('..', '')
			start_path = start_path.replace('\\\\', '\\').replace('//', '/')
			
			if not host or not share:
				return jsonify({'error': 'Computer and share are required'}), 400
				
			if not query and not cred_hunt:
				return jsonify({'error': 'Query is required or cred_hunt must be enabled'}), 400

			try:
				client = self.powerview.conn.init_smb_session(host)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			smb_client = SMBClient(client)
			
			mode = "cred_hunt" if cred_hunt else "content+regex" if content_search and use_regex else "content" if content_search else "regex" if use_regex else "pattern"
			case_mode = "case-sensitive" if case_sensitive else "case-insensitive"
			logging.info(f"[SMB SEARCH] Starting {mode} ({case_mode}) search on {host}\\{share} (depth {depth}){' for pattern ' + query if query else ''}")
			
			found_items = []
			visited_paths = set()
			error_paths = set()
			
			# Compile regex if using regex search
			regex_pattern = None
			if use_regex:
				try:
					import re
					regex_flags = re.MULTILINE
					if not case_sensitive:
						regex_flags |= re.IGNORECASE
					regex_pattern = re.compile(query, regex_flags)
				except re.error:
					return jsonify({'error': 'Invalid regex pattern'}), 400

			def is_credential_file(file_name):
				if not cred_hunt:
					return False
					
				file_lower = file_name.lower()
				
				# Check exact matches for special filenames
				if file_lower in special_files:
					return True
					
				# Check credential file patterns
				for pattern in credential_file_patterns:
					if fnmatch.fnmatch(file_lower, pattern):
						return True
						
				return False

			def should_check_content(file_name, file_size):
				if not content_search and not cred_hunt:
					return False
				
				if file_size > max_file_size:
					return False
				
				if is_credential_file(file_name):
					return True
					
				file_ext = os.path.splitext(file_name.lower())[1]
				return file_ext in file_extensions

			def search_content(file_path, item_name, item_details):
				try:
					file_content = smb_client.cat(share, file_path)
					if not file_content:
						return False
						
					is_credential_match = is_credential_file(item_name)
					if is_credential_match:
						item_details["match_type"] = "credential_file"
						item_details["is_credential_file"] = True
						
					try:
						# Try to decode as UTF-8 first
						text_content = file_content.decode('utf-8', errors='replace')
					except (UnicodeDecodeError, AttributeError):
						try:
							# If that fails, try Latin-1
							text_content = file_content.decode('latin-1', errors='replace')
						except:
							# If all fails, use raw bytes search
							if use_regex and regex_pattern:
								return bool(regex_pattern.search(str(file_content))) or is_credential_match
							else:
								return (query in str(file_content) if case_sensitive else query.lower() in str(file_content).lower()) or is_credential_match
					
					if use_regex and regex_pattern:
						match = regex_pattern.search(text_content)
						if match:
							# Add match context to the result
							start = max(0, match.start() - 50)
							end = min(len(text_content), match.end() + 50)
							match_context = text_content[start:end]
							item_details["content_match"] = match_context.strip()
							item_details["match_position"] = match.start()
							return True
					elif query:
						if case_sensitive:
							if query in text_content:
								# Find the first occurrence and add context
								pos = text_content.find(query)
								start = max(0, pos - 50)
								end = min(len(text_content), pos + len(query) + 50)
								match_context = text_content[start:end]
								item_details["content_match"] = match_context.strip()
								item_details["match_position"] = pos
								return True
						else:
							if query.lower() in text_content.lower():
								# Find the first occurrence and add context
								pos = text_content.lower().find(query.lower())
								start = max(0, pos - 50)
								end = min(len(text_content), pos + len(query) + 50)
								match_context = text_content[start:end]
								item_details["content_match"] = match_context.strip()
								item_details["match_position"] = pos
								return True
							
					return is_credential_match
				except Exception as e:
					logging.debug(f"[SMB CONTENT SEARCH] Error reading {file_path}: {str(e)}")
					return False

			def search_recursive(current_path, current_depth):
				if current_depth > depth:
					return
					
				if current_path in visited_paths:
					return
					
				visited_paths.add(current_path)
				
				path_log = current_path if current_path else '\\' 
				logging.debug(f"[SMB SEARCH] Searching {path_log} (depth {current_depth})")

				try:
					items = smb_client.ls(share, current_path)
					for item in items:
						item_name = item.get_longname()
						if item_name in ['.', '..']:
							continue

						temp_path = os.path.join(current_path, item_name)
						full_item_path = temp_path.replace('/', '\\') 
						if full_item_path.startswith('\\') and not current_path:
							full_item_path = full_item_path[1:]

						# Create item details dictionary
						item_details = {
							"name": item_name,
							"path": full_item_path,
							"is_directory": item.is_directory(),
							"size": item.get_filesize(),
							"created": str(item.get_ctime()),
							"modified": str(item.get_mtime()),
							"accessed": str(item.get_atime()),
							"share": share,
							"match_type": "name"
						}

						# Skip based on item type filter
						if (item_type == 'files' and item.is_directory()) or (item_type == 'directories' and not item.is_directory()):
							if item.is_directory():
								# Still search directories even if we're only looking for files
								search_recursive(full_item_path, current_depth + 1)
							continue

						# Check for credential files first
						if not item.is_directory() and cred_hunt and is_credential_file(item_name):
							cred_file_details = item_details.copy()
							cred_file_details["match_type"] = "credential_file"
							cred_file_details["is_credential_file"] = True
							logging.debug(f"[SMB SEARCH] Found credential file: {full_item_path}")
							found_items.append(cred_file_details)

						# Check filename match
						if query:
							name_match = False
							if use_regex and regex_pattern:
								name_match = bool(regex_pattern.search(item_name))
							else:
								if case_sensitive:
									name_match = fnmatch.fnmatch(item_name, query)
								else:
									name_match = fnmatch.fnmatch(item_name.lower(), query.lower())
							
							# Add item if filename matches
							if name_match:
								logging.debug(f"[SMB SEARCH] Found name match: {full_item_path}")
								found_items.append(item_details.copy())
						
						# Check content match for files only
						if not item.is_directory() and should_check_content(item_name, item.get_filesize()):
							content_match_details = item_details.copy()
							content_match_details["match_type"] = "content"
							
							if search_content(full_item_path, item_name, content_match_details):
								match_type = "content match" if "content_match" in content_match_details else "credential file"
								logging.debug(f"[SMB SEARCH] Found {match_type} in: {full_item_path}")
								found_items.append(content_match_details)

						# Continue recursion if it's a directory
						if item.is_directory():
							search_recursive(full_item_path, current_depth + 1)
				except Exception as e:
					error_paths.add(current_path)
					logging.debug(f"[SMB SEARCH] Error accessing path {current_path}: {str(e)}")

			search_recursive(start_path, 0)
			
			total_items = len(found_items)
			if cred_hunt:
				logging.info(f"[SMB SEARCH] Found {total_items} potential credential files/matches")
			else:
				logging.info(f"[SMB SEARCH] Found {total_items} matching items for '{query}'")
			
			if error_paths:
				logging.debug(f"[SMB SEARCH] Encountered access errors in {len(error_paths)} paths")
			
			return jsonify({
				'items': found_items,
				'total': total_items,
				'search_info': {
					'pattern': query,
					'search_mode': mode,
					'case_sensitive': case_sensitive,
					'content_search': content_search,
					'cred_hunt': cred_hunt,
					'share': share,
					'host': host,
					'max_depth': depth,
					'item_type': item_type,
					'paths_searched': len(visited_paths),
					'error_paths': len(error_paths),
					'file_extensions_searched': file_extensions if content_search else None
				}
			})

		except Exception as e:
			logging.error(f"[SMB SEARCH] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_login_as(self):
		"""Handles requests to the /api/login_as endpoint."""
		try:
			data = request.json
			username = data.get('username')
			password = data.get('password')
			domain = data.get('domain')
			lmhash = data.get('lmhash')
			nthash = data.get('nthash')
			auth_aes_key = data.get('auth_aes_key')

			if not username:
				return jsonify({'error': 'Username is required'}), 400

			success = self.powerview.login_as(
				username=username,
				password=password,
				domain=domain,
				lmhash=lmhash,
				nthash=nthash,
				auth_aes_key=auth_aes_key
			)

			if success:
				try:
					current_identity = self.powerview.conn.who_am_i()
					message = f"Successfully logged in as {current_identity}"
					connection_info = {
						'domain': self.powerview.domain,
						'username': self.powerview.conn.get_username(),
						'is_admin': self.powerview.is_admin,
						'status': 'OK' if self.powerview.is_connection_alive() else 'KO',
						'protocol': self.powerview.conn.get_proto(),
						'ldap_address': self.powerview.conn.get_ldap_address(),
						'nameserver': self.powerview.conn.get_nameserver(),
					}
					return jsonify({'status': 'success', 'message': message, 'connection_info': connection_info}), 200
				except Exception as inner_e:
					logging.error(f"Error fetching identity after login_as for {username}: {str(inner_e)}")
					return jsonify({'status': 'success', 'message': f"Login attempt for {username} processed, but failed to confirm new identity."}), 200
			else:
				message = f"Failed to login as {username}@{domain or self.powerview.domain}. Check credentials or permissions."
				logging.warning(message)
				return jsonify({'status': 'failure', 'error': message}), 401 # Use 401 for authentication failure

		except Exception as e:
			logging.error(f"Unexpected exception during login_as for {username}: {str(e)}")
			return jsonify({'error': f"An unexpected error occurred during login: {str(e)}"}), 500

	def handle_smb_sessions(self):
		try:
			stats = self.powerview.conn.get_smb_session_stats()
			
			sessions = {}
			if 'hosts' in stats:
				for host, host_stats in stats['hosts'].items():
					sessions[host] = {
						'computer': host,
						'connected': host_stats.get('is_alive', False),
						'last_used': datetime.fromtimestamp(host_stats.get('last_used', 0)).strftime('%Y-%m-%d %H:%M:%S') if 'last_used' in host_stats else 'N/A',
						'use_count': host_stats.get('use_count', 0),
						'age': host_stats.get('age', 0),
						'last_check': datetime.fromtimestamp(host_stats.get('last_check_time', 0)).strftime('%Y-%m-%d %H:%M:%S') if 'last_check_time' in host_stats else 'N/A'
					}
			
			return jsonify({'sessions': sessions})
		except Exception as e:
			logging.error(f"Error fetching SMB sessions: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_search_stream(self):
		"""Server-Sent Event progressive search wrapper around handle_smb_search logic."""
		try:
			# Grab and normalise parameters from query-string
			args = request.args
			host = args.get('computer', '').lower()
			share = args.get('share')
			query = args.get('query', '')
			start_path = args.get('start_path', '')
			depth = int(args.get('depth', 3))
			use_regex = args.get('use_regex', 'false').lower() == 'true'
			content_search = args.get('content_search', 'false').lower() == 'true'
			case_sensitive = args.get('case_sensitive', 'false').lower() == 'true'
			cred_hunt = args.get('cred_hunt', 'false').lower() == 'true'
			item_type = args.get('item_type', 'all')

			if not host or not share:
				return jsonify({'error': 'Computer and share are required'}), 400

			try:
				client = self.powerview.conn.init_smb_session(host)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			smb_client = SMBClient(client)

			# Prepare helpers
			import re, fnmatch, os
			regex_pattern = None
			if use_regex and query:
				flags = re.MULTILINE | (0 if case_sensitive else re.IGNORECASE)
				try:
					regex_pattern = re.compile(query, flags)
				except re.error:
					return jsonify({'error': 'Invalid regex pattern'}), 400

			def name_match(filename):
				if not query:
					return False
				if use_regex and regex_pattern:
					return bool(regex_pattern.search(filename))
				if case_sensitive:
					return fnmatch.fnmatch(filename, query)
				return fnmatch.fnmatch(filename.lower(), query.lower())

			def content_match(path, filename):
				if not content_search and not cred_hunt:
					return False, None
				try:
					blob = smb_client.cat(share, path)
					if not blob:
						return False, None
					try:
						text = blob.decode('utf-8', errors='replace')
					except Exception:
						text = str(blob)

					if cred_hunt:
						return True, None
					if query:
						if use_regex and regex_pattern:
							m = regex_pattern.search(text)
							if m:
								return True, text[m.start():m.end()+100]
						else:
							needle = query if case_sensitive else query.lower()
							hay = text if case_sensitive else text.lower()
							idx = hay.find(needle)
							if idx != -1:
								return True, text[idx:idx+100]
					return False, None
				except Exception:
					return False, None

			def event_stream():
				visited = set()
				stack = [(start_path, 0)]
				total = 0
				while stack:
					current_path, cur_depth = stack.pop()
					if cur_depth > depth or current_path in visited:
						continue
					visited.add(current_path)
					try:
						items = smb_client.ls(share, current_path)
					except Exception:
						continue
					for itm in items:
						name = itm.get_longname()
						if name in ['.', '..']:
							continue
						full_path = os.path.join(current_path, name).replace('/', '\\')
						if full_path.startswith('\\') and not current_path:
							full_path = full_path[1:]

						is_directory = itm.is_directory()
						item_details = {
							'name': name,
							'path': full_path,
							'is_directory': is_directory,
							'size': itm.get_filesize(),
							'share': share,
							'match_type': 'name'
						}

						# Skip based on item type filter
						if (item_type == 'files' and is_directory) or (item_type == 'directories' and not is_directory):
							if is_directory:
								# Still search directories even if we're only looking for files
								stack.append((full_path, cur_depth + 1))
							continue

						matched = False
						if name_match(name):
							matched = True
						elif not is_directory:
							cm, ctx = content_match(full_path, name)
							if cm:
								matched = True
								item_details['match_type'] = 'content'
								if ctx:
									item_details['content_match'] = ctx

						if matched:
							yield f"data: {json.dumps({'type':'found','item': item_details})}\n\n"
							total += 1

						if is_directory:
							stack.append((full_path, cur_depth + 1))

				yield f"data: {json.dumps({'type':'done','total': total})}\n\n"

			headers = {
				'Content-Type': 'text/event-stream',
				'Cache-Control': 'no-cache',
				'X-Accel-Buffering': 'no'
			}
			return Response(stream_with_context(event_stream()), headers=headers)
		except Exception as e:
			logging.error(f"[SMB SEARCH STREAM] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_properties(self):
		try:
			data = request.json
			computer = data.get('computer').lower()
			share = data.get('share')
			path = data.get('path')

			if not computer or not share:
				return jsonify({'error': 'Missing required parameters'}), 400

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first'}), 400

			smb_client = SMBClient(client)

			if not path:
				share_info = smb_client.share_info(share)
				def convert_bytes(obj):
					if isinstance(obj, dict):
						return {k: convert_bytes(v) for k, v in obj.items()}
					elif isinstance(obj, list):
						return [convert_bytes(i) for i in obj]
					elif isinstance(obj, bytes):
						return obj.decode('utf-8')
					return obj
				share_info = convert_bytes(share_info)
				if share_info.get('sd_info'):
					share_info['owner'] = self.powerview.convertfrom_sid(share_info['sd_info'].get('OwnerSid'))
					share_info['group'] = self.powerview.convertfrom_sid(share_info['sd_info'].get('GroupSid'))
					share_info['dacl'] = share_info['sd_info'].get('Dacl')
					for ace in share_info['dacl'] or []:
						ace['trustee'] = self.powerview.convertfrom_sid(ace['trustee'])
				return jsonify(share_info)

			try:
				file_info = smb_client.get_file_info(share, path)
				file_info['owner'] = self.powerview.convertfrom_sid(file_info['sd_info']['OwnerSid'])
				file_info['group'] = self.powerview.convertfrom_sid(file_info['sd_info']['GroupSid'])
				file_info['dacl'] = file_info['sd_info']['Dacl']
				for ace in file_info['dacl']:
					ace['trustee'] = self.powerview.convertfrom_sid(ace['trustee'])
				for ts_field in ['created', 'modified', 'accessed']:
					if ts_field in file_info:
						try:
							ts_str = file_info[ts_field]
							file_info[ts_field + '_formatted'] = ts_str
						except Exception as e:
							logging.debug(f"Could not format timestamp {ts_field}: {str(e)}")
				try:
					path = path.replace('/', '\\')
					file_info['full_path'] = f"\\\\{computer}\\{share}\\{path}"
					file_info['computer'] = computer
					file_info['share'] = share
				except Exception as attr_err:
					logging.warning(f"Could not get additional file attributes: {str(attr_err)}")
				return jsonify(file_info)
			except Exception as e:
				return jsonify({'error': f'Failed to get file properties: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB PROPERTIES] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_set_security(self):
		try:
			data = request.json
			computer = data.get('computer', '').lower()
			share = data.get('share')
			path = data.get('path')
			username = data.get('username')
			mask = data.get('mask', 'fullcontrol').lower()
			ace_type = data.get('ace_type', 'allow').lower()
			
			if not all([computer, share, path, username]):
				return jsonify({'error': 'Missing required parameters. Computer, share, path, and username are required.'}), 400
				
			if ace_type not in ['allow', 'deny']:
				return jsonify({'error': 'Invalid ace_type. Must be "allow" or "deny".'}), 400

			if mask not in ['fullcontrol', 'modify', 'readandexecute', 'readandwrite', 'read', 'write']:
				return jsonify({'error': 'Invalid mask. Must be "fullcontrol", "modify", "readandexecute", "readandwrite", "read", or "write".'}), 400

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first.'}), 400

			if is_valid_sid(username):
				sid = username
			else:
				sid = self.powerview.convertto_sid(username)
			
			if sid is None or not is_valid_sid(sid):
				return jsonify({'error': f'Username {username} is not found in the domain. Use a SID instead.'}), 400

			smb_client = SMBClient(client)
			
			try:
				result = smb_client.set_file_security(share, path, sid, ace_type, mask)
				if result:
					return jsonify({'status': 'success', 'message': 'File security set successfully'}), 200
				else:
					return jsonify({'error': 'Failed to set file security'}), 500
			except Exception as e:
				return jsonify({'error': f'Failed to set file security: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB SET SECURITY] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_remove_security(self):
		try:
			data = request.json
			computer = data.get('computer', '').lower()
			share = data.get('share')
			path = data.get('path')
			username = data.get('username')
			mask = data.get('mask')
			ace_type = data.get('ace_type')
			
			if not all([computer, share, path, username]):
				return jsonify({'error': 'Missing required parameters. Computer, share, path, and username are required.'}), 400

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first.'}), 400

			if is_valid_sid(username):
				sid = username
			else:
				sid = self.powerview.convertto_sid(username)
			
			if sid is None or not is_valid_sid(sid):
				return jsonify({'error': f'Username {username} is not found in the domain. Use a SID instead.'}), 400

			smb_client = SMBClient(client)
			
			try:
				result = smb_client.remove_file_security(share, path, sid, mask, ace_type)
				if result:
					return jsonify({'status': 'success', 'message': 'ACE removed successfully'}), 200
				else:
					return jsonify({'error': 'No matching ACEs found to remove'}), 404
			except Exception as e:
				return jsonify({'error': f'Failed to remove ACE: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB REMOVE SECURITY] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_set_share_security(self):
		try:
			data = request.json
			computer = data.get('computer', '').lower()
			share = data.get('share')
			username = data.get('username')
			mask = data.get('mask', 'fullcontrol').lower()
			ace_type = data.get('ace_type', 'allow').lower()
			
			if not all([computer, share, username]):
				return jsonify({'error': 'Missing required parameters. Computer, share, and username are required.'}), 400
				
			if ace_type not in ['allow', 'deny']:
				return jsonify({'error': 'Invalid ace_type. Must be "allow" or "deny".'}), 400

			if mask not in ['fullcontrol', 'modify', 'readandexecute', 'readandwrite', 'read', 'write']:
				return jsonify({'error': 'Invalid mask. Must be "fullcontrol", "modify", "readandexecute", "readandwrite", "read", or "write".'}), 400

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first.'}), 400

			if is_valid_sid(username):
				sid = username
			else:
				sid = self.powerview.convertto_sid(username)
			
			if sid is None or not is_valid_sid(sid):
				return jsonify({'error': f'Username {username} is not found in the domain. Use a SID instead.'}), 400

			smb_client = SMBClient(client)
			
			try:
				result = smb_client.set_share_security(share, sid, mask, ace_type)
				if result:
					permission_name = mask.title().replace('and', ' & ')
					action = 'granted' if ace_type == 'allow' else 'denied'
					return jsonify({
						'status': 'success', 
						'message': f'{permission_name} permission {action} for {username} on share {share}'
					}), 200
				else:
					return jsonify({'error': 'Failed to set share security'}), 500
			except Exception as e:
				return jsonify({'error': f'Failed to set share security: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB SET SHARE SECURITY] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_smb_remove_share_security(self):
		try:
			data = request.json
			computer = data.get('computer', '').lower()
			share = data.get('share')
			username = data.get('username')
			mask = data.get('mask')
			ace_type = data.get('ace_type')
			
			if not all([computer, share, username]):
				return jsonify({'error': 'Missing required parameters. Computer, share, and username are required.'}), 400

			try:
				client = self.powerview.conn.init_smb_session(computer)
			except Exception as e:
				return jsonify({'error': 'No active SMB session. Please connect first.'}), 400

			if is_valid_sid(username):
				sid = username
			else:
				sid = self.powerview.convertto_sid(username)
			
			if sid is None or not is_valid_sid(sid):
				return jsonify({'error': f'Username {username} is not found in the domain. Use a SID instead.'}), 400

			smb_client = SMBClient(client)
			
			try:
				result = smb_client.remove_share_security(share, sid, mask, ace_type)
				if result:
					return jsonify({'status': 'success', 'message': 'Share security removed successfully'}), 200
				else:
					return jsonify({'error': 'No matching ACEs found to remove'}), 404
			except Exception as e:
				return jsonify({'error': f'Failed to remove share security: {str(e)}'}), 500

		except Exception as e:
			logging.error(f"[SMB REMOVE SHARE SECURITY] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_computer_restart(self):
		try:
			data = request.json or {}
			computer_input = data.get('computer')
			if not computer_input:
				return jsonify({'error': 'Computer name/IP is required'}), 400
			username = data.get('username')
			password = data.get('password')
			domain = data.get('domain')
			lmhash = data.get('lmhash')
			nthash = data.get('nthash')
			if username and ('/' in username or '\\' in username):
				domain, username = username.replace('/', '\\').split('\\', 1)
			if username and not (password or lmhash or nthash):
				return jsonify({'error': 'Password or hash is required when specifying a username'}), 400
			resolved_host = self.powerview._resolve_host(computer_input)
			if resolved_host is None:
				return jsonify({'error': 'FQDN must be used for kerberos authentication'}), 400
			host = resolved_host
			smbConn = self.powerview.conn.init_smb_session(
				host,
				username=username,
				password=password,
				domain=domain,
				lmhash=lmhash,
				nthash=nthash,
				show_exceptions=False
			)
			if not smbConn:
				return jsonify({'error': f'Failed to connect to {host}'}), 400
			ts = TSHandler(smb_connection=smbConn, target_ip=host, doKerberos=self.powerview.use_kerberos, stack_trace=self.powerview.args.stack_trace)
			success = ts.do_shutdown(logoff=True, shutdown=False, reboot=True, poweroff=False)
			if success:
				return jsonify({'status': 'OK', 'message': f'Restart signal sent to {host}'}), 200
			return jsonify({'error': f'Failed to restart {host}'}), 500
		except Exception as e:
			logging.error(f"[RESTART COMPUTER] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_computer_shutdown(self):
		try:
			data = request.json or {}
			computer_input = data.get('computer')
			if not computer_input:
				return jsonify({'error': 'Computer name/IP is required'}), 400
			username = data.get('username')
			password = data.get('password')
			domain = data.get('domain')
			lmhash = data.get('lmhash')
			nthash = data.get('nthash')
			if username and ('/' in username or '\\' in username):
				domain, username = username.replace('/', '\\').split('\\', 1)
			if username and not (password or lmhash or nthash):
				return jsonify({'error': 'Password or hash is required when specifying a username'}), 400
			resolved_host = self.powerview._resolve_host(computer_input)
			if resolved_host is None:
				return jsonify({'error': 'FQDN must be used for kerberos authentication'}), 400
			host = resolved_host
			smbConn = self.powerview.conn.init_smb_session(
				host,
				username=username,
				password=password,
				domain=domain,
				lmhash=lmhash,
				nthash=nthash,
				show_exceptions=False
			)
			if not smbConn:
				return jsonify({'error': f'Failed to connect to {host}'}), 400
			ts = TSHandler(smb_connection=smbConn, target_ip=host, doKerberos=self.powerview.use_kerberos, stack_trace=self.powerview.args.stack_trace)
			success = ts.do_shutdown(logoff=True, shutdown=True, reboot=False, poweroff=False)
			if success:
				return jsonify({'status': 'OK', 'message': f'Shutdown signal sent to {host}'}), 200
			return jsonify({'error': f'Failed to shutdown {host}'}), 500
		except Exception as e:
			logging.error(f"[SHUTDOWN COMPUTER] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500

	def handle_computer_tasklist(self):
		try:
			data = request.json or {}
			computer_input = data.get('computer')
			if not computer_input:
				return jsonify({'error': 'Computer name/IP is required'}), 400
			username = data.get('username')
			password = data.get('password')
			domain = data.get('domain')
			lmhash = data.get('lmhash')
			nthash = data.get('nthash')
			pid = data.get('pid')
			name = data.get('name')
			if isinstance(pid, str) and pid.isdigit():
				pid = int(pid)
			if username and ('/' in username or '\\' in username):
				domain, username = username.replace('/', '\\').split('\\', 1)
			if username and not (password or lmhash or nthash):
				return jsonify({'error': 'Password or hash is required when specifying a username'}), 400
			resolved_host = self.powerview._resolve_host(computer_input)
			if resolved_host is None:
				return jsonify({'error': 'FQDN must be used for kerberos authentication'}), 400
			host = resolved_host
			smbConn = self.powerview.conn.init_smb_session(
				host,
				username=username,
				password=password,
				domain=domain,
				lmhash=lmhash,
				nthash=nthash,
				show_exceptions=False
			)
			if not smbConn:
				return jsonify({'error': f'Failed to connect to {host}'}), 400
			ts = TSHandler(smb_connection=smbConn, target_ip=host, doKerberos=self.powerview.use_kerberos, stack_trace=self.powerview.args.stack_trace)
			result = ts.do_tasklist(pid=pid, name=name)
			return jsonify(make_serializable(result))
		except Exception as e:
			logging.error(f"[TASKLIST COMPUTER] Error: {str(e)}")
			return jsonify({'error': str(e)}), 500