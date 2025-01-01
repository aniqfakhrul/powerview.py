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
		self.app.add_url_rule('/utils', 'utils', self.render_utils, methods=['GET'])
		self.app.add_url_rule('/api/get/<method_name>', 'get_operation', self.handle_get_operation, methods=['GET', 'POST'])
		self.app.add_url_rule('/api/set/<method_name>', 'set_operation', self.handle_set_operation, methods=['POST'])
		self.app.add_url_rule('/api/add/<method_name>', 'add_operation', self.handle_add_operation, methods=['POST'])
		self.app.add_url_rule('/api/invoke/<method_name>', 'invoke_operation', self.handle_invoke_operation, methods=['POST'])
		self.app.add_url_rule('/api/remove/<method_name>', 'remove_operation', self.handle_remove_operation, methods=['POST'])
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
			]},
			{"name": "Utils", "icon": "fas fa-toolbox", "link": "/utils"},
			{"name": "Logs", "icon": "far fa-file-alt", "button_id": "toggle-command-history"},
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
			'nav_items': self.nav_items
		}
		return render_template('oupage.html', **context)

	def render_gpo(self):
		context = {
			'title': 'Powerview.py - GPOs',
			'nav_items': self.nav_items
		}
		return render_template('gpopage.html', **context)

	def render_utils(self):
		context = {
			'title': 'Powerview.py - Utils',
			'nav_items': self.nav_items
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