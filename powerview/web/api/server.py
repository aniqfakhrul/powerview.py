#!/usr/bin/env python3
from flask import Flask, jsonify, request, render_template
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
		self.app.add_url_rule('/users', 'users', self.render_users, methods=['GET'])
		self.app.add_url_rule('/computers', 'computers', self.render_computers, methods=['GET'])
		self.app.add_url_rule('/utils', 'utils', self.render_utils, methods=['GET'])
		self.app.add_url_rule('/api/get/<method_name>', 'get_operation', self.handle_get_operation, methods=['GET', 'POST'])
		self.app.add_url_rule('/api/set/<method_name>', 'set_operation', self.handle_set_operation, methods=['POST'])
		self.app.add_url_rule('/api/add/<method_name>', 'add_operation', self.handle_add_operation, methods=['POST'])
		self.app.add_url_rule('/api/invoke/<method_name>', 'invoke_operation', self.handle_invoke_operation, methods=['POST'])
		self.app.add_url_rule('/api/remove/<method_name>', 'remove_operation', self.handle_remove_operation, methods=['POST'])
		self.app.add_url_rule('/api/convert/<method_name>', 'convert_operation', self.handle_convert_operation, methods=['POST'])
		self.app.add_url_rule('/api/get/domaininfo', 'domaininfo', self.handle_domaininfo, methods=['GET'])
		self.app.add_url_rule('/health', 'health', self.handle_health, methods=['GET'])
		self.app.add_url_rule('/api/status', 'status', self.handle_status, methods=['GET'])
		self.app.add_url_rule('/api/logs', 'logs', self.render_logs, methods=['GET'])
		self.app.add_url_rule('/api/history', 'history', self.render_history, methods=['GET'])
		self.app.add_url_rule('/api/ldap_rebind', 'ldap_rebind', self.handle_ldap_rebind, methods=['GET'])
		self.app.add_url_rule('/api/execute', 'execute_command', self.execute_command, methods=['POST'])

		self.nav_items = [
			{"name": "Tree View", "icon": "fas fa-folder-tree", "link": "/"},
			{"name": "Modules", "icon": "fas fa-cubes", "subitems": [
				{"name": "Users", "icon": "far fa-user", "link": "/users"},
				{"name": "Computers", "icon": "fas fa-display", "link": "/computers"},
			]},
			{"name": "Utils", "icon": "fas fa-toolbox", "link": "/utils"},
			{"name": "Logs", "icon": "far fa-file-alt", "button_id": "toggle-command-history"},
		]

	def render_index(self):
		context = {	
			'nav_items': self.nav_items
		}
		return render_template('index.html', **context)

	def render_users(self):
		context = {
			'nav_items': self.nav_items,
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
				{'id': 'physicaldeliveryofficename-toggle', 'name': 'physicalDeliveryOfficeName', 'active': 'false', 'attribute': 'physicalDeliveryOfficeName'},
				{'id': 'serviceprincipalname-toggle', 'name': 'servicePrincipalName', 'active': 'false', 'attribute': 'servicePrincipalName'},
				{'id': 'memberof-toggle', 'name': 'memberOf', 'active': 'false', 'attribute': 'memberOf'},
				{'id': 'accountexpires-toggle', 'name': 'accountExpires', 'active': 'false', 'attribute': 'accountExpires'}
			]
		}
		return render_template('userspage.html', **context)

	def render_computers(self):
		context = {
			'nav_items': self.nav_items,
			'ldap_properties': [
				{'id': 'all-toggle', 'name': 'All', 'active': 'false', 'attribute': '*'},
				{'id': 'samaccountname-toggle', 'name': 'sAMAccountname', 'active': 'true', 'attribute': 'sAMAccountName'},
				{'id': 'cn-toggle', 'name': 'cn', 'active': 'true', 'attribute': 'cn'},
				{'id': 'operatingsystem-toggle', 'name': 'operatingSystem', 'active': 'true', 'attribute': 'operatingSystem'},
				{'id': 'operatingsystemversion-toggle', 'name': 'operatingSystemVersion', 'active': 'true', 'attribute': 'operatingSystemVersion'},
				{'id': 'description-toggle', 'name': 'description', 'active': 'false', 'attribute': 'description'},
				{'id': 'useraccountcontrol-toggle', 'name': 'userAccountControl', 'active': 'false', 'attribute': 'userAccountControl'},
				{'id': 'serviceprincipalname-toggle', 'name': 'servicePrincipalName', 'active': 'false', 'attribute': 'servicePrincipalName'},
				{'id': 'memberof-toggle', 'name': 'memberOf', 'active': 'false', 'attribute': 'memberOf'}
			]
		}
		return render_template('computerpage.html', **context)

	def render_utils(self):
		context = {
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

	def handle_convert_operation(self, method_name):
		return self.handle_operation(f"convertfrom_{method_name}")

	def handle_domaininfo(self):
		domain_info = {
			'domain': self.powerview.domain,
			'root_dn': self.powerview.root_dn,
			'dc_dnshostname': self.powerview.dc_dnshostname,
			'flatName': self.powerview.flatName,
			'is_admin': self.powerview.is_admin,
		}
		return jsonify(domain_info)

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

	def handle_status(self):
		return jsonify({'status': 'OK' if self.powerview.is_connection_alive() else 'KO'})

	def handle_ldap_rebind(self):
		return jsonify({'status': 'OK' if self.powerview.conn.reset_connection() else 'KO'})

	def render_history(self):
		try:
			with open(self.history_file_path, 'r') as history_file:
				history_lines = history_file.readlines()
				last_50_lines = history_lines[-50:]
				history = [line.strip() for line in last_50_lines]
			return jsonify({'result': history})
		except Exception as e:
			return jsonify({'error': str(e)}), 500

	def render_logs(self):
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
