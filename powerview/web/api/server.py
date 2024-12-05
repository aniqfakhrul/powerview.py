#!/usr/bin/env python3
from flask import Flask, jsonify, request, render_template
import logging
from contextlib import redirect_stdout, redirect_stderr
import io
import os
import sys
import threading
from datetime import date

from powerview.web.api.helpers import make_serializable

class APIServer:
	def __init__(self, powerview, host="127.0.0.1", port=5000):
		self.app = Flask(__name__, static_folder='../../web/front-end/static', template_folder='../../web/front-end/templates')
		cli = sys.modules['flask.cli']
		cli.show_server_banner = lambda *x: None

		self.powerview = powerview
		self.host = host
		self.port = port

		# Define routes
		self.app.add_url_rule('/', 'index', self.render_index, methods=['GET'])
		self.app.add_url_rule('/api/get/<method_name>', 'get_operation', self.handle_get_operation, methods=['GET', 'POST'])
		self.app.add_url_rule('/api/set/<method_name>', 'set_operation', self.handle_set_operation, methods=['POST'])
		self.app.add_url_rule('/api/add/<method_name>', 'add_operation', self.handle_add_operation, methods=['POST'])
		self.app.add_url_rule('/api/invoke/<method_name>', 'invoke_operation', self.handle_invoke_operation, methods=['POST'])
		self.app.add_url_rule('/api/remove/<method_name>', 'remove_operation', self.handle_remove_operation, methods=['POST'])
		self.app.add_url_rule('/api/get/domaininfo', 'domaininfo', self.handle_domaininfo, methods=['GET'])
		self.app.add_url_rule('/health', 'health', self.handle_health, methods=['GET'])
		self.app.add_url_rule('/api/status', 'status', self.handle_status, methods=['GET'])
		self.app.add_url_rule('/api/history', 'history', self.render_history, methods=['GET'])
		self.app.add_url_rule('/api/ldap_rebind', 'ldap_rebind', self.handle_ldap_rebind, methods=['GET'])

	def render_index(self):
		return render_template('index.html')

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

	def handle_domaininfo(self):
		domain_info = {
			'domain': self.powerview.domain,
			'root_dn': self.powerview.root_dn,
			'dc_dnshostname': self.powerview.dc_dnshostname,
			'flatName': self.powerview.flatName,
			'is_admin': self.powerview.is_admin,
		}
		return jsonify(domain_info)

	def handle_health(self):
		return jsonify({'status': 'ok'})

	def handle_status(self):
		return jsonify({'status': 'OK' if self.powerview.is_connection_alive() else 'KO'})

	def handle_ldap_rebind(self):
		return jsonify({'status': 'OK' if self.powerview.conn.reset_connection() else 'KO'})

	def render_history(self):
		try:
			page = int(request.args.get('page', 1))
			limit = int(request.args.get('limit', 10))

			max_limit = 100
			if limit > max_limit:
				raise ValueError(f"Limit of {limit} exceeds the maximum allowed value of {max_limit}")

			components = [self.powerview.flatName.lower(), self.powerview.args.username.lower(), self.powerview.args.ldap_address.lower()]
			folder_name = '-'.join(filter(None, components)) or "default-log"
			file_name = "%s.log" % date.today()
			file_path = os.path.join(os.path.expanduser('~/.powerview/logs/'), folder_name, file_name)

			def read_logs(file_path, start, end):
				with open(file_path, 'r') as log_file:
					for current_line, line in enumerate(log_file):
						if current_line >= start:
							if current_line < end:
								yield line
							else:
								break

			start = (page - 1) * limit
			end = start + limit

			paginated_logs = list(read_logs(file_path, start, end))

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

			total_logs = sum(1 for _ in open(file_path, 'r'))

			return jsonify({'logs': formatted_logs, 'total': total_logs, 'page': page, 'limit': limit})
		except Exception as e:
			return jsonify({'error': str(e)}), 500

	def handle_operation(self, full_method_name):
		method = getattr(self.powerview, full_method_name, None)
		
		if not method:
			return jsonify({'error': f'Method {full_method_name} not found'}), 404

		params = request.args.to_dict() if request.method == 'GET' else request.json or {}

		try:
			result = method(**params)
			serializable_result = make_serializable(result)
			return jsonify(serializable_result)
		except Exception as e:
			return jsonify({'error': str(e)}), 500

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
