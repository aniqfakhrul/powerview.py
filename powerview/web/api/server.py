#!/usr/bin/env python3
from flask import Flask, jsonify, request, render_template
import logging
from contextlib import redirect_stdout, redirect_stderr
import io
import sys
import threading

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
