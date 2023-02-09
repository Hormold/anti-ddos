"""Rate limit Cloudflare API"""
# Valid actions: simulate, ban, challenge, js_challenge, managed_challenge
import requests

class Cloudflare:

	def __init__(self, api_key):
		self.api_key = api_key
		self.headers = {
			'Authorization': 'Bearer ' + self.api_key,
			'Content-Type': 'application/json',
		}
		self.get_all_zones();

	def get_all_zones(self):
		url = 'https://api.cloudflare.com/client/v4/zones'
		response = requests.get(url, headers=self.headers)
		zones = {}
		for zone in response.json()['result']:
			zones[zone['name']] = zone['id']
		self.zones = zones
		print(f'[Cloudflare] Zones Loaded ({len(zones)})')
		

	def generate_rule (self, endpoint, action):
		# Endpoint can be: sub.domain.com/api/v1/endpoint
		# Remove GET parameters, if any
		endpoint = endpoint.split('?')[0]
		endpoint = endpoint.split('/', 1)[1]


		rule = {
			"description": "GeneratedRule",
			#"expression": "(http.request.uri.path matches \"^/api/\")",
			"expression": "(http.request.uri.path contains \""+endpoint+"\")",
			"action": "block",
			"ratelimit": {
				"characteristics": [
					"ip.src",
					"cf.colo.id"
				],
				"period": 60,
				"requests_per_period": 100,
				"mitigation_timeout": 600
			},
			"action_parameters": {
				"response": {
					"status_code": 404,
					"content": "{\"success\": false, \"error\": \"Sorry, our website is under DDOS attack by some assholes. Automatic system detects your activity as bot, just wait a little and try again! Sorry!\"}",
					"content_type": "application/json"
				}
			}
		}
		print('Generated rule: ', rule)
		return [rule]

	def get_existing_rules (self, zone_id):
		url = 'https://api.cloudflare.com/client/v4/zones/' + zone_id + '/rulesets/phases/http_ratelimit/entrypoint';
		response = requests.get(url, headers=self.headers)
		print(f'[{zone_id}] Existing rules: ', response.json())
		return response.json()

	def delete_rule (self, rule_id, zone_id):
		print(f'[{zone_id}] Deleting rule: ', rule_id)
		url = 'https://api.cloudflare.com/client/v4/zones/' + zone_id + '/rulesets/' + rule_id
		response = requests.delete(url, headers=self.headers)
		return response.json()

	def delete_all_generated_rules (self, zone_id):
		rules = self.get_existing_rules(zone_id)
		for rule in rules['result']['rules']:
			if rule['description'] == 'GeneratedRule':
				self.delete_rule(rule['id'], zone_id)

	def add_rule (self, rule, zone_id):
		url = 'https://api.cloudflare.com/client/v4/zones/' + zone_id + '/rulesets/phases/http_ratelimit/entrypoint'
		response = requests.put(url, headers=self.headers, json=rule)
		return response.json()

	def run (self, endpoint, action):
		# Get zone id from endpoint
		zone_id = None
		for zone in self.zones:
			if endpoint.find(zone) != -1:
				zone_id = self.zones[zone]
				break
		if zone_id is None:
			print('Zone for endpoint not found', endpoint)
			return False
		else:
			print('Zone for endpoint found', zone_id)

		rule = self.generate_rule(endpoint, action)
		print(f'[{zone_id}] Generated rule: ', rule) 
		self.delete_all_generated_rules(zone_id)
		result = self.add_rule(rule, zone_id)
		print(f'[{zone_id}] Result: ', result)