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
		print('Loaded zones: ', zones)
		

	def generate_rule (endpoint, action):
		# Endpoint can be: sub.domain.com/api/v1/endpoint
		# Remove GET parameters, if any
		endpoint = endpoint.split('?')[0]
		# Remove trailing slash if any
		#endpoint = endpoint.rstrip('/')
		# Remove http(s)://
		endpoint = endpoint.replace('http://', '').replace('https://', '')

		# Generate rule
		rule = {
			"match": {
				"request": {
					"methods": ["_ALL_"],
					"schemes": ["_ALL_"],
					"url": endpoint
				},
			},
			"threshold": 10,
			"period": 10,
			"action": {
				"mode": action,
				"timeout": 10,
			},
			"description": "GeneratedRule",
		};

		return rule

	def get_existing_rules (self, zone_id):
		url = 'https://api.cloudflare.com/client/v4/zones/' + zone_id + '/rate_limits'	
		response = requests.get(url, headers=self.headers)
		return rules.json()

	def delete_rule (self, rule_id, zone_id):
		url = 'https://api.cloudflare.com/client/v4/zones/' + zone_id + '/rate_limits/' + rule_id
		response = requests.delete(url, headers=self.headers)
		return response.json()

	def delete_all_generated_rules (self, zone_id):
		rules = self.get_existing_rules(zone_id)
		for rule in rules['result']:
			if rule['description'] == 'GeneratedRule':
				self.delete_rule(rule['id'], zone_id)

	def add_rule (self, rule, zone_id):
		url = 'https://api.cloudflare.com/client/v4/zones/' + zone_id + '/rate_limits'
		response = requests.post(url, headers=self.headers, json=rule)
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

		rule = self.generate_rule(endpoint, action)
		self.delete_all_generated_rules(zone_id)
		self.add_rule(rule, zone_id)