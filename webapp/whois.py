from .dnstwist import domain_tld


import re
import socket
from datetime import datetime


class Whois():
	WHOIS_IANA = 'whois.iana.org'
	TIMEOUT = 2.0
	WHOIS_TLD = {
		'com': 'whois.verisign-grs.com',
		'net': 'whois.verisign-grs.com',
		'org': 'whois.pir.org',
		'info': 'whois.afilias.net',
		'pl': 'whois.dns.pl',
		'us': 'whois.nic.us',
		'co': 'whois.nic.co',
		'cn': 'whois.cnnic.cn',
		'ru': 'whois.tcinet.ru',
		'in': 'whois.registry.in',
		'eu': 'whois.eu',
		'uk': 'whois.nic.uk',
		'de': 'whois.denic.de',
		'nl': 'whois.domain-registry.nl',
		'br': 'whois.registro.br',
		'jp': 'whois.jprs.jp',
	}

	def __init__(self):
		self.whois_tld = self.WHOIS_TLD

	def _brute_datetime(self, s):
		formats = ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S%z', '%Y-%m-%d %H:%M', '%Y.%m.%d %H:%M',
			'%Y.%m.%d %H:%M:%S', '%d.%m.%Y %H:%M:%S', '%a %b %d %Y', '%d-%b-%Y', '%Y-%m-%d')
		for f in formats:
			try:
				dt = datetime.strptime(s, f)
				return dt
			except ValueError:
				pass
		return None

	def _extract(self, response):
		fields = {
			'registrar': (r'[\r\n]registrar[ .]*:\s+(?:name:\s)?(?P<registrar>[^\r\n]+)', str),
			'creation_date': (r'[\r\n](?:created(?: on)?|creation date|registered(?: on)?)[ .]*:\s+(?P<creation_date>[^\r\n]+)', self._brute_datetime),
		}
		result = {'text': response}
		response_reduced = '\r\n'.join([x.strip() for x in response.splitlines() if not x.startswith('%')])
		for field, (pattern, func) in fields.items():
			match = re.search(pattern, response_reduced, re.IGNORECASE | re.MULTILINE)
			if match:
				result[field] = func(match.group(1))
			else:
				result[field] = None
		return result

	def query(self, query, server=None):
		_, _, tld = domain_tld(query)
		server = server or self.whois_tld.get(tld, self.WHOIS_IANA)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(self.TIMEOUT)
		response = b''
		try:
			sock.connect((server, 43))
			sock.send(query.encode() + b'\r\n')
			while True:
				buf = sock.recv(4096)
				if not buf:
					break
				response += buf
			if server and server != self.WHOIS_IANA and tld not in self.whois_tld:
				self.whois_tld[tld] = server
		except (socket.timeout, socket.gaierror):
			return ''
		finally:
			sock.close()
		response = response.decode('utf-8', errors='ignore')
		refer = re.search(r'refer:\s+(?P<server>[-.a-z0-9]+)', response, re.IGNORECASE | re.MULTILINE)
		if refer:
			return self.query(query, refer.group('server'))
		return response

	def whois(self, domain, server=None):
		return self._extract(self.query(domain, server))