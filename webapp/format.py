from webapp.dnstwist import idna


import json


class Format():
	def __init__(self, domains=[]):
		self.domains = domains

	def json(self, indent=4, sort_keys=True):
		return json.dumps(self.domains, indent=indent, sort_keys=sort_keys)

	def csv(self):
		cols = ['fuzzer', 'domain']
		for domain in self.domains:
			for k in domain.keys() - cols:
				cols.append(k)
		cols = cols[:2] + sorted(cols[2:])
		csv = [','.join(cols)]
		for domain in self.domains:
			row = []
			for val in [domain.get(c, '') for c in cols]:
				if isinstance(val, str):
					if ',' in val:
						row.append('"{}"'.format(val))
					else:
						row.append(val)
				elif isinstance(val, list):
					row.append(';'.join(val))
				elif isinstance(val, int):
					row.append(str(val))
			csv.append(','.join(row))
		return '\n'.join(csv)

	def list(self):
		return '\n'.join([x.get('domain') for x in sorted(self.domains)])

	def cli(self):
		cli = []
		domains = list(self.domains)
		if sys.stdout.encoding.lower() == 'utf-8':
			for domain in domains:
				domain.update(domain=idna.decode(domain.get('domain')))
		wfuz = max([len(x.get('fuzzer', '')) for x in domains]) + 1
		wdom = max([len(x.get('domain', '')) for x in domains]) + 1
		kv = lambda k, v: FG_YEL + k + FG_CYA + v + FG_RST if k else FG_CYA + v + FG_RST
		for domain in domains:
			inf = []
			if 'dns_a' in domain:
				inf.append(';'.join(domain['dns_a']) + (kv('/', domain['geoip'].replace(' ', '')) if 'geoip' in domain else ''))
			if 'dns_aaaa' in domain:
				inf.append(';'.join(domain['dns_aaaa']))
			if 'dns_ns' in domain:
				inf.append(kv('NS:', ';'.join(domain['dns_ns'])))
			if 'dns_mx' in domain:
				inf.append(kv('SPYING-MX:' if domain.get('mx_spy') else 'MX:', ';'.join(domain['dns_mx'])))
			if 'banner_http' in domain:
				inf.append(kv('HTTP:', domain['banner_http']))
			if 'banner_smtp' in domain:
				inf.append(kv('SMTP:', domain['banner_smtp']))
			if 'whois_registrar' in domain:
				inf.append(kv('REGISTRAR:', domain['whois_registrar']))
			if 'whois_created' in domain:
				inf.append(kv('CREATED:', domain['whois_created']))
			if domain.get('ssdeep', 0) > 0:
				inf.append(kv('SSDEEP:', '{}%'.format(domain['ssdeep'])))
			if domain.get('tlsh', 0) > 0:
				inf.append(kv('TLSH:', '{}%'.format(domain['tlsh'])))
			if domain.get('phash', 0) > 0:
				inf.append(kv('PHASH:', '{}%'.format(domain['phash'])))
			cli.append('{}{[fuzzer]:<{}}{} {[domain]:<{}} {}'.format(FG_BLU, domain, wfuz, FG_RST, domain, wdom, ' '.join(inf or ['-'])))
		return '\n'.join(cli)