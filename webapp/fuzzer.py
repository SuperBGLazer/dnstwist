from webapp.Permutation import Permutation
from webapp.dnstwist import VALID_FQDN_REGEX, domain_tld, idna


class Fuzzer():
	glyphs_idn_by_tld = {
		**dict.fromkeys(['ad', 'cz', 'sk', 'uk', 'co.uk', 'nl', 'edu', 'us'], {
			# IDN not supported by the corresponding registry
		}),
		**dict.fromkeys(['jp', 'co.jp', 'ad.jp', 'ne.jp'], {
		}),
		**dict.fromkeys(['cn', 'com.cn', 'tw', 'com.tw', 'net.tw'], {
		}),
		**dict.fromkeys(['info'], {
			'a': ('á', 'ä', 'å', 'ą'),
			'c': ('ć', 'č'),
			'e': ('é', 'ė', 'ę'),
			'i': ('í', 'į'),
			'l': ('ł',),
			'n': ('ñ', 'ń'),
			'o': ('ó', 'ö', 'ø', 'ő'),
			's': ('ś', 'š'),
			'u': ('ú', 'ü', 'ū', 'ű', 'ų'),
			'z': ('ź', 'ż', 'ž'),
			'ae': ('æ',),
		}),
		**dict.fromkeys(['br', 'com.br'], {
			'a': ('à', 'á', 'â', 'ã'),
			'c': ('ç',),
			'e': ('é', 'ê'),
			'i': ('í',),
			'o': ('ó', 'ô', 'õ'),
			'u': ('ú', 'ü'),
			'y': ('ý', 'ÿ'),
		}),
		**dict.fromkeys(['dk'], {
			'a': ('ä', 'å'),
			'e': ('é',),
			'o': ('ö', 'ø'),
			'u': ('ü',),
			'ae': ('æ',),
		}),
		**dict.fromkeys(['eu', 'de', 'pl'], {
			'a': ('á', 'à', 'ă', 'â', 'å', 'ä', 'ã', 'ą', 'ā'),
			'c': ('ć', 'ĉ', 'č', 'ċ', 'ç'),
			'd': ('ď', 'đ'),
			'e': ('é', 'è', 'ĕ', 'ê', 'ě', 'ë', 'ė', 'ę', 'ē'),
			'g': ('ğ', 'ĝ', 'ġ', 'ģ'),
			'h': ('ĥ', 'ħ'),
			'i': ('í', 'ì', 'ĭ', 'î', 'ï', 'ĩ', 'į', 'ī'),
			'j': ('ĵ',),
			'k': ('ķ', 'ĸ'),
			'l': ('ĺ', 'ľ', 'ļ', 'ł'),
			'n': ('ń', 'ň', 'ñ', 'ņ'),
			'o': ('ó', 'ò', 'ŏ', 'ô', 'ö', 'ő', 'õ', 'ø', 'ō'),
			'r': ('ŕ', 'ř', 'ŗ'),
			's': ('ś', 'ŝ', 'š', 'ş'),
			't': ('ť', 'ţ', 'ŧ'),
			'u': ('ú', 'ù', 'ŭ', 'û', 'ů', 'ü', 'ű', 'ũ', 'ų', 'ū'),
			'w': ('ŵ',),
			'y': ('ý', 'ŷ', 'ÿ'),
			'z': ('ź', 'ž', 'ż'),
			'ae': ('æ',),
			'oe': ('œ',),
		}),
		**dict.fromkeys(['fi'], {
			'3': ('ʒ',),
			'a': ('á', 'ä', 'å', 'â'),
			'c': ('č',),
			'd': ('đ',),
			'g': ('ǧ', 'ǥ'),
			'k': ('ǩ',),
			'n': ('ŋ',),
			'o': ('õ', 'ö'),
			's': ('š',),
			't': ('ŧ',),
			'z': ('ž',),
		}),
		**dict.fromkeys(['no'], {
			'a': ('á', 'à', 'ä', 'å'),
			'c': ('č', 'ç'),
			'e': ('é', 'è', 'ê'),
			'i': ('ï',),
			'n': ('ŋ', 'ń', 'ñ'),
			'o': ('ó', 'ò', 'ô', 'ö', 'ø'),
			's': ('š',),
			't': ('ŧ',),
			'u': ('ü',),
			'z': ('ž',),
			'ae': ('æ',),
		}),
		**dict.fromkeys(['be', 'fr', 're', 'yt', 'pm', 'wf', 'tf', 'ch', 'li'], {
			'a': ('à', 'á', 'â', 'ã', 'ä', 'å'),
			'c': ('ç',),
			'e': ('è', 'é', 'ê', 'ë'),
			'i': ('ì', 'í', 'î', 'ï'),
			'n': ('ñ',),
			'o': ('ò', 'ó', 'ô', 'õ', 'ö'),
			'u': ('ù', 'ú', 'û', 'ü'),
			'y': ('ý', 'ÿ'),
			'ae': ('æ',),
			'oe': ('œ',),
		}),
		**dict.fromkeys(['ca'], {
			'a': ('à', 'â'),
			'c': ('ç',),
			'e': ('è', 'é', 'ê', 'ë'),
			'i': ('î', 'ï'),
			'o': ('ô',),
			'u': ('ù', 'û', 'ü'),
			'y': ('ÿ',),
			'ae': ('æ',),
			'oe': ('œ',),
		}),
	}

	glyphs_unicode = {
		'2': ('ƻ',),
		'3': ('ʒ',),
		'5': ('ƽ',),
		'a': ('ạ', 'ă', 'ȧ', 'ɑ', 'å', 'ą', 'â', 'ǎ', 'á', 'ə', 'ä', 'ã', 'ā', 'à'),
		'b': ('ḃ', 'ḅ', 'ƅ', 'ʙ', 'ḇ', 'ɓ'),
		'c': ('č', 'ᴄ', 'ċ', 'ç', 'ć', 'ĉ', 'ƈ'),
		'd': ('ď', 'ḍ', 'ḋ', 'ɖ', 'ḏ', 'ɗ', 'ḓ', 'ḑ', 'đ'),
		'e': ('ê', 'ẹ', 'ę', 'è', 'ḛ', 'ě', 'ɇ', 'ė', 'ĕ', 'é', 'ë', 'ē', 'ȩ'),
		'f': ('ḟ', 'ƒ'),
		'g': ('ǧ', 'ġ', 'ǵ', 'ğ', 'ɡ', 'ǥ', 'ĝ', 'ģ', 'ɢ'),
		'h': ('ȟ', 'ḫ', 'ḩ', 'ḣ', 'ɦ', 'ḥ', 'ḧ', 'ħ', 'ẖ', 'ⱨ', 'ĥ'),
		'i': ('ɩ', 'ǐ', 'í', 'ɪ', 'ỉ', 'ȋ', 'ɨ', 'ï', 'ī', 'ĩ', 'ị', 'î', 'ı', 'ĭ', 'į', 'ì'),
		'j': ('ǰ', 'ĵ', 'ʝ', 'ɉ'),
		'k': ('ĸ', 'ǩ', 'ⱪ', 'ḵ', 'ķ', 'ᴋ', 'ḳ'),
		'l': ('ĺ', 'ł', 'ɫ', 'ļ', 'ľ'),
		'm': ('ᴍ', 'ṁ', 'ḿ', 'ṃ', 'ɱ'),
		'n': ('ņ', 'ǹ', 'ń', 'ň', 'ṅ', 'ṉ', 'ṇ', 'ꞑ', 'ñ', 'ŋ'),
		'o': ('ö', 'ó', 'ȯ', 'ỏ', 'ô', 'ᴏ', 'ō', 'ò', 'ŏ', 'ơ', 'ő', 'õ', 'ọ', 'ø'),
		'p': ('ṗ', 'ƿ', 'ƥ', 'ṕ'),
		'q': ('ʠ',),
		'r': ('ʀ', 'ȓ', 'ɍ', 'ɾ', 'ř', 'ṛ', 'ɽ', 'ȑ', 'ṙ', 'ŗ', 'ŕ', 'ɼ', 'ṟ'),
		's': ('ṡ', 'ș', 'ŝ', 'ꜱ', 'ʂ', 'š', 'ś', 'ṣ', 'ş'),
		't': ('ť', 'ƫ', 'ţ', 'ṭ', 'ṫ', 'ț', 'ŧ'),
		'u': ('ᴜ', 'ų', 'ŭ', 'ū', 'ű', 'ǔ', 'ȕ', 'ư', 'ù', 'ů', 'ʉ', 'ú', 'ȗ', 'ü', 'û', 'ũ', 'ụ'),
		'v': ('ᶌ', 'ṿ', 'ᴠ', 'ⱴ', 'ⱱ', 'ṽ'),
		'w': ('ᴡ', 'ẇ', 'ẅ', 'ẃ', 'ẘ', 'ẉ', 'ⱳ', 'ŵ', 'ẁ'),
		'x': ('ẋ', 'ẍ'),
		'y': ('ŷ', 'ÿ', 'ʏ', 'ẏ', 'ɏ', 'ƴ', 'ȳ', 'ý', 'ỿ', 'ỵ'),
		'z': ('ž', 'ƶ', 'ẓ', 'ẕ', 'ⱬ', 'ᴢ', 'ż', 'ź', 'ʐ'),
		'ae': ('æ',),
		'oe': ('œ',),
	}

	glyphs_ascii = {
		'0': ('o',),
		'1': ('l', 'i'),
		'3': ('8',),
		'6': ('9',),
		'8': ('3',),
		'9': ('6',),
		'b': ('d', 'lb'),
		'c': ('e',),
		'd': ('b', 'cl', 'dl'),
		'e': ('c',),
		'g': ('q',),
		'h': ('lh',),
		'i': ('1', 'l'),
		'k': ('lc',),
		'l': ('1', 'i'),
		'm': ('n', 'nn', 'rn'),
		'n': ('m', 'r'),
		'o': ('0',),
		'q': ('g',),
		'u': ('v',),
		'v': ('u',),
		'w': ('vv',),
		'rn': ('m',),
		'cl': ('d',),
	}

	latin_to_cyrillic = {
		'a': 'а', 'b': 'ь', 'c': 'с', 'd': 'ԁ', 'e': 'е', 'g': 'ԍ', 'h': 'һ',
		'i': 'і', 'j': 'ј', 'k': 'к', 'l': 'ӏ', 'm': 'м', 'o': 'о', 'p': 'р',
		'q': 'ԛ', 's': 'ѕ', 't': 'т', 'v': 'ѵ', 'w': 'ԝ', 'x': 'х', 'y': 'у',
	}

	qwerty = {
		'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
		'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
		'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
	}
	qwertz = {
		'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
		'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
		'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
	}
	azerty = {
		'1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
		'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp',
		'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
	}
	keyboards = [qwerty, qwertz, azerty]

	def __init__(self, domain, dictionary=[], tld_dictionary=[]):
		self.subdomain, self.domain, self.tld = domain_tld(domain)
		self.domain = idna.decode(self.domain)
		self.dictionary = list(dictionary)
		self.tld_dictionary = list(tld_dictionary)
		self.domains = set()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		return

	def _bitsquatting(self):
		masks = [1, 2, 4, 8, 16, 32, 64, 128]
		chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
		for i, c in enumerate(self.domain):
			for mask in masks:
				b = chr(ord(c) ^ mask)
				if b in chars:
					yield self.domain[:i] + b + self.domain[i+1:]

	def _cyrillic(self):
		cdomain = self.domain
		for l, c in self.latin_to_cyrillic.items():
			cdomain = cdomain.replace(l, c)
		for c, l in zip(cdomain, self.domain):
			if c == l:
				return []
		return [cdomain]

	def _homoglyph(self):
		md = lambda a, b: {k: set(a.get(k, [])) | set(b.get(k, [])) for k in set(a.keys()) | set(b.keys())}
		glyphs = md(self.glyphs_ascii, self.glyphs_idn_by_tld.get(self.tld, self.glyphs_unicode))
		def mix(domain):
			for i, c in enumerate(domain):
				for g in glyphs.get(c, []):
					yield domain[:i] + g + domain[i+1:]
			for i in range(len(domain)-1):
				win = domain[i:i+2]
				for c in {win[0], win[1], win}:
					for g in glyphs.get(c, []):
						yield domain[:i] + win.replace(c, g) + domain[i+2:]
		result1 = set(mix(self.domain))
		result2 = set()
		for r in result1:
			result2.update(set(mix(r)))
		return result1 | result2

	def _hyphenation(self):
		return {self.domain[:i] + '-' + self.domain[i:] for i in range(1, len(self.domain))}

	def _insertion(self):
		result = set()
		for i in range(0, len(self.domain)-1):
			prefix, orig_c, suffix = self.domain[:i], self.domain[i], self.domain[i+1:]
			for c in (c for keys in self.keyboards for c in keys.get(orig_c, [])):
				result.update({
					prefix + c + orig_c + suffix,
					prefix + orig_c + c + suffix
				})
		return result

	def _omission(self):
		return {self.domain[:i] + self.domain[i+1:] for i in range(len(self.domain))}

	def _repetition(self):
		return {self.domain[:i] + c + self.domain[i:] for i, c in enumerate(self.domain)}

	def _replacement(self):
		for i, c in enumerate(self.domain):
			pre = self.domain[:i]
			suf = self.domain[i+1:]
			for layout in self.keyboards:
				for r in layout.get(c, ''):
					yield pre + r + suf

	def _subdomain(self):
		for i in range(1, len(self.domain)-1):
			if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
				yield self.domain[:i] + '.' + self.domain[i:]

	def _transposition(self):
		return {self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:] for i in range(len(self.domain)-1)}

	def _vowel_swap(self):
		vowels = 'aeiou'
		for i in range(0, len(self.domain)):
			for vowel in vowels:
				if self.domain[i] in vowels:
					yield self.domain[:i] + vowel + self.domain[i+1:]

	def _plural(self):
		for i in range(2, len(self.domain)-2):
			yield self.domain[:i+1] + ('es' if self.domain[i] in ('s', 'x', 'z') else 's') + self.domain[i+1:]


	def _addition(self):
		result = set()
		if '-' in self.domain:
			parts = self.domain.split('-')
			result = {'-'.join(parts[:p]) + chr(i) + '-' + '-'.join(parts[p:]) for i in (*range(48, 58), *range(97, 123)) for p in range(1, len(parts))}
		result.update({self.domain + chr(i) for i in (*range(48, 58), *range(97, 123))})
		return result


	def _dictionary(self):
		result = set()
		for word in self.dictionary:
			if not (self.domain.startswith(word) and self.domain.endswith(word)):
				result.update({
					self.domain + '-' + word,
					self.domain + word,
					word + '-' + self.domain,
					word + self.domain
				})
		if '-' in self.domain:
			parts = self.domain.split('-')
			for word in self.dictionary:
				result.update({
					'-'.join(parts[:-1]) + '-' + word,
					word + '-' + '-'.join(parts[1:])
				})
		return result

	def _tld(self):
		if self.tld in self.tld_dictionary:
			self.tld_dictionary.remove(self.tld)
		return set(self.tld_dictionary)

	def generate(self, fuzzers=[]):
		self.domains = set()
		if not fuzzers or '*original' in fuzzers:
			self.domains.add(Permutation(fuzzer='*original', domain='.'.join(filter(None, [self.subdomain, self.domain, self.tld]))))
		for f_name in fuzzers or [
			'addition', 'bitsquatting', 'cyrillic', 'homoglyph', 'hyphenation',
			'insertion', 'omission', 'plural', 'repetition', 'replacement',
			'subdomain', 'transposition', 'vowel-swap', 'dictionary',
		]:
			try:
				f = getattr(self, '_' + f_name.replace('-', '_'))
			except AttributeError:
				pass
			else:
				for domain in f():
					self.domains.add(Permutation(fuzzer=f_name, domain='.'.join(filter(None, [self.subdomain, domain, self.tld]))))
		if not fuzzers or 'tld-swap' in fuzzers:
			for tld in self._tld():
				self.domains.add(Permutation(fuzzer='tld-swap', domain='.'.join(filter(None, [self.subdomain, self.domain, tld]))))
		if not fuzzers or 'various' in fuzzers:
			if '.' in self.tld:
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain, self.tld.split('.')[-1]]))))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain + self.tld]))))
			if '.' not in self.tld:
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain + self.tld, self.tld]))))
			if self.tld != 'com' and '.' not in self.tld:
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain + '-' + self.tld, 'com']))))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain + self.tld, 'com']))))
			if self.subdomain:
				self.domains.add(Permutation(fuzzer='various', domain='.'.join([self.subdomain + self.domain, self.tld])))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join([self.subdomain.replace('.', '') + self.domain, self.tld])))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join([self.subdomain + '-' + self.domain, self.tld])))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join([self.subdomain.replace('.', '-') + '-' + self.domain, self.tld])))
		def _punycode(domain):
			try:
				domain['domain'] = idna.encode(domain['domain']).decode()
			except Exception:
				domain['domain'] = ''
			return domain
		self.domains = set(map(_punycode, self.domains))
		for domain in self.domains.copy():
			if not VALID_FQDN_REGEX.match(domain.get('domain')):
				self.domains.discard(domain)

	def permutations(self, registered=False, unregistered=False, dns_all=False, unicode=False):
		if (registered and not unregistered):
			domains = [x.copy() for x in self.domains if x.is_registered()]
		elif (unregistered and not registered):
			domains = [x.copy() for x in self.domains if not x.is_registered()]
		else:
			domains = [x.copy() for x in self.domains]
		if not dns_all:
			def _cutdns(x):
				if x.is_registered():
					for k in ('dns_ns', 'dns_a', 'dns_aaaa', 'dns_mx'):
						if k in x:
							x[k] = x[k][:1]
				return x
			domains = map(_cutdns, domains)
		if unicode:
			def _punydecode(x):
				x.domain = idna.decode(x.domain)
				return x
			domains = map(_punydecode, domains)
		return sorted(domains)