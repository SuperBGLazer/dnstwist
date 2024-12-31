class Permutation(dict):
	def __getattr__(self, item):
		if item in self:
			return self[item]
		raise AttributeError("object has no attribute '{}'".format(item)) from None

	__setattr__ = dict.__setitem__

	def __init__(self, **kwargs):
		super(dict, self).__init__()
		self['fuzzer'] = kwargs.pop('fuzzer', '')
		self['domain'] = kwargs.pop('domain', '')
		for k, v in kwargs.items():
			self[k] = v

	def __hash__(self):
		return hash(self['domain'])

	def __eq__(self, other):
		return self['domain'] == other['domain']

	def __lt__(self, other):
		if self['fuzzer'] == other['fuzzer']:
			if len(self) > 2 and len(other) > 2:
				return self.get('dns_a', [''])[0] + self['domain'] < other.get('dns_a', [''])[0] + other['domain']
			else:
				return self['domain'] < other['domain']
		return self['fuzzer'] < other['fuzzer']

	def is_registered(self):
		return len(self) > 2

	def copy(self):
		return Permutation(**self)