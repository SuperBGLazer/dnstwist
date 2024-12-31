#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r'''
     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__|

Generate and resolve domain variations to detect typo squatting,
phishing and corporate espionage.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

__author__ = 'Marcin Ulikowski'
__version__ = '20240812'
__email__ = 'marcin@ulikowski.pl'

import re
import sys
import socket

from webapp.Format import Format
from webapp.Fuzzer import Fuzzer
from webapp.HeadlessBrowser import HeadlessBrowser
from webapp.Scanner import Scanner
from webapp.UrlOpener import UrlOpener
from webapp.UrlParser import UrlParser
from webapp.Whois import Whois
from webapp.pHash import pHash
socket.setdefaulttimeout(12.0)
import signal
import time
import argparse
import threading
import os
import queue
import urllib.request
import urllib.parse
from io import BytesIO

def _debug(msg):
	if 'DEBUG' in os.environ:
		if isinstance(msg, Exception):
			print('{}:{} {}'.format(__file__, msg.__traceback__.tb_lineno, str(msg)), file=sys.stderr, flush=True)
		else:
			print(str(msg), file=sys.stderr, flush=True)

try:
	MODULE_PIL = True
except ImportError as e:
	_debug(e)
	MODULE_PIL = False

try:
	MODULE_SELENIUM = True
except ImportError as e:
	_debug(e)
	MODULE_SELENIUM = False

try:
	from dns.resolver import Resolver, NXDOMAIN, NoNameservers
	from dns.exception import DNSException
	MODULE_DNSPYTHON = True
except ImportError as e:
	_debug(e)
	MODULE_DNSPYTHON = False

GEOLITE2_MMDB = os.environ.get('GEOLITE2_MMDB' , os.path.join(os.path.dirname(__file__), 'GeoLite2-Country.mmdb'))
try:
	import geoip2.database
	_ = geoip2.database.Reader(GEOLITE2_MMDB)
except Exception as e:
	_debug(e)
	try:
		import GeoIP
		_ = GeoIP.new(-1)
	except Exception as e:
		_debug(e)
		MODULE_GEOIP = False
	else:
		MODULE_GEOIP = True
		class geoip:
			def __init__(self):
				self.reader = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
			def country_by_addr(self, ipaddr):
				return self.reader.country_name_by_addr(ipaddr)
else:
	MODULE_GEOIP = True
	class geoip:
		def __init__(self):
			self.reader = geoip2.database.Reader(GEOLITE2_MMDB)
		def country_by_addr(self, ipaddr):
			return self.reader.country(ipaddr).country.name

try:
	import ssdeep
	MODULE_SSDEEP = True
except ImportError as e:
	_debug(e)
	try:
		import ppdeep as ssdeep
		MODULE_SSDEEP = True
	except ImportError as e:
		_debug(e)
		MODULE_SSDEEP = False

try:
	import tlsh
	MODULE_TLSH = True
except ImportError as e:
	_debug(e)
	MODULE_TLSH = False

# try:
# except ImportError as e:
# 	_debug(e)
# 	class idna:
# 		@staticmethod
# 		def decode(domain):
# 			return domain.encode().decode('idna')
# 		@staticmethod
# 		def encode(domain):
# 			return domain.encode('idna')


VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)', re.IGNORECASE)
USER_AGENT_STRING = 'Mozilla/5.0 ({} {}-bit) dnstwist/{}'.format(sys.platform, sys.maxsize.bit_length() + 1, __version__)

REQUEST_TIMEOUT_DNS = 2.5
REQUEST_RETRIES_DNS = 2
REQUEST_TIMEOUT_HTTP = 5
REQUEST_TIMEOUT_SMTP = 5
THREAD_COUNT_DEFAULT = min(32, os.cpu_count() + 4)

if sys.platform != 'win32' and sys.stdout.isatty():
	FG_RND = '\x1b[3{}m'.format(int(time.time())%8+1)
	FG_YEL = '\x1b[33m'
	FG_CYA = '\x1b[36m'
	FG_BLU = '\x1b[34m'
	FG_RST = '\x1b[39m'
	ST_BRI = '\x1b[1m'
	ST_CLR = '\x1b[1K'
	ST_RST = '\x1b[0m'
else:
	FG_RND = FG_YEL = FG_CYA = FG_BLU = FG_RST = ST_BRI = ST_CLR = ST_RST = ''

devnull = os.devnull


def domain_tld(domain):
	try:
		from tld import parse_tld
	except ImportError:
		ctld = ['org', 'com', 'net', 'gov', 'edu', 'co', 'mil', 'nom', 'ac', 'info', 'biz']
		d = domain.rsplit('.', 3)
		if len(d) < 2:
			return '', d[0], ''
		if len(d) == 2:
			return '', d[0], d[1]
		if len(d) > 2:
			if d[-2] in ctld:
				return '.'.join(d[:-3]), d[-3], '.'.join(d[-2:])
			else:
				return '.'.join(d[:-2]), d[-2], d[-1]
	else:
		d = parse_tld(domain, fix_protocol=True)[::-1]
		if d[1:] == d[:-1] and None in d:
			d = tuple(domain.rsplit('.', 2))
			d = ('',) * (3-len(d)) + d
		return d


def cleaner(func):
	def wrapper(*args, **kwargs):
		result = func(*args, **kwargs)
		if threading.current_thread() is threading.main_thread():
			for sig in (signal.SIGINT, signal.SIGTERM):
				signal.signal(sig, signal.default_int_handler)
		sys.argv = sys.argv[0:1]
		return result
	return wrapper


@cleaner
def run(**kwargs):
	parser = argparse.ArgumentParser(
		usage='%s [OPTION]... DOMAIN' % sys.argv[0],
		add_help=False,
		description=
		'''Domain name permutation engine for detecting homograph phishing attacks, '''
		'''typosquatting, fraud and brand impersonation.''',
		formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=30)
		)

	parser.add_argument('domain', help='Domain name or URL to scan')
	parser.add_argument('-a', '--all', action='store_true', help='Print all DNS records instead of the first ones')
	parser.add_argument('-b', '--banners', action='store_true', help='Determine HTTP and SMTP service banners')
	parser.add_argument('-d', '--dictionary', type=str, metavar='FILE', help='Generate more domains using dictionary FILE')
	parser.add_argument('-f', '--format', type=str, default='cli', help='Output format: cli, csv, json, list (default: cli)')
	parser.add_argument('--fuzzers', type=str, metavar='LIST', help='Use only selected fuzzing algorithms (separated with commas)')
	parser.add_argument('-g', '--geoip', action='store_true', help='Lookup for GeoIP location')
	parser.add_argument('--lsh', type=str, metavar='LSH', nargs='?', const='ssdeep',
		help='Evaluate web page similarity with LSH algorithm: ssdeep, tlsh (default: ssdeep)')
	parser.add_argument('--lsh-url', metavar='URL', help='Override URL to fetch the original web page from')
	parser.add_argument('-m', '--mxcheck', action='store_true', help='Check if MX host can be used to intercept emails')
	parser.add_argument('-o', '--output', type=str, metavar='FILE', help='Save output to FILE')
	parser.add_argument('-r', '--registered', action='store_true', help='Show only registered domain names')
	parser.add_argument('-u', '--unregistered', action='store_true', help='Show only unregistered domain names')
	parser.add_argument('-p', '--phash', action='store_true', help='Render web pages and evaluate visual similarity')
	parser.add_argument('--phash-url', metavar='URL', help='Override URL to render the original web page from')
	parser.add_argument('--screenshots', metavar='DIR', help='Save web page screenshots into DIR')
	parser.add_argument('-s', '--ssdeep', action='store_true', help=argparse.SUPPRESS)
	parser.add_argument('--ssdeep-url', help=argparse.SUPPRESS)
	parser.add_argument('-t', '--threads', type=int, metavar='NUM', default=THREAD_COUNT_DEFAULT,
		help='Start specified NUM of threads (default: %s)' % THREAD_COUNT_DEFAULT)
	parser.add_argument('-w', '--whois', action='store_true', help='Lookup WHOIS database for creation date and registrar')
	parser.add_argument('--tld', type=str, metavar='FILE', help='Swap TLD for the original domain from FILE')
	parser.add_argument('--nameservers', type=str, metavar='LIST', help='DNS or DoH servers to query (separated with commas)')
	parser.add_argument('--useragent', type=str, metavar='STRING', default=USER_AGENT_STRING,
		help='Set User-Agent STRING (default: %s)' % USER_AGENT_STRING)
	parser.add_argument('--version', action='version', version='dnstwist {}'.format(__version__), help=argparse.SUPPRESS)

	if kwargs:
		sys.argv = ['']
		for k, v in kwargs.items():
			if k in ('domain',):
				sys.argv.append(v)
			else:
				if v is not False:
					sys.argv.append('--' + k.replace('_', '-'))
				if not isinstance(v, bool):
					sys.argv.append(str(v))
		def _parser_error(msg):
			raise Exception(msg) from None
		parser.error = _parser_error

	if not sys.argv[1:] or '-h' in sys.argv or '--help' in sys.argv:
		print('{}dnstwist {} by <{}>{}\n'.format(ST_BRI, __version__, __email__, ST_RST))
		parser.print_help()
		return

	args = parser.parse_args()

	threads = []
	jobs = queue.Queue()

	def p_cli(text):
		if args.format == 'cli' and sys.stdout.isatty(): print(text, end='', flush=True)
	def p_err(text):
		print(str(text), file=sys.stderr, flush=True)

	def signal_handler(signal, frame):
		if threads:
			print('\nstopping threads... ', file=sys.stderr, flush=True)
			jobs.queue.clear()
			for worker in threads:
				worker.stop()
			threads.clear()
		sys.tracebacklimit = 0
		raise KeyboardInterrupt

	if args.registered and args.unregistered:
		parser.error('arguments --registered and --unregistered are mutually exclusive')

	if args.ssdeep:
		p_err('WARNING: argument --ssdeep is deprecated, use --lsh ssdeep instead')
		args.lsh = 'ssdeep'
	if args.ssdeep_url:
		p_err('WARNING: argument --ssdeep-url is deprecated, use --lsh-url instead')
		args.lsh_url = args.ssdeep_url

	if not args.lsh and args.lsh_url:
		parser.error('argument --lsh-url requires --lsh')

	if args.lsh and args.lsh not in ('ssdeep', 'tlsh'):
		parser.error('invalid LSH algorithm (choose ssdeep or tlsh)')

	if not args.phash:
		if args.phash_url:
			parser.error('argument --phash-url requires --phash')
		if args.screenshots:
			parser.error('argument --screenshots requires --phash')

	if not kwargs and args.format not in ('cli', 'csv', 'json', 'list'):
		parser.error('invalid output format (choose from cli, csv, json, list)')

	if args.threads < 1:
		parser.error('number of threads must be greater than zero')

	fuzzers = []
	if args.fuzzers:
		fuzzers = [x.strip().lower() for x in set(args.fuzzers.split(','))]
		if args.dictionary and 'dictionary' not in fuzzers:
			parser.error('argument --dictionary cannot be used with selected fuzzing algorithms (consider enabling fuzzer: dictionary)')
		if args.tld and 'tld-swap' not in fuzzers:
			parser.error('argument --tld cannot be used with selected fuzzing algorithms (consider enabling fuzzer: tld-swap)')
		# important: this should enable all available fuzzers
		with Fuzzer('example.domain', ['foo'], ['bar']) as fuzz:
			fuzz.generate()
			all_fuzzers = sorted({x.get('fuzzer') for x in fuzz.permutations()})
			if not set(fuzzers).issubset(all_fuzzers):
				parser.error('argument --fuzzers takes a comma-separated list with at least one of the following: {}'.format(' '.join(all_fuzzers)))
			del all_fuzzers

	nameservers = []
	if args.nameservers:
		if not MODULE_DNSPYTHON:
			parser.error('missing DNSPython library')
		nameservers = args.nameservers.split(',')
		for addr in nameservers:
			if re.match(r'^https://[a-z0-9.-]{4,253}/dns-query$', addr):
				try:
					from dns.query import https
				except ImportError:
					parser.error('DNS-over-HTTPS requires DNSPython 2.x or newer')
				else:
					del https
				continue
			if re.match(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$', addr):
				continue
			parser.error('invalid nameserver: {}'.format(addr))

	dictionary = []
	if args.dictionary:
		re_subd = re.compile(r'^(?:(?:xn--)[a-z0-9-]{3,59}|[a-z0-9-]{1,63})$')
		try:
			with open(args.dictionary, encoding='utf-8') as f:
				dictionary = [x for x in set(f.read().lower().splitlines()) if re_subd.match(x)]
		except UnicodeDecodeError:
			parser.error('UTF-8 decode error when reading: {}'.format(args.dictionary))
		except OSError as err:
			parser.error('unable to open {} ({})'.format(args.dictionary, err.strerror.lower()))

	tld = []
	if args.tld:
		re_tld = re.compile(r'^[a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63})?$')
		try:
			with open(args.tld, encoding='utf-8') as f:
				tld = [x for x in set(f.read().lower().splitlines()) if re_tld.match(x)]
		except UnicodeDecodeError:
			parser.error('UTF-8 decode error when reading: {}'.format(args.tld))
		except OSError as err:
			parser.error('unable to open {} ({})'.format(args.tld, err.strerror.lower()))

	if args.output:
		sys._stdout = sys.stdout
		try:
			sys.stdout = open(args.output, 'w' if args.output == os.devnull else 'x')
		except OSError as err:
			parser.error('unable to open {} ({})'.format(args.output, err.strerror.lower()))


	lsh_url = None
	if args.lsh:
		if args.lsh == 'ssdeep' and not MODULE_SSDEEP:
			parser.error('missing ssdeep library')
		if args.lsh == 'tlsh' and not MODULE_TLSH:
			parser.error('missing py-tlsh library')
		if args.lsh_url:
			try:
				lsh_url = UrlParser(args.lsh_url)
			except ValueError:
				parser.error('invalid domain name: ' + args.lsh_url)

	phash_url = None
	if args.phash or args.screenshots:
		if not MODULE_PIL:
			parser.error('missing Python Imaging Library (PIL)')
		if not MODULE_SELENIUM:
			parser.error('missing Selenium Webdriver')
		try:
			_ = HeadlessBrowser()
		except Exception as e:
			parser.error(str(e))
		if args.screenshots:
			if not os.access(args.screenshots, os.W_OK | os.X_OK):
				parser.error('insufficient access permissions: %s' % args.screenshots)
		if args.phash_url:
			try:
				phash_url = UrlParser(args.phash_url)
			except ValueError:
				parser.error('invalid domain name: ' + args.phash_url)

	if args.geoip:
		if not MODULE_GEOIP:
			parser.error('missing geoip2 library or database file (check $GEOLITE2_MMDB environment variable)')

	try:
		url = UrlParser(args.domain)
	except Exception:
		parser.error('invalid domain name: ' + args.domain)

	if threading.current_thread() is threading.main_thread():
		for sig in (signal.SIGINT, signal.SIGTERM):
			signal.signal(sig, signal_handler)

	fuzz = Fuzzer(url.domain, dictionary=dictionary, tld_dictionary=tld)
	fuzz.generate(fuzzers=fuzzers)
	domains = fuzz.domains

	if not domains:
		parser.error('selected fuzzing algorithms do not generate any permutations for provided input domain')

	if args.format == 'list':
		print(Format(domains).list())
		if hasattr(sys, '_stdout'):
			sys.stdout = sys._stdout
		return list(map(dict, domains)) if kwargs else None

	if not MODULE_DNSPYTHON:
		p_err('WARNING: DNS features are limited due to lack of DNSPython library')

	p_cli(FG_RND + ST_BRI +
r'''     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__| {%s}

''' % __version__ + FG_RST + ST_RST)

	if args.lsh or args.phash:
		proxies = urllib.request.getproxies()
		if proxies:
			p_cli('using proxy: {}\n'.format(' '.join(set(proxies.values()))))

	lsh_init = str()
	lsh_effective_url = str()
	if args.lsh:
		request_url = lsh_url.full_uri() if lsh_url else url.full_uri()
		p_cli('fetching content from: {} '.format(request_url))
		try:
			r = UrlOpener(request_url,
				timeout=REQUEST_TIMEOUT_HTTP,
				headers={'User-Agent': args.useragent},
				verify=True)
		except Exception as e:
			if kwargs:
				raise
			p_err(e)
			sys.exit(1)
		else:
			p_cli('> {} [{:.1f} KB]\n'.format(r.url.split('?')[0], len(r.content)/1024))
			if args.lsh == 'ssdeep':
				lsh_init = ssdeep.hash(r.normalized_content)
			elif args.lsh == 'tlsh':
				lsh_init = tlsh.hash(r.normalized_content)
			lsh_effective_url = r.url.split('?')[0]
			# hash blank if content too short or insufficient entropy
			if lsh_init in (None, '', 'TNULL', '3::'):
				args.lsh = None

	if args.phash:
		request_url = phash_url.full_uri() if phash_url else url.full_uri()
		p_cli('rendering web page: {}\n'.format(request_url))
		browser = HeadlessBrowser(useragent=args.useragent)
		try:
			browser.get(request_url)
			screenshot = browser.screenshot()
		except Exception as e:
			if kwargs:
				raise
			p_err(e)
			sys.exit(1)
		else:
			phash = pHash(BytesIO(screenshot))
			browser.stop()

	for task in domains:
		jobs.put(task)

	sid = int.from_bytes(os.urandom(4), sys.byteorder)
	for _ in range(args.threads):
		worker = Scanner(jobs)
		worker.id = sid
		worker.url = url
		worker.option_extdns = MODULE_DNSPYTHON
		if args.geoip:
			worker.option_geoip = True
		if args.banners:
			worker.option_banners = True
		if args.lsh and lsh_init:
			worker.option_lsh = args.lsh
			worker.lsh_init = lsh_init
			worker.lsh_effective_url = lsh_effective_url
		if args.phash:
			worker.option_phash = True
			worker.phash_init = phash
			worker.screenshot_dir = args.screenshots
		if args.mxcheck:
			worker.option_mxcheck = True
		if args.nameservers:
			worker.nameservers = nameservers
		worker.useragent = args.useragent
		worker.start()
		threads.append(worker)

	p_cli('started {} scanner threads\n'.format(args.threads))

	ttime = 0
	ival = 0.2
	while True:
		time.sleep(ival)
		ttime += ival
		dlen = len(domains)
		comp = dlen - jobs.qsize()
		if not comp:
			continue
		rate = int(comp / ttime) + 1
		eta = jobs.qsize() // rate
		found = sum([1 for x in domains if x.is_registered()])
		p_cli(ST_CLR + '\rpermutations: {:.2%} of {} | found: {} | eta: {:d}m {:02d}s | speed: {:d} qps'.format(comp/dlen,
			dlen, found, eta//60, eta%60, rate))
		if jobs.empty():
			break
		if sum([1 for x in threads if x.is_alive()]) == 0:
			break
	p_cli('\n')

	for worker in threads:
		worker.stop()
	for worker in threads:
		worker.join()

	domains = fuzz.permutations(registered=args.registered, unregistered=args.unregistered, dns_all=args.all)

	if args.whois:
		total = sum([1 for x in domains if x.is_registered()])
		whois = Whois()
		for i, domain in enumerate([x for x in domains if x.is_registered()]):
			p_cli(ST_CLR + '\rWHOIS: {} ({:.2%})'.format(domain['domain'], (i+1)/total))
			try:
				wreply = whois.whois('.'.join(domain_tld(domain['domain'])[1:]))
			except Exception as e:
				_debug(e)
			else:
				if wreply.get('creation_date'):
					domain['whois_created'] = wreply.get('creation_date').strftime('%Y-%m-%d')
				if wreply.get('registrar'):
					domain['whois_registrar'] = wreply.get('registrar')
		p_cli('\n')

	p_cli('\n')

	if domains:
		if args.format == 'csv':
			print(Format(domains).csv())
		elif args.format == 'json':
			print(Format(domains).json())
		elif args.format == 'cli':
			print(Format(domains).cli())

	if hasattr(sys, '_stdout'):
		sys.stdout = sys._stdout

	if kwargs:
		return list(map(dict, domains))


if __name__ == '__main__':
	try:
		run()
	except BrokenPipeError:
		pass
