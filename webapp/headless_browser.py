import os
import urllib.request


class HeadlessBrowser():
	WEBDRIVER_TIMEOUT = 12
	WEBDRIVER_ARGUMENTS = (
		'--disable-dev-shm-usage',
		'--ignore-certificate-errors',
		'--headless',
		'--incognito',
		'--no-sandbox',
		'--disable-gpu',
		'--disable-extensions',
		'--disk-cache-size=0',
		'--aggressive-cache-discard',
		'--disable-notifications',
		'--disable-remote-fonts',
		'--disable-sync',
		'--window-size=1366,768',
		'--hide-scrollbars',
		'--disable-audio-output',
		'--dns-prefetch-disable',
		'--no-default-browser-check',
		'--disable-background-networking',
		'--enable-features=NetworkService,NetworkServiceInProcess',
		'--disable-background-timer-throttling',
		'--disable-backgrounding-occluded-windows',
		'--disable-breakpad',
		'--disable-client-side-phishing-detection',
		'--disable-component-extensions-with-background-pages',
		'--disable-default-apps',
		'--disable-features=TranslateUI',
		'--disable-hang-monitor',
		'--disable-ipc-flooding-protection',
		'--disable-prompt-on-repost',
		'--disable-renderer-backgrounding',
		'--force-color-profile=srgb',
		'--metrics-recording-only',
		'--no-first-run',
		'--password-store=basic',
		'--use-mock-keychain',
		'--disable-blink-features=AutomationControlled',
		)

	def __init__(self, useragent=None):
		chrome_options = webdriver.ChromeOptions()
		for opt in self.WEBDRIVER_ARGUMENTS:
			chrome_options.add_argument(opt)
		proxies = urllib.request.getproxies()
		if proxies:
			proxy_string = ';'.join(['{}={}'.format(scheme, url) for scheme, url in proxies.items()])
			chrome_options.add_argument('--proxy-server={}'.format(proxy_string))
		chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])
		chrome_options.add_experimental_option('useAutomationExtension', False)
		self.driver = webdriver.Chrome(options=chrome_options)
		self.driver.set_page_load_timeout(self.WEBDRIVER_TIMEOUT)
		self.driver.execute_cdp_cmd('Network.setUserAgentOverride', {'userAgent':
			useragent or self.driver.execute_script('return navigator.userAgent').replace('Headless', '')
			})
		self.get = self.driver.get
		self.screenshot = self.driver.get_screenshot_as_png

	def stop(self):
		try:
			self.driver.close()
			self.driver.quit()
		except Exception:
			pass
		try:
			pid = True
			while pid:
				pid, status = os.waitpid(-1, os.WNOHANG)
		except ChildProcessError:
			pass

	def __del__(self):
		self.stop()