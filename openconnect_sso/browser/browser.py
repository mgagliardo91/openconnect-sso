from asyncio import InvalidStateError
import os
import json
import os
import structlog
from logging import CRITICAL

from datetime import datetime
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver import DesiredCapabilities
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.utils import ChromeType
from selenium.webdriver.common.proxy import Proxy, ProxyType
from ..config import DisplayMode

logger = structlog.get_logger()


class Browser:
    def __init__(self, cfg, proxy=None, display_mode=DisplayMode.SHOWN):
        self.cfg = cfg
        self.proxy = proxy
        self.display_mode = display_mode

    def __enter__(self):
        chrome_options = Options()
        capabilities = DesiredCapabilities.CHROME

        if self.display_mode == DisplayMode.HIDDEN:
            chrome_options.add_argument("headless")
            chrome_options.add_argument("no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")

        if self.proxy:
            proxy = Proxy()
            proxy.proxy_type = ProxyType.MANUAL
            parsed = urlparse(self.proxy)
            if parsed.scheme.startswith("socks5"):
                proxy.socks_proxy = f"{parsed.hostname}:{parsed.port}"
            elif parsed.scheme.startswith("http"):
                proxy.http_proxy = f"{parsed.hostname}:{parsed.port}"
            elif parsed.scheme.startswith("ssl"):
                proxy.ssl_proxy = f"{parsed.hostname}:{parsed.port}"
            else:
                raise ValueError("Unsupported proxy type", parsed.scheme)

            proxy.add_to_capabilities(capabilities)

        chrome_base_version = (
            f"_{os.getenv('CHROME_BASE_VERSION')}"
            if os.getenv("CHROME_BASE_VERSION") is not None
            else ""
        )
        self.driver = webdriver.Chrome(
            ChromeDriverManager(
                chrome_type=ChromeType.CHROMIUM,
                log_level=CRITICAL,
                latest_release_url=f"https://chromedriver.storage.googleapis.com/LATEST_RELEASE{chrome_base_version}",
            ).install(),
            options=chrome_options,
            desired_capabilities=capabilities,
        )
        return self

    def authenticate_at(self, url, expected_cookie_name, override_script):
        try:
            self.driver.get(url)
            if self.cfg.credentials:
                script = self.get_script(self.cfg.credentials, override_script)
                self.driver.execute_script(script)
                return WebDriverWait(self.driver, self.cfg.authenticate_timeout).until(
                    lambda driver: get_cookie(
                        self.driver.get_cookies(), expected_cookie_name
                    )
                    if has_cookie(driver.get_cookies(), expected_cookie_name)
                    else False
                )
        except TimeoutException:
            if self.display_mode == DisplayMode.HIDDEN:
                self.save_screenshot()
            raise InvalidStateError(
                f"Failed to locate cookie with name {expected_cookie_name}"
            )

    def save_screenshot(self):
        current_time = datetime.now().strftime("%Y%m%d-%H%M%S")
        save_path = os.path.join(os.getcwd(), f"failed-exchange_{current_time}.png")
        try:
            self.driver.save_screenshot(save_path)
            logger.error(f"Saved screenshot to location {save_path}")
        except Exception as e:
            logger.error(f"Unable to save screenshot", error=e)

    def get_script(self, credentials, override_script):
        if override_script:
            with open(override_script) as f:
                os.environ["USERNAME"] = credentials.username
                os.environ["PASSWORD"] = credentials.password
                return os.path.expandvars(f.read())

        for url_pattern, rules in self.cfg.auto_fill_rules.items():
            return f"""
// ==UserScript==
// @include {url_pattern}
// ==/UserScript==

function autoFill() {{
    {get_selectors(rules, credentials)}
    setTimeout(autoFill, 1000);
}}
autoFill();
"""

    def __exit__(self, exc_type, exc_value, t):
        self.driver.close()
        return True


def has_cookie(cookies, cookie_name):
    return get_cookie(cookies, cookie_name) is not None


def get_cookie(cookies, cookie_name):
    for c in cookies:
        if c["name"] == cookie_name:
            return c["value"]

    return None


def get_selectors(rules, credentials):
    statements = []
    for rule in rules:
        selector = json.dumps(rule.selector)
        if rule.action == "stop":
            statements.append(
                f"""var elem = document.querySelector({selector}); if (elem) {{ return; }}"""
            )
        elif rule.fill:
            value = json.dumps(getattr(credentials, rule.fill, None))
            if value:
                statements.append(
                    f"""var elem = document.querySelector({selector}); if (elem) {{ elem.dispatchEvent(new Event("focus")); elem.value = {value}; elem.dispatchEvent(new Event("blur")); }}"""
                )
            else:
                logger.warning(
                    "Credential info not available",
                    type=rule.fill,
                    possibilities=dir(credentials),
                )
        elif rule.action == "click":
            statements.append(
                f"""var elem = document.querySelector({selector}); if (elem) {{ elem.dispatchEvent(new Event("focus")); elem.click(); }}"""
            )
    return "\n".join(statements)
