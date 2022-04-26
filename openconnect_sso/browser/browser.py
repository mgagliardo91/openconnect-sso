from __future__ import annotations

import json
import os
from logging import CRITICAL
from types import TracebackType
from typing import Any
from urllib.parse import urlparse

import structlog
from selenium import webdriver
from selenium.webdriver import DesiredCapabilities
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.utils import ChromeType

from openconnect_sso import config

from ..config import AutoFillRule, Credentials, DisplayMode

logger = structlog.get_logger()


class Browser:
    def __init__(
        self, proxy: str | None = None, display_mode: DisplayMode = DisplayMode.SHOWN
    ) -> None:
        self.cfg = config.load()
        self.proxy = proxy
        self.display_mode = display_mode

    def __enter__(self) -> Browser:
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

    def authenticate_at(
        self, url: str, credentials: Credentials | None, expected_cookie_name: str
    ) -> Any:
        self.driver.get(url)
        if credentials:
            for url_pattern, rules in self.cfg.auto_fill_rules.items():
                script = f"""
// ==UserScript==
// @include {url_pattern}
// ==/UserScript==

function autoFill() {{
    {get_selectors(rules, credentials)}
    setTimeout(autoFill, 1000);
}}
autoFill();
"""
        self.driver.execute_script(script)  # type: ignore
        WebDriverWait(self.driver, 10).until(
            lambda driver: has_cookie(driver.get_cookies(), expected_cookie_name)
        )
        return get_cookie(
            self.driver.get_cookies(),  # type: ignore
            expected_cookie_name,
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        self.driver.close()
        return True


def has_cookie(cookies: list[dict[str, Any]], cookie_name: str) -> bool:
    return get_cookie(cookies, cookie_name) is not None


def get_cookie(cookies: list[dict[str, Any]], cookie_name: str) -> Any:
    for c in cookies:
        if c["name"] == cookie_name:
            return c["value"]

    return None


def get_selectors(rules: list[AutoFillRule], credentials: Credentials) -> str:
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
