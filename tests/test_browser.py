from __future__ import annotations

from pytest_httpserver import HTTPServer

from openconnect_sso.browser import Browser
from openconnect_sso.config import Credentials, DisplayMode


def test_browser_context_manager_should_work_in_empty_context_manager() -> None:
    with Browser() as _:
        pass


def test_browser_shown_cookies_accessible(httpserver: HTTPServer) -> None:
    with Browser(display_mode=DisplayMode.SHOWN) as browser:
        httpserver.expect_request("/authenticate").respond_with_data(
            "<html><body>Hello</body></html>",
            headers={"Set-Cookie": "cookie-name=cookie-value"},
        )
        auth_url = httpserver.url_for("/authenticate")
        cred = Credentials("username", "password")
        value = browser.authenticate_at(auth_url, cred, "cookie-name")
        assert value == "cookie-value"


def test_browser_hidden_cookies_accessible(httpserver: HTTPServer) -> None:
    with Browser(display_mode=DisplayMode.HIDDEN) as browser:
        httpserver.expect_request("/authenticate").respond_with_data(
            "<html><body>Hello</body></html>",
            headers={"Set-Cookie": "cookie-name=cookie-value"},
        )
        auth_url = httpserver.url_for("/authenticate")
        cred = Credentials("username", "password")
        value = browser.authenticate_at(auth_url, cred, "cookie-name")
        assert value == "cookie-value"
