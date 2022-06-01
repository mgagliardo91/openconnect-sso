from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from openconnect_sso.browser import Browser

if TYPE_CHECKING:
    from openconnect_sso.authenticator import AuthRequestResponse
    from openconnect_sso.config import Credentials, DisplayMode


log = structlog.get_logger()


def authenticate_in_browser(
    proxy: str | None,
    auth_info: AuthRequestResponse,
    credentials: Credentials | None,
    display_mode: DisplayMode,
) -> Any:
    with Browser(proxy, display_mode) as browser:
        return browser.authenticate_at(
            auth_info.login_url, credentials, auth_info.token_cookie_name
        )
