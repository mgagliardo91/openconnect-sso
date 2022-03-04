import structlog

from openconnect_sso.browser import Browser

log = structlog.get_logger()


def authenticate_in_browser(cfg, proxy, auth_info, override_script, display_mode):
    with Browser(cfg, proxy, display_mode) as browser:
        return browser.authenticate_at(
            auth_info.login_url, auth_info.token_cookie_name, override_script
        )
