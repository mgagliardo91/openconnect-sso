from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import requests
import structlog
from lxml import etree, objectify

from openconnect_sso.config import HostProfile
from openconnect_sso.saml_authenticator import authenticate_in_browser

if TYPE_CHECKING:
    from openconnect_sso.config import Credentials, DisplayMode

# See https://stackoverflow.com/a/41041028
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":HIGH:!DH:!aNULL"  # type: ignore


logger = structlog.get_logger()


class Authenticator:
    def __init__(
        self,
        host: HostProfile,
        proxy: str | None = None,
        credentials: Credentials | None = None,
    ) -> None:
        self.host = host
        self.proxy = proxy
        self.credentials = credentials
        self.session = create_http_session(proxy)

    async def authenticate(self, display_mode: DisplayMode) -> AuthCompleteResponse:
        self._detect_authentication_target_url()

        response = self._start_authentication()
        if not isinstance(response, AuthRequestResponse):
            logger.error(
                "Could not start authentication. Invalid response type in current state",
                response=response,
            )
            raise AuthenticationError(response)

        if response.auth_error:
            logger.error(
                "Could not start authentication. Response contains error",
                error=response.auth_error,
                response=response,
            )
            raise AuthenticationError(response)

        auth_request_response = response

        sso_token = self._authenticate_in_browser(auth_request_response, display_mode)

        response = self._complete_authentication(auth_request_response, sso_token)
        if not isinstance(response, AuthCompleteResponse):
            logger.error(
                "Could not finish authentication. Invalid response type in current state",
                response=response,
            )
            raise AuthenticationError(response)

        return response

    def _detect_authentication_target_url(self) -> None:
        # Follow possible redirects in a GET request
        # Authentication will occcur using a POST request on the final URL
        response = requests.get(self.host.vpn_url)
        response.raise_for_status()
        self.host.address = response.url
        logger.debug("Auth target url", url=self.host.vpn_url)

    def _start_authentication(
        self,
    ) -> AuthRequestResponse | AuthCompleteResponse | None:
        request = _create_auth_init_request(self.host, self.host.vpn_url)
        logger.debug("Sending auth init request", content=request)
        response = self.session.post(self.host.vpn_url, request)
        logger.debug("Auth init response received", content=response.content)
        return parse_response(response)

    def _authenticate_in_browser(
        self, auth_request_response: AuthRequestResponse, display_mode: DisplayMode
    ) -> Any:
        return authenticate_in_browser(
            self.proxy, auth_request_response, self.credentials, display_mode
        )

    def _complete_authentication(
        self, auth_request_response: AuthRequestResponse, sso_token: str
    ) -> AuthRequestResponse | AuthCompleteResponse | None:
        request = _create_auth_finish_request(
            self.host, auth_request_response, sso_token
        )
        logger.debug("Sending auth finish request", content=request)
        response = self.session.post(self.host.vpn_url, request)
        logger.debug("Auth finish response received", content=response.content)
        return parse_response(response)


class AuthenticationError(Exception):
    pass


class AuthResponseError(AuthenticationError):
    pass


def create_http_session(proxy: str | None) -> requests.Session:
    session = requests.Session()
    session.proxies = {"http": proxy, "https": proxy}  # type: ignore
    session.headers.update(
        {
            "User-Agent": "AnyConnect Linux_64 4.7.00136",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "X-Transcend-Version": "1",
            "X-Aggregate-Auth": "1",
            "X-Support-HTTP-Auth": "true",
            "Content-Type": "application/x-www-form-urlencoded",
            # I know, it is invalid but that’s what Anyconnect sends
        }
    )
    return session


E = objectify.ElementMaker(annotate=False)


def _create_auth_init_request(host: HostProfile, url: str) -> Any:
    ConfigAuth = getattr(E, "config-auth")
    Version = E.version
    DeviceId = getattr(E, "device-id")
    GroupSelect = getattr(E, "group-select")
    GroupAccess = getattr(E, "group-access")
    Capabilities = E.capabilities
    AuthMethod = getattr(E, "auth-method")

    root = ConfigAuth(
        {"client": "vpn", "type": "init", "aggregate-auth-version": "2"},
        Version({"who": "vpn"}, "4.7.00136"),
        DeviceId("linux-64"),
        GroupSelect(host.name),
        GroupAccess(url),
        Capabilities(AuthMethod("single-sign-on-v2")),
    )
    return etree.tostring(
        root, pretty_print=True, xml_declaration=True, encoding="UTF-8"
    )


def parse_response(
    resp: requests.Response,
) -> AuthRequestResponse | AuthCompleteResponse | None:
    resp.raise_for_status()
    xml = objectify.fromstring(resp.content)
    t = xml.get("type")
    if t == "auth-request":
        return parse_auth_request_response(xml)
    elif t == "complete":
        return parse_auth_complete_response(xml)
    return None


def parse_auth_request_response(
    xml: objectify.ObjectifiedElement,
) -> AuthRequestResponse:
    assert xml.auth.get("id") == "main"

    try:
        resp = AuthRequestResponse(
            auth_id=xml.auth.get("id"),
            auth_title=getattr(xml.auth, "title", ""),
            auth_message=xml.auth.message,
            auth_error=getattr(xml.auth, "error", ""),
            opaque=xml.opaque,
            login_url=xml.auth["sso-v2-login"],
            login_final_url=xml.auth["sso-v2-login-final"],
            token_cookie_name=xml.auth["sso-v2-token-cookie-name"],
        )
    except AttributeError as exc:
        raise AuthResponseError(exc)

    logger.info(
        "Response received",
        id=resp.auth_id,
        title=resp.auth_title,
        message=resp.auth_message,
    )
    return resp


@dataclass
class AuthRequestResponse:
    auth_id: str
    auth_title: str
    auth_message: str
    auth_error: str
    login_url: str
    login_final_url: str
    token_cookie_name: str
    opaque: Any


def parse_auth_complete_response(
    xml: objectify.ObjectifiedElement,
) -> AuthCompleteResponse:
    assert xml.auth.get("id") == "success"
    resp = AuthCompleteResponse(
        auth_id=xml.auth.get("id"),
        auth_message=xml.auth.message,
        session_token=xml["session-token"],
        server_cert_hash=xml.config["vpn-base-config"]["server-cert-hash"],
    )
    logger.info("Response received", id=resp.auth_id, message=resp.auth_message)
    return resp


@dataclass
class AuthCompleteResponse:
    auth_id: str
    auth_message: str
    session_token: str
    server_cert_hash: str


def _create_auth_finish_request(
    host: HostProfile, auth_info: AuthRequestResponse, sso_token: str
) -> str:
    ConfigAuth = getattr(E, "config-auth")
    Version = E.version
    DeviceId = getattr(E, "device-id")
    SessionToken = getattr(E, "session-token")
    SessionId = getattr(E, "session-id")
    Auth = E.auth
    SsoToken = getattr(E, "sso-token")

    root = ConfigAuth(
        {"client": "vpn", "type": "auth-reply", "aggregate-auth-version": "2"},
        Version({"who": "vpn"}, "4.7.00136"),
        DeviceId("linux-64"),
        SessionToken(),
        SessionId(),
        auth_info.opaque,
        Auth(SsoToken(sso_token)),
    )
    return etree.tostring(  # type: ignore
        root, pretty_print=True, xml_declaration=True, encoding="UTF-8"
    )
