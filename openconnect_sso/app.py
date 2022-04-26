from __future__ import annotations

import asyncio
import getpass
import json
import logging
import os
import shlex
import signal
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any, Coroutine

import structlog
from prompt_toolkit import HTML
from prompt_toolkit.shortcuts import radiolist_dialog
from requests.exceptions import HTTPError

from openconnect_sso import config
from openconnect_sso.authenticator import (
    AuthCompleteResponse,
    Authenticator,
    AuthResponseError,
)
from openconnect_sso.config import Config, Credentials, DisplayMode, HostProfile
from openconnect_sso.profile import get_profiles

logger = structlog.get_logger()


def run(args: Namespace) -> int:
    configure_logger(logging.getLogger(), args.log_level)

    cfg = config.load()

    try:
        if os.name == "nt":
            asyncio.set_event_loop(asyncio.ProactorEventLoop())  # type: ignore
        auth_response, selected_profile = asyncio.get_event_loop().run_until_complete(
            _run(args, cfg)
        )
    except KeyboardInterrupt:
        logger.warn("CTRL-C pressed, exiting")
        return 130
    except ValueError as e:
        msg, retval = e.args
        logger.error(msg)
        return retval  # type: ignore
    except AuthResponseError as exc:
        logger.error(
            f'Required attributes not found in response ("{exc}", does this endpoint do SSO?), exiting'
        )
        return 3
    except HTTPError as exc:
        logger.error(f"Request error: {exc}")
        return 4

    config.save(cfg)

    if args.authenticate:
        logger.warn("Exiting after login, as requested")
        details = {
            "host": selected_profile.vpn_url,
            "cookie": auth_response.session_token,
            "fingerprint": auth_response.server_cert_hash,
        }
        if args.authenticate == "json":
            print(json.dumps(details, indent=4))
        elif args.authenticate == "shell":
            print(
                "\n".join(f"{k.upper()}={shlex.quote(v)}" for k, v in details.items())
            )
        return 0

    try:
        return run_openconnect(
            auth_response, selected_profile, args.proxy, args.openconnect_args
        )
    except KeyboardInterrupt:
        logger.warn("CTRL-C pressed, exiting")
        return 0
    finally:
        handle_disconnect(cfg.on_disconnect)


def configure_logger(logger: logging.Logger, level: logging._Level) -> None:
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer()
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)


async def _run(
    args: Namespace, cfg: Config
) -> tuple[AuthCompleteResponse, HostProfile]:
    credentials = None
    if cfg.credentials:
        credentials = cfg.credentials
    elif args.user:
        credentials = Credentials(args.user)

    if credentials and not credentials.password:
        if sys.stdin.isatty():
            credentials.password = getpass.getpass(prompt=f"Password ({args.user}): ")
        else:
            print(f"Password ({args.user}): ")
            credentials.password = sys.stdin.readline().rstrip()

        cfg.credentials = credentials

    if cfg.default_profile and not (args.use_profile_selector or args.server):
        selected_profile = cfg.default_profile
    elif args.use_profile_selector or args.profile_path:
        profiles = get_profiles(Path(args.profile_path))
        if not profiles:
            raise ValueError("No profile found", 17)

        selected_profile = await select_profile(profiles)  # type: ignore
        if not selected_profile:
            raise ValueError("No profile selected", 18)
    elif args.server:
        selected_profile = config.HostProfile(
            args.server, args.usergroup, args.authgroup
        )
    else:
        raise ValueError(
            "Cannot determine server address. Invalid arguments specified.", 19
        )

    cfg.default_profile = selected_profile

    display_mode = config.DisplayMode[args.browser_display_mode.upper()]

    auth_response = await authenticate_to(
        selected_profile, args.proxy, credentials, display_mode
    )

    if args.on_disconnect and not cfg.on_disconnect:
        cfg.on_disconnect = args.on_disconnect

    return auth_response, selected_profile


async def select_profile(profile_list: list[HostProfile]) -> HostProfile | None:
    selection: HostProfile | None = await radiolist_dialog(
        title="Select AnyConnect profile",
        text=HTML(
            "The following AnyConnect profiles are detected.\n"
            "The selection will be <b>saved</b> and not asked again unless the <pre>--profile-selector</pre> command line option is used"
        ),
        values=[(p, p.name) for i, p in enumerate(profile_list)],  # type: ignore
    ).run_async()
    # Somehow prompt_toolkit sets up a bogus signal handler upon exit
    # TODO: Report this issue upstream
    if hasattr(signal, "SIGWINCH"):
        asyncio.get_event_loop().remove_signal_handler(signal.SIGWINCH)
    if not selection:
        return selection
    logger.info("Selected profile", profile=selection.name)
    return selection


def authenticate_to(
    host: HostProfile,
    proxy: str,
    credentials: Credentials | None,
    display_mode: DisplayMode,
) -> Coroutine[Any, Any, AuthCompleteResponse]:
    logger.info("Authenticating to VPN endpoint", name=host.name, address=host.address)
    return Authenticator(host, proxy, credentials).authenticate(display_mode)


def run_openconnect(
    auth_info: AuthCompleteResponse, host: HostProfile, proxy: str, args: list[str]
) -> int:
    command_line = [
        "sudo",
        "openconnect",
        "--cookie-on-stdin",
        "--servercert",
        auth_info.server_cert_hash,
        *args,
        host.vpn_url,
    ]
    if proxy:
        command_line.extend(["--proxy", proxy])

    session_token = auth_info.session_token.encode("utf-8")
    logger.debug("Starting OpenConnect", command_line=command_line)
    return subprocess.run(command_line, input=session_token).returncode


def handle_disconnect(command: str) -> int | None:
    if command:
        logger.info("Running command on disconnect", command_line=command)
        return subprocess.run(command, timeout=5, shell=True).returncode
    return None
