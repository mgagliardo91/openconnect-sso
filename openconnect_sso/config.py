from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlparse, urlunparse

import keyring
import keyring.errors
import structlog
import toml
import xdg.BaseDirectory

logger = structlog.get_logger()

APP_NAME = "openconnect-sso"
T = TypeVar("T")


def load() -> Config:
    path = xdg.BaseDirectory.load_first_config(APP_NAME)
    if not path:
        return Config()
    config_path = Path(path) / "config.toml"
    if not config_path.exists():
        return Config()
    with config_path.open() as config_file:
        try:
            return Config.from_dict(toml.load(config_file))
        except Exception:
            logger.error(
                "Could not load configuration file, ignoring",
                path=config_path,
                exc_info=True,
            )
            return Config()


def save(config: Config) -> None:
    path = xdg.BaseDirectory.save_config_path(APP_NAME)
    config_path = Path(path) / "config.toml"
    try:
        config_path.touch()
        with config_path.open("w") as config_file:
            toml.dump(config.as_dict(), config_file)
    except Exception:
        logger.error(
            "Could not save configuration file", path=config_path, exc_info=True
        )


class ConfigNode:
    @classmethod
    def from_dict(cls: type[T], d: dict[str, Any] | None) -> T | None:
        if d is None:
            return None
        return cls(**d)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HostProfile(ConfigNode):
    address: str
    user_group: str
    name: str

    @property
    def vpn_url(self) -> str:
        parts = urlparse(self.address)
        group = self.user_group or parts.path
        if parts.path == self.address and not self.user_group:
            group = ""
        return urlunparse(
            (parts.scheme or "https", parts.netloc or self.address, group, "", "", "")
        )


@dataclass
class AutoFillRule(ConfigNode):
    selector: str
    fill: str | None = None
    action: str | None = None


def get_default_auto_fill_rules() -> dict[str, list[AutoFillRule]]:
    return {
        "https://*": [
            AutoFillRule(selector="div[id=passwordError]", action="stop"),
            AutoFillRule(selector="input[type=email]", fill="username"),
            AutoFillRule(selector="input[type=password]", fill="password"),
            AutoFillRule(selector="input[type=submit]", action="click"),
        ]
    }


@dataclass
class Credentials(ConfigNode):
    username: str
    _password: str | None = None

    @property
    def password(self) -> str | None:
        if self._password:
            return self._password

        try:
            return keyring.get_password(APP_NAME, self.username)
        except keyring.errors.KeyringError:
            logger.info("Cannot retrieve saved password from keyring.")
            return ""

    @password.setter
    def password(self, value: str) -> None:
        self._password = value

        try:
            keyring.set_password(APP_NAME, self.username, value)
        except keyring.errors.KeyringError:
            logger.info("Cannot save password to keyring.")


@dataclass
class Config(ConfigNode):
    default_profile: HostProfile | None = None
    credentials: Credentials | None = None
    auto_fill_rules: dict[str, list[AutoFillRule]] = field(
        default_factory=get_default_auto_fill_rules
    )
    on_disconnect: str = field(default_factory=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:  # type: ignore
        return Config(
            default_profile=HostProfile.from_dict(data.get("default_profile")),
            credentials=Credentials.from_dict(data.get("credentials")),
            auto_fill_rules={
                n: [AutoFillRule(**r) for r in rule]
                for n, rule in data["auto_fill_rules"].items()
            },
        )


class DisplayMode(enum.Enum):
    HIDDEN = 0
    SHOWN = 1
