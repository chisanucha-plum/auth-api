import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from structlog import get_logger

load_dotenv()

logger = get_logger(__name__)


@dataclass
class Application:
    host: str
    title: str
    version: str
    redirect_slashes: bool

    @staticmethod
    def from_dict(obj: Any) -> "Application":
        _host = str(obj.get("host"))
        _title = str(obj.get("title"))
        _version = str(obj.get("version"))
        _redirect_slashes = bool(obj.get("redirect_slashes", False))
        return Application(
            host=_host,
            title=_title,
            version=_version,
            redirect_slashes=_redirect_slashes,
        )


@dataclass
class CORS:
    allow_origins: list[str]
    allow_credentials: bool
    allow_methods: list[str]
    allow_headers: list[str]

    @staticmethod
    def from_dict(obj: Any) -> "CORS":
        _allow_origins = obj.get("allow_origins", ["*"])
        _allow_credentials = obj.get("allow_credentials", True)
        _allow_methods = obj.get("allow_methods", ["*"])
        _allow_headers = obj.get("allow_headers", ["*"])

        return CORS(
            allow_origins=_allow_origins,
            allow_credentials=_allow_credentials,
            allow_methods=_allow_methods,
            allow_headers=_allow_headers,
        )


@dataclass
class Http:
    timeout: int = 60

    @staticmethod
    def from_dict(obj: Any) -> "Http":
        obj = obj or {}
        _timeout = int(obj.get("timeout", 10))
        return Http(timeout=_timeout)


@dataclass
class Postgres:
    host: str
    port: int
    user: str
    password: str
    database: str

    @staticmethod
    def from_dict(obj: dict) -> "Postgres":
        _host = str(obj.get("host"))
        _port = int(obj.get("port"))
        _user = str(obj.get("user"))
        _password = str(obj.get("password"))
        _database = str(obj.get("database"))
        return Postgres(_host, _port, _user, _password, _database)


@dataclass
class Redis:
    host: str
    port: int
    db: int
    password: str | None = None

    @staticmethod
    def from_dict(obj: dict) -> "Redis":
        _host = str(obj.get("host"))
        _port = int(obj.get("port"))
        _db = int(obj.get("db"))
        _password = obj.get("password")
        return Redis(_host, _port, _db, _password)


@dataclass
class Key:
    secret_key: str
    algorithm: str = "HS256"
    access_token_minutes: int = 30

    @staticmethod
    def from_dict(obj: Any) -> "Key":
        _secret_key = str(obj.get("secret_key"))
        _algorithm = str(obj.get("algorithm", "HS256"))
        _access_token_minutes = int(obj.get("access_token_minutes", 30))
        return Key(
            secret_key=_secret_key,
            algorithm=_algorithm,
            access_token_minutes=_access_token_minutes,
        )


@dataclass
class RefreshTokenCookie:
    key: str
    value: str
    httponly: bool
    secure: bool
    max_age: int
    path: str
    domain: str | None
    samesite: Literal["lax", "strict", "none"] = "lax"

    @staticmethod
    def from_dict(obj: Any) -> "RefreshTokenCookie":
        _key = str(obj.get("key"))
        _value = str(obj.get("value"))
        _httponly = bool(obj.get("httponly", False))
        _secure = bool(obj.get("secure", False))
        _samesite = str(obj.get("samesite", "lax"))
        _max_age = int(obj.get("max_age", 2592000))
        _path = str(obj.get("path", "/"))
        _domain = obj.get("domain")

        return RefreshTokenCookie(
            key=_key,
            value=_value,
            httponly=_httponly,
            secure=_secure,
            samesite=_samesite,
            max_age=_max_age,
            path=_path,
            domain=_domain,
        )


# @dataclass
# class Keycloak:
#     access_token_url: str
#     scope: str
#     client_id: str
#     client_secret: str

#     @staticmethod
#     def from_dict(obj: Any) -> "Keycloak":
#         _access_token_url = str(obj.get("access_token_url"))
#         _scope = str(obj.get("scope", "openid email profile"))
#         _client_id = str(obj.get("client_id"))
#         _client_secret = str(obj.get("client_secret"))

#         return Keycloak(
#             access_token_url=_access_token_url,
#             scope=_scope,
#             client_id=_client_id,
#             client_secret=_client_secret,
#         )


@dataclass
class Configuration:
    application: Application
    cors: CORS
    http: Http
    postgres: Postgres
    redis: Redis
    key: Key
    refresh_token_cookie: RefreshTokenCookie
    # keycloak: Keycloak

    @staticmethod
    def from_dict(obj: Any) -> "Configuration":
        _application = Application.from_dict(obj.get("application"))
        _cors = CORS.from_dict(obj.get("cors"))
        _http = Http.from_dict(obj.get("http"))
        # _keycloak = Keycloak.from_dict(obj.get("keycloak"))
        _postgres = Postgres.from_dict(obj.get("postgres"))
        _redis = Redis.from_dict(obj.get("redis"))
        _key = Key.from_dict(obj.get("key"))
        _refresh_token_cookie = RefreshTokenCookie.from_dict(
            obj.get("refresh_token_cookie")
        )

        return Configuration(
            _application,
            _cors,
            _http,
            _postgres,
            _redis,
            _key,
            _refresh_token_cookie,
            # _keycloak,
        )

    @staticmethod
    @lru_cache
    def get_config() -> "Configuration":
        site = os.environ.get("SITE", "development")

        with Path(f"config.{site}.json").open(encoding="utf-8") as f:
            config_json = json.load(f)
            logger.info(f"Loaded configuration for site: {site}")
            return Configuration.from_dict(config_json)
