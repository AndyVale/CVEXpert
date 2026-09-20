"""URL normalization and public-destination validation for external references."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import SplitResult, urlsplit, urlunsplit


class UnsafeUrlError(ValueError):
    """A URL is malformed or points outside the permitted public HTTP boundary."""


def normalize_http_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UnsafeUrlError("Reference URL must be a non-empty string")
    raw = value.strip()
    if any(ord(character) < 32 for character in raw):
        raise UnsafeUrlError("Reference URL contains control characters")
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UnsafeUrlError("Reference URL scheme must be HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeUrlError("Reference URL must not contain credentials")
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeUrlError("Reference URL must contain a hostname")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise UnsafeUrlError("Reference URL hostname or port is invalid") from error
    if ":" in ascii_hostname and not ascii_hostname.startswith("["):
        rendered_host = f"[{ascii_hostname}]"
    else:
        rendered_host = ascii_hostname
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        rendered_host = f"{rendered_host}:{port}"
    path = parsed.path or "/"
    return urlunsplit(SplitResult(scheme, rendered_host, path, parsed.query, ""))


def validate_public_http_url(
    value: str,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> str:
    normalized = normalize_http_url(value)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname
    assert hostname is not None
    try:
        addresses = {
            item[4][0]
            for item in resolver(
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        }
    except OSError as error:
        raise UnsafeUrlError("Reference hostname could not be resolved") from error
    if not addresses:
        raise UnsafeUrlError("Reference hostname resolved to no addresses")
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as error:
            raise UnsafeUrlError("Reference hostname resolved to an invalid address") from error
        if not ip.is_global:
            raise UnsafeUrlError("Reference hostname resolved to a non-public address")
    return normalized
