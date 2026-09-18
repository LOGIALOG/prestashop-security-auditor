from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from typing import Callable, Sequence

import httpcore
import httpx


class EgressPolicyError(ValueError):
    pass


class UnsafeDestinationError(EgressPolicyError):
    pass


class DnsResolutionError(EgressPolicyError):
    pass


EXPLICIT_DENY_V4 = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "169.254.169.254/32",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
)
EXPLICIT_DENY_V6 = tuple(
    ipaddress.ip_network(network)
    for network in (
        "::/128",
        "::1/128",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "fd00:ec2::254/128",
    )
)


def _normalize(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_public_destination(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = _normalize(ipaddress.ip_address(address) if isinstance(address, str) else address)
    if ip.is_multicast or ip.is_reserved or not ip.is_global:
        return False
    denied = EXPLICIT_DENY_V4 if ip.version == 4 else EXPLICIT_DENY_V6
    return not any(ip in network for network in denied)


def _system_getaddrinfo(host: str, port: int) -> tuple[str, ...]:
    infos = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    return tuple(addresses)


async def resolve_public_addresses(
    host: str,
    port: int,
    *,
    timeout: float | None,
    resolver: Callable[[str, int], Sequence[str]] | None = None,
) -> tuple[str, ...]:
    lookup = resolver or _system_getaddrinfo
    try:
        if timeout is None:
            addresses = await asyncio.to_thread(lookup, host, port)
        else:
            addresses = await asyncio.wait_for(asyncio.to_thread(lookup, host, port), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise DnsResolutionError("DNS resolution timed out") from exc
    except (socket.gaierror, OSError) as exc:
        raise DnsResolutionError("DNS resolution failed") from exc
    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for address in addresses:
        try:
            parsed.append(_normalize(ipaddress.ip_address(address)))
        except ValueError as exc:
            raise DnsResolutionError("DNS returned an invalid address") from exc
    if not parsed:
        raise DnsResolutionError("DNS returned no addresses")
    for ip in parsed:
        if not is_public_destination(ip):
            raise UnsafeDestinationError("DNS resolved to a non-public destination")
    return tuple(str(ip) for ip in parsed)


class SafeAsyncNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        inner: httpcore.AsyncNetworkBackend | None = None,
        *,
        resolver: Callable[[str, int], Sequence[str]] | None = None,
    ) -> None:
        self._inner = inner or httpcore.AnyIOBackend()
        self._resolver = resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object | None = None,
    ) -> httpcore.AsyncNetworkStream:
        started = time.monotonic()
        addresses = await resolve_public_addresses(host, port, timeout=timeout, resolver=self._resolver)
        last_error: BaseException | None = None
        for address in addresses:
            remaining: float | None = None
            if timeout is not None:
                remaining = max(0.0, timeout - (time.monotonic() - started))
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=remaining,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise DnsResolutionError("no validated destination available")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: object | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise EgressPolicyError("unix sockets are not permitted for public egress")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class SafeAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    def __init__(
        self,
        *,
        verify: bool | str | object = True,
        trust_env: bool = False,
        limits: httpx.Limits | None = None,
        socket_options: object | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        super().__init__(
            verify=verify,
            trust_env=trust_env,
            http1=True,
            http2=False,
            limits=limits or httpx.Limits(),
            retries=0,
            socket_options=socket_options,
        )
        previous = self._pool
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=previous._ssl_context,
            max_connections=previous._max_connections,
            max_keepalive_connections=previous._max_keepalive_connections,
            keepalive_expiry=previous._keepalive_expiry,
            http1=True,
            http2=False,
            retries=0,
            local_address=previous._local_address,
            uds=None,
            network_backend=network_backend or SafeAsyncNetworkBackend(),
            socket_options=previous._socket_options,
        )


def build_safe_async_transport(
    *,
    network_backend: httpcore.AsyncNetworkBackend | None = None,
) -> SafeAsyncHTTPTransport:
    return SafeAsyncHTTPTransport(network_backend=network_backend)


def build_safe_async_client(
    *,
    timeout: float | None = 12.0,
    headers: dict[str, str] | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=build_safe_async_transport(),
        follow_redirects=False,
        timeout=timeout,
        headers=headers,
    )
