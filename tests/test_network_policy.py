import asyncio
import socket
import ssl
import threading

import httpcore
import httpx
import pytest

from backend.app import network_policy as np


@pytest.mark.parametrize(
    "address,expected",
    [
        ("93.184.216.34", True),
        ("2606:4700:4700::1111", True),
        ("127.0.0.1", False),
        ("10.0.0.1", False),
        ("172.16.0.1", False),
        ("192.168.1.1", False),
        ("169.254.1.1", False),
        ("169.254.169.254", False),
        ("224.0.0.1", False),
        ("240.0.0.1", False),
        ("0.0.0.0", False),
        ("100.64.0.1", False),
        ("192.0.2.1", False),
        ("198.51.100.1", False),
        ("203.0.113.1", False),
        ("198.18.0.1", False),
        ("::1", False),
        ("fc00::1", False),
        ("fe80::1", False),
        ("ff02::1", False),
        ("::", False),
        ("2001:db8::1", False),
        ("2001::1", False),
        ("::ffff:127.0.0.1", False),
        ("::ffff:10.0.0.1", False),
        ("::ffff:93.184.216.34", True),
        ("fd00:ec2::254", False),
        ("64:ff9b::1", False),
        ("64:ff9b::a00:1", False),
        ("64:ff9b:1::1", False),
        ("2002:0a00:0001::1", False),
    ],
)
def test_ip_classification(address, expected):
    assert np.is_public_destination(address) is expected


def test_resolver_accepts_single_public():
    addresses = asyncio.run(np.resolve_public_addresses("shop.test", 443, timeout=1, resolver=lambda h, p: ("93.184.216.34",)))
    assert addresses == ("93.184.216.34",)


def test_resolver_rejects_unsafe():
    with pytest.raises(np.UnsafeDestinationError):
        asyncio.run(np.resolve_public_addresses("shop.test", 443, timeout=1, resolver=lambda h, p: ("10.0.0.1",)))


def test_resolver_rejects_mixed_before_connect():
    with pytest.raises(np.UnsafeDestinationError):
        asyncio.run(
            np.resolve_public_addresses("shop.test", 443, timeout=1, resolver=lambda h, p: ("93.184.216.34", "10.0.0.1"))
        )


def test_resolver_rejects_empty_and_gaierror():
    with pytest.raises(np.DnsResolutionError):
        asyncio.run(np.resolve_public_addresses("shop.test", 443, timeout=1, resolver=lambda h, p: ()))
    with pytest.raises(np.DnsResolutionError):
        asyncio.run(
            np.resolve_public_addresses("shop.test", 443, timeout=1, resolver=lambda h, p: (_ for _ in ()).throw(socket.gaierror("no")))
        )


def test_resolver_timeout_fails_closed():
    import time

    def slow(host, port):
        time.sleep(0.2)
        return ("93.184.216.34",)

    with pytest.raises(np.DnsResolutionError):
        asyncio.run(np.resolve_public_addresses("shop.test", 443, timeout=0.01, resolver=slow))


def test_resolver_runs_off_event_loop_and_timeout_none():
    seen = {}

    def resolver(host, port):
        seen["thread"] = threading.current_thread().name
        return ("93.184.216.34",)

    asyncio.run(np.resolve_public_addresses("shop.test", 443, timeout=None, resolver=resolver))
    assert seen["thread"].startswith("asyncio_")


class _FakeStream:
    def __init__(self):
        self.server_hostname = None

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.server_hostname = server_hostname
        return self

    async def read(self, max_bytes, timeout=None):
        raise RuntimeError("read after capture")

    async def write(self, buffer, timeout=None):
        return None

    async def aclose(self):
        return None

    def get_extra_info(self, info):
        return None


class _FakeBackend(httpcore.AnyIOBackend):
    def __init__(self, stream=None):
        super().__init__()
        self.stream = stream or _FakeStream()
        self.hosts = []
        self.fail_first = False
        self.raise_type = httpcore.ConnectError

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.hosts.append(host)
        if self.fail_first and len(self.hosts) == 1:
            raise self.raise_type("synthetic")
        return self.stream


def test_backend_dials_validated_ip_literal_never_hostname():
    inner = _FakeBackend()
    backend = np.SafeAsyncNetworkBackend(inner=inner, resolver=lambda h, p: ("93.184.216.34",))
    asyncio.run(backend.connect_tcp("shop.test", 443, timeout=1))
    assert inner.hosts == ["93.184.216.34"]
    assert "shop.test" not in inner.hosts


def test_backend_multi_address_fallback_is_deterministic():
    inner = _FakeBackend()
    inner.fail_first = True
    backend = np.SafeAsyncNetworkBackend(inner=inner, resolver=lambda h, p: ("93.184.216.34", "93.184.216.35"))
    asyncio.run(backend.connect_tcp("shop.test", 443, timeout=1))
    assert inner.hosts == ["93.184.216.34", "93.184.216.35"]


def test_backend_connect_timeout_fallback_is_explicit():
    inner = _FakeBackend()
    inner.fail_first = True
    inner.raise_type = httpcore.ConnectTimeout
    backend = np.SafeAsyncNetworkBackend(inner=inner, resolver=lambda h, p: ("93.184.216.34", "93.184.216.35"))
    asyncio.run(backend.connect_tcp("shop.test", 443, timeout=1))
    assert inner.hosts == ["93.184.216.34", "93.184.216.35"]


def test_backend_all_validated_failures_propagate():
    class AllFail(_FakeBackend):
        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            self.hosts.append(host)
            raise httpcore.ConnectTimeout("synthetic")

    inner = AllFail()
    backend = np.SafeAsyncNetworkBackend(inner=inner, resolver=lambda h, p: ("93.184.216.34", "93.184.216.35"))
    with pytest.raises(httpcore.ConnectTimeout):
        asyncio.run(backend.connect_tcp("shop.test", 443, timeout=1))
    assert inner.hosts == ["93.184.216.34", "93.184.216.35"]


def test_backend_unsafe_resolution_never_dials():
    inner = _FakeBackend()
    backend = np.SafeAsyncNetworkBackend(inner=inner, resolver=lambda h, p: ("10.0.0.1",))
    with pytest.raises(np.UnsafeDestinationError):
        asyncio.run(backend.connect_tcp("shop.test", 443, timeout=1))
    assert inner.hosts == []


def test_backend_revalidates_changed_answer_on_new_connection():
    answers = iter([("93.184.216.34",), ("10.0.0.1",)])
    inner = _FakeBackend()
    backend = np.SafeAsyncNetworkBackend(inner=inner, resolver=lambda h, p: next(answers))
    stream = asyncio.run(backend.connect_tcp("shop.test", 443, timeout=1))
    assert stream is inner.stream
    with pytest.raises(np.UnsafeDestinationError):
        asyncio.run(backend.connect_tcp("shop.test", 443, timeout=1))
    assert inner.hosts == ["93.184.216.34"]


def test_backend_rejects_unix_socket():
    backend = np.SafeAsyncNetworkBackend()
    with pytest.raises(np.EgressPolicyError):
        asyncio.run(backend.connect_unix_socket("/tmp/socket"))


def test_tls_server_hostname_is_original_host_and_context_verifies():
    stream = _FakeStream()
    inner = _FakeBackend(stream)
    backend = np.SafeAsyncNetworkBackend(inner=inner, resolver=lambda h, p: ("93.184.216.34",))
    context = ssl.create_default_context()
    connection = httpcore.AsyncHTTPConnection(
        origin=httpcore.Origin(scheme=b"https", host=b"shop.test", port=443),
        ssl_context=context,
        network_backend=backend,
    )
    request = httpcore.Request(method=b"GET", url=httpcore.URL(scheme=b"https", host=b"shop.test", port=443, target=b"/"))
    with pytest.raises(Exception):
        asyncio.run(connection.handle_async_request(request))
    assert inner.hosts == ["93.184.216.34"]
    assert stream.server_hostname == "shop.test"
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_transport_installs_safe_backend_in_pool():
    transport = np.build_safe_async_transport()
    assert isinstance(transport, np.SafeAsyncHTTPTransport)
    assert isinstance(transport._pool, httpcore.AsyncConnectionPool)
    assert isinstance(transport._pool._network_backend, np.SafeAsyncNetworkBackend)
    assert transport._pool._http2 is False
    assert transport._pool._retries == 0


def test_safe_client_has_finite_timeout_and_no_env_trust(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/cert.pem")
    monkeypatch.setenv("SSL_CERT_DIR", "/nonexistent/certs")

    client = np.build_safe_async_client()
    try:
        assert isinstance(client._transport, np.SafeAsyncHTTPTransport)
        assert client.timeout.connect == 12.0
        assert client.timeout.read == 12.0
        context = client._transport._pool._ssl_context
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
    finally:
        asyncio.run(client.aclose())
