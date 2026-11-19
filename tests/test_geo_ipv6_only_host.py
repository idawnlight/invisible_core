"""A direct session on a host that only has IPv6 is refused, with a reason.

The persona declares ``v6=0`` for every session, so the engine asks A records only
and the browser has no IPv4 route to use on such a host: it would have no
connectivity at all. The core says so at launch instead of handing back a browser
that loads nothing.

The direct egress echo is therefore made over IPv4 ONLY (the persona is IPv4-only,
and an echo over IPv6 would hand back an address the session never uses). When that
echo cannot connect and an IPv6-only echo can, the host is IPv6-only.

The family is forced on the request's own sockets (a session whose adapter binds
``0.0.0.0``, or ``::`` for the IPv6 probe) and never on urllib3's global
``allowed_gai_family``. Most tests here stub ``_geo._http_get`` and read the family
asked for; the last group opens real sockets on loopback, to prove that the binding
is what keeps a request on its family.
"""
from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import urllib3.util.connection as u3conn

from invisible_core import _geo
from invisible_core._geo import GeoTimezoneError, discover_egress_ip, prepare_session_geo

pytestmark = pytest.mark.unit

_REAL_HTTP_GET = _geo._http_get   # before the autouse fixture of conftest.py refuses it

HTTP = {"server": "http://gw.example:8080", "username": "u", "password": "p"}
V6_URLS = {"https://api6.ipify.org", "https://ipv6.icanhazip.com"}
REFUSAL = "an IPv6-only host without a proxy is not supported"


class _Resp:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def _install(monkeypatch, *, v4, v6):
    """Stub the echo. ``v4`` and ``v6`` are the replies for the IPv4 and IPv6 echoes:
    a string answers, an exception is raised. Records (url, family asked, proxies)."""
    calls = []

    def fake_get(url, **kw):
        calls.append((url, kw.get("family", socket.AF_INET), kw.get("proxies")))
        reply = v6 if url in V6_URLS else v4
        if isinstance(reply, BaseException):
            raise reply
        return _Resp(reply)

    monkeypatch.setattr(_geo, "_http_get", fake_get)
    return calls


def _down():
    return requests.exceptions.ConnectionError("Network is unreachable")


def test_direct_echo_is_made_over_ipv4_only(monkeypatch):
    original = u3conn.allowed_gai_family
    calls = _install(monkeypatch, v4="203.0.113.7", v6=_down())
    assert discover_egress_ip(None) == "203.0.113.7"
    assert [c[1] for c in calls] == [socket.AF_INET]
    assert u3conn.allowed_gai_family is original  # never touched


def test_the_global_family_is_not_touched_when_the_echo_raises(monkeypatch):
    original = u3conn.allowed_gai_family
    _install(monkeypatch, v4=_down(), v6=_down())
    with pytest.raises(GeoTimezoneError):
        discover_egress_ip(None)
    assert u3conn.allowed_gai_family is original


def test_ipv4_echo_down_and_ipv6_echo_up_is_refused(monkeypatch):
    calls = _install(monkeypatch, v4=_down(), v6="2001:db8::1")
    with pytest.raises(GeoTimezoneError) as ei:
        discover_egress_ip(None)
    assert ei.value.kind == "ipv6_only_no_proxy"
    msg = str(ei.value)
    assert REFUSAL in msg
    assert "proxy" in msg and "IPv4" in msg
    # The probe is made over IPv6, and only after the IPv4 echoes failed.
    assert calls[-1][0] in V6_URLS and calls[-1][1] == socket.AF_INET6
    assert all(c[0] not in V6_URLS for c in calls[:len(_geo._IP_ECHO_ENDPOINTS)])


def test_both_echoes_down_keeps_todays_failure(monkeypatch):
    _install(monkeypatch, v4=_down(), v6=_down())
    with pytest.raises(GeoTimezoneError) as ei:
        discover_egress_ip(None)
    assert ei.value.kind == "connect_failed"
    assert REFUSAL not in str(ei.value)


def test_a_bad_ipv4_answer_is_not_an_ipv6_only_host(monkeypatch):
    """The IPv4 echo CONNECTED and said something wrong: not a routing fact."""
    _install(monkeypatch, v4="<html>captive portal</html>", v6="2001:db8::1")
    with pytest.raises(GeoTimezoneError) as ei:
        discover_egress_ip(None)
    assert ei.value.kind == "endpoint_not_an_ip"


@pytest.mark.parametrize("answer", ["203.0.113.9", "not an address", ""])
def test_an_ipv6_echo_that_does_not_answer_with_an_ipv6_address_proves_nothing(
        monkeypatch, answer):
    _install(monkeypatch, v4=_down(), v6=answer)
    with pytest.raises(GeoTimezoneError) as ei:
        discover_egress_ip(None)
    assert ei.value.kind == "connect_failed"


def test_with_a_proxy_nothing_is_forced_and_nothing_is_diagnosed(monkeypatch):
    calls = _install(monkeypatch, v4=_down(), v6="2001:db8::1")
    with pytest.raises(GeoTimezoneError) as ei:
        discover_egress_ip(HTTP)
    assert ei.value.kind == "connect_failed"
    assert REFUSAL not in str(ei.value)
    assert all(c[0] not in V6_URLS for c in calls)  # no IPv6 probe
    assert all(c[2] for c in calls)                 # every request went through the proxy


def test_launch_geo_refuses_even_with_an_explicit_zone_and_locale(monkeypatch):
    """Connectivity is not a geo question: an explicit zone does not make a browser
    with no route usable, so the refusal is not the swallowed discovery failure."""
    _install(monkeypatch, v4=_down(), v6="2001:db8::1")
    with pytest.raises(GeoTimezoneError) as ei:
        prepare_session_geo("Europe/Rome", None, "it-IT")
    assert ei.value.kind == "ipv6_only_no_proxy"


def test_launch_geo_with_a_proxy_is_not_refused_for_the_host_family(monkeypatch):
    _install(monkeypatch, v4="203.0.113.7", v6=_down())
    geo = prepare_session_geo("Europe/Rome", HTTP, "it-IT")
    assert geo.egress_ip == "203.0.113.7"


def test_launch_geo_both_echoes_down_and_an_explicit_zone_still_goes_on(monkeypatch):
    _install(monkeypatch, v4=_down(), v6=_down())
    geo = prepare_session_geo("Europe/Rome", None, "it-IT")
    assert geo.timezone == "Europe/Rome" and geo.egress_ip is None


# --- the binding itself: real sockets, on loopback only --------------------------------------------------------------


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"203.0.113.7"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _serve(cls, host):
    server = cls((host, 0), _Echo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def v4_echo():
    server, thread = _serve(ThreadingHTTPServer, "127.0.0.1")
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(5)


@pytest.fixture
def v6_echo():
    try:
        server, thread = _serve(_V6Server, "::1")
    except OSError:
        pytest.skip("no IPv6 loopback on this host")
    yield f"http://[::1]:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    thread.join(5)


def test_the_ipv4_binding_reaches_an_ipv4_address_and_only_that(monkeypatch, v4_echo, v6_echo):
    original = u3conn.allowed_gai_family
    monkeypatch.setenv("NO_PROXY", "*")   # loopback must not be sent to a proxy of the host
    ok = _REAL_HTTP_GET(v4_echo, timeout=(5, 5), family=socket.AF_INET)
    assert ok.text == "203.0.113.7"
    with pytest.raises(requests.exceptions.ConnectionError):
        _REAL_HTTP_GET(v6_echo, timeout=(5, 5), family=socket.AF_INET)
    assert u3conn.allowed_gai_family is original


def test_the_ipv6_binding_reaches_an_ipv6_address_and_only_that(monkeypatch, v4_echo, v6_echo):
    monkeypatch.setenv("NO_PROXY", "*")
    ok = _REAL_HTTP_GET(v6_echo, timeout=(5, 5), family=socket.AF_INET6)
    assert ok.text == "203.0.113.7"
    with pytest.raises(requests.exceptions.ConnectionError):
        _REAL_HTTP_GET(v4_echo, timeout=(5, 5), family=socket.AF_INET6)


def test_a_tls_connection_is_opened_from_the_bound_address(monkeypatch):
    """The echoes are https: the binding must reach the TLS connection too. The socket is
    never opened - the connect function is replaced and records what it was asked."""
    seen = []

    def fake_create_connection(address, timeout=None, source_address=None, socket_options=None):
        seen.append(source_address)
        raise OSError("stop here")

    monkeypatch.setattr(u3conn, "create_connection", fake_create_connection)
    monkeypatch.setenv("NO_PROXY", "*")
    for family, source in ((socket.AF_INET, ("0.0.0.0", 0)), (socket.AF_INET6, ("::", 0))):
        with pytest.raises(requests.exceptions.ConnectionError):
            _REAL_HTTP_GET("https://echo.invalid/", timeout=(1, 1), family=family)
        assert seen[-1] == source


def test_a_request_through_a_proxy_is_not_bound_to_a_family(monkeypatch):
    got = {}

    def fake_requests_get(url, **kw):
        got.update(kw)
        return _Resp("203.0.113.7")

    monkeypatch.setattr(_geo.requests, "get", fake_requests_get)
    _REAL_HTTP_GET("https://echo.invalid/", proxies={"https": "http://gw.example:8080"}, timeout=(1, 1))
    assert got["proxies"] == {"https": "http://gw.example:8080"}
