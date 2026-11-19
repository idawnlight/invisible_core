"""Launches that ask for the egress at the same moment share ONE measurement, and a direct answer is kept for two minutes.

⛔ THE KNOWN-BAD, measured on GitHub runners with four browsers launched together in one process and no proxy: every launch made its own HTTPS request to an
echo service, and each of them swapped urllib3's GLOBAL `allowed_gai_family` under one process-wide lock held for the whole request, so the four requests ran in
series (0.24 / 0.48 / 0.83 / 1.1 s on Windows).

These tests open real sockets, on loopback only: a fake echo server counts how often it is asked and delays every answer, so what is counted is the
requests, not a helper. No fixed ports (port 0), every server is shut down, and the margins are wide on purpose: the point is one delay against four, not a
stopwatch.
"""
from __future__ import annotations

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import urllib3.util.connection as u3conn

from invisible_core import _geo
from invisible_core._geo import GeoTimezoneError, discover_egress_ip

pytestmark = pytest.mark.unit

_REAL_HTTP_GET = getattr(_geo, "_http_get", None)   # before the autouse fixture of conftest.py refuses it

DELAY = 1.0
EXIT = "203.0.113.7"


class _Echo(ThreadingHTTPServer):
    """Answers any GET with `self.reply` after `self.delay` seconds, counting the hits."""

    daemon_threads = True

    def __init__(self, reply=EXIT, delay=DELAY, status=200):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):  # noqa: N802
                with self.lock:
                    self.hits += 1
                    status_now = self.status
                time.sleep(self.delay)
                body = self.reply.encode()
                handler.send_response(status_now)
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

            def log_message(handler, *a):
                pass

        super().__init__(("127.0.0.1", 0), Handler)
        self.lock = threading.Lock()
        self.hits = 0
        self.reply = reply
        self.delay = delay
        self.status = status
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}"

    def stop(self):
        self.shutdown()
        self.server_close()
        self._thread.join(5)


@pytest.fixture
def servers():
    made = []

    def make(**kw):
        server = _Echo(**kw)
        made.append(server)
        return server

    yield make
    for server in made:
        server.stop()


@pytest.fixture
def real_network(monkeypatch):
    """What the conftest took away: the real way to the network, loopback echo endpoints and no proxy of the host in between."""
    monkeypatch.setattr(_geo, "requests", requests)
    if _REAL_HTTP_GET is not None:
        monkeypatch.setattr(_geo, "_http_get", _REAL_HTTP_GET)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")


def _concurrently(calls):
    """Run every callable on its own thread, all released together. Returns (results, errors, seconds)."""
    results, errors = [None] * len(calls), [None] * len(calls)
    gate = threading.Barrier(len(calls))

    def run(i):
        gate.wait()
        try:
            results[i] = calls[i]()
        except BaseException as exc:  # noqa: BLE001 - the test reads it
            errors[i] = exc

    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(calls))]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return results, errors, time.monotonic() - started


def test_four_concurrent_launches_measure_the_egress_once(real_network, servers, monkeypatch):
    echo = servers()
    monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", (echo.url,))

    results, errors, seconds = _concurrently([lambda: discover_egress_ip(None)] * 4)

    assert errors == [None] * 4
    assert results == [EXIT] * 4
    assert echo.hits == 1, "each launch asked the echo itself"
    # One delay when shared, four when queued behind each other (the old lock).
    assert seconds < 2.5 * DELAY, f"the launches waited for each other: {seconds:.2f}s for a {DELAY}s echo"


def test_a_launch_inside_the_interval_makes_no_request_and_one_after_it_does(real_network, servers, monkeypatch):
    echo = servers(delay=0.0)
    monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", (echo.url,))
    now = [1000.0]
    monkeypatch.setattr(_geo, "_egress_clock", lambda: now[0], raising=False)

    assert discover_egress_ip(None) == EXIT
    assert echo.hits == 1

    now[0] += 119.0
    assert discover_egress_ip(None) == EXIT
    assert echo.hits == 1, "a launch inside the interval asked the network"

    echo.reply = "198.51.100.9"
    now[0] += 2.0   # the interval is over
    assert discover_egress_ip(None) == "198.51.100.9"
    assert echo.hits == 2


def test_the_interval_is_the_one_the_wrapper_rechecks_the_exit_on():
    assert _geo._EGRESS_SHARED_FOR_S == 120.0


def test_a_failure_is_not_kept_and_every_waiter_gets_it(real_network, servers, monkeypatch):
    echo = servers(delay=0.5, status=500)
    monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", (echo.url,))

    _, errors, _ = _concurrently([lambda: discover_egress_ip(None)] * 3)

    assert all(isinstance(e, GeoTimezoneError) for e in errors), errors
    assert echo.hits == 1, "each launch repeated the measurement that was failing"
    assert errors[0] is errors[1] is errors[2], "the waiters did not get the error of THEIR measurement"

    echo.status = 200
    echo.delay = 0.0
    assert discover_egress_ip(None) == EXIT   # the failure was not kept
    assert echo.hits == 2


def test_requests_through_two_proxies_do_not_wait_for_each_other(real_network, servers, monkeypatch):
    # A plain-HTTP echo URL through an HTTP proxy is an absolute-URI GET sent to the proxy, so the fake echo server IS the proxy.
    # The endpoint is a name no resolver knows: only the proxy can answer it.
    proxy_a = servers(reply="203.0.113.1", delay=1.5)
    proxy_b = servers(reply="203.0.113.2", delay=1.5)
    monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", ("http://echo.invalid/",))

    results, errors, seconds = _concurrently([
        lambda: discover_egress_ip({"server": f"http://127.0.0.1:{proxy_a.server_address[1]}"}),
        lambda: discover_egress_ip({"server": f"http://127.0.0.1:{proxy_b.server_address[1]}"}),
    ])

    assert errors == [None, None]
    assert sorted(results) == ["203.0.113.1", "203.0.113.2"], "a proxied answer was shared or kept"
    assert (proxy_a.hits, proxy_b.hits) == (1, 1)
    assert seconds < 1.8 * 1.5, f"the proxied requests queued behind each other: {seconds:.2f}s"


def test_a_proxied_answer_is_not_kept_and_does_not_feed_a_direct_launch(real_network, servers, monkeypatch):
    proxy = servers(reply="203.0.113.1", delay=0.0)
    direct = servers(reply="198.51.100.9", delay=0.0)
    via_proxy = {"server": f"http://127.0.0.1:{proxy.server_address[1]}"}

    monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", ("http://echo.invalid/",))
    assert discover_egress_ip(via_proxy) == "203.0.113.1"
    assert discover_egress_ip(via_proxy) == "203.0.113.1"
    assert proxy.hits == 2, "a request through a proxy was answered from what was kept"

    monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", (direct.url,))
    assert discover_egress_ip(None) == "198.51.100.9"   # the proxy's exit is not the host's


def test_no_measurement_writes_urllib3_s_global_family(real_network, servers, monkeypatch):
    """The family is forced on the request's own sockets. A write to urllib3's `allowed_gai_family`, even one that is put back, is
    seen by every other connection of the process while it lasts."""
    echo = servers(delay=0.0)
    monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", (echo.url,))
    module = sys.modules[u3conn.__name__]
    original = u3conn.allowed_gai_family
    writes = []

    class _Spy(type(module)):
        def __setattr__(self, name, value):
            if name == "allowed_gai_family":
                writes.append(value)
            super().__setattr__(name, value)

    module.__class__ = _Spy
    try:
        assert discover_egress_ip(None) == EXIT
        assert echo.hits == 1
        monkeypatch.setattr(_geo, "_egress_kept", None, raising=False)
        # The failing path too: a refused connection, then the IPv6-only probe.
        monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", ("http://127.0.0.1:9/",))
        monkeypatch.setattr(_geo, "_IPV6_ECHO_ENDPOINTS", ("http://[::1]:9/",))
        with pytest.raises(GeoTimezoneError):
            discover_egress_ip(None)
    finally:
        module.__class__ = type(module).__mro__[1]
    assert writes == []
    assert u3conn.allowed_gai_family is original


def test_a_failed_bind_is_not_reported_as_a_dns_failure(real_network, monkeypatch):
    """A name that resolves to both families, IPv4 refused and the IPv6 address last: the bound IPv4 socket cannot even try that address,
    and the last error urllib3 met is a `gaierror` of the bind. It must reach the diagnosis as a connection failure, not as 'this host has
    no working DNS' (and the IPv6-only detection depends on the kind being `connect_failed`)."""
    import socket

    real = socket.getaddrinfo

    def both(host, port, *a, **kw):
        if host == "echo.invalid":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9)),
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 9, 0, 0))]
        return real(host, port, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", both)
    monkeypatch.setattr(_geo, "_IP_ECHO_ENDPOINTS", ("http://echo.invalid:9/",))
    monkeypatch.setattr(_geo, "_IPV6_ECHO_ENDPOINTS", ())
    with pytest.raises(GeoTimezoneError) as err:
        discover_egress_ip(None)
    assert err.value.kind == "connect_failed", err.value
