"""FastAPI 接口层测试。

TestClient 会在独立线程的独立事件循环中运行应用，因此所有本地假服务
（DNS/UDP、HTTP/TCP）都通过应用的 lifespan 钩子在 *同一* 循环内创建。
"""

from __future__ import annotations

import asyncio
import importlib
import os
import threading
import time
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from app.probe import dns_wire
from app.probe.concurrency import TargetKey


class InLoopDns:
    def __init__(self) -> None:
        self.zones: dict[str, list[str]] = {}
        self.queried_names: list[str] = []
        self._transport = None

    def connection_made(self, transport):  # noqa: ANN001
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        msg = dns_wire.parse_message(data, require_qr=False)
        q = msg.questions[0]
        self.queried_names.append(q.qname.lower())
        if q.qname.lower() in self.zones:
            reply = dns_wire.build_response(msg.qid, q, answers=self.zones[q.qname.lower()])
        else:
            reply = dns_wire.build_response(
                msg.qid, q, rcode=dns_wire.RCODE_NAME_ERROR
            )
        self._transport.sendto(reply, addr)


class InLoopHttp:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], tuple[int, dict, str]] = {}
        self.requests: list[dict] = []
        self._server = None
        self.port = 0
        self._gates: dict[tuple[str, str], tuple[asyncio.Event, asyncio.Event]] = {}
        self._delays: dict[tuple[str, str], float] = {}

    def gate(self, host, path):  # noqa: ANN001
        arrived = asyncio.Event()
        release = asyncio.Event()
        self._gates[(host.lower(), path)] = (arrived, release)
        return arrived, release

    def delay(self, host, path, seconds):  # noqa: ANN001
        self._delays[(host.lower(), path)] = seconds

    def route(self, host, path, status=200, headers=None, body="ok"):  # noqa: ANN001
        self.routes[(host.lower(), path)] = (status, headers or {}, body)

    async def _handle(self, reader, writer):  # noqa: ANN001
        try:
            line = await reader.readline()
            if not line:
                return
            method, path, _ = line.decode().split(" ", 2)
            headers = {}
            while True:
                h = await reader.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                k, v = h.decode().split(":", 1)
                headers[k.strip().lower()] = v.strip()
            host = headers.get("host", "").split(":")[0].lower()
            self.requests.append({"method": method, "host": host, "path": path})
            status, extra, body = self.routes.get((host, path), (404, {}, "nf"))
            delay = self._delays.get((host, path))
            if delay:
                await asyncio.sleep(delay)
            gate = self._gates.get((host, path))
            if gate is not None:
                arrived, release = gate
                arrived.set()
                await release.wait()
            head = [
                f"HTTP/1.1 {status} X\r\n",
                f"Content-Length: {len(body)}\r\n",
                "Connection: close\r\n",
            ]
            for k, v in extra.items():
                head.append(f"{k}: {v}\r\n")
            head.append("\r\n")
            head.append(body)
            writer.write("".join(head).encode())
            await writer.drain()
        except (ConnectionError, ValueError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()


@pytest.fixture()
def client(monkeypatch, demo_certs):
    _cert, _key, cafile = demo_certs
    dns = InLoopDns()
    httpd = InLoopHttp()

    import app.probe.main as main_mod

    @asynccontextmanager
    async def test_lifespan(app):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: dns, local_addr=("127.0.0.1", 0)
        )
        dns._transport = transport
        dns_port = transport.get_extra_info("socket").getsockname()[1]
        await httpd.start()

        monkeypatch.setenv("ALLOWED_CIDRS", "127.0.0.1/32")
        monkeypatch.setenv("DNS_SERVER", "127.0.0.1")
        monkeypatch.setenv("DNS_PORT", str(dns_port))
        monkeypatch.setenv("DNS_RETRIES", "0")
        monkeypatch.setenv("DNS_TIMEOUT", "2.0")
        monkeypatch.setenv("CA_BUNDLE", str(cafile))
        monkeypatch.setenv("CONNECT_TIMEOUT", "3.0")
        monkeypatch.setenv("READ_TIMEOUT", "5.0")
        monkeypatch.setenv("TLS_TIMEOUT", "5.0")
        monkeypatch.setenv("PROBE_OVERALL_TIMEOUT", "15.0")
        monkeypatch.setenv("MAX_CONCURRENCY", "2")

        import app.probe.config as config_mod
        import app.probe.dns_client as dns_client_mod

        importlib.reload(config_mod)
        importlib.reload(dns_client_mod)
        importlib.reload(main_mod)
        main_mod.app.router.lifespan_context = test_lifespan
        try:
            yield
        finally:
            transport.close()
            await httpd.stop()

    main_mod.app.router.lifespan_context = test_lifespan
    dns.zones = {"api-good.test": ["127.0.0.1"]}
    httpd.route("api-good.test", "/")
    with TestClient(main_mod.app) as c:
        c._dns = dns
        c._http = httpd
        yield c


def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"


def test_policy_endpoint(client):
    body = client.get("/api/v1/policy").json()
    assert body["allowed_cidrs"] == ["127.0.0.1/32"]
    assert body["ip_versions"] == ["IPv4"]
    assert body["max_redirects"] == 3
    assert body["tls_verify"] is True
    assert body["concurrency"]["total_slots"] == 2
    assert body["concurrency"]["per_target_slots"] == 1
    assert body["concurrency"]["in_use"] == 0


def test_probe_ok(client):
    port = client._http.port
    r = client.post("/api/v1/probe", json={"url": f"http://api-good.test:{port}/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "ok"
    assert body["hops"][0]["connected_peer"] == f"127.0.0.1:{port}"
    assert body["hops"][0]["resolved_addresses"] == ["127.0.0.1"]
    assert client._http.requests[-1]["host"] == "api-good.test"


def test_probe_blocked_reports_reason(client):
    client._dns.zones = {"api-bad.test": ["8.8.8.8"]}
    r = client.post("/api/v1/probe", json={"url": "http://api-bad.test/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "blocked"
    assert "白名单" in body["summary"]
    assert body["hops"][-1]["request_sent"] is False
    assert all(req["host"] != "api-bad.test" for req in client._http.requests)


def test_probe_blocked_returns_structured_hop(client):
    client._dns.zones = {"api-mix.test": ["127.0.0.1", "9.9.9.9"]}
    body = client.post(
        "/api/v1/probe", json={"url": "http://api-mix.test/"}
    ).json()
    assert body["outcome"] == "blocked"
    hop = body["hops"][-1]
    assert hop["resolved_addresses"] == ["127.0.0.1", "9.9.9.9"]
    assert hop["approved_addresses"] == []
    assert hop["connected_peer"] is None


def test_probe_invalid_scheme_reported(client):
    # 非法 scheme 在跳内被静态拦截，返回结构化 blocked（不产生流量）
    r = client.post("/api/v1/probe", json={"url": "ftp://api-good.test/"})
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "blocked"
    assert body["hops"][-1]["request_sent"] is False


def test_probe_bad_method_422(client):
    r = client.post(
        "/api/v1/probe",
        json={"url": "http://api-good.test/", "method": "POST"},
    )
    assert r.status_code == 422


def test_openapi_docs_available(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


def test_target_slot_exhausted_returns_429_immediately(client):
    """总名额 2（单目标 1）：慢目标在飞时同目标第 2 个请求立即 429。"""
    port = client._http.port
    client._dns.zones = {"api-slow.test": ["127.0.0.1"]}
    client._http.delay("api-slow.test", "/slow", 1.0)
    client._http.route("api-slow.test", "/slow")
    url = f"http://api-slow.test:{port}/slow"

    results: dict[str, object] = {}

    def slow_request():
        results["slow"] = client.post("/api/v1/probe", json={"url": url})

    worker = threading.Thread(target=slow_request)
    worker.start()
    try:
        deadline = time.monotonic() + 3
        while not any(
            r["host"] == "api-slow.test" for r in client._http.requests
        ):
            assert time.monotonic() < deadline, "慢请求未进入目标"
            time.sleep(0.01)
        started = time.monotonic()
        busy = client.post("/api/v1/probe", json={"url": url})
        elapsed = time.monotonic() - started
        assert busy.status_code == 429
        assert elapsed < 0.5
        detail = busy.json()["detail"]
        assert detail["target"] == f"api-slow.test:{port}"
        assert detail["hops"] == []  # 入口即拒，无任何流量
        assert detail["concurrency"]["per_target_slots"] == 1
    finally:
        worker.join(timeout=5)
    assert results["slow"].status_code == 200


def test_redirect_rejection_429_keeps_completed_hops(client):
    """跳转目标名额已满：429 中保留第 1 跳的请求/响应，第 2 跳零流量。"""
    port = client._http.port
    client._dns.zones = {"api-start.test": ["127.0.0.1"]}
    client._http.route(
        "api-start.test", "/go",
        status=302, headers={"Location": "http://api-busy.test/next"},
    )
    # 预占 api-busy.test 的唯一单目标名额（模拟另一个在飞探测）
    import app.probe.main as main_mod

    limiter = main_mod.probe_slots
    busy_target = TargetKey.from_parts("api-busy.test", 80)
    assert limiter.acquire(busy_target).granted
    try:
        r = client.post(
            "/api/v1/probe",
            json={"url": f"http://api-start.test:{port}/go"},
        )
    finally:
        limiter.release(busy_target)

    assert r.status_code == 429
    detail = r.json()["detail"]
    assert detail["target"] == "api-busy.test:80"
    hops = detail["hops"]
    assert [h["outcome"] for h in hops] == ["redirected", "rejected"]
    assert hops[0]["status_code"] == 302
    assert hops[0]["request_sent"] is True
    assert hops[0]["location"] == "http://api-busy.test/next"
    assert hops[1]["request_sent"] is False
    assert hops[1]["connected_peer"] is None
    # 被拒跳从未被解析或连接
    assert "api-busy.test" not in client._dns.queried_names
    assert limiter.snapshot()["in_use"] == 0


def test_slow_target_does_not_block_other_target(client):
    """慢目标占满自身名额，但总名额 2 仍留 1 格给其他目标。"""
    port = client._http.port
    client._dns.zones = {
        "api-slow2.test": ["127.0.0.1"],
        "api-fast.test": ["127.0.0.1"],
    }
    client._http.delay("api-slow2.test", "/slow", 1.0)
    client._http.route("api-slow2.test", "/slow")
    client._http.route("api-fast.test", "/")

    results: dict[str, object] = {}

    def slow_request():
        results["slow"] = client.post(
            "/api/v1/probe",
            json={"url": f"http://api-slow2.test:{port}/slow"},
        )

    worker = threading.Thread(target=slow_request)
    worker.start()
    try:
        deadline = time.monotonic() + 3
        while not any(
            r["host"] == "api-slow2.test" for r in client._http.requests
        ):
            assert time.monotonic() < deadline, "慢请求未进入目标"
            time.sleep(0.01)
        fast = client.post(
            "/api/v1/probe",
            json={"url": f"http://api-fast.test:{port}/"},
        )
        assert fast.status_code == 200
        assert fast.json()["outcome"] == "ok"
    finally:
        worker.join(timeout=5)
    assert results["slow"].status_code == 200


def test_slot_released_after_completion(client):
    """探测完成后名额归还，同目标可继续探测（不会一直被 429）。"""
    port = client._http.port
    client._dns.zones = {"api-repeat.test": ["127.0.0.1"]}
    client._http.route("api-repeat.test", "/")
    for _ in range(3):
        r = client.post(
            "/api/v1/probe", json={"url": f"http://api-repeat.test:{port}/"}
        )
        assert r.status_code == 200
    assert client.get("/api/v1/policy").json()["concurrency"]["in_use"] == 0
