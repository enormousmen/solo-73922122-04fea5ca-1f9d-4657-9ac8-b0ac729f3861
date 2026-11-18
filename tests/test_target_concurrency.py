"""并发名额的引擎级交错测试（真实 DNS/TCP，可控慢目标）。

关键交错：
* 单个慢目标占满自己的名额后，第 3 个同目标请求立即被拒（不排队）；
* 慢目标在飞期间，其他目标仍能探测（名额保留）；
* 总名额为 1 时沿用旧行为：任何目标都被全局名额挡住；
* 跳转按新目标重新准入，且准入发生在新目标的 DNS 查询/连接之前；
* 跳转被拒时 429 保留已完成跳的请求/响应记录；
* 取消、超时、TLS 失败都会归还名额，随后可继续探测；
* 大小写/末尾点不同但规范化后相同的目标共享名额。
"""

import asyncio

import pytest

from app.probe.concurrency import TargetBusyError, TargetKey, TargetLimiter


async def _wait_for(predicate, timeout: float = 3.0) -> None:
    """轮询等待条件成立（避免依赖固定 sleep 的脆弱性）。"""
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("等待条件超时")
        await asyncio.sleep(0.01)


def _target(host: str, port: int) -> TargetKey:
    return TargetKey.from_parts(host, port)


class TestPerTargetSlots:
    async def test_slow_target_cannot_take_all_slots(
        self, fake_dns, http_server, make_prober
    ):
        """总名额 2：慢目标最多占 1，另一格始终可供其他目标使用。"""
        fake_dns.set_zones({"slow.test": ["127.0.0.1"], "other.test": ["127.0.0.1"]})
        http_server.route("other.test", "/")
        arrived, release = http_server.gate("slow.test", "/slow")
        http_server.route("slow.test", "/slow")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter, read_timeout=5.0)

        slow_url = f"http://slow.test:{http_server.port}/slow"
        slow_task = asyncio.create_task(prober.probe(slow_url))
        await asyncio.wait_for(arrived.wait(), 3.0)

        # 第 2 个同目标请求：单目标名额已满 -> 立即 429，不排队
        with pytest.raises(TargetBusyError) as busy:
            await prober.probe(slow_url)
        assert "单目标上限" in busy.value.reason
        assert busy.value.target == f"slow.test:{http_server.port}"
        assert busy.value.hops == []  # 入口即被拒，未产生任何跳/流量

        # 慢目标仍在飞，但其他目标可用剩下的名额
        other_hops = await asyncio.wait_for(
            prober.probe(f"http://other.test:{http_server.port}/"), 3.0
        )
        assert other_hops[-1].outcome == "ok"
        assert limiter.snapshot()["in_use"] == 1  # 只剩慢目标

        release.set()
        slow_hops = await asyncio.wait_for(slow_task, 3.0)
        assert slow_hops[-1].outcome == "ok"
        assert limiter.snapshot()["in_use"] == 0  # 完成后名额全部归还

    async def test_busy_check_is_immediate_not_queued(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"q.test": ["127.0.0.1"]})
        arrived, release = http_server.gate("q.test", "/slow")
        http_server.route("q.test", "/slow")
        prober = make_prober(limiter=TargetLimiter(2))

        url = f"http://q.test:{http_server.port}/slow"
        task = asyncio.create_task(prober.probe(url))
        await asyncio.wait_for(arrived.wait(), 3.0)

        loop = asyncio.get_running_loop()
        started = loop.time()
        with pytest.raises(TargetBusyError):
            await prober.probe(url)
        elapsed = loop.time() - started
        assert elapsed < 0.5  # 满额立即拒绝，未排队等待释放

        release.set()
        await asyncio.wait_for(task, 3.0)

    async def test_total_one_keeps_legacy_global_limit(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"one.test": ["127.0.0.1"], "two.test": ["127.0.0.1"]})
        http_server.route("two.test", "/")
        arrived, release = http_server.gate("one.test", "/slow")
        http_server.route("one.test", "/slow")
        prober = make_prober(limiter=TargetLimiter(1))

        task = asyncio.create_task(
            prober.probe(f"http://one.test:{http_server.port}/slow")
        )
        await asyncio.wait_for(arrived.wait(), 3.0)

        # 不同目标也被唯一全局名额挡住 —— 与旧行为一致
        with pytest.raises(TargetBusyError) as busy:
            await prober.probe(f"http://two.test:{http_server.port}/")
        assert "全局" in busy.value.reason

        release.set()
        await asyncio.wait_for(task, 3.0)
        hops = await prober.probe(f"http://two.test:{http_server.port}/")
        assert hops[-1].outcome == "ok"

    async def test_normalized_hostnames_share_slot(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"case.test": ["127.0.0.1"]})
        arrived, release = http_server.gate("case.test", "/slow")
        http_server.route("case.test", "/slow")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter)

        port = http_server.port
        task = asyncio.create_task(
            prober.probe(f"http://CASE.Test:{port}/slow")
        )
        await asyncio.wait_for(arrived.wait(), 3.0)

        # 大小写 / 末尾根点不同，但规范化后是同一目标同一端口
        with pytest.raises(TargetBusyError):
            await prober.probe(f"http://case.test.:{port}/slow")
        release.set()
        await asyncio.wait_for(task, 3.0)
        assert limiter.snapshot()["in_use"] == 0

    async def test_different_ports_are_different_targets(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"port.test": ["127.0.0.1"]})
        arrived, release = http_server.gate("port.test", "/slow")
        http_server.route("port.test", "/slow")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter)

        task = asyncio.create_task(
            prober.probe(f"http://port.test:{http_server.port}/slow")
        )
        await asyncio.wait_for(arrived.wait(), 3.0)
        # 同一主机但另一个（无服务的）端口：目标键不同，不会被同目标上限挡住；
        # 探测本身会因连接失败而 error，但不能是 429。
        other = await prober.probe(f"http://port.test:{http_server.port + 1}/")
        assert other[-1].outcome == "error"
        release.set()
        await asyncio.wait_for(task, 3.0)


class TestRedirectAdmission:
    async def test_redirect_re_admits_new_target(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"r1.test": ["127.0.0.1"], "r2.test": ["127.0.0.1"]})
        http_server.route(
            "r1.test", "/go",
            status=302,
            headers=[("Location", f"http://r2.test:{http_server.port}/done")],
        )
        http_server.route("r2.test", "/done")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter)

        hops = await prober.probe(f"http://r1.test:{http_server.port}/go")

        assert [h.outcome for h in hops] == ["redirected", "ok"]
        # 新目标名额已角色转换：旧目标无残留，新目标完成后也已归还
        assert limiter.snapshot()["in_use"] == 0
        assert limiter.snapshot()["targets"] == {}

    async def test_redirect_rejection_occurs_before_dns_and_connect(
        self, fake_dns, http_server, make_prober
    ):
        """新目标名额已满：必须在解析/连接它之前拒绝，且不占旧目标名额。"""
        fake_dns.set_zones({"start.test": ["127.0.0.1"]})
        http_server.route(
            "start.test", "/go",
            status=302,
            headers=[("Location", "http://busy.test/next")],
        )
        limiter = TargetLimiter(2)
        busy_target = _target("busy.test", 80)
        # 预占 busy.test 的唯一（N-1=1）名额，模拟另一个在飞探测
        assert limiter.acquire(busy_target).granted
        prober = make_prober(limiter=limiter)

        with pytest.raises(TargetBusyError) as busy:
            await prober.probe(f"http://start.test:{http_server.port}/go")

        # busy.test 从未被解析（无 A 查询），也没有任何跳发起连接
        assert "busy.test" not in fake_dns.queried_names
        assert busy.value.target == "busy.test:80"
        assert limiter.snapshot()["targets"] == {"busy.test:80": 1}  # 旧目标已归还

        # 已完成第 1 跳的请求/响应记录被保留，含 302 与 Location
        hops = busy.value.hops
        assert len(hops) == 2
        assert hops[0].hop == 1
        assert hops[0].outcome == "redirected"
        assert hops[0].status_code == 302
        assert hops[0].request_sent is True
        assert hops[0].connected_peer == f"127.0.0.1:{http_server.port}"
        assert hops[0].location == "http://busy.test/next"
        # 被拒的那一跳明确记录，且没有任何流量
        assert hops[1].outcome == "rejected"
        assert hops[1].request_sent is False
        assert hops[1].connected_peer is None
        assert "单目标上限" in (hops[1].reject_reason or "")

        limiter.release(busy_target)

    async def test_redirect_releases_old_slot_for_others(
        self, fake_dns, http_server, make_prober
    ):
        """跳转期间旧目标名额立即归还，其他请求可继续探测旧目标。"""
        fake_dns.set_zones({
            "src.test": ["127.0.0.1"],
            "dst.test": ["127.0.0.1"],
        })
        http_server.route(
            "src.test", "/go",
            status=302,
            headers=[("Location", f"http://dst.test:{http_server.port}/slow")],
        )
        http_server.route("dst.test", "/slow")
        arrived, release = http_server.gate("dst.test", "/slow")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter)

        task = asyncio.create_task(
            prober.probe(f"http://src.test:{http_server.port}/go")
        )
        await asyncio.wait_for(arrived.wait(), 3.0)
        # 此刻在飞的是 dst.test，src.test 名额已归还
        snap = limiter.snapshot()
        assert snap["targets"] == {f"dst.test:{http_server.port}": 1}
        assert limiter.in_use_for(_target("src.test", http_server.port)) == 0

        release.set()
        hops = await asyncio.wait_for(task, 3.0)
        assert hops[-1].outcome == "ok"
        assert limiter.snapshot()["in_use"] == 0


class TestSlotRelease:
    async def test_cancel_releases_slot(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"cancel.test": ["127.0.0.1"]})
        arrived, release = http_server.gate("cancel.test", "/slow")
        http_server.route("cancel.test", "/slow")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter)

        url = f"http://cancel.test:{http_server.port}/slow"
        task = asyncio.create_task(prober.probe(url))
        await asyncio.wait_for(arrived.wait(), 3.0)
        assert limiter.snapshot()["in_use"] == 1

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()
        # 取消后名额立即归还：同目标可再次探测
        await _wait_for(lambda: limiter.snapshot()["in_use"] == 0)

        http_server.route("cancel.test", "/")
        hops = await prober.probe(f"http://cancel.test:{http_server.port}/")
        assert hops[-1].outcome == "ok"
        assert limiter.snapshot()["in_use"] == 0

    async def test_outer_timeout_releases_slot(
        self, fake_dns, http_server, make_prober
    ):
        """模拟 API 层 asyncio.wait_for 超时取消探测：名额归还。"""
        fake_dns.set_zones({"timeout.test": ["127.0.0.1"]})
        arrived, release = http_server.gate("timeout.test", "/slow")
        http_server.route("timeout.test", "/slow")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter, read_timeout=10.0)

        url = f"http://timeout.test:{http_server.port}/slow"
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(prober.probe(url), timeout=0.4)
        release.set()
        assert limiter.snapshot()["in_use"] == 0
        assert limiter.snapshot()["targets"] == {}

    async def test_read_timeout_releases_slot(
        self, fake_dns, http_server, make_prober
    ):
        """跳内读取超时（hop error）同样归还名额。"""
        fake_dns.set_zones({"slowread.test": ["127.0.0.1"]})
        arrived, release = http_server.gate("slowread.test", "/slow")
        http_server.route("slowread.test", "/slow")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter, read_timeout=0.2)

        hops = await prober.probe(
            f"http://slowread.test:{http_server.port}/slow"
        )
        release.set()
        assert hops[-1].outcome == "error"
        assert "超时" in (hops[-1].error or "")
        assert limiter.snapshot()["in_use"] == 0

    async def test_tls_failure_releases_slot(
        self, fake_dns, https_server, make_prober
    ):
        """TLS 校验失败 -> error，但名额已归还，后续探测不受影响。"""
        fake_dns.set_zones({"mismatch.test": ["127.0.0.1"]})
        https_server.route("mismatch.test", "/")
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter)

        hops = await prober.probe(
            f"https://mismatch.test:{https_server.port}/"
        )
        assert hops[-1].outcome == "error"
        assert "证书校验失败" in hops[-1].error
        assert limiter.snapshot()["in_use"] == 0

        # 同一目标（同 host+port）可立即再次探测，而不是被旧名额卡住
        hops2 = await prober.probe(
            f"https://mismatch.test:{https_server.port}/"
        )
        assert hops2[-1].outcome == "error"
        assert limiter.snapshot()["in_use"] == 0

    async def test_blocked_target_releases_slot(
        self, fake_dns, make_prober
    ):
        fake_dns.set_zones({"denied.test": ["8.8.8.8"]})
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter)
        hops = await prober.probe("http://denied.test/")
        assert hops[-1].outcome == "blocked"
        assert limiter.snapshot()["in_use"] == 0

    async def test_invalid_url_does_not_leak_or_consume_slot(
        self, fake_dns, make_prober
    ):
        limiter = TargetLimiter(2)
        prober = make_prober(limiter=limiter)
        hops = await prober.probe("ftp://x.test/")
        assert hops[-1].outcome == "blocked"
        assert limiter.snapshot()["in_use"] == 0
