"""并发准入单元测试：规范化键、两级名额、跳转换名额、归还语义。"""

import pytest

from app.probe.concurrency import (
    TargetBusyError,
    TargetKey,
    TargetLimiter,
    normalize_hostname,
)


class TestNormalizeHostname:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("Example.COM", "example.com"),
            ("example.com.", "example.com"),
            ("example.com...", "example.com"),
            ("  Allowed.Demo.Test  ", "allowed.demo.test"),
            ("127.0.0.1", "127.0.0.1"),
            ("::1", "::1"),
        ],
    )
    def test_normalization(self, raw, expected):
        assert normalize_hostname(raw) == expected

    def test_case_and_trailing_dot_share_one_key(self):
        assert TargetKey.from_parts("Example.COM.", 80) == TargetKey.from_parts(
            "example.com", 80
        )

    def test_port_is_part_of_key(self):
        assert TargetKey.from_parts("a.test", 80) != TargetKey.from_parts("a.test", 8080)

    def test_scheme_default_port_is_caller_choice(self):
        # 规范化层只看 host+port；默认端口由调用方按 scheme 补齐
        key = TargetKey.from_parts("a.test", 443)
        assert str(key) == "a.test:443"


class TestTargetLimiter:
    def test_total_two_allows_one_per_target(self):
        limiter = TargetLimiter(2)
        assert limiter.per_target_limit == 1
        a = TargetKey.from_parts("a.test", 80)
        b = TargetKey.from_parts("b.test", 80)
        assert limiter.acquire(a).granted
        second = limiter.acquire(a)
        assert not second.granted
        assert "单目标上限" in second.reason
        # 另一个目标仍可用剩下的一格
        assert limiter.acquire(b).granted
        assert not limiter.acquire(b).granted

    def test_total_four_reserves_a_slot_per_target(self):
        limiter = TargetLimiter(4)
        assert limiter.per_target_limit == 3
        a = TargetKey.from_parts("a.test", 80)
        b = TargetKey.from_parts("b.test", 80)
        assert [limiter.acquire(a).granted for _ in range(3)] == [True] * 3
        assert not limiter.acquire(a).granted
        assert limiter.acquire(b).granted  # 第 4 格始终留给其他目标

    def test_total_slots_one_keeps_legacy_behavior(self):
        limiter = TargetLimiter(1)
        assert limiter.per_target_limit == 1
        a = TargetKey.from_parts("a.test", 80)
        b = TargetKey.from_parts("b.test", 80)
        assert limiter.acquire(a).granted
        busy_b = limiter.acquire(b)
        assert not busy_b.granted
        assert "全局" in busy_b.reason  # 只有一个全局名额，沿用旧行为
        limiter.release(a)
        assert limiter.acquire(b).granted

    def test_global_limit_still_applies(self):
        limiter = TargetLimiter(3)
        keys = [TargetKey.from_parts(f"t{i}.test", 80) for i in range(3)]
        assert all(limiter.acquire(k).granted for k in keys)
        # 每个目标 1 个、共 3 个目标 -> 全局 3 格已满
        assert not limiter.acquire(TargetKey.from_parts("t9.test", 80)).granted

    def test_release_is_balanced_and_idempotent(self):
        limiter = TargetLimiter(2)
        a = TargetKey.from_parts("a.test", 80)
        limiter.acquire(a)
        limiter.release(a)
        limiter.release(a)  # 重复归还安全
        assert limiter.snapshot()["in_use"] == 0
        assert limiter.snapshot()["targets"] == {}
        assert limiter.acquire(a).granted

    def test_redirect_hands_slot_to_new_target(self):
        limiter = TargetLimiter(2)
        old = TargetKey.from_parts("old.test", 80)
        new = TargetKey.from_parts("new.test", 80)
        assert limiter.acquire(old).granted
        limiter.release(old)  # 跳转：先归还旧目标
        assert limiter.acquire(new).granted
        assert limiter.snapshot()["targets"] == {"new.test:80": 1}

    def test_invalid_total(self):
        with pytest.raises(ValueError):
            TargetLimiter(0)

    def test_busy_error_carries_hops(self):
        hops = [{"hop": 1, "status_code": 302}]
        exc = TargetBusyError(TargetKey.from_parts("x.test", 80), "busy", hops)
        assert exc.hops == hops
        assert exc.target == "x.test:80"
        assert str(exc) == "busy"
