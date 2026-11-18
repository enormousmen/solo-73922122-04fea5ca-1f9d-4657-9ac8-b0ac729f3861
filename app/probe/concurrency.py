"""按“规范化主机名 + 端口”分配的探测并发准入。

设计目标：
* 全局总名额 ``N``（``MAX_CONCURRENCY``）限制整机在飞探测数量；
* ``N >= 2`` 时单个目标最多占用 ``N - 1`` 个名额，至少留 1 个名额给
  其他目标，避免某个慢目标把全局名额全部占满；
* ``N == 1`` 时沿用原行为：只有一个全局名额，不额外限制单目标，任何目标
  都可能占满该名额；
* 准入失败立即返回（``acquire`` 是同步、无等待的），不排队、不阻塞事件循环。

所有方法都在单个事件循环内调用；``acquire``/``release`` 内部没有任何
``await``，因此“检查 + 计数”是原子的，也不会在取消/超时清理阶段被再次
取消。跳转时调用方必须先 ``release`` 旧目标，再 ``acquire`` 新目标。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


def normalize_hostname(hostname: str) -> str:
    """规范化用于并发名额计算的主机名（不做 DNS 解析）。

    * 去除首尾空白与末尾根点；
    * 统一小写（DNS 主机名大小写不敏感）；
    * 非 ASCII 域名按 IDNA 转成 ASCII；
    * IP 字面量用 ``ipaddress`` 的规范文本表示（如压缩 IPv6）。
    """
    host = hostname.strip().lower()
    while host.endswith("."):
        host = host[:-1]
    if any(ord(ch) > 127 for ch in host):
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


@dataclass(frozen=True)
class TargetKey:
    """一个并发名额键：规范化主机名 + 实际连接端口。"""

    hostname: str
    port: int

    @classmethod
    def from_parts(cls, hostname: str, port: int) -> "TargetKey":
        return cls(normalize_hostname(hostname), port)

    def __str__(self) -> str:
        return f"{self.hostname}:{self.port}"


@dataclass(frozen=True)
class Admission:
    """一次准入结果；``granted`` 为 False 时 ``reason`` 说明 429 原因。"""

    granted: bool
    reason: str | None = None


class TargetBusyError(Exception):
    """目标或全局并发名额已满，调用方应立即返回 HTTP 429。

    ``hops`` 保留此前已完成跳的完整请求/响应记录（含被拒跳的记录），
    便于调用方在 429 响应体中返回部分结果。
    """

    def __init__(self, target: TargetKey, reason: str, hops: list) -> None:
        super().__init__(reason)
        self.target = str(target)
        self.reason = reason
        self.hops = list(hops)


class TargetLimiter:
    """全局 + 按目标的两级并发名额。

    ``per_target_limit``：N == 1 时为 1（仅受全局名额约束）；N >= 2 时为
    N - 1，保证单个目标无法占满所有名额。
    """

    def __init__(self, total_slots: int) -> None:
        if total_slots < 1:
            raise ValueError("总并发名额必须 >= 1")
        self.total_slots = total_slots
        self.per_target_limit = (
            1 if total_slots == 1 else total_slots - 1
        )
        self._in_use = 0
        self._by_target: dict[TargetKey, int] = {}

    def acquire(self, target: TargetKey) -> Admission:
        """尝试占用一个名额；不等待，满额立即失败。"""
        used_by_target = self._by_target.get(target, 0)
        # N == 1 时不设单目标上限，只看唯一的全局名额（沿用旧行为）
        if self.total_slots > 1 and used_by_target >= self.per_target_limit:
            return Admission(
                False,
                f"目标 {target} 的并发名额已满（单目标上限 "
                f"{self.per_target_limit}，总名额 {self.total_slots}，"
                "其余名额保留给其他目标），请求被立即拒绝（429）",
            )
        if self._in_use >= self.total_slots:
            return Admission(
                False,
                f"全局探测并发名额已满（{self.total_slots}），"
                "请求被立即拒绝（429）",
            )
        self._in_use += 1
        self._by_target[target] = used_by_target + 1
        return Admission(True)

    def release(self, target: TargetKey) -> None:
        """归还名额；重复归还是安全的（不会把计数降为负数）。"""
        used_by_target = self._by_target.get(target, 0)
        if used_by_target <= 0:
            return
        if used_by_target == 1:
            self._by_target.pop(target, None)
        else:
            self._by_target[target] = used_by_target - 1
        if self._in_use > 0:
            self._in_use -= 1

    def in_use_for(self, target: TargetKey) -> int:
        return self._by_target.get(target, 0)

    def snapshot(self) -> dict:
        """当前在飞名额快照（用于观测与测试）。"""
        return {
            "total_slots": self.total_slots,
            "per_target_limit": self.per_target_limit,
            "in_use": self._in_use,
            "targets": {
                str(target): count for target, count in self._by_target.items()
            },
        }
