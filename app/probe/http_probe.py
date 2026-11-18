"""HTTP/HTTPS 出站探测引擎。

安全模型（每一跳都完整执行，跳转目标也不例外）：

  URL 静态校验 → 按目标 host+port 并发准入 → DNS A 记录查询
  → *全部* 解析地址过白名单 → 仅向已批准 IP 建 TCP（运行时不再解析）
  → HTTPS 按原域名校验证书 → 发送一次请求 → 读取响应
  → 若是跳转则归还旧名额、对新目标重新准入，再重复上述流程

因此：
* DNS 在检查后变化、连接重试、HTTP 跳转都不会让请求进入未获准网段；
* 被策略拒绝的目标在任何 socket 建立之前就被拦下，收不到探测请求；
* 每跳最多把已批准的地址各试一次，重试绝不重新解析 DNS；
* 慢目标只能占满自己的名额（N>=2 时为 N-1 格），不会饿死其他目标；
* 跳转目标在准入完成前既不解析也不连接，且不占旧目标名额等待。
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from .concurrency import Admission, TargetBusyError, TargetKey, TargetLimiter
from .connection import TlsInfo, build_ssl_context, open_tcp, start_tls
from .dns_client import DnsError, DnsResolver
from .policy import (
    AddressPolicy,
    PolicyError,
    is_ip_literal,
    parse_target,
)

DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 3
MAX_BYTES = 64 * 1024


@dataclass
class HopReport:
    hop: int
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_addresses: list[str] = field(default_factory=list)
    approved_addresses: list[str] = field(default_factory=list)
    connected_peer: str | None = None
    tls: dict | None = None
    request_sent: bool = False
    status_code: int | None = None
    reason: str | None = None
    location: str | None = None
    redirect_count: int = 0
    outcome: str = "pending"  # ok | redirected | blocked | error
    reject_reason: str | None = None
    error: str | None = None

    def mark_blocked(self, reason: str) -> None:
        self.outcome = "blocked"
        self.reject_reason = reason
        self.reason = reason

    def mark_error(self, message: str) -> None:
        self.outcome = "error"
        self.error = message
        self.reason = message


class Prober:
    def __init__(
        self,
        policy: AddressPolicy,
        resolver: DnsResolver,
        ca_bundle: str | None = None,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        tls_timeout: float = 8.0,
        max_redirects: int = MAX_REDIRECTS,
        max_bytes: int = MAX_BYTES,
        limiter: TargetLimiter | None = None,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._ssl = build_ssl_context(ca_bundle)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._tls_timeout = tls_timeout
        self._max_redirects = max_redirects
        self._max_bytes = max_bytes
        # 独立使用引擎（如测试）时默认不启用准入；API 层始终注入限流器。
        # 单名额限流器的行为即旧版“全局单并发上限”。
        self._limiter = limiter

    def _acquire(self, target: TargetKey):
        if self._limiter is None:
            return Admission(True)
        return self._limiter.acquire(target)

    def _release(self, target: TargetKey | None) -> None:
        if self._limiter is not None and target is not None:
            self._limiter.release(target)

    async def probe(self, url: str, method: str = "GET") -> list[HopReport]:
        """探测入口；并发满额时抛 TargetBusyError（携带已完成跳的记录）。"""
        method = method.upper()
        if method not in ("GET", "HEAD"):
            raise PolicyError("探测仅支持 GET/HEAD 方法")
        hops: list[HopReport] = []
        redirects = 0
        current = url
        # 入口目标先做静态解析，用规范化后的 host+port 申请名额；
        # 这一步不产生任何 DNS 查询或连接。URL 本身非法时不占名额，
        # 交由 _do_hop 记录为 blocked（与原有 API 行为一致）。
        try:
            entry_key: TargetKey | None = self._static_key(url)
        except PolicyError:
            entry_key = None
        if entry_key is not None:
            admission = self._acquire(entry_key)
            if not admission.granted:
                raise TargetBusyError(
                    entry_key,
                    admission.reason or self._busy_reason(entry_key),
                    hops,
                )
        current_key = entry_key
        held = entry_key is not None
        try:
            while True:
                hop_idx = len(hops) + 1
                hop = HopReport(
                    hop=hop_idx, url=current, scheme="", hostname="", port=0
                )
                hops.append(hop)
                next_url = await self._do_hop(hop, current, method)
                if hop.outcome in ("blocked", "error"):
                    return hops
                if next_url is None:
                    hop.outcome = "ok"
                    return hops
                # 发生跳转：为下一跳重新准入。先归还旧目标名额，再尝试
                # 新目标；准入发生在任何 DNS 解析 / socket 连接之前。
                redirects += 1
                hop.redirect_count = redirects
                hop.outcome = "redirected"
                if redirects > self._max_redirects:
                    limit_hop = HopReport(
                        hop=len(hops) + 1,
                        url=next_url,
                        scheme="",
                        hostname="",
                        port=0,
                    )
                    limit_hop.mark_blocked(
                        f"已跟随 {self._max_redirects} 次跳转，达到上限，"
                        f"拒绝继续访问: {next_url}"
                    )
                    hops.append(limit_hop)
                    return hops
                try:
                    next_key = self._static_key(next_url)
                except PolicyError:
                    # 非法跳转目标由下一跳 _do_hop 记录为 blocked，
                    # 这里仍沿用当前名额执行一次（不会产生流量）。
                    current = next_url
                    continue
                if next_key == current_key:
                    # 同一目标：名额已持有，无需重复申请
                    current = next_url
                    continue
                # 跳转目标与当前目标不同：先归还旧目标名额，再按新目标
                # 重新准入。两步都是同步操作（无 await），不会出现与其他
                # 请求交错的窗口；也绝不占着旧目标名额等待新名额。
                self._release(current_key)
                held = False
                admission = self._acquire(next_key)
                if not admission.granted:
                    # 拒收：立即返回 429；已完成跳（含当前跳）的请求/响应
                    # 记录全部保留在 hops 中，被拒跳未产生任何流量。
                    reject_hop = HopReport(
                        hop=len(hops) + 1,
                        url=next_url,
                        scheme="",
                        hostname="",
                        port=0,
                    )
                    reject_hop.outcome = "rejected"
                    reject_hop.reject_reason = (
                        admission.reason or self._busy_reason(next_key)
                    )
                    hops.append(reject_hop)
                    raise TargetBusyError(
                        next_key,
                        admission.reason or self._busy_reason(next_key),
                        hops,
                    )
                held = True
                current_key = next_key
                current = next_url
        finally:
            if held:
                self._release(current_key)

    def _static_key(self, url: str) -> TargetKey:
        """仅做 URL 静态解析，得到并发名额键（无 DNS、无连接）。"""
        scheme, host, port, _user, _raw = parse_target(url)
        return TargetKey.from_parts(host, port or DEFAULT_PORTS[scheme])

    def _busy_reason(self, target: TargetKey) -> str:
        limiter = self._limiter
        per_target = limiter.per_target_limit if limiter else 1
        total = limiter.total_slots if limiter else 1
        return (
            f"目标 {target} 并发名额已满（单目标上限 {per_target}，"
            f"总名额 {total}），请求被立即拒绝（429）"
        )

    async def _do_hop(self, hop: HopReport, url: str, method: str) -> str | None:
        # 1) URL 静态校验（不产生任何网络流量）
        try:
            scheme, host, port, _user, raw = parse_target(url)
        except PolicyError as exc:
            hop.mark_blocked(str(exc))
            return None
        hop.scheme = scheme
        hop.hostname = host
        hop.port = port or DEFAULT_PORTS[scheme]

        # 2) 解析 + 白名单：IP 字面量直接校验；域名只问配置的解析器
        try:
            if is_ip_literal(host):
                resolved = [host]
            else:
                resolved = await self._resolver.resolve_a(host)
            hop.resolved_addresses = list(resolved)
            approved = self._policy.check_resolved(resolved)
            hop.approved_addresses = [str(ip) for ip in approved]
        except (PolicyError, DnsError) as exc:
            hop.mark_blocked(str(exc))
            return None

        # 3) 仅对已批准地址尝试连接，每个地址一次，绝不重新解析
        last_err: str | None = None
        for ip in approved:
            connected = await self._try_one_address(hop, ip, scheme, host, method)
            if connected is not None:
                # 该地址连接成功：清除此前地址尝试留下的错误，避免残留
                hop.error = None
                reader, writer, tls_info = connected
                try:
                    return await self._send_and_read(
                        hop, reader, writer, method, host, hop.port, url
                    )
                except PolicyError as exc:
                    # 响应阶段的策略性错误（如响应头超限、非法状态行）：
                    # 记录为本跳错误，不逃逸到 API 入口
                    hop.mark_error(str(exc))
                    return None
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, ssl.SSLError):
                        pass
            last_err = hop.error or hop.reject_reason
        # 所有已批准地址均连接失败
        hop.mark_error(f"全部已批准地址连接失败（未尝试任何未获准地址）: {last_err}")
        return None

    async def _try_one_address(self, hop, ip: ipaddress.IPv4Address,
                               scheme: str, host: str, method: str):
        try:
            reader, writer, peer = await open_tcp(
                ip, hop.port, self._connect_timeout
            )
            hop.connected_peer = peer
            if scheme == "https":
                reader, writer, tls_info = await start_tls(
                    writer, reader, host, self._ssl, self._tls_timeout
                )
                hop.tls = asdict(tls_info)
            return reader, writer, tls_info if scheme == "https" else None
        except PolicyError as exc:
            # 记录失败原因后继续试下一个 *已批准* 地址
            hop.connected_peer = None
            hop.tls = None
            hop.error = str(exc)
            return None

    async def _send_and_read(
        self, hop: HopReport, reader, writer, method: str,
        host: str, port: int, url: str,
    ) -> str | None:
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        authority = host if (
            (parts.scheme == "http" and port == 80)
            or (parts.scheme == "https" and port == 443)
        ) else f"{host}:{port}"
        request_lines = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: egress-probe/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        try:
            writer.write(request_lines.encode("ascii", errors="replace"))
            await writer.drain()
            hop.request_sent = True
            response = await asyncio.wait_for(
                self._read_response(reader), timeout=self._read_timeout
            )
        except asyncio.TimeoutError as exc:
            hop.mark_error(f"读取响应超时（{self._read_timeout}s）")
            return None
        except OSError as exc:
            hop.mark_error(f"连接读写错误: {exc}")
            return None

        hop.status_code = response["status"]
        hop.reason = response["reason"]
        if response["status"] in REDIRECT_STATUSES:
            location = response["headers"].get("location")
            hop.location = location
            if not location:
                hop.mark_error(f"收到 {response['status']} 跳转但缺少 Location 头")
                return None
            try:
                next_url = normalize_redirect(url, location)
            except PolicyError as exc:
                # 跳转目标违反策略（非 HTTP(S)、userinfo 等）：在建立任何
                # 到目标的连接前拒绝，标记为 blocked 并保留已收到的 Location
                hop.mark_blocked(str(exc))
                return None
            return next_url
        return None

    async def _read_response(self, reader) -> dict:
        # 逐字节读到头部结束（慢服务器一次只发几个字节也能正确处理）；
        # body 在 Connection: close 下读到对端关闭即可，
        # 但为保护自身只读取上限字节，超出即截断。
        header_blob = b""
        while b"\r\n\r\n" not in header_blob:
            chunk = await reader.read(1)
            if not chunk:
                break
            header_blob += chunk
            if len(header_blob) > self._max_bytes:
                raise PolicyError("响应头部超过大小上限")
        text = header_blob.decode("iso-8859-1")
        lines = text.split("\r\n")
        status_line = lines[0]
        if not status_line.startswith("HTTP/"):
            raise PolicyError(f"非法 HTTP 响应行: {status_line[:80]!r}")
        try:
            _proto, rest = status_line.split(" ", 1)
            status_text, reason = rest.split(" ", 1) if " " in rest else (rest, "")
            status = int(status_text)
        except (IndexError, ValueError) as exc:
            raise PolicyError(f"无法解析状态行: {status_line[:80]!r}") from exc
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        body_read = 0
        while body_read < self._max_bytes:
            chunk = await reader.read(4096)
            if not chunk:
                break
            body_read += len(chunk)
        return {"status": status, "reason": reason, "headers": headers}


def normalize_redirect(base_url: str, location: str) -> str:
    """规范化跳转目标，并限制 scheme 为 http/https（相对 Location 也支持）。"""
    location = location.strip()
    if len(location) > 2048:
        raise PolicyError("跳转 Location 过长")
    if location.startswith("//"):
        # 协议相对 URL：继承当前 scheme
        location = urlsplit(base_url).scheme + ":" + location
    next_url = urljoin(base_url, location)
    scheme = urlsplit(next_url).scheme.lower()
    if scheme not in ("http", "https"):
        raise PolicyError(
            f"跳转到非 HTTP(S) 协议 {scheme!r}，拒绝: {next_url}"
        )
    if urlsplit(next_url).username is not None:
        raise PolicyError("跳转目标 URL 禁止携带 userinfo")
    return next_url
