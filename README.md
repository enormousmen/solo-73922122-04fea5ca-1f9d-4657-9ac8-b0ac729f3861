# 出站探测 API（Egress Probe）

运维人员在启用外部回调（webhook）前，需要确认回调地址**可达**且**不会访问禁区**。
本服务提供一个 FastAPI 出站探测接口：提交 HTTP/HTTPS URL，返回**逐跳状态、DNS 解析
地址、实际连接地址与拒绝原因**，用于调整出口白名单。

## 安全模型（核心保证）

每一跳都完整执行下列流程，跳转目标也不例外：

```
URL 静态校验（不产生流量）
   └─ 并发准入：按“规范化主机名 + 端口”申请名额（满额立即 429）
        └─ DNS A 记录查询（只问配置的解析器，绝不用系统 getaddrinfo）
             └─ 全部解析地址逐个过 IPv4 CIDR 白名单
                  └─ 全部获准才连接；任一地址在禁区 → 整体拒绝（不返回部分结果）
                       └─ 仅向“检查时已批准的 IP”建 TCP，运行时不再解析 DNS
                            └─ HTTPS 用原域名做 SNI 并验证证书（不可关闭校验）
                                 └─ 发送一次请求、读取响应
                                      └─ 3xx 跳转：归还旧名额 → 对新目标重新准入
                                         （准入前不解析/不连接）→ 重复整套流程（最多 3 次）
```

由此满足：

| 要求 | 实现方式 |
| --- | --- |
| 仅支持 IPv4 | IPv6 字面量、IPv6 CIDR、AAAA 均拒绝；策略层只接受 `IPv4Address` |
| 启动时配置允许的 CIDR | 环境变量 `ALLOWED_CIDRS`（逗号分隔），非法配置直接拒绝启动 |
| 每跳全部解析地址均获准才连接 | `AddressPolicy.check_resolved` 对完整 A 记录列表做“全或无”判定 |
| 最多跟随 3 次跳转 | `MAX_REDIRECTS=3`（硬上限，启动配置仅允许 0..3） |
| DNS 检查后变化不能进入禁区 | 连接目标固定为校验通过的 IP 字面量，连接阶段不触发任何 DNS |
| 连接重试不能进入禁区 | 重试只在**已批准**的地址集合内逐个尝试，绝不重新解析 |
| 跳转不能进入禁区 | 每个跳转目标重新走“解析→全量校验→连接”，被拒即停 |
| 被拒目标收不到探测请求 | 拒绝发生在任何 socket 创建之前；集成测试与目标访问日志双向验证 |
| HTTPS 按原域名验证证书 | `check_hostname=True`、`CERT_REQUIRED`，SNI/校验均用原域名，无关闭开关 |
| 慢探测不阻塞其他请求 | 全异步 + 单事件循环；按目标分配并发名额，满额立即返回 429；单请求总超时 |
| 单个慢目标不能占满全局名额 | 总名额 `N>=2` 时单目标最多占 `N-1`，剩余名额始终留给其他目标 |
| 跳转不占旧名额等待、不预解析 | 跳转时先归还旧目标名额，按新目标 host+port 重新准入；准入成功前不解析、不连接下一跳 |

## 目录结构

```
app/
  probe/            探测服务
    policy.py       IPv4 CIDR 白名单与 URL 静态校验（所有连接决策的唯一入口）
    dns_wire.py     自研 DNS 线协议（RFC1035 子集，查询/应答/压缩指针防护）
    dns_client.py   异步 DNS 客户端（仅向配置的解析器发 A 查询）
    connection.py   固定到已批准 IP 的 TCP 连接 + 强制校验的 TLS
    http_probe.py   逐跳 HTTP/1.1 探测引擎、跳转规范化与上限
    config.py       环境变量配置（启动时校验）
    concurrency.py  按目标（规范化主机名+端口）分配的并发准入
    main.py         FastAPI 应用（/api/v1/probe、/docs）
  dns_service/      本地可切换解析的 DNS（UDP/53 + HTTP 控制面 profile 热切换）
  targets/          演示目标（HTTP/8080、HTTPS/8443，含各类跳转、/slow 慢目标与访问记录）
  certinit/         生成演示 CA、服务器证书、合并 CA bundle
dns-profiles/       DNS 场景：allowed / swapped / mixed / loop
compose.yaml        一键启动的完整演示环境
tests/              测试（策略、DNS 协议、TLS、跳转、并发名额、API 全链路）
scripts/demo.sh     演示脚本（含慢目标并发名额演示）
```

## 快速开始

```bash
docker compose up -d --build
# 探测 API（仅绑定本机回环）
open http://127.0.0.1:8000/docs
```

演示环境网络拓扑（全部 IPv4，静态地址）：

| 网络 | 网段 | 用途 |
| --- | --- | --- |
| `net_dns` | 172.31.0.0/24 | 本地 DNS（172.31.0.53），探测服务唯一使用的解析器 |
| `net_allowed` | 172.31.10.0/24 | 允许目标（172.31.10.10）——**白名单唯一放行的网段** |
| `net_denied` | 172.31.20.0/24 | 禁止目标（172.31.20.10） |

目标服务同时监听标准端口 `80/443`（供跳转 URL 直接使用）与演示端口
`8080/8443`，HTTP 与 HTTPS 行为一致；可用环境变量
`TARGET_HTTP_PORTS` / `TARGET_HTTPS_PORTS` 覆盖监听端口。

> probe 容器**同时接入** `net_denied`（路由层可达），但白名单不含该网段。
> 这证明拦截来自应用层白名单策略，而不是网络隔离。

### 一键演示

```bash
./scripts/demo.sh
```

## API

### `POST /api/v1/probe`

请求体：

```json
{ "url": "https://example.com/path", "method": "GET" }
```

响应（关键字段）：

```json
{
  "outcome": "blocked",
  "summary": "第 1 跳被策略拒绝: 解析结果包含未获准网段的地址: 172.31.20.10；...",
  "allowed_cidrs": ["172.31.10.0/24"],
  "dns_server": "172.31.0.53:53",
  "max_redirects": 3,
  "hops": [
    {
      "hop": 1,
      "url": "http://forbidden.demo.test/secret",
      "hostname": "forbidden.demo.test",
      "resolved_addresses": ["172.31.20.10"],
      "approved_addresses": [],
      "connected_peer": null,
      "request_sent": false,
      "outcome": "blocked",
      "reject_reason": "解析结果包含未获准网段的地址: 172.31.20.10；..."
    }
  ]
}
```

每跳字段含义：

- `resolved_addresses`：DNS 实际返回的全部 A 记录；
- `approved_addresses`：通过白名单的地址（被整体拒绝时为空）；
- `connected_peer`：**实际**建立 TCP 连接的 `ip:port`（固定为已批准 IP）；
- `tls`：TLS 版本、套件、证书 subject/SAN（HTTPS 时）；
- `request_sent`：是否真的发出了 HTTP 请求（被策略拒绝时恒为 `false`）；
- `outcome`：`ok` / `redirected` / `blocked` / `error`（429 响应中的被拒跳为 `rejected`）；
- `reject_reason` / `error`：拒绝或失败的具体原因。

辅助接口：`GET /api/v1/policy`（当前白名单、超时与并发名额快照）、`GET /healthz`。

### 按目标并发名额

全局总名额由 `MAX_CONCURRENCY`（记为 `N`）控制，名额键为
**规范化主机名 + 实际连接端口**（主机名统一小写、去掉末尾根点、非 ASCII
按 IDNA 转 ASCII；IP 字面量用规范文本）。端口取 URL 中显式端口，缺省时按
scheme 补 80/443；因此 `http://A.test/` 与 `http://a.test.:80/` 共用名额，
而同一主机的不同端口互不影响。

| 总名额 N | 单目标上限 | 行为 |
| --- | --- | --- |
| `N = 1` | 1（不额外限制） | 沿用原行为：唯一全局名额，任何目标都能占满，其他请求 429 |
| `N >= 2` | `N - 1` | 单目标最多占 `N-1`，至少保留 1 格给其他目标 |

满额判定是**同步、立即**的：不排队、不等待释放，直接返回 `429`。探测结束
（成功、被策略拒绝、连接/TLS 失败、读取超时）或被取消（含总超时 408）时
都会归还名额。

**跳转的准入顺序**（每一跳）：

1. 收到 3xx 并规范化 Location；
2. **先归还旧目标名额**（绝不在等待新名额时占用旧目标名额）；
3. 按新目标 host+port 重新申请名额；
4. 申请成功后才解析域名、建立连接；
5. 申请失败 → 立即 429，不解析、不连接新目标。

跳转被拒的 429 响应保留之前已完成跳的完整请求/响应记录，并追加一条
`outcome=rejected` 的被拒跳（`request_sent=false`、`connected_peer=null`）：

```json
{
  "detail": {
    "message": "目标 busy.test:80 的并发名额已满（单目标上限 1，总名额 2，...）",
    "target": "busy.test:80",
    "concurrency": {"total_slots": 2, "per_target_slots": 1, "in_use": 1,
                    "active_targets": {"busy.test:80": 1}},
    "hops": [
      {"hop": 1, "url": "http://start.test/go", "status_code": 302,
       "outcome": "redirected", "request_sent": true,
       "connected_peer": "172.31.10.10:80", "location": "http://busy.test/next"},
      {"hop": 2, "url": "http://busy.test/next", "outcome": "rejected",
       "request_sent": false, "connected_peer": null,
       "reject_reason": "目标 busy.test:80 的并发名额已满..."}
    ]
  }
}
```

入口目标满额时 `hops` 为空列表（尚未产生任何流量）。

## 演示场景与 DNS profile 切换

本地 DNS 的解析数据按 profile 组织，可热切换：

```bash
# 查看当前 profile 与全部解析数据
curl http://127.0.0.1:8053/profiles
# 切换
curl -X POST http://127.0.0.1:8053/profiles/switch \
  -H 'Content-Type: application/json' -d '{"profile":"swapped"}'
```

| profile | 演示点 |
| --- | --- |
| `allowed` | 正常解析到允许网段 |
| `swapped` | 同名域名从允许地址换到禁止地址（**检查后换址 / DNS rebinding**） |
| `mixed` | 一次应答同时含允许与禁止地址，验证“全部获准才连接” |
| `loop` | 连环 307 跳转，验证 3 次跳转上限 |

慢目标演示（`compose.yaml` 默认 `MAX_CONCURRENCY=2`，单目标上限 1）：

- `http://allowed.demo.test/slow?seconds=6`：自身会挂起 6 秒；
- 在飞期间再次探测同一 host:port → **429 立即返回**（`detail.hops` 为空）；
- 同时探测 `http://www.allowed.demo.test/` → **200 正常返回**（剩下 1 格）；
- `scripts/demo.sh` 第 7 段自动演示这一交错并打印 `/api/v1/policy` 的
  并发快照。

把 `MAX_CONCURRENCY` 调大的等价关系：`N=4` 时单目标最多 3 格，第 4 格
始终留给其他目标；`N=1` 时恢复为旧的单一全局名额行为。

## 配置项（探测服务环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ALLOWED_CIDRS` | （必填） | 逗号分隔的 IPv4 CIDR 白名单 |
| `DNS_SERVER` / `DNS_PORT` | 127.0.0.1 / 53 | 唯一允许使用的解析器（IP 字面量） |
| `DNS_TIMEOUT` / `DNS_RETRIES` | 3.0 / 1 | DNS 单次超时与重试次数 |
| `CA_BUNDLE` | 系统信任库 | 信任 CA 文件（演示环境为系统 CA + 演示 CA 合并） |
| `CONNECT_TIMEOUT` / `TLS_TIMEOUT` / `READ_TIMEOUT` | 5 / 8 / 10 秒 | 各阶段超时 |
| `MAX_REDIRECTS` | 3 | 跳转上限，仅允许 0..3 |
| `MAX_CONCURRENCY` | 64 | 全局在飞探测名额，超出立即返回 429；`>=2` 时单目标最多占 `N-1` |
| `PROBE_OVERALL_TIMEOUT` | 30 | 单请求总超时，超时返回 408 |

> `compose.yaml` 中演示用 `MAX_CONCURRENCY=2`（单目标上限 1），便于直观
> 观察“慢目标 + 其他目标”的交错；代码默认值为 64。

## 测试

```bash
pip install -r requirements.txt pytest pytest-asyncio httpx
pytest -q
```

96 个测试覆盖：CIDR/URL 策略、DNS 编解码与压缩指针环路、全链路探测、
混合解析整体拒绝、检查后换址、跳转上限/跳禁区/非 HTTP 协议、HTTPS 证书
主机名校验与不受信证书拒绝、慢探测并发非阻塞、API 层，以及并发名额：
规范化键合并、`N=1` 旧行为、`N>=2` 单目标上限与保留名额、跳转重新准入
（准入前不解析/不连接）、跳转被拒 429 保留已完成跳记录、取消/超时/
TLS 失败/策略拒绝后的名额归还。

## 设计边界与说明

- 探测只实现 GET/HEAD、HTTP/1.1，读取响应体有 64KB 上限，仅用于连通性判断；
- 不跟随 cookie、不发送请求体、不执行任何页面脚本；
- DNS 仅做 A 记录查询（AAAA 不存在即天然 IPv4-only）；
- 演示 CA 与证书仅用于本地/compose 演示，生产环境应使用真实 PKI 并通过
  `CA_BUNDLE` 指定信任根。
