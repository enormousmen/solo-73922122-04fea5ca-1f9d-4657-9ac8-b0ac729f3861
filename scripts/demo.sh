#!/usr/bin/env bash
# 出站探测 API 演示脚本（compose 环境内或本地裸机均可运行）。
#
# 用法（compose 内，目标为标准 80/443 端口）：
#   ./scripts/demo.sh
# 本地裸机演示（目标监听 8080/8443）：
#   PROBE_BASE=http://127.0.0.1:8001 DNS_CTRL=http://127.0.0.1:8054 \
#     HTTP_PORT=8080 HTTPS_PORT=8443 ./scripts/demo.sh
#
# 前置：docker compose up -d --build 已就绪。
set -euo pipefail

BASE="${PROBE_BASE:-http://127.0.0.1:8000}"
DNS_CTRL="${DNS_CTRL:-http://127.0.0.1:8053}"
# compose 内目标使用标准 80/443；本地裸机可用 HTTP_PORT/HTTPS_PORT 覆盖
HPORT="${HTTP_PORT:+:${HTTP_PORT}}"
SPORT="${HTTPS_PORT:+:${HTTPS_PORT}}"
TARGET_REQ_PORT="${HTTP_PORT:-8080}"

# probe_url "<描述>" "<url>" [method]
probe_url() {
  local desc="$1" url="$2" method="${3:-GET}"
  local body
  body="$(jq -n --arg u "$url" --arg m "$method" '{url:$u, method:$m}')"
  echo
  echo "================================================================"
  echo "▶ ${desc}"
  echo "  POST ${BASE}/api/v1/probe  ${body}"
  curl -sS -X POST "${BASE}/api/v1/probe" \
    -H 'Content-Type: application/json' \
    -d "$body" | jq .
}

switch_profile() {
  local profile="$1"
  echo "--- 切换本地 DNS profile -> ${profile}"
  curl -sS -X POST "${DNS_CTRL}/profiles/switch" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg p "$profile" '{profile:$p}')" | jq -r '.active'
}

echo "### 0. 当前策略"
curl -sS "${BASE}/api/v1/policy" | jq .

# 1) 允许的目标（HTTP + HTTPS，证书按原域名验证）
switch_profile allowed
probe_url "允许的 HTTP 目标" "http://allowed.demo.test${HPORT}/"
probe_url "允许的 HTTPS 目标（受信演示 CA，按原域名校验）" \
  "https://https.allowed.demo.test${SPORT}/secure"

# 2) 禁止目标：被白名单拦截，目标收不到请求
probe_url "禁止网段目标（必须 blocked，且 request_sent=false）" \
  "http://forbidden.demo.test${HPORT}/secret"

# 3) 检查后换址：allowed -> swapped，同名域名换到禁区
switch_profile swapped
probe_url "检查后换址（DNS rebinding）：同名域名解析到禁区，连接前拦截" \
  "http://swapped.demo.test${HPORT}/"

# 4) 混合解析：一次应答含允许+禁止地址，整体拒绝
switch_profile mixed
probe_url "混合 A 记录（允许+禁止地址同时返回）：整体拒绝" \
  "http://multi-a.demo.test${HPORT}/"

# 5) 跳转：正常跳转、跳禁区拦截、非 HTTP 协议、3 次上限
switch_profile allowed
probe_url "正常跳转到允许目标" \
  "http://redirect-ok.demo.test${HPORT}/redirect-allowed"
probe_url "跳转到禁止网段：第二跳拦截，禁区零请求" \
  "http://allowed.demo.test${HPORT}/redirect-forbidden"
probe_url "跳转到非 HTTP(S) 协议：拒绝" \
  "http://allowed.demo.test${HPORT}/redirect-scheme"

switch_profile loop
probe_url "跳转链超过 3 次上限：第 5 跳未连接即拦截" \
  "http://loop1.demo.test${HPORT}/loop/1"
switch_profile allowed

# 6) 仅 IPv4 / 入口校验
probe_url "IPv6 字面量：拒绝" "http://[2001:db8::1]/"
probe_url "非 HTTP(S) scheme：拒绝" "ftp://allowed.demo.test${HPORT}/"
probe_url "URL 携带 userinfo：拒绝" "http://u:p@allowed.demo.test${HPORT}/"

# 7) 按目标并发名额：慢目标不能占满全局名额
#    当前 MAX_CONCURRENCY=2 -> 单目标上限 1：
#      * 慢目标在飞时，同目标第二个请求立即 429；
#      * 其他目标仍可用剩下的 1 格正常探测。
echo
echo "================================================================"
echo "▶ 并发名额：单个慢目标 vs 其他目标（总名额 2，单目标上限 1）"
slow_url="http://allowed.demo.test${HPORT}/slow?seconds=6"
fast_url="http://www.allowed.demo.test${HPORT}/"
echo "  - 后台启动慢探测: POST ${slow_url}"
curl -sS -o /tmp/slow-probe.json -w '    slow 请求 HTTP %{http_code}，耗时 %{time_total}s\n' \
  -X POST "${BASE}/api/v1/probe" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$slow_url" '{url:$u, method:"GET"}')" &
slow_pid=$!

# 等待慢目标确认在飞（用并发快照判断，避免固定 sleep 的竞态）
slow_target="allowed.demo.test:${HTTP_PORT:-80}"
for _ in $(seq 1 100); do
  if curl -sS "${BASE}/api/v1/policy" \
      | jq -e --arg t "$slow_target" \
        '.concurrency.active_targets[$t] >= 1' >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

echo "  - 慢目标在飞时，向同一目标再次探测（预期 429，且立即返回）:"
curl -sS -o /tmp/busy-probe.json -w '    同目标请求 HTTP %{http_code}，耗时 %{time_total}s\n' \
  -X POST "${BASE}/api/v1/probe" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$slow_url" '{url:$u, method:"GET"}')"
jq '{detail: .detail.message, target: .detail.target, hops: .detail.hops}' \
  /tmp/busy-probe.json

echo "  - 同时向另一个目标探测（预期 200，未被慢目标阻塞）:"
curl -sS -o /tmp/fast-probe.json -w '    其他目标请求 HTTP %{http_code}，耗时 %{time_total}s\n' \
  -X POST "${BASE}/api/v1/probe" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$fast_url" '{url:$u, method:"GET"}')"
jq '{outcome, summary, elapsed_ms}' /tmp/fast-probe.json

wait "$slow_pid"
echo "  - 慢探测最终结果:"
jq '{outcome, summary, elapsed_ms}' /tmp/slow-probe.json
echo "  - 当前并发名额快照（完成后应为 0）:"
curl -sS "${BASE}/api/v1/policy" | jq '.concurrency'

echo
echo "### 验证禁止目标从未收到探测请求（应返回空列表）:"
curl -sS "http://127.0.0.1:${TARGET_REQ_PORT}/_requests" \
  | jq '[.[] | select(.host=="forbidden.demo.test")]'

echo
echo "演示完成。交互式文档: ${BASE}/docs"
