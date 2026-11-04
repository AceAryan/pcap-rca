#!/usr/bin/env bash
# Generate labelled fault-injection captures in isolated network namespaces.
#
#   client 10.10.1.2 ---- 10.10.1.1 router 10.10.2.1 ---- 10.10.2.2 server
#   (c-eth0)              (r-eth0)        (r-eth1)        (s-eth0)
#
# Each scenario builds a fresh topology, captures on the client's interface
# (the usual troubleshooting vantage point), and writes <scenario>.pcap plus
# <scenario>.json with the ground truth (see docs/event_types.md for the
# event IDs). The host's real interfaces are never touched.
#
# Requires: Linux or WSL2, root, iproute2, iptables, tcpdump, python3, dig
# Optional: ethtool (turns off segmentation offload so the capture shows
#           wire-sized packets), tc netem (loss / delay / reorder scenarios)
#
# Each label also lists which flows carry the fault ("flow_labels", every
# other flow is NORMAL) and the scenario's parameters ("params"), so the
# captures double as a labelled training set (pcap_rca.dataset).
#
# Usage:  sudo data/scripts/capture_faults.sh [--list] [scenario ...]
#             canonical set, fixed parameters -> data/synthetic/
#         sudo data/scripts/capture_faults.sh --runs N [--seed S] [--start-run K] [scenario ...]
#             N runs per scenario with random parameters (loss %, delay, MTU,
#             attempt counts...) -> data/synthetic_runs/<scenario>__rNNN.*
#             (--start-run K numbers them from K, to add runs to an existing set)
#         OUT=/some/dir sudo -E data/scripts/capture_faults.sh ...
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUT_GIVEN=false
[[ -n ${OUT:-} ]] && OUT_GIVEN=true
OUT=${OUT:-$(cd "$HERE/.." && pwd)/synthetic}

CLI=rca-cli RTR=rca-rtr SRV=rca-srv
C_IP=10.10.1.2 R1_IP=10.10.1.1 R2_IP=10.10.2.1 S_IP=10.10.2.2

SCENARIOS=(
  baseline
  tcp_loss tcp_reorder tcp_high_latency
  tcp_syn_timeout tcp_conn_refused tcp_rst_midstream tcp_zero_window
  tcp_pmtu_ok tcp_pmtu_blackhole
  icmp_port_unreachable icmp_admin_prohibited icmp_host_unreachable
  icmp_net_unreachable icmp_routing_loop icmp_traceroute
  dns_nxdomain dns_servfail dns_refused dns_timeout dns_slow
  dns_tcp_fallback dns_nodata dns_resolver_down
  http_errors tls_bad_cert tls_no_server_hello auth_bruteforce
)
NETEM_SCENARIOS=" tcp_loss tcp_reorder tcp_high_latency "
# netem's default queue holds 1000 packets: with tens of ms of delay at veth
# speed it overflows and tail-drops bursts, adding loss nobody asked for
# (seen as 156-segment gaps in a reorder run). Make it effectively unbounded.
NETEM_LIMIT=1000000
TLS_SCENARIOS=" tls_bad_cert tls_no_server_hello "

# --------------------------------------------------------------------------
# Topology
# --------------------------------------------------------------------------

in_cli() { ip netns exec "$CLI" "$@"; }
in_rtr() { ip netns exec "$RTR" "$@"; }
in_srv() { ip netns exec "$SRV" "$@"; }

helper_cli() { in_cli python3 "$HERE/fault_helpers.py" "$@"; }
# Servers run in the background; teardown kills everything in the namespace.
helper_srv() { in_srv python3 "$HERE/fault_helpers.py" "$@" >/dev/null 2>&1 & }

teardown() {
  local ns
  for ns in "$CLI" "$RTR" "$SRV"; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
  done
}

setup() {
  teardown
  local ns
  for ns in "$CLI" "$RTR" "$SRV"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    # Deterministic ICMP: no per-destination rate limiting, no redirects.
    ip netns exec "$ns" sysctl -qw net.ipv4.icmp_ratelimit=0
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.send_redirects=0
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.send_redirects=0
  done
  ip link add c-eth0 netns "$CLI" type veth peer name r-eth0 netns "$RTR"
  ip link add r-eth1 netns "$RTR" type veth peer name s-eth0 netns "$SRV"
  ip -n "$CLI" addr add "$C_IP/24" dev c-eth0
  ip -n "$RTR" addr add "$R1_IP/24" dev r-eth0
  ip -n "$RTR" addr add "$R2_IP/24" dev r-eth1
  ip -n "$SRV" addr add "$S_IP/24" dev s-eth0

  local pair
  for pair in "$CLI c-eth0" "$RTR r-eth0" "$RTR r-eth1" "$SRV s-eth0"; do
    set -- $pair
    ip -n "$1" link set "$2" up
    ip netns exec "$1" sysctl -qw "net.ipv4.conf.$2.send_redirects=0"
    if $HAVE_ETHTOOL; then
      ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1 || true
    fi
  done

  ip -n "$CLI" route add default via "$R1_IP"
  ip -n "$SRV" route add default via "$R2_IP"
  in_rtr sysctl -qw net.ipv4.ip_forward=1
  # Keep Linux from silently working around PMTU problems.
  in_cli sysctl -qw net.ipv4.tcp_mtu_probing=0
}

start_capture() {
  CAP_NAME=$SC
  # Capture to Linux-native storage with a 64 MB buffer: writing straight to
  # a slow mount (e.g. /mnt/d under WSL) makes the kernel drop packets during
  # bursts, which would corrupt the ground truth.
  # --immediate-mode: otherwise libpcap holds packets in partly filled
  # TPACKET_V3 blocks, and whatever is still held when tcpdump is stopped
  # is silently lost.
  # Not via in_cli: $! must be tcpdump itself (ip netns exec execs it), not a
  # wrapper subshell, so the kill below reaches it.
  ip netns exec "$CLI" tcpdump -i c-eth0 -s 0 -B 65536 --immediate-mode -U -Z root \
    -w "$CAP_TMP/$SC.pcap" 2>"$CAP_TMP/$SC.log" &
  CAP_PID=$!
  sleep 1
}

stop_capture() {
  sleep 1
  # End-of-capture marker: one ICMP echo to the router, so the capture's last
  # timestamp is "when we stopped", not "when the last fault packet was seen".
  helper_cli echo "$R1_IP"
  sleep 0.2
  # TERM, not INT: background jobs of a non-interactive shell ignore SIGINT.
  kill -TERM "$CAP_PID" 2>/dev/null || true
  wait "$CAP_PID" 2>/dev/null || true
  local dropped
  dropped=$(sed -n 's/^\([0-9]*\) packets\{0,1\} dropped by kernel.*/\1/p' "$CAP_TMP/$CAP_NAME.log")
  if [[ ${dropped:-0} -ne 0 ]]; then
    echo "ERROR: tcpdump dropped $dropped packets in $CAP_NAME; capture is incomplete" >&2
    exit 1
  fi
  mv -f "$CAP_TMP/$CAP_NAME.pcap" "$OUT/$CAP_NAME.pcap"
}

# --------------------------------------------------------------------------
# Parameters and labels
# --------------------------------------------------------------------------

# pick VAR first [others...]: the canonical run uses the first value; with
# --runs, a random one. (No $(...) subshell: subshells would replay the same
# $RANDOM sequence.) Every pick is recorded in the label's "params".
pick() {
  local var=$1; shift
  local value=$1
  if $RANDOMIZE; then
    local values=("$@")
    value=${values[RANDOM % ${#values[@]}]}
  fi
  printf -v "$var" '%s' "$value"
  PARAMS+="${PARAMS:+, }\"${var,,}\": \"$value\""
}

# flows <json list>: which flows carry the fault, e.g.
#   flows '[{"match": {"proto": "tcp", "server_port": 9000}, "label": "FIREWALL_DROP"}]'
# Matching keys: proto (tcp/udp/icmp), server_ip, server_port, server_ports [lo, hi].
# Every other flow is NORMAL.
flows() { FLOW_LABELS=$1; }

# label <root_cause|null> <expected-json> <may_also-json> <notes>
#   expected: events the detectors must report; an integer is an exact count,
#             null means "at least one".
#   may_also: events that are legitimate side effects of the fault.
# Anything else reported for this capture counts as a false positive.
label() {
  local rc=$1
  [[ $rc != null ]] && rc="\"$rc\""
  cat > "$OUT/$SC.json" <<EOF
{
  "scenario": "$SC_BASE",
  "pcap": "$SC.pcap",
  "vantage": "client",
  "client": "$C_IP",
  "server": "$S_IP",
  "root_cause": $rc,
  "expected": $2,
  "may_also": $3,
  "params": {${PARAMS}},
  "flow_labels": ${FLOW_LABELS},
  "default_label": "NORMAL",
  "notes": "$4"
}
EOF
}

q() { in_cli dig "@${RESOLVER:-$S_IP}" +tries=1 +timeout=3 "$@" >/dev/null 2>&1 || true; }

# Flow label for "this service on the server".
svc() { echo "[{\"match\": {\"proto\": \"$1\", \"server_port\": $2}, \"label\": \"$3\"}]"; }
DNS_FLOWS() {
  echo "[{\"match\": {\"server_ip\": \"${2:-$S_IP}\", \"server_port\": 53}, \"label\": \"$1\"}]"
}

# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

sc_baseline() {
  pick LOOKUPS 3 1 2 4 5
  pick FETCHES 3 1 2 4
  pick SIZE 2000000 500000 1000000 3000000
  helper_srv http-server "$S_IP" 8080
  helper_srv dns-server "$S_IP"
  sleep 1
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do q "ok$n.test"; done
  helper_cli fetch "http://$S_IP:8080/bytes/$SIZE" --count "$FETCHES"
  stop_capture
  flows '[]'
  label null '{}' '[]' "Clean DNS lookups and HTTP downloads. Any fault event is a false positive."
}

sc_tcp_loss() {
  pick LOSS_PCT 3 1 2 4 5 8
  pick FETCHES 3 2 4
  pick SIZE 5000000 2000000 3000000
  helper_srv http-server "$S_IP" 8080
  in_rtr tc qdisc add dev r-eth0 root netem limit "$NETEM_LIMIT" loss "$LOSS_PCT%"
  sleep 1
  start_capture
  helper_cli fetch "http://$S_IP:8080/bytes/$SIZE" --count "$FETCHES"
  stop_capture
  flows "$(svc tcp 8080 PATH_LOSS)"
  label PATH_LOSS \
    '{"TCP_RETRANSMISSION": null, "TCP_DUP_ACK": null, "TCP_LOST_SEGMENT": null}' \
    '["TCP_OUT_OF_ORDER", "TCP_ZERO_WINDOW"]' \
    "$LOSS_PCT% random loss on the router->client link, upstream of the capture point. Data held behind a hole can briefly fill the client's receive buffer (a short zero window)."
}

sc_tcp_reorder() {
  pick REORDER_PCT 25 10 15 35
  pick DELAY_MS 20 10 30
  helper_srv http-server "$S_IP" 8080
  in_rtr tc qdisc add dev r-eth0 root netem limit "$NETEM_LIMIT" delay "${DELAY_MS}ms" reorder "$REORDER_PCT%" 50%
  sleep 1
  start_capture
  helper_cli fetch "http://$S_IP:8080/bytes/5000000" --count 2
  stop_capture
  flows "$(svc tcp 8080 PACKET_REORDERING)"
  label PACKET_REORDERING \
    '{"TCP_OUT_OF_ORDER": null}' \
    '["TCP_DUP_ACK", "TCP_RETRANSMISSION", "TCP_LOST_SEGMENT", "TCP_ZERO_WINDOW"]' \
    "$REORDER_PCT% of packets skip a $DELAY_MS ms delay on the router->client link. No loss. Data held behind a hole can briefly fill the client's receive buffer (a short zero window)."
}

sc_tcp_high_latency() {
  pick DELAY_MS 400 350 500 700
  pick FETCHES 3 2 4
  helper_srv http-server "$S_IP" 8080
  in_rtr tc qdisc add dev r-eth0 root netem limit "$NETEM_LIMIT" delay "${DELAY_MS}ms"
  sleep 1
  start_capture
  helper_cli fetch "http://$S_IP:8080/bytes/20000" --count "$FETCHES"
  stop_capture
  flows "$(svc tcp 8080 HIGH_LATENCY_PATH)"
  label HIGH_LATENCY_PATH \
    '{"TCP_HIGH_RTT": null}' '[]' \
    "$DELAY_MS ms added on the router->client link. Usually one HIGH_RTT per connection, but at high delays the router's ARP request is delayed too, the first SYN is resent, and Karn's rule (correctly) takes no RTT sample from that handshake."
}

sc_tcp_syn_timeout() {
  pick ATTEMPTS 3 1 2 4
  helper_srv http-server "$S_IP" 8080
  in_srv iptables -A INPUT -p tcp --dport 9000 -j DROP
  sleep 1
  start_capture
  helper_cli fetch "http://$S_IP:8080/bytes/1000"
  helper_cli connect "$S_IP" 9000 --count "$ATTEMPTS" --timeout 4
  stop_capture
  flows "$(svc tcp 9000 FIREWALL_DROP)"
  label FIREWALL_DROP \
    "{\"TCP_SYN_TIMEOUT\": $ATTEMPTS}" '[]' \
    "Server silently drops port 9000. One fetch to port 8080 shows the host itself is up."
}

sc_tcp_conn_refused() {
  pick ATTEMPTS 3 1 2 5
  sleep 0.5
  start_capture
  helper_cli connect "$S_IP" 9001 --count "$ATTEMPTS"
  stop_capture
  flows "$(svc tcp 9001 SERVICE_DOWN)"
  label SERVICE_DOWN \
    "{\"TCP_CONN_REFUSED\": $ATTEMPTS}" '[]' \
    "Nothing listening on port 9001; the kernel answers SYN with RST/ACK."
}

sc_tcp_rst_midstream() {
  pick FETCHES 2 3 4
  helper_srv rst-server "$S_IP" 9002
  sleep 1
  start_capture
  helper_cli fetch "http://$S_IP:9002/" --count "$FETCHES"
  stop_capture
  flows "$(svc tcp 9002 ABRUPT_TERMINATION)"
  label ABRUPT_TERMINATION \
    "{\"TCP_RST_MIDSTREAM\": $FETCHES}" '[]' \
    "Server sends 20 KB of a 1 MB response, then aborts with RST."
}

sc_tcp_zero_window() {
  pick SLOW_S 4 2 3 5
  pick RCVBUF 4096 2048
  helper_srv http-server "$S_IP" 8080
  sleep 1
  start_capture
  helper_cli slow-fetch "$S_IP" 8080 /bytes/2000000 --rcvbuf "$RCVBUF" --slow-seconds "$SLOW_S"
  stop_capture
  flows "$(svc tcp 8080 RECEIVER_BOTTLENECK)"
  label RECEIVER_BOTTLENECK \
    '{"TCP_ZERO_WINDOW": null}' '["TCP_RETRANSMISSION"]' \
    "Client reads 512 B every 50 ms with a $RCVBUF-byte receive buffer for $SLOW_S s, then drains. The client advertises the zero window; zero-window probes are part of the event, not retransmissions. The starved receiver occasionally discards an in-window segment, which the server then genuinely retransmits."
}

# The router's server-facing link has a smaller MTU while both hosts use
# 1500, so the server still advertises MSS 1460 and the client's full-size
# uploads don't fit. (The server only sends small ACKs towards the router.)
pmtu_setup() {
  pick MTU 1200 1000 1280 1400
  helper_srv sink-server "$S_IP" 9100
  ip -n "$RTR" link set r-eth1 mtu "$MTU"
}

sc_tcp_pmtu_ok() {
  pmtu_setup
  pick SIZE 500000 200000 1000000
  sleep 1
  start_capture
  helper_cli upload "$S_IP" 9100 "$SIZE"
  stop_capture
  flows "$(svc tcp 9100 MTU_MISMATCH)"
  label MTU_MISMATCH \
    '{"ICMP_FRAG_NEEDED": null}' '["TCP_RETRANSMISSION"]' \
    "$MTU-byte MTU hop; the router sends ICMP fragmentation-needed and the upload recovers."
}

sc_tcp_pmtu_blackhole() {
  pmtu_setup
  in_rtr iptables -A OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP
  sleep 1
  start_capture
  helper_cli upload "$S_IP" 9100 500000 --timeout 8
  stop_capture
  flows "$(svc tcp 9100 PMTU_BLACKHOLE)"
  label PMTU_BLACKHOLE \
    '{"TCP_RETRANSMISSION": null}' '[]' \
    "Same $MTU-byte hop, but the router's ICMP is filtered: handshake succeeds, full-size segments are retransmitted with backoff and never ACKed, and no ICMP_FRAG_NEEDED is visible."
}

sc_icmp_port_unreachable() {
  pick DATAGRAMS 3 1 2 5
  sleep 0.5
  start_capture
  helper_cli udp-send "$S_IP" 9999 --count "$DATAGRAMS"
  stop_capture
  flows "$(svc udp 9999 SERVICE_DOWN)"
  label SERVICE_DOWN \
    "{\"ICMP_PORT_UNREACHABLE\": $DATAGRAMS}" '[]' \
    "UDP datagrams to a closed port on the server."
}

sc_icmp_admin_prohibited() {
  pick ATTEMPTS 3 1 2 4
  in_rtr iptables -A FORWARD -p tcp --dport 9003 -j REJECT --reject-with icmp-admin-prohibited
  sleep 0.5
  start_capture
  helper_cli connect "$S_IP" 9003 --count "$ATTEMPTS" --timeout 2
  stop_capture
  flows "$(svc tcp 9003 ADMIN_BLOCK)"
  label ADMIN_BLOCK \
    "{\"ICMP_ADMIN_PROHIBITED\": $ATTEMPTS}" '[]' \
    "Router firewall rejects TCP/9003 with ICMP 3/13. The ICMP source (10.10.1.1) identifies the blocking device."
}

sc_icmp_host_unreachable() {
  pick ATTEMPTS 2 1 3
  sleep 0.5
  start_capture
  helper_cli connect 10.10.2.99 80 --count "$ATTEMPTS" --timeout 5
  stop_capture
  flows '[{"match": {"server_ip": "10.10.2.99"}, "label": "HOST_UNREACHABLE"}]'
  label HOST_UNREACHABLE \
    '{"ICMP_HOST_UNREACHABLE": null}' '[]' \
    "10.10.2.99 is on the router's connected subnet but doesn't exist; ARP fails and the router returns ICMP 3/1 after about 3 s. SYN retransmissions before that belong to the failed handshake."
}

sc_icmp_net_unreachable() {
  pick ATTEMPTS 2 1 3
  sleep 0.5
  start_capture
  helper_cli connect 10.10.9.9 80 --count "$ATTEMPTS" --timeout 3
  stop_capture
  flows '[{"match": {"server_ip": "10.10.9.9"}, "label": "NO_ROUTE"}]'
  label NO_ROUTE \
    '{"ICMP_NET_UNREACHABLE": null}' '[]' \
    "The router has no route for 10.10.9.0/24 (and no default route)."
}

sc_icmp_routing_loop() {
  pick PROBES 3 1 2 5
  # Router sends 10.10.4.0/24 to the server, whose default route points back.
  in_srv sysctl -qw net.ipv4.ip_forward=1
  ip -n "$RTR" route add 10.10.4.0/24 via "$S_IP"
  sleep 0.5
  start_capture
  helper_cli udp-send 10.10.4.4 5000 --count "$PROBES"
  stop_capture
  flows '[{"match": {"server_ip": "10.10.4.4"}, "label": "ROUTING_LOOP"}]'
  label ROUTING_LOOP \
    "{\"ICMP_TTL_EXCEEDED\": $PROBES}" '[]' \
    "Packets to 10.10.4.4 bounce router<->server until TTL 64 runs out. Probes left with a normal TTL, which separates this from traceroute."
}

sc_icmp_traceroute() {
  pick PROBES 3 1 2
  sleep 0.5
  start_capture
  helper_cli udp-send "$S_IP" 33434 --count "$PROBES" --ttl 1 --port-step 1
  helper_cli udp-send "$S_IP" 33440 --count "$PROBES" --ttl 2 --port-step 1
  stop_capture
  flows '[]'
  label null \
    "{\"ICMP_TTL_EXCEEDED\": $PROBES, \"ICMP_PORT_UNREACHABLE\": $PROBES}" '[]' \
    "Traceroute-style probes (TTL 1 then 2, high UDP ports). The events are real, but no root-cause rule should fire."
}

dns_setup() {
  helper_srv dns-server "$S_IP"
  sleep 1
}

sc_dns_nxdomain() {
  pick LOOKUPS 5 2 3 8
  dns_setup
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do q "nx$n.test"; done
  stop_capture
  flows "$(DNS_FLOWS NAME_NOT_FOUND)"
  label NAME_NOT_FOUND "{\"DNS_NXDOMAIN\": $LOOKUPS}" '[]' "Lookups of names that don't exist."
}

sc_dns_servfail() {
  pick LOOKUPS 3 1 2 5
  dns_setup
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do q "servfail$n.test"; done
  stop_capture
  flows "$(DNS_FLOWS RESOLVER_FAILURE)"
  label RESOLVER_FAILURE "{\"DNS_SERVFAIL\": $LOOKUPS}" '[]' "Resolver answers SERVFAIL."
}

sc_dns_refused() {
  pick LOOKUPS 3 1 2 5
  dns_setup
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do q "refused$n.test"; done
  stop_capture
  flows "$(DNS_FLOWS RESOLVER_REFUSED)"
  label RESOLVER_REFUSED "{\"DNS_REFUSED\": $LOOKUPS}" '[]' "Resolver answers REFUSED."
}

sc_dns_timeout() {
  pick LOOKUPS 2 1 3
  pick TRIES 3 2 4
  dns_setup
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do
    in_cli dig "@$S_IP" +tries="$TRIES" +timeout=1 "drop$n.test" >/dev/null 2>&1 || true
  done
  sleep 2
  stop_capture
  flows "$(DNS_FLOWS RESOLVER_FAILURE)"
  label RESOLVER_FAILURE \
    "{\"DNS_TIMEOUT\": $LOOKUPS, \"DNS_RETRANSMISSION\": $((LOOKUPS * (TRIES - 1)))}" '[]' \
    "$LOOKUPS names, $TRIES tries each, never answered: one transaction per name, the extra tries are retransmissions."
}

sc_dns_slow() {
  pick LOOKUPS 3 2 4
  dns_setup
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do q "slow$n.test"; done
  stop_capture
  flows "$(DNS_FLOWS SLOW_RESOLVER)"
  label SLOW_RESOLVER "{\"DNS_SLOW_RESPONSE\": $LOOKUPS}" '[]' "Every answer arrives 1.5 s after the query."
}

sc_dns_tcp_fallback() {
  pick LOOKUPS 2 1 3
  dns_setup
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do q "big$n.test"; done
  stop_capture
  flows '[]'
  label null "{\"DNS_TCP_FALLBACK\": $LOOKUPS}" '[]' \
    "UDP answers are truncated (TC=1); dig retries over TCP and succeeds. Normal behaviour, so no root cause."
}

sc_dns_nodata() {
  pick LOOKUPS 3 1 2 4
  dns_setup
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do q "nodata$n.test"; done
  stop_capture
  flows '[]'
  label null "{\"DNS_NODATA\": $LOOKUPS}" '[]' "NOERROR with an empty answer section. Informational."
}

sc_dns_resolver_down() {
  pick LOOKUPS 2 1 3
  sleep 0.5
  start_capture
  for ((n = 1; n <= LOOKUPS; n++)); do RESOLVER=10.10.2.53 q "ok$n.test"; done
  stop_capture
  flows "$(DNS_FLOWS RESOLVER_UNREACHABLE 10.10.2.53)"
  label RESOLVER_UNREACHABLE \
    '{"DNS_TIMEOUT": null, "ICMP_HOST_UNREACHABLE": null}' '["DNS_RETRANSMISSION"]' \
    "Configured resolver 10.10.2.53 doesn't exist; the router returns host-unreachable for the queries."
}

sc_http_errors() {
  pick CODES "500 503 502" "500 502" "503 504 500 502"
  local codes=($CODES)
  helper_srv http-server "$S_IP" 8080
  sleep 1
  start_capture
  for code in "${codes[@]}"; do helper_cli fetch "http://$S_IP:8080/status/$code"; done
  stop_capture
  flows "$(svc tcp 8080 APP_ERRORS)"
  label APP_ERRORS "{\"HTTP_ERROR_RESPONSE\": ${#codes[@]}}" '[]' \
    "Plain-HTTP server errors: $CODES."
}

sc_auth_bruteforce() {
  pick CONNECTIONS 5 4 8
  pick PER_CONNECTION 3 2 4
  pick CRACKED no yes
  local last_correct=() failures=$((CONNECTIONS * PER_CONNECTION))
  if [[ $CRACKED == yes ]]; then last_correct=(--last-correct); failures=$((failures - 1)); fi
  helper_srv login-server "$S_IP" 21
  sleep 1
  start_capture
  helper_cli guess-logins "$S_IP" 21 --connections "$CONNECTIONS" \
    --per-connection "$PER_CONNECTION" "${last_correct[@]}"
  stop_capture
  flows "$(svc tcp 21 BRUTE_FORCE)"
  label BRUTE_FORCE "{\"AUTH_FAILURE\": $failures}" '[]' \
    "Password guessing against a clear-text FTP-style login: $CONNECTIONS connections, $PER_CONNECTION guesses each; last guess correct: $CRACKED."
}

sc_tls_bad_cert() {
  pick ATTEMPTS 2 1 3
  # Self-signed certificate: the verifying client aborts with a fatal alert.
  # TLS 1.2 is forced because TLS 1.3 would encrypt that alert.
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=pcap-rca.test" \
    -keyout "$CAP_TMP/tls.key" -out "$CAP_TMP/tls.crt" >/dev/null 2>&1
  helper_srv tls-server "$S_IP" 8443 "$CAP_TMP/tls.crt" "$CAP_TMP/tls.key"
  sleep 1
  start_capture
  helper_cli tls-connect "$S_IP" 8443 --count "$ATTEMPTS"
  stop_capture
  flows "$(svc tcp 8443 TLS_FAILURE)"
  label TLS_FAILURE "{\"TLS_HANDSHAKE_FAILURE\": $ATTEMPTS}" '["TCP_RST_MIDSTREAM"]' \
    "Server presents a self-signed certificate over TLS 1.2; the client rejects it with a clear-text fatal alert (unknown_ca), then aborts the connection with RST."
}

sc_tls_no_server_hello() {
  pick ATTEMPTS 2 1 3
  # Something listens on the port but never speaks TLS.
  helper_srv sink-server "$S_IP" 8443
  sleep 1
  start_capture
  helper_cli tls-connect "$S_IP" 8443 --count "$ATTEMPTS" --timeout 2
  stop_capture
  flows "$(svc tcp 8443 TLS_FAILURE)"
  label TLS_FAILURE "{\"TLS_HANDSHAKE_FAILURE\": $ATTEMPTS}" '[]' \
    "TCP connects but the ClientHello is never answered; the client gives up after 2 s."
}

# --------------------------------------------------------------------------

preflight() {
  [[ $(id -u) -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
  local cmd missing=()
  for cmd in ip iptables tcpdump python3 dig; do
    command -v "$cmd" >/dev/null || missing+=("$cmd")
  done
  if ((${#missing[@]})); then
    echo "Missing: ${missing[*]}" >&2
    echo "Debian/Ubuntu: apt install iproute2 iptables tcpdump python3 dnsutils ethtool" >&2
    exit 1
  fi

  HAVE_ETHTOOL=false
  command -v ethtool >/dev/null && HAVE_ETHTOOL=true
  $HAVE_ETHTOOL || echo "warning: ethtool not found; captures may contain oversized GSO packets" >&2

  HAVE_NETEM=false
  ip netns add rca-probe
  ip netns exec rca-probe tc qdisc add dev lo root netem delay 1ms >/dev/null 2>&1 && HAVE_NETEM=true
  ip netns del rca-probe
  $HAVE_NETEM || echo "warning: tc netem unavailable (modprobe sch_netem?); skipping:$NETEM_SCENARIOS" >&2

  HAVE_OPENSSL=false
  command -v openssl >/dev/null && HAVE_OPENSSL=true
  $HAVE_OPENSSL || echo "warning: openssl not found; skipping:$TLS_SCENARIOS" >&2
}

main() {
  # Run everything on one CPU. A veth transmit is processed on the sending
  # CPU's backlog, so a sender that migrates between CPUs mid-burst gets its
  # packets reordered, adding out-of-order events the scenario never asked for
  # (seen in the baseline). Children inherit the affinity.
  if [[ -z ${RCA_PINNED:-} ]] && command -v taskset >/dev/null; then
    RCA_PINNED=1 exec taskset -c 0 "$0" "$@"
  fi
  local runs=0 seed="" first_run=1 selected=()
  while (($#)); do
    case $1 in
      --list) printf '%s\n' "${SCENARIOS[@]}"; exit 0 ;;
      --runs) runs=$2; shift 2 ;;
      --seed) seed=$2; shift 2 ;;
      --start-run) first_run=$2; shift 2 ;;
      *) selected+=("$1"); shift ;;
    esac
  done
  ((${#selected[@]})) || selected=("${SCENARIOS[@]}")

  RANDOMIZE=false
  if ((runs > 0)); then
    RANDOMIZE=true
    $OUT_GIVEN || OUT=$(cd "$HERE/.." && pwd)/synthetic_runs
    [[ -n $seed ]] && RANDOM=$seed
  fi

  local name
  for name in "${selected[@]}"; do
    declare -F "sc_$name" >/dev/null || { echo "Unknown scenario: $name (try --list)" >&2; exit 1; }
  done

  preflight
  mkdir -p "$OUT"
  CAP_TMP=$(mktemp -d)
  trap 'teardown; rm -rf "$CAP_TMP"' EXIT

  local run
  local last_run=$((runs > 0 ? first_run + runs - 1 : 1))
  for ((run = (runs > 0 ? first_run : 1); run <= last_run; run++)); do
    for name in "${selected[@]}"; do
      if [[ $NETEM_SCENARIOS == *" $name "* ]] && ! $HAVE_NETEM; then
        echo "--- $name (skipped: no netem)"
        continue
      fi
      if [[ $TLS_SCENARIOS == *" $name "* ]] && ! $HAVE_OPENSSL; then
        echo "--- $name (skipped: no openssl)"
        continue
      fi
      SC_BASE=$name SC=$name PARAMS="" FLOW_LABELS='[]'
      ((runs > 0)) && printf -v SC '%s__r%03d' "$name" "$run"
      echo "--- $SC"
      setup
      "sc_$name"
      teardown
    done
  done
  echo "Captures and labels written to $OUT"
}

main "$@"
