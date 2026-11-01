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
# Usage:  sudo data/scripts/capture_faults.sh [--list] [scenario ...]
#         OUT=/some/dir sudo -E data/scripts/capture_faults.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
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
  http_errors tls_bad_cert tls_no_server_hello
)
NETEM_SCENARIOS=" tcp_loss tcp_reorder tcp_high_latency "
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
  CAP_NAME=$1
  # Capture to Linux-native storage with a 64 MB buffer: writing straight to
  # a slow mount (e.g. /mnt/d under WSL) makes the kernel drop packets during
  # bursts, which would corrupt the ground truth.
  # --immediate-mode: otherwise libpcap holds packets in partly filled
  # TPACKET_V3 blocks, and whatever is still held when tcpdump is stopped
  # is silently lost.
  # Not via in_cli: $! must be tcpdump itself (ip netns exec execs it), not a
  # wrapper subshell, so the kill below reaches it.
  ip netns exec "$CLI" tcpdump -i c-eth0 -s 0 -B 65536 --immediate-mode -U -Z root \
    -w "$CAP_TMP/$1.pcap" 2>"$CAP_TMP/$1.log" &
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

# label <scenario> <root_cause|null> <expected-json> <may_also-json> <notes>
#   expected: events the detectors must report; an integer is an exact count,
#             null means "at least one".
#   may_also: events that are legitimate side effects of the fault.
# Anything else reported for this capture counts as a false positive.
label() {
  local rc=$2
  [[ $rc != null ]] && rc="\"$rc\""
  cat > "$OUT/$1.json" <<EOF
{
  "scenario": "$1",
  "pcap": "$1.pcap",
  "vantage": "client",
  "client": "$C_IP",
  "server": "$S_IP",
  "root_cause": $rc,
  "expected": $3,
  "may_also": $4,
  "notes": "$5"
}
EOF
}

q() { in_cli dig "@${RESOLVER:-$S_IP}" +tries=1 +timeout=3 "$@" >/dev/null 2>&1 || true; }

# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

sc_baseline() {
  helper_srv http-server "$S_IP" 8080
  helper_srv dns-server "$S_IP"
  sleep 1
  start_capture baseline
  q ok1.test; q ok2.test; q ok3.test
  helper_cli fetch "http://$S_IP:8080/bytes/2000000" --count 3
  stop_capture
  label baseline null '{}' '[]' "Clean DNS lookups and HTTP downloads. Any fault event is a false positive."
}

sc_tcp_loss() {
  helper_srv http-server "$S_IP" 8080
  in_rtr tc qdisc add dev r-eth0 root netem loss 3%
  sleep 1
  start_capture tcp_loss
  helper_cli fetch "http://$S_IP:8080/bytes/5000000" --count 3
  stop_capture
  label tcp_loss PATH_LOSS \
    '{"TCP_RETRANSMISSION": null, "TCP_DUP_ACK": null, "TCP_LOST_SEGMENT": null}' \
    '["TCP_OUT_OF_ORDER", "TCP_ZERO_WINDOW"]' \
    "3% random loss on the router->client link, upstream of the capture point. Data held behind a hole can briefly fill the client's receive buffer (a short zero window)."
}

sc_tcp_reorder() {
  helper_srv http-server "$S_IP" 8080
  in_rtr tc qdisc add dev r-eth0 root netem delay 20ms reorder 25% 50%
  sleep 1
  start_capture tcp_reorder
  helper_cli fetch "http://$S_IP:8080/bytes/5000000" --count 2
  stop_capture
  label tcp_reorder PACKET_REORDERING \
    '{"TCP_OUT_OF_ORDER": null}' \
    '["TCP_DUP_ACK", "TCP_RETRANSMISSION", "TCP_LOST_SEGMENT", "TCP_ZERO_WINDOW"]' \
    "25% of packets skip a 20 ms delay on the router->client link. No loss. Data held behind a hole can briefly fill the client's receive buffer (a short zero window)."
}

sc_tcp_high_latency() {
  helper_srv http-server "$S_IP" 8080
  in_rtr tc qdisc add dev r-eth0 root netem delay 400ms
  sleep 1
  start_capture tcp_high_latency
  helper_cli fetch "http://$S_IP:8080/bytes/20000" --count 3
  stop_capture
  label tcp_high_latency HIGH_LATENCY_PATH \
    '{"TCP_HIGH_RTT": 3}' '[]' \
    "400 ms added on the router->client link; one HIGH_RTT per connection."
}

sc_tcp_syn_timeout() {
  helper_srv http-server "$S_IP" 8080
  in_srv iptables -A INPUT -p tcp --dport 9000 -j DROP
  sleep 1
  start_capture tcp_syn_timeout
  helper_cli fetch "http://$S_IP:8080/bytes/1000"
  helper_cli connect "$S_IP" 9000 --count 3 --timeout 4
  stop_capture
  label tcp_syn_timeout FIREWALL_DROP \
    '{"TCP_SYN_TIMEOUT": 3}' '[]' \
    "Server silently drops port 9000. One fetch to port 8080 shows the host itself is up."
}

sc_tcp_conn_refused() {
  sleep 0.5
  start_capture tcp_conn_refused
  helper_cli connect "$S_IP" 9001 --count 3
  stop_capture
  label tcp_conn_refused SERVICE_DOWN \
    '{"TCP_CONN_REFUSED": 3}' '[]' \
    "Nothing listening on port 9001; the kernel answers SYN with RST/ACK."
}

sc_tcp_rst_midstream() {
  helper_srv rst-server "$S_IP" 9002
  sleep 1
  start_capture tcp_rst_midstream
  helper_cli fetch "http://$S_IP:9002/" --count 2
  stop_capture
  label tcp_rst_midstream ABRUPT_TERMINATION \
    '{"TCP_RST_MIDSTREAM": 2}' '[]' \
    "Server sends 20 KB of a 1 MB response, then aborts with RST."
}

sc_tcp_zero_window() {
  helper_srv http-server "$S_IP" 8080
  sleep 1
  start_capture tcp_zero_window
  helper_cli slow-fetch "$S_IP" 8080 /bytes/2000000 --rcvbuf 4096 --slow-seconds 4
  stop_capture
  label tcp_zero_window RECEIVER_BOTTLENECK \
    '{"TCP_ZERO_WINDOW": null}' '["TCP_RETRANSMISSION"]' \
    "Client reads 512 B every 50 ms with a tiny receive buffer for 4 s, then drains. The client advertises the zero window; zero-window probes are part of the event, not retransmissions. The starved receiver occasionally discards an in-window segment, which the server then genuinely retransmits."
}

# The router's server-facing link has a 1200-byte MTU while both hosts use
# 1500, so the server still advertises MSS 1460 and the client's full-size
# uploads don't fit. (The server only sends small ACKs towards the router.)
pmtu_setup() {
  helper_srv sink-server "$S_IP" 9100
  ip -n "$RTR" link set r-eth1 mtu 1200
}

sc_tcp_pmtu_ok() {
  pmtu_setup
  sleep 1
  start_capture tcp_pmtu_ok
  helper_cli upload "$S_IP" 9100 500000
  stop_capture
  label tcp_pmtu_ok MTU_MISMATCH \
    '{"ICMP_FRAG_NEEDED": null}' '["TCP_RETRANSMISSION"]' \
    "1200-byte MTU hop; the router sends ICMP fragmentation-needed and the upload recovers."
}

sc_tcp_pmtu_blackhole() {
  pmtu_setup
  in_rtr iptables -A OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP
  sleep 1
  start_capture tcp_pmtu_blackhole
  helper_cli upload "$S_IP" 9100 500000 --timeout 8
  stop_capture
  label tcp_pmtu_blackhole PMTU_BLACKHOLE \
    '{"TCP_RETRANSMISSION": null}' '[]' \
    "Same 1200-byte hop, but the router's ICMP is filtered: handshake succeeds, full-size segments are retransmitted with backoff and never ACKed, and no ICMP_FRAG_NEEDED is visible."
}

sc_icmp_port_unreachable() {
  sleep 0.5
  start_capture icmp_port_unreachable
  helper_cli udp-send "$S_IP" 9999 --count 3
  stop_capture
  label icmp_port_unreachable SERVICE_DOWN \
    '{"ICMP_PORT_UNREACHABLE": 3}' '[]' \
    "UDP datagrams to a closed port on the server."
}

sc_icmp_admin_prohibited() {
  in_rtr iptables -A FORWARD -p tcp --dport 9003 -j REJECT --reject-with icmp-admin-prohibited
  sleep 0.5
  start_capture icmp_admin_prohibited
  helper_cli connect "$S_IP" 9003 --count 3 --timeout 2
  stop_capture
  label icmp_admin_prohibited ADMIN_BLOCK \
    '{"ICMP_ADMIN_PROHIBITED": 3}' '[]' \
    "Router firewall rejects TCP/9003 with ICMP 3/13. The ICMP source (10.10.1.1) identifies the blocking device."
}

sc_icmp_host_unreachable() {
  sleep 0.5
  start_capture icmp_host_unreachable
  helper_cli connect 10.10.2.99 80 --count 2 --timeout 5
  stop_capture
  label icmp_host_unreachable HOST_UNREACHABLE \
    '{"ICMP_HOST_UNREACHABLE": null}' '[]' \
    "10.10.2.99 is on the router's connected subnet but doesn't exist; ARP fails and the router returns ICMP 3/1 after about 3 s. SYN retransmissions before that belong to the failed handshake."
}

sc_icmp_net_unreachable() {
  sleep 0.5
  start_capture icmp_net_unreachable
  helper_cli connect 10.10.9.9 80 --count 2 --timeout 3
  stop_capture
  label icmp_net_unreachable NO_ROUTE \
    '{"ICMP_NET_UNREACHABLE": null}' '[]' \
    "The router has no route for 10.10.9.0/24 (and no default route)."
}

sc_icmp_routing_loop() {
  # Router sends 10.10.4.0/24 to the server, whose default route points back.
  in_srv sysctl -qw net.ipv4.ip_forward=1
  ip -n "$RTR" route add 10.10.4.0/24 via "$S_IP"
  sleep 0.5
  start_capture icmp_routing_loop
  helper_cli udp-send 10.10.4.4 5000 --count 3
  stop_capture
  label icmp_routing_loop ROUTING_LOOP \
    '{"ICMP_TTL_EXCEEDED": 3}' '[]' \
    "Packets to 10.10.4.4 bounce router<->server until TTL 64 runs out. Probes left with a normal TTL, which separates this from traceroute."
}

sc_icmp_traceroute() {
  sleep 0.5
  start_capture icmp_traceroute
  helper_cli udp-send "$S_IP" 33434 --count 3 --ttl 1 --port-step 1
  helper_cli udp-send "$S_IP" 33440 --count 3 --ttl 2 --port-step 1
  stop_capture
  label icmp_traceroute null \
    '{"ICMP_TTL_EXCEEDED": 3, "ICMP_PORT_UNREACHABLE": 3}' '[]' \
    "Traceroute-style probes (TTL 1 then 2, high UDP ports). The events are real, but no root-cause rule should fire."
}

dns_setup() {
  helper_srv dns-server "$S_IP"
  sleep 1
}

sc_dns_nxdomain() {
  dns_setup
  start_capture dns_nxdomain
  for n in 1 2 3 4 5; do q "nx$n.test"; done
  stop_capture
  label dns_nxdomain NAME_NOT_FOUND '{"DNS_NXDOMAIN": 5}' '[]' "Five lookups of names that don't exist."
}

sc_dns_servfail() {
  dns_setup
  start_capture dns_servfail
  for n in 1 2 3; do q "servfail$n.test"; done
  stop_capture
  label dns_servfail RESOLVER_FAILURE '{"DNS_SERVFAIL": 3}' '[]' "Resolver answers SERVFAIL."
}

sc_dns_refused() {
  dns_setup
  start_capture dns_refused
  for n in 1 2 3; do q "refused$n.test"; done
  stop_capture
  label dns_refused RESOLVER_REFUSED '{"DNS_REFUSED": 3}' '[]' "Resolver answers REFUSED."
}

sc_dns_timeout() {
  dns_setup
  start_capture dns_timeout
  for n in 1 2; do in_cli dig "@$S_IP" +tries=3 +timeout=1 "drop$n.test" >/dev/null 2>&1 || true; done
  sleep 2
  stop_capture
  label dns_timeout RESOLVER_FAILURE \
    '{"DNS_TIMEOUT": 2, "DNS_RETRANSMISSION": 4}' '[]' \
    "Two names, three tries each, never answered: two transactions with two retransmissions each."
}

sc_dns_slow() {
  dns_setup
  start_capture dns_slow
  for n in 1 2 3; do q "slow$n.test"; done
  stop_capture
  label dns_slow SLOW_RESOLVER '{"DNS_SLOW_RESPONSE": 3}' '[]' "Every answer arrives 1.5 s after the query."
}

sc_dns_tcp_fallback() {
  dns_setup
  start_capture dns_tcp_fallback
  q big1.test; q big2.test
  stop_capture
  label dns_tcp_fallback null '{"DNS_TCP_FALLBACK": 2}' '[]' \
    "UDP answers are truncated (TC=1); dig retries over TCP and succeeds. Normal behaviour, so no root cause."
}

sc_dns_nodata() {
  dns_setup
  start_capture dns_nodata
  for n in 1 2 3; do q "nodata$n.test"; done
  stop_capture
  label dns_nodata null '{"DNS_NODATA": 3}' '[]' "NOERROR with an empty answer section. Informational."
}

sc_dns_resolver_down() {
  sleep 0.5
  start_capture dns_resolver_down
  RESOLVER=10.10.2.53 q ok.test
  RESOLVER=10.10.2.53 q ok2.test
  stop_capture
  label dns_resolver_down RESOLVER_UNREACHABLE \
    '{"DNS_TIMEOUT": null, "ICMP_HOST_UNREACHABLE": null}' '["DNS_RETRANSMISSION"]' \
    "Configured resolver 10.10.2.53 doesn't exist; the router returns host-unreachable for the queries."
}

sc_http_errors() {
  helper_srv http-server "$S_IP" 8080
  sleep 1
  start_capture http_errors
  for code in 404 500 503; do helper_cli fetch "http://$S_IP:8080/status/$code"; done
  stop_capture
  label http_errors APP_ERRORS '{"HTTP_ERROR_RESPONSE": 3}' '[]' \
    "Plain-HTTP 404, 500 and 503 responses. Phase-2 (app_events) ground truth."
}

sc_tls_bad_cert() {
  # Self-signed certificate: the verifying client aborts with a fatal alert.
  # TLS 1.2 is forced because TLS 1.3 would encrypt that alert.
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=pcap-rca.test" \
    -keyout "$CAP_TMP/tls.key" -out "$CAP_TMP/tls.crt" >/dev/null 2>&1
  helper_srv tls-server "$S_IP" 8443 "$CAP_TMP/tls.crt" "$CAP_TMP/tls.key"
  sleep 1
  start_capture tls_bad_cert
  helper_cli tls-connect "$S_IP" 8443 --count 2
  stop_capture
  label tls_bad_cert TLS_FAILURE '{"TLS_HANDSHAKE_FAILURE": 2}' '["TCP_RST_MIDSTREAM"]' \
    "Server presents a self-signed certificate over TLS 1.2; the client rejects it with a clear-text fatal alert (unknown_ca), then aborts the connection with RST."
}

sc_tls_no_server_hello() {
  # Something listens on the port but never speaks TLS.
  helper_srv sink-server "$S_IP" 8443
  sleep 1
  start_capture tls_no_server_hello
  helper_cli tls-connect "$S_IP" 8443 --count 2 --timeout 2
  stop_capture
  label tls_no_server_hello TLS_FAILURE '{"TLS_HANDSHAKE_FAILURE": 2}' '[]' \
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
  if [[ ${1:-} == --list ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
  fi
  local selected=("$@")
  ((${#selected[@]})) || selected=("${SCENARIOS[@]}")

  local name
  for name in "${selected[@]}"; do
    declare -F "sc_$name" >/dev/null || { echo "Unknown scenario: $name (try --list)" >&2; exit 1; }
  done

  preflight
  mkdir -p "$OUT"
  CAP_TMP=$(mktemp -d)
  trap 'teardown; rm -rf "$CAP_TMP"' EXIT

  for name in "${selected[@]}"; do
    if [[ $NETEM_SCENARIOS == *" $name "* ]] && ! $HAVE_NETEM; then
      echo "--- $name (skipped: no netem)"
      continue
    fi
    if [[ $TLS_SCENARIOS == *" $name "* ]] && ! $HAVE_OPENSSL; then
      echo "--- $name (skipped: no openssl)"
      continue
    fi
    echo "--- $name"
    setup
    "sc_$name"
    teardown
  done
  echo "Captures and labels written to $OUT"
}

main "$@"
