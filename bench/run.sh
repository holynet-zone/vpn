#!/usr/bin/env bash
#
# HolyNet vs wireguard-go throughput bench (Docker, single host, veth bridge).
#
# Reproduces the head-to-head numbers in PERFORMANCE.md and, for HolyNet,
# collects the data needed for the single-core datapath analysis:
#   - iperf3 forward / reverse / parallel throughput
#   - inner-TCP retransmits (iperf3 JSON)
#   - outer-UDP drop counters (nstat: Udp*Errors) on both ends
#   - optional on-CPU perf profile of the server datapath (PROFILE=1, needs sudo)
#
# Topology: two containers on a dedicated bridge network.
#   bench-srv (10.77.0.2)  runs the VPN server + iperf3 -s on the tunnel IP
#   bench-cli (10.77.0.3)  runs the VPN client + iperf3 -c over the tunnel
#
# Usage:
#   bench/run.sh build          # build the vpnbench image + release binary
#   bench/run.sh holynet        # bench HolyNet only
#   bench/run.sh wg             # bench wireguard-go only
#   bench/run.sh all            # both, printed side by side   (default)
#   bench/run.sh clean          # tear down containers/network
#
# Env knobs:
#   DUR=20            per-test seconds
#   STREAMS=8         parallel-stream count for the -P test
#   MTU=1420          tunnel MTU
#   OFFLOAD=1         HolyNet TUN GRO/TSO offload (0 => HOLYNET_DISABLE_OFFLOAD=1)
#   PROFILE=0         1 => perf record the server datapath during the fwd test (sudo)
#   TUNE=0            1 => raise rmem/wmem ceilings + fq qdisc in containers
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

IMAGE=${IMAGE:-vpnbench:latest}
NET=${NET:-vpnbench-net}
SUBNET=10.77.0.0/24
SRV_IP=10.77.0.2
CLI_IP=10.77.0.3
BIN=${BIN:-target/release/holynet}

DUR=${DUR:-20}
STREAMS=${STREAMS:-8}
MTU=${MTU:-1420}
OFFLOAD=${OFFLOAD:-1}
PROFILE=${PROFILE:-0}
TUNE=${TUNE:-0}

TUN_SRV_IP=10.8.0.1          # HolyNet server tunnel IP (iperf3 -s target)
WG_SRV_IP=10.9.0.1           # wireguard-go server tunnel IP
WG_CLI_IP=10.9.0.2
WG_PORT=51820

RUNDIR="$ROOT/bench/.run"
SHARED=/shared

c_grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
c_red(){ printf '\033[31m%s\033[0m\n' "$*"; }
c_hdr(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

b64key(){ head -c32 /dev/urandom | base64 | tr -d '='; }   # 32-byte base64-nopad

# ---------------------------------------------------------------- build --------
do_build(){
  c_hdr "building vpnbench image"
  docker build -f bench/Dockerfile.bench -t "$IMAGE" bench/
  c_hdr "building holynet release binary (host glibc)"
  cargo build --release -p holynet
  c_grn "binary: $BIN ($(du -h "$BIN" | cut -f1))"
}

# --------------------------------------------------------------- helpers -------
net_up(){
  docker network inspect "$NET" >/dev/null 2>&1 || \
    docker network create --subnet "$SUBNET" "$NET" >/dev/null
}

# start a long-lived privileged container we exec into
spawn(){  # spawn <name> <ip>
  local name=$1 ip=$2
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "$NET" --ip "$ip" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 \
    -v "$ROOT/$BIN:/holynet:ro" \
    -v "$RUNDIR:$SHARED" \
    "$IMAGE" sleep infinity >/dev/null
}

dexec(){ docker exec "$@"; }

tune_container(){  # tune <name>
  [ "$TUNE" = 1 ] || return 0
  dexec "$1" sh -c "sysctl -w net.core.rmem_max=$((64*1024*1024)) net.core.wmem_max=$((64*1024*1024)) >/dev/null; tc qdisc replace dev eth0 root fq 2>/dev/null || true"
}

# host PID of a process inside a container (for host-side perf)
host_pid(){  # host_pid <cname> <pattern>
  docker top "$1" -eo pid,args 2>/dev/null | awk -v p="$2" 'NR>1 && $0 ~ p {print $1; exit}'
}

nstat_reset(){ dexec "$1" nstat -n >/dev/null 2>&1 || true; }
nstat_udp(){   dexec "$1" sh -c "nstat -az 2>/dev/null | grep -Ei 'Udp.*(InErrors|RcvbufErrors|SndbufErrors|NoPorts)|IpInDiscards' || true"; }
# TCP reordering vs real-loss discriminator. High DSACKRecv / TCPOFOQueue with
# ~zero LostRetransmit => the "retransmits" are spurious (packets reordered, not
# dropped). This is the signature of an in-datapath reordering bug.
nstat_tcp(){   dexec "$1" sh -c "nstat -az 2>/dev/null | grep -Ei 'TcpRetransSegs|TCPLostRetransmit|TCPDSACK(Recv|OldSent)|TCPOFOQueue|TCPReord|TCPFastRetrans|TCPSpuriousRTOs' || true"; }

# TUN + eth0 tx/rx drops and qdisc drops — where inner-TCP loss actually happens
# when UDP socket counters stay clean (batching bursts overflow a queue).
iface_stats(){  # iface_stats <cname>
  dexec "$1" sh -c '
    tun=""
    for i in /sys/class/net/*; do [ -e "$i/tun_flags" ] && tun="$tun $(basename "$i")"; done
    for d in $tun eth0; do
      [ -n "$d" ] || continue
      echo "-- $d --"
      ip -s link show "$d" | grep -A1 -E "RX:|TX:"
    done
    echo "-- qdisc --"
    tc -s qdisc show 2>/dev/null | grep -E "qdisc|dropped" | head -12
  '
}

# parse iperf3 -J: throughput Gbit/s + retransmits (JSON file as $1)
parse_iperf(){  # parse_iperf <jsonfile>
  python3 - "$1" <<'PY'
import sys,json
try:
    e=json.load(open(sys.argv[1]))["end"]
except Exception:
    print("ERR 0"); sys.exit(0)
# receiver bps is the honest number; retransmits live on the sender
recv=e["sum_received"]["bits_per_second"]
retr=e.get("sum_sent",{}).get("retransmits",0)
print(f'{recv/1e9:.2f} {retr}')
PY
}

# ---------------------------------------------------------------- holynet ------
holynet_bench(){
  c_hdr "HolyNet  (offload=$OFFLOAD, mtu=$MTU)"
  mkdir -p "$RUNDIR"; rm -f "$RUNDIR"/connection-*.toml
  net_up
  spawn bench-srv "$SRV_IP"
  spawn bench-cli "$CLI_IP"
  tune_container bench-srv; tune_container bench-cli

  local SPRIV CPRIV PSK envoff=()
  SPRIV=$(b64key); CPRIV=$(b64key); PSK=$(b64key)
  [ "$OFFLOAD" = 0 ] && envoff=(-e HOLYNET_DISABLE_OFFLOAD=1)

  # server config
  dexec bench-srv sh -c "cat > /conf/config.toml <<EOF
[general]
host = \"0.0.0.0\"
port = 26256
secret_key = \"$SPRIV\"
storage = \"/conf/db\"

[interface]
name = \"hn0\"
mtu = $MTU
address = \"$TUN_SRV_IP\"
prefix = 24
offload = $([ "$OFFLOAD" = 1 ] && echo true || echo false)

[runtime]
workers = ${WORKERS:-0}
decrypt_workers = ${DECRYPT_WORKERS:-0}
so_rcvbuf = 1073741824
so_sndbuf = 1073741824
out_udp_buf = 1000
out_tun_buf = 1000
handshake_buf = 1000
data_udp_buf = 1000
data_tun_buf = 1000
EOF"

  # register the client -> writes /shared/connection-*.toml (host = server IP)
  dexec -w "$SHARED" bench-srv /holynet server --config /conf/config.toml \
      users add -h "$SRV_IP" -p 26256 -s "$CPRIV" --psk "$PSK" >/dev/null
  local conn
  conn=$(basename "$(ls -t "$RUNDIR"/connection-*.toml | head -1)")

  # Optional cipher override (ALG=ChaCha20Poly1305 | Aes256). File is root-owned
  # (written in-container), so edit it from container root.
  [ -n "${ALG:-}" ] && dexec bench-srv sh -c "sed -i 's/^alg = .*/alg = \"$ALG\"/' '$SHARED/$conn'"

  # opt-in client encrypt/decrypt pools. `users add` writes the connection file
  # without a [runtime] section, so append a full one when either pool is
  # requested. ENCRYPT_WORKERS spreads the send (forward) crypto; the client
  # CLIENT_DECRYPT_WORKERS spreads the receive (reverse/download) crypto.
  if [ "${ENCRYPT_WORKERS:-0}" != 0 ] || [ "${CLIENT_DECRYPT_WORKERS:-0}" != 0 ]; then
    # File is root-owned (written inside the container); the dir is writable,
    # so rebuild via a temp file + mv (append redirection would be denied).
    local tmp; tmp=$(mktemp)
    cp "$RUNDIR/$conn" "$tmp"
    cat >> "$tmp" <<EOF

[runtime]
handshake_timeout = 3000
keepalive = 5
encrypt_workers = ${ENCRYPT_WORKERS:-0}
decrypt_workers = ${CLIENT_DECRYPT_WORKERS:-0}
so_rcvbuf = 1073741824
so_sndbuf = 1073741824
out_udp_buf = 1000
out_tun_buf = 1000
data_udp_buf = 1000
data_tun_buf = 1000
EOF
    mv "$tmp" "$RUNDIR/$conn"
  fi

  # start server + iperf3 -s
  dexec "${envoff[@]}" -e RUST_LOG="${SRV_LOG:-holynet=info}" -d bench-srv sh -c "/holynet server --config /conf/config.toml start > /tmp/srv.log 2>&1"
  sleep 2
  dexec -d bench-srv sh -c "iperf3 -s -B $TUN_SRV_IP >/tmp/iperf.log 2>&1"

  # start client, wait for tunnel
  dexec "${envoff[@]}" -e RUST_LOG="${CLI_LOG:-holynet=info}" -d bench-cli sh -c "/holynet connect '$SHARED/$conn' > /tmp/cli.log 2>&1"
  local ok=0
  for _ in $(seq 1 30); do
    if dexec bench-cli ping -c1 -W1 "$TUN_SRV_IP" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" = 1 ] || { c_red "tunnel did not come up"; c_red "--- client log ---"; dexec bench-cli sh -c 'cat /tmp/cli.log' 2>/dev/null | tail -40; dexec bench-cli ip a; return 1; }
  c_grn "tunnel up: $CLI_IP -> $TUN_SRV_IP"

  run_suite bench-srv bench-cli "$TUN_SRV_IP"
}

# ------------------------------------------------------------- wireguard-go ----
wg_bench(){
  c_hdr "wireguard-go  (mtu=$MTU)"
  # shellcheck disable=SC1091
  source "$ROOT/bench/wgkeys.env"
  net_up
  spawn bench-srv "$SRV_IP"
  spawn bench-cli "$CLI_IP"
  tune_container bench-srv; tune_container bench-cli

  # server wg0
  dexec bench-srv sh -c "wireguard-go wg0 && \
    wg set wg0 private-key <(echo '$SPRIV') listen-port $WG_PORT \
      peer '$CPUB' allowed-ips $WG_CLI_IP/32 && \
    ip addr add $WG_SRV_IP/24 dev wg0 && ip link set wg0 mtu $MTU up"
  # client wg1
  dexec bench-cli sh -c "wireguard-go wg1 && \
    wg set wg1 private-key <(echo '$CPRIV') \
      peer '$SPUB' endpoint $SRV_IP:$WG_PORT allowed-ips $WG_SRV_IP/32 \
      persistent-keepalive 25 && \
    ip addr add $WG_CLI_IP/24 dev wg1 && ip link set wg1 mtu $MTU up"

  dexec -d bench-srv sh -c "iperf3 -s -B $WG_SRV_IP >/tmp/iperf.log 2>&1"
  local ok=0
  for _ in $(seq 1 30); do
    if dexec bench-cli ping -c1 -W1 "$WG_SRV_IP" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" = 1 ] || { c_red "wg tunnel did not come up"; return 1; }
  c_grn "wg tunnel up: $WG_CLI_IP -> $WG_SRV_IP"

  run_suite bench-srv bench-cli "$WG_SRV_IP"
}

# --------------------------------------------------------------- test suite ----
run_suite(){  # run_suite <srv> <cli> <target-ip>
  local srv=$1 cli=$2 tip=$3 res

  # wait until iperf3 -s is actually accepting on the tunnel IP
  for _ in $(seq 1 15); do
    dexec "$cli" iperf3 -c "$tip" -t 1 >/dev/null 2>&1 && break
    sleep 1
  done

  nstat_reset "$srv"; nstat_reset "$cli"

  # forward (client -> server)
  if [ "$PROFILE" = 1 ]; then
    local pid; pid=$(host_pid "$srv" 'server .* start')
    if [ -n "$pid" ]; then
      c_grn "perf record server pid $pid (fwd, ${DUR}s) — needs sudo"
      # Rootless docker: root can't drive the user's `docker exec`, so generate
      # load as the current user (background) and sample the server's host pid
      # from root in parallel (root can attach perf to any host pid).
      dexec "$cli" iperf3 -c "$tip" -t "$DUR" -J >"$RUNDIR/fwd.json" 2>/dev/null &
      local ipid=$!
      # System-wide: rootless docker's `docker top` pid is a container-namespace
      # pid, not the host pid perf needs, so `-p` misses. `-a` captures the whole
      # host; we filter to comm=holynet in the report. -e task-clock = software
      # timer (works without a hardware PMU; VMs often lack a virtualized one).
      printf '%s\n' "${SUDO_PW:-}" | sudo -S -p '' perf record -a -e task-clock -g -F 999 -o "$RUNDIR/perf.data" -- sleep "$DUR" || true
      wait "$ipid" 2>/dev/null || true
      sudo -n chown "$(id -u):$(id -g)" "$RUNDIR/perf.data" 2>/dev/null || true
    fi
  elif [ "${DIAG:-0}" = 1 ]; then
    # Per-thread on-CPU sampling (no sudo): find the busiest datapath threads on
    # both ends during the forward test. Reveals which single-threaded stage caps.
    dexec -d "$srv" sh -c "top -bH -d1 -n$((DUR)) 2>/dev/null > /tmp/top_srv.txt"
    dexec -d "$cli" sh -c "top -bH -d1 -n$((DUR)) 2>/dev/null > /tmp/top_cli.txt"
    dexec "$cli" iperf3 -c "$tip" -t "$DUR" -J >"$RUNDIR/fwd.json" 2>/dev/null
  else
    dexec "$cli" iperf3 -c "$tip" -t "$DUR" -J >"$RUNDIR/fwd.json" 2>/dev/null
  fi
  res=$(parse_iperf "$RUNDIR/fwd.json"); printf '  fwd  (1 stream)   %s Gbit/s   retr=%s\n' $res
  if [ "${DIAG:-0}" = 1 ]; then
    for side in srv cli; do
      c_hdr "top threads ($side, fwd) — MAX %CPU per thread across the whole run"
      # Aggregate the peak %CPU each thread (TID) reached over all snapshots, so a
      # writer that saturates one core mid-transfer is visible even when the final
      # snapshot is idle. top -bH cols: PID(1) ... %CPU(9) %MEM(10) TIME+(11) CMD(12).
      dexec "bench-$side" sh -c "awk '/^[[:space:]]*[0-9]+/{p=\$1;c=\$9+0;if(c>m[p]){m[p]=c;n[p]=\$12}} END{for(k in m)printf \"%6.1f %%CPU  %s (tid %s)\n\",m[k],n[k],k}' /tmp/top_${side}.txt | sort -rn | head -15" 2>/dev/null || true
    done
  fi

  # reverse (server -> client)
  dexec "$cli" iperf3 -c "$tip" -t "$DUR" -R -J >"$RUNDIR/rev.json" 2>/dev/null
  res=$(parse_iperf "$RUNDIR/rev.json"); printf '  rev  (1 stream)   %s Gbit/s   retr=%s\n' $res

  # parallel
  dexec "$cli" iperf3 -c "$tip" -t "$DUR" -P "$STREAMS" -J >"$RUNDIR/par.json" 2>/dev/null
  res=$(parse_iperf "$RUNDIR/par.json"); printf '  par  (%s streams)  %s Gbit/s   retr=%s\n' "$STREAMS" $res

  c_hdr "outer-UDP drop counters (server)"; nstat_udp "$srv"
  c_hdr "outer-UDP drop counters (client)"; nstat_udp "$cli"
  c_hdr "TCP reorder/retrans counters (server)"; nstat_tcp "$srv"
  c_hdr "TCP reorder/retrans counters (client)"; nstat_tcp "$cli"
  c_hdr "interface / qdisc drops (server)"; iface_stats "$srv"
  c_hdr "interface / qdisc drops (client)"; iface_stats "$cli"
  [ -f "$RUNDIR/perf.data" ] && c_grn "perf: sudo perf report -i $RUNDIR/perf.data"
  if [ "${SRVSTATS:-0}" = 1 ]; then
    c_hdr "server datapath stats (/tmp/srv.log)"
    dexec "$srv" sh -c 'grep -i STAT /tmp/srv.log | tail -30' 2>/dev/null || true
  fi
}

# --------------------------------------------------------------- teardown ------
do_clean(){
  docker rm -f bench-srv bench-cli >/dev/null 2>&1 || true
  c_grn "containers removed (network $NET kept)"
}
trap 'do_clean' EXIT

case "${1:-all}" in
  build)   do_build ;;
  holynet) holynet_bench ;;
  wg)      wg_bench ;;
  all)     holynet_bench; do_clean; wg_bench ;;
  clean)   trap - EXIT; do_clean; docker network rm "$NET" >/dev/null 2>&1 || true ;;
  *) echo "usage: $0 {build|holynet|wg|all|clean}"; exit 1 ;;
esac
