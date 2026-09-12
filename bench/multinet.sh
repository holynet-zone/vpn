#!/usr/bin/env bash
#
# HolyNet multi-network bench (Docker, single host).
#
# One client joins two non-overlapping networks at once (`connect connA connB`)
# and routes each subnet through its own tunnel. Verifies both tunnels come up
# and measures throughput to each, plus a simultaneous run to show they coexist.
#
#   netA: server srvA 10.77.0.2, subnet 10.8.0.0/24  (tun 10.8.0.1)
#   netB: server srvB 10.77.0.6, subnet 10.20.0.0/24 (tun 10.20.0.1)
#   client joins both; traffic to 10.8.0.1 -> tunA, to 10.20.0.1 -> tunB.
#
# Usage:
#   bench/run.sh build     # build image + release binary first (shared)
#   bench/multinet.sh
#   bench/multinet.sh clean
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
IMAGE=${IMAGE:-vpnbench:latest}
NET=${NET:-vpnbench-net}
SUBNET=10.77.0.0/24
SRVA_IP=10.77.0.2
SRVB_IP=10.77.0.6
CLI_IP=10.77.0.3
PORT=26256
BIN=${BIN:-target/release/holynet}
DUR=${DUR:-15}
STREAMS=${STREAMS:-8}
MTU=${MTU:-1420}
OFFLOAD=${OFFLOAD:-1}
TUN_A=10.8.0.1
TUN_B=10.20.0.1
RUNDIR="$ROOT/bench/.run"
SHARED=/shared

c_grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
c_red(){ printf '\033[31m%s\033[0m\n' "$*"; }
c_hdr(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
strip(){ sed 's/\x1b\[[0-9;]*m//g'; }
b64key(){ head -c32 /dev/urandom | base64 | tr -d '='; }

net_up(){ docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet "$SUBNET" "$NET" >/dev/null; }
spawn(){
  docker rm -f "$1" >/dev/null 2>&1 || true
  docker run -d --name "$1" --network "$NET" --ip "$2" \
    --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
    -v "$ROOT/$BIN:/holynet:ro" -v "$RUNDIR:$SHARED" "$IMAGE" sleep infinity >/dev/null
}
dexec(){ docker exec "$@"; }
parse_iperf(){ python3 - "$1" <<'PY'
import sys,json
try: e=json.load(open(sys.argv[1]))["end"]
except Exception: print("ERR 0"); sys.exit(0)
print(f'{e["sum_received"]["bits_per_second"]/1e9:.2f} {e.get("sum_sent",{}).get("retransmits",0)}')
PY
}

server_config(){ # <name> <secret> <tunip>
  local offbool; offbool=$([ "$OFFLOAD" = 1 ] && echo true || echo false)
  dexec "$1" sh -c "mkdir -p /conf; cat > /conf/config.toml <<EOF
[general]
host = \"0.0.0.0\"
port = $PORT
secret_key = \"$2\"
storage = \"/conf/db\"

[interface]
name = \"hn0\"
mtu = $MTU
address = \"$3\"
prefix = 24
offload = $offbool

[runtime]
workers = 0
decrypt_workers = 0
so_rcvbuf = 1073741824
so_sndbuf = 1073741824
out_udp_buf = 1000
out_tun_buf = 1000
handshake_buf = 1000
data_udp_buf = 1000
data_tun_buf = 1000
EOF"
}

do_clean(){ docker rm -f bench-srva bench-srvb bench-mcli >/dev/null 2>&1 || true; c_grn "containers removed (network $NET kept)"; }

do_run(){
  [ -x "$ROOT/$BIN" ] || { c_red "missing $BIN — run: bench/run.sh build"; exit 1; }
  mkdir -p "$RUNDIR"; rm -f "$RUNDIR"/conn[AB].toml "$RUNDIR"/connection-*.toml
  net_up
  spawn bench-srva "$SRVA_IP"
  spawn bench-srvb "$SRVB_IP"

  local SA SB CA CB PA PB
  SA=$(b64key); SB=$(b64key); CA=$(b64key); CB=$(b64key); PA=$(b64key); PB=$(b64key)

  # netA
  server_config bench-srva "$SA" "$TUN_A"
  dexec -w "$SHARED" bench-srva /holynet server --config /conf/config.toml \
    users add -h "$SRVA_IP" -p "$PORT" -s "$CA" --psk "$PA" >/dev/null
  mv "$(ls -t "$RUNDIR"/connection-*.toml | head -1)" "$RUNDIR/connA.toml"
  # netB
  server_config bench-srvb "$SB" "$TUN_B"
  dexec -w "$SHARED" bench-srvb /holynet server --config /conf/config.toml \
    users add -h "$SRVB_IP" -p "$PORT" -s "$CB" --psk "$PB" >/dev/null
  mv "$(ls -t "$RUNDIR"/connection-*.toml | head -1)" "$RUNDIR/connB.toml"

  local off=(); [ "$OFFLOAD" = 0 ] && off=(-e HOLYNET_DISABLE_OFFLOAD=1)
  dexec "${off[@]}" -d bench-srva sh -c "/holynet server --config /conf/config.toml start >/tmp/srv.log 2>&1"
  dexec "${off[@]}" -d bench-srvb sh -c "/holynet server --config /conf/config.toml start >/tmp/srv.log 2>&1"
  sleep 2
  dexec -d bench-srva sh -c "iperf3 -s -B $TUN_A >/tmp/iperf.log 2>&1"
  dexec -d bench-srvb sh -c "iperf3 -s -B $TUN_B >/tmp/iperf.log 2>&1"
  sleep 1

  spawn bench-mcli "$CLI_IP"
  dexec -d bench-mcli sh -c "/holynet connect '$SHARED/connA.toml' '$SHARED/connB.toml' >/tmp/cli.log 2>&1"

  # wait for BOTH tunnels
  local ok=0
  for _ in $(seq 1 30); do
    if dexec bench-mcli ping -c1 -W1 "$TUN_A" >/dev/null 2>&1 \
       && dexec bench-mcli ping -c1 -W1 "$TUN_B" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  if [ "$ok" != 1 ]; then
    c_red "both tunnels did not come up"; dexec bench-mcli sh -c 'tail -40 /tmp/cli.log' 2>/dev/null || true
    dexec bench-mcli sh -c 'ip route; ip -br a' 2>/dev/null || true
    return 1
  fi
  c_grn "both tunnels up: $TUN_A (netA) + $TUN_B (netB)"
  c_hdr "routing (client)"; dexec bench-mcli sh -c "ip route | grep -E '10\\.(8|20)\\.'" 2>/dev/null || true

  c_hdr "HolyNet multi-network bench (mtu=$MTU, dur=${DUR}s)"
  local res
  dexec bench-mcli iperf3 -c "$TUN_A" -t "$DUR" -J >"$RUNDIR/netA.json" 2>/dev/null
  res=$(parse_iperf "$RUNDIR/netA.json"); printf '  netA   fwd  %s Gbit/s  retr=%s\n' $res
  dexec bench-mcli iperf3 -c "$TUN_B" -t "$DUR" -J >"$RUNDIR/netB.json" 2>/dev/null
  res=$(parse_iperf "$RUNDIR/netB.json"); printf '  netB   fwd  %s Gbit/s  retr=%s\n' $res

  # simultaneous: both networks at once
  dexec bench-mcli iperf3 -c "$TUN_A" -t "$DUR" -J >"$RUNDIR/simA.json" 2>/dev/null &
  local pa=$!
  dexec bench-mcli iperf3 -c "$TUN_B" -t "$DUR" -J >"$RUNDIR/simB.json" 2>/dev/null &
  local pb=$!
  wait "$pa" "$pb" || true
  local ra rb
  ra=$(parse_iperf "$RUNDIR/simA.json"); rb=$(parse_iperf "$RUNDIR/simB.json")
  printf '  sim    netA %s Gbit/s + netB %s Gbit/s (simultaneous)\n' "$(echo $ra | cut -d' ' -f1)" "$(echo $rb | cut -d' ' -f1)"
}

trap 'do_clean' EXIT
case "${1:-run}" in
  run)   do_run ;;
  clean) trap - EXIT; do_clean; docker network rm "$NET" >/dev/null 2>&1 || true ;;
  *) echo "usage: $0 {run|clean}"; exit 1 ;;
esac
