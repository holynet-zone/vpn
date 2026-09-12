#!/usr/bin/env bash
#
# HolyNet multi-hop relay throughput bench (Docker, single host).
#
# Measures how much the transparent inter-node relay costs by running the same
# client/server tunnel over two topologies and printing them side by side:
#
#   baseline : client ───────────────▶ server        (direct, no relay)
#   2-hop    : client ──▶ relay ──────▶ server        (connect --via relay)
#   3-hop    : client ──▶ relay ──▶ relay ──▶ server  (TODO: needs multi-hop chaining)
#
# The relay resolves the destination through its signed node registry (so it
# only forwards to a known node) and never sees plaintext — the client runs an
# end-to-end Noise session with the server through it.
#
# Topology (all on one docker bridge):
#   bench-srv   10.77.0.2   server node, terminates the tunnel, iperf3 -s on TUN
#   bench-relay 10.77.0.4   relay node (signed registry knows the server)
#   bench-cli   10.77.0.3   client; direct for baseline, --via relay for 2-hop
#
# Usage:
#   bench/run.sh build        # build image + release binary first (shared)
#   bench/relay.sh            # run baseline + 2-hop
#   bench/relay.sh clean
#
# Env knobs: DUR, STREAMS, MTU, OFFLOAD  (same meaning as run.sh)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

IMAGE=${IMAGE:-vpnbench:latest}
NET=${NET:-vpnbench-net}
SUBNET=10.77.0.0/24
SRV_IP=10.77.0.2
CLI_IP=10.77.0.3
RELAY_IP=10.77.0.4
PORT=26256
BIN=${BIN:-target/release/holynet}

DUR=${DUR:-20}
STREAMS=${STREAMS:-8}
MTU=${MTU:-1420}
OFFLOAD=${OFFLOAD:-1}

TUN_SRV_IP=10.8.0.1          # server tunnel subnet 10.8.0.0/24
TUN_RELAY_IP=10.10.0.1       # relay's own tunnel subnet (unused for traffic)

RUNDIR="$ROOT/bench/.run"
SHARED=/shared

c_grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
c_red(){ printf '\033[31m%s\033[0m\n' "$*"; }
c_hdr(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
strip(){ sed 's/\x1b\[[0-9;]*m//g'; }
b64key(){ head -c32 /dev/urandom | base64 | tr -d '='; }

net_up(){ docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet "$SUBNET" "$NET" >/dev/null; }
spawn(){ # spawn <name> <ip>
  docker rm -f "$1" >/dev/null 2>&1 || true
  docker run -d --name "$1" --network "$NET" --ip "$2" \
    --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
    -v "$ROOT/$BIN:/holynet:ro" -v "$RUNDIR:$SHARED" \
    "$IMAGE" sleep infinity >/dev/null
}
dexec(){ docker exec "$@"; }

parse_iperf(){ python3 - "$1" <<'PY'
import sys,json
try: e=json.load(open(sys.argv[1]))["end"]
except Exception: print("ERR 0"); sys.exit(0)
recv=e["sum_received"]["bits_per_second"]
retr=e.get("sum_sent",{}).get("retransmits",0)
print(f'{recv/1e9:.2f} {retr}')
PY
}

server_config(){ # server_config <name> <secret> <tunip> <tunsub_prefix> [authority]
  local name=$1 secret=$2 tunip=$3 auth=${4:-}
  local offbool; offbool=$([ "$OFFLOAD" = 1 ] && echo true || echo false)
  dexec "$name" sh -c "mkdir -p /conf; cat > /conf/config.toml <<EOF
[general]
host = \"0.0.0.0\"
port = $PORT
secret_key = \"$secret\"
storage = \"/conf/db\"
$( [ -n "$auth" ] && echo "authority = \"$auth\"" )

[interface]
name = \"hn0\"
mtu = $MTU
address = \"$tunip\"
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

# run the iperf suite over an already-up tunnel to $TUN_SRV_IP
measure(){ # measure <label>
  local label=$1 res
  dexec bench-cli iperf3 -c "$TUN_SRV_IP" -t "$DUR" -J >"$RUNDIR/${label}_fwd.json" 2>/dev/null
  res=$(parse_iperf "$RUNDIR/${label}_fwd.json"); printf '  %-8s fwd  %s Gbit/s  retr=%s\n' "$label" $res
  dexec bench-cli iperf3 -c "$TUN_SRV_IP" -t "$DUR" -R -J >"$RUNDIR/${label}_rev.json" 2>/dev/null
  res=$(parse_iperf "$RUNDIR/${label}_rev.json"); printf '  %-8s rev  %s Gbit/s  retr=%s\n' "$label" $res
  dexec bench-cli iperf3 -c "$TUN_SRV_IP" -t "$DUR" -P "$STREAMS" -J >"$RUNDIR/${label}_par.json" 2>/dev/null
  res=$(parse_iperf "$RUNDIR/${label}_par.json"); printf '  %-8s par  %s Gbit/s  retr=%s\n' "$label" $res
}

# (re)start the client with given connect args, wait for the tunnel, measure
client_phase(){ # client_phase <label> <connect-args...>
  local label=$1; shift
  spawn bench-cli "$CLI_IP"
  dexec -e RUST_LOG="${CLI_LOG:-holynet=warn}" -d bench-cli \
    sh -c "/holynet connect $* '$SHARED/$CONN' > /tmp/cli.log 2>&1"
  local ok=0
  for _ in $(seq 1 30); do
    dexec bench-cli ping -c1 -W1 "$TUN_SRV_IP" >/dev/null 2>&1 && { ok=1; break; }
    sleep 1
  done
  if [ "$ok" != 1 ]; then
    c_red "[$label] tunnel did not come up"; dexec bench-cli sh -c 'tail -30 /tmp/cli.log' 2>/dev/null || true
    return 1
  fi
  c_grn "[$label] tunnel up"
  measure "$label"
  docker rm -f bench-cli >/dev/null 2>&1 || true
}

do_clean(){ docker rm -f bench-srv bench-relay bench-cli >/dev/null 2>&1 || true; c_grn "containers removed (network $NET kept)"; }

do_run(){
  [ -x "$ROOT/$BIN" ] || { c_red "missing $BIN — run: bench/run.sh build"; exit 1; }
  mkdir -p "$RUNDIR"; rm -f "$RUNDIR"/connection-*.toml "$RUNDIR"/authority.key
  net_up
  spawn bench-srv "$SRV_IP"
  spawn bench-relay "$RELAY_IP"

  local SPRIV RPRIV CPRIV PSK
  SPRIV=$(b64key); RPRIV=$(b64key); CPRIV=$(b64key); PSK=$(b64key)

  # --- server: account enrollment for the client (Phase 2), no node authority ---
  server_config bench-srv "$SPRIV" "$TUN_SRV_IP"
  dexec -w "$SHARED" bench-srv /holynet server --config /conf/config.toml \
    users add -h "$SRV_IP" -p "$PORT" -s "$CPRIV" --psk "$PSK" >/dev/null
  CONN=$(basename "$(ls -t "$RUNDIR"/connection-*.toml | head -1)")
  local SRV_NODE_PK
  SRV_NODE_PK=$(dexec bench-srv /holynet server --config /conf/config.toml pubkey | strip | awk '$1=="PubKey"{print $2}')

  # --- node authority (host): sign the server's registry record ---
  local AUTH_PUB SRV_RECORD
  AUTH_PUB=$("$ROOT/$BIN" authority init --out "$RUNDIR/authority.key" | strip | awk '$1=="Authority"{print $2; exit}')
  SRV_RECORD=$("$ROOT/$BIN" authority sign --node-pk "$SRV_NODE_PK" \
    --endpoint "$SRV_IP:$PORT" --subnet 10.8.0.0 --prefix 24 --label ru \
    --key "$RUNDIR/authority.key" | strip | awk '$1=="Record"{print $2; exit}')

  # --- relay: signed registry that knows the server; no client accounts needed ---
  server_config bench-relay "$RPRIV" "$TUN_RELAY_IP" "$AUTH_PUB"
  dexec bench-relay /holynet server --config /conf/config.toml nodes import "$SRV_RECORD" >/dev/null

  # start server + relay + iperf
  dexec $( [ "$OFFLOAD" = 0 ] && echo "-e HOLYNET_DISABLE_OFFLOAD=1" ) -e RUST_LOG="${SRV_LOG:-holynet=warn}" \
    -d bench-srv sh -c "/holynet server --config /conf/config.toml start > /tmp/srv.log 2>&1"
  dexec $( [ "$OFFLOAD" = 0 ] && echo "-e HOLYNET_DISABLE_OFFLOAD=1" ) -e RUST_LOG="${RELAY_LOG:-holynet=warn}" \
    -d bench-relay sh -c "/holynet server --config /conf/config.toml start > /tmp/relay.log 2>&1"
  sleep 2
  dexec -d bench-srv sh -c "iperf3 -s -B $TUN_SRV_IP >/tmp/iperf.log 2>&1"
  sleep 1

  c_hdr "HolyNet relay bench (offload=$OFFLOAD, mtu=$MTU, dur=${DUR}s)"
  client_phase baseline || true
  client_phase 2-hop --via "$RELAY_IP:$PORT" || true
  printf '  %-8s (needs multi-hop chaining / source-routing — not built yet)\n' "3-hop"
}

trap 'do_clean' EXIT
case "${1:-run}" in
  run)   do_run ;;
  clean) trap - EXIT; do_clean; docker network rm "$NET" >/dev/null 2>&1 || true ;;
  *) echo "usage: $0 {run|clean}"; exit 1 ;;
esac
