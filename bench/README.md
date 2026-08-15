# HolyNet throughput bench

Reproducible Docker bench that puts **HolyNet** and **wireguard-go** side by side on
one host over a veth bridge, and — for HolyNet — collects everything needed to reason
about the single-core datapath: iperf3 forward/reverse/parallel throughput, inner-TCP
retransmits, and the counters that tell **loss apart from reordering**
(UDP `*Errors`, TCP `DSACKRecv`/`OFOQueue`, qdisc/iface drops), plus an optional
on-CPU `perf` profile of the server.

## Prerequisites

- Docker, and the current user in the `docker` group.
- Host tools: `python3`, `perf` (only for `PROFILE=1`, needs `sudo`).
- `bench/wgkeys.env` — static WireGuard keypairs for the wg comparison (already checked in).

## Usage

```bash
bench/run.sh build      # build vpnbench image + release binary (host glibc)
bench/run.sh holynet    # bench HolyNet only
bench/run.sh wg         # bench wireguard-go only
bench/run.sh all        # both                     (default)
bench/run.sh clean      # tear down containers + network
```

The HolyNet binary is the host `target/release/holynet` bind-mounted into an Arch
container (host and container are both glibc/Arch — no musl rebuild needed). Run
`bench/run.sh build` after code changes, or `cargo build --release -p holynet` yourself.

## Knobs (env vars)

| var       | default | meaning                                                         |
|-----------|---------|-----------------------------------------------------------------|
| `DUR`     | 20      | seconds per test                                                |
| `STREAMS` | 8       | parallel-stream count for the `-P` test                         |
| `MTU`     | 1420    | tunnel MTU                                                      |
| `OFFLOAD` | 1       | HolyNet TUN GRO/TSO offload (`0` ⇒ `HOLYNET_DISABLE_OFFLOAD=1`) |
| `WORKERS` | 0       | server worker/socket count (`0` = nproc)                        |
| `PROFILE` | 0       | `1` ⇒ `perf record` the server datapath during fwd (needs sudo) |
| `TUNE`    | 0       | `1` ⇒ raise rmem/wmem ceilings + `fq` qdisc in containers       |

Examples:

```bash
DUR=15 WORKERS=1 bench/run.sh holynet     # single worker (isolates reordering)
OFFLOAD=0 bench/run.sh holynet            # per-packet path, no GSO/GRO batching
PROFILE=1 bench/run.sh holynet            # + on-CPU flamegraph data in bench/.run/perf.data
```

## Reading the output

- **`retr`** is inner-TCP retransmits. High `retr` with **zero** UDP/qdisc/iface drops
  and high **`TCPDSACKRecv`** = *spurious* retransmits from **reordering**, not loss.
- **`TCPOFOQueue`** on the receiver counts out-of-order packets queued — the direct
  reordering signal.
- All raw iperf3 JSON + `perf.data` land in `bench/.run/` (gitignored).
