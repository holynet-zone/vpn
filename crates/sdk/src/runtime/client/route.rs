//! Client-side multi-hop path planning: Dijkstra over `client + nodes` with RTT
//! as the edge weight (client->node from the client's own probes, node->node from
//! the gossiped overlay). The client alone picks the path; relays stay dumb.

use std::collections::HashMap;

use crate::crypto::PublicKey;
use crate::protocol::{EdgeMetric, NodeEntry};

/// Lowest-latency path to `target`. `client_rtts` are the client's own probes
/// (micros) to reachable nodes; `edges` with `rtt_micros = None` are skipped.
/// Returns `[first_hop, .., target]` (dial `first_hop`, relay through the rest),
/// or `None` if unreachable. A one-element result means connect directly.
pub fn plan_route(
    nodes: &[NodeEntry],
    edges: &[EdgeMetric],
    client_rtts: &[(PublicKey, u32)],
    target: &PublicKey,
) -> Option<Vec<PublicKey>> {
    let n = nodes.len();
    let idx: HashMap<&PublicKey, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, e)| (&e.node_pk, i))
        .collect();
    let target_i = *idx.get(target)?;

    let mut adj: Vec<Vec<(usize, u64)>> = vec![Vec::new(); n];
    for e in edges {
        if let (Some(&f), Some(&t), Some(w)) = (idx.get(&e.from), idx.get(&e.to), e.rtt_micros) {
            adj[f].push((t, w as u64));
        }
    }

    const INF: u64 = u64::MAX;
    let mut dist = vec![INF; n];
    // `prev[i] == None` means the client is `i`'s predecessor (a direct probe).
    let mut prev: Vec<Option<usize>> = vec![None; n];
    let mut visited = vec![false; n];
    for (pk, rtt) in client_rtts {
        if let Some(&i) = idx.get(pk)
            && (*rtt as u64) < dist[i]
        {
            dist[i] = *rtt as u64;
            prev[i] = None;
        }
    }

    // O(V^2) is fine: the node graph is tiny, so no binary heap.
    loop {
        let mut u = None;
        let mut best = INF;
        for v in 0..n {
            if !visited[v] && dist[v] < best {
                best = dist[v];
                u = Some(v);
            }
        }
        let Some(u) = u else { break };
        if u == target_i {
            break;
        }
        visited[u] = true;
        for &(v, w) in &adj[u] {
            let nd = dist[u].saturating_add(w);
            if nd < dist[v] {
                dist[v] = nd;
                prev[v] = Some(u);
            }
        }
    }

    if dist[target_i] == INF {
        return None;
    }
    let mut path = Vec::new();
    let mut cur = target_i;
    loop {
        path.push(nodes[cur].node_pk.clone());
        match prev[cur] {
            Some(p) => cur = p,
            None => break,
        }
    }
    path.reverse();
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use std::net::SocketAddr;

    fn pk() -> PublicKey {
        PublicKey::from_secret(&SecretKey::generate_x25519())
    }

    fn node(k: &PublicKey, label: &str) -> NodeEntry {
        NodeEntry {
            node_pk: k.clone(),
            endpoint: format!("203.0.113.1:{}", 5000 + label.len())
                .parse::<SocketAddr>()
                .unwrap(),
            subnet: "10.0.0.0".parse().unwrap(),
            prefix: 18,
            label: label.into(),
        }
    }

    fn edge(from: &PublicKey, to: &PublicKey, rtt: Option<u32>) -> EdgeMetric {
        EdgeMetric {
            from: from.clone(),
            to: to.clone(),
            rtt_micros: rtt,
            updated_ms: 1,
        }
    }

    #[test]
    fn direct_when_target_is_nearest() {
        let t = pk();
        let nodes = vec![node(&t, "t")];
        let path = plan_route(&nodes, &[], &[(t.clone(), 100)], &t).unwrap();
        assert_eq!(path, vec![t]);
    }

    #[test]
    fn relayed_when_cheaper_than_direct() {
        // client->R = 10, R->T = 10 (total 20) beats client->T direct = 100.
        let r = pk();
        let t = pk();
        let nodes = vec![node(&r, "r"), node(&t, "t")];
        let edges = vec![edge(&r, &t, Some(10))];
        let client = vec![(r.clone(), 10), (t.clone(), 100)];
        let path = plan_route(&nodes, &edges, &client, &t).unwrap();
        assert_eq!(path, vec![r, t]);
    }

    #[test]
    fn multi_hop_chain() {
        // client->A=1, A->B=1, B->T=1 (total 3) beats client->T direct=100.
        let a = pk();
        let b = pk();
        let t = pk();
        let nodes = vec![node(&a, "a"), node(&b, "b"), node(&t, "t")];
        let edges = vec![edge(&a, &b, Some(1)), edge(&b, &t, Some(1))];
        let client = vec![(a.clone(), 1), (t.clone(), 100)];
        let path = plan_route(&nodes, &edges, &client, &t).unwrap();
        assert_eq!(path, vec![a, b, t]);
    }

    #[test]
    fn none_when_unreachable() {
        let a = pk();
        let t = pk();
        let nodes = vec![node(&a, "a"), node(&t, "t")];
        // Client reaches A, but no edge A->T and no direct probe to T.
        let path = plan_route(&nodes, &[], &[(a.clone(), 10)], &t);
        assert!(path.is_none());
    }

    #[test]
    fn unreachable_edge_is_skipped() {
        // A->T is down (None); the direct probe is the only way.
        let a = pk();
        let t = pk();
        let nodes = vec![node(&a, "a"), node(&t, "t")];
        let edges = vec![edge(&a, &t, None)];
        let path = plan_route(&nodes, &edges, &[(a.clone(), 5), (t.clone(), 80)], &t).unwrap();
        assert_eq!(path, vec![t]);
    }
}
