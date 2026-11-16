"""backend/checks/resilience.py  (owner: D)"""
import networkx as nx

INFRA = {"router", "switch"}


def _build_graph(topology):
    g = nx.Graph()
    for d in topology["devices"]:
        g.add_node(d["id"], type=d["type"], name=d.get("name", d["id"]))
    for link in topology["links"]:
        a, b = link["a"]["device"], link["b"]["device"]
        if a == b or a not in g or b not in g:
            continue
        if g.has_edge(a, b):
            g[a][b]["count"] += 1      # parallel links = redundancy
        else:
            g.add_edge(a, b, count=1)
    return g


def _parts(graph):
    """Connected components, largest first, deterministic order."""
    return sorted(nx.connected_components(graph),
                  key=lambda c: (-len(c), sorted(c)))


def _infra(g):
    return g.subgraph([n for n, t in g.nodes(data="type") if t in INFRA]).copy()


def run(topology):
    g = _build_graph(topology)
    name = lambda n: g.nodes[n]["name"]
    findings = []

    def add(severity, category, message, devices, suggestion):
        findings.append({
            "id": f"R-{len(findings) + 1:03d}",
            "severity": severity,
            "category": category,
            "message": message,
            "devices": devices,
            "suggestion": suggestion,
        })

    # 1. Isolated segments
    for comp in _parts(g)[1:]:
        names = ", ".join(sorted(name(n) for n in comp))
        add("error", "structure",
            f"Isolated segment: {names} cannot reach the rest of the network",
            sorted(comp),
            "Connect this segment to the main network with at least one link")

    # 2. Single points of failure among routers/switches
    infra = _infra(g)

    for node in sorted(nx.articulation_points(infra)):
        scope = infra.subgraph(nx.node_connected_component(infra, node)).copy()
        scope.remove_node(node)
        parts = _parts(scope)
        cut_off = sorted(n for p in parts[1:] for n in p)
        add("error", "resilience",
            f"{name(node)} is a single point of failure: if it fails, the network "
            f"splits into {len(parts)} parts and {', '.join(name(n) for n in cut_off)} "
            f"lose connectivity to the main part",
            [node] + cut_off,
            "Add a redundant link or second device so traffic has an alternate path")

    for u, v in nx.bridges(infra):
        if infra[u][v]["count"] > 1:
            continue
        add("warning", "resilience",
            f"Link {name(u)}-{name(v)} is a single point of failure: it is the "
            f"only path between two parts of the network",
            [u, v],
            "Add a second link between these devices or an alternate route")

    # 3. Hosts with a single uplink
    uplinks = {}
    for n, t in g.nodes(data="type"):
        if t == "host" and g.degree(n) == 1:
            (peer,) = g.neighbors(n)
            if g[n][peer]["count"] == 1:
                uplinks.setdefault(peer, []).append(n)
    for peer, hosts in sorted(uplinks.items()):
        names = ", ".join(sorted(name(h) for h in hosts))
        verb = "depends" if len(hosts) == 1 else "depend"
        add("info", "resilience",
            f"{names} {verb} on {name(peer)} as their only connection",
            sorted(hosts) + [peer],
            "Fine for end-user PCs; servers should connect to two switches")
        # 4. Layer 2 loops (cycles made only of switches; routers stop broadcasts)
    switches = g.subgraph([n for n, t in g.nodes(data="type") if t == "switch"])
    for comp in _parts(switches):
        sub = switches.subgraph(comp)
        link_count = sum(d["count"] for _, _, d in sub.edges(data=True))
        loops = link_count - len(comp) + 1     # independent loops in this group
        if loops > 0:
            names = ", ".join(sorted(name(n) for n in comp))
            add("warning", "resilience",
                f"Layer 2 loop among switches {names} ({loops} independent "
                f"loop{'s' if loops > 1 else ''}). Without Spanning Tree Protocol, "
                f"broadcasts circulate forever and can bring the network down",
                sorted(comp),
                "Enable STP/RSTP on these switches, or remove a link to break the loop")
    return findings


def simulate_failure(topology, device_id):
    """What-if: remove one device and report the damage."""
    g = _build_graph(topology)
    if device_id not in g:
        raise ValueError(f"Unknown device: {device_id}")

    failed_name = g.nodes[device_id]["name"]
    had_router = any(t == "router" for _, t in g.nodes(data="type"))
    g.remove_node(device_id)

    parts = _parts(g)
    cut_off = sorted(n for p in parts[1:] for n in p)

    hosts_without_router = []
    if had_router:
        for p in parts:
            if not any(g.nodes[x]["type"] == "router" for x in p):
                hosts_without_router += [n for n in p if g.nodes[n]["type"] == "host"]

    return {
        "failed": device_id,
        "failed_name": failed_name,
        "parts": len(parts),
        "cut_off": cut_off,
        "hosts_without_router": sorted(hosts_without_router),
    }


def redundancy_score(topology):
    """0-100 score: 50% device redundancy, 30% link redundancy, 20% connectivity."""
    g = _build_graph(topology)
    infra = _infra(g)

    n_infra = infra.number_of_nodes()
    spof_nodes = len(list(nx.articulation_points(infra)))
    device_part = 1 - spof_nodes / n_infra if n_infra else 1.0

    n_links = infra.number_of_edges()
    bridges = sum(1 for u, v in nx.bridges(infra) if infra[u][v]["count"] == 1)
    link_part = 1 - bridges / n_links if n_links else 1.0

    total = g.number_of_nodes()
    conn_part = len(_parts(g)[0]) / total if total else 1.0

    score = round(50 * device_part + 30 * link_part + 20 * conn_part)
    label = "Good" if score >= 80 else "Fair" if score >= 50 else "Poor"
    return {
        "score": score,
        "label": label,
        "breakdown": {
            "devices": round(device_part * 100),
            "links": round(link_part * 100),
            "connectivity": round(conn_part * 100),
        },
    }


if __name__ == "__main__":
    def topo(devs, links):
        return {
            "devices": [{"id": i, "type": t, "name": i.upper()} for i, t in devs],
            "links": [{"id": f"l{k}", "a": {"device": a}, "b": {"device": b}}
                      for k, (a, b) in enumerate(links)],
        }

    devs = [("r1", "router"), ("sw1", "switch"), ("sw2", "switch"),
            ("h1", "host"), ("h2", "host"), ("h3", "host")]
    chain = [("r1", "sw1"), ("sw1", "sw2"), ("sw1", "h1"),
             ("sw2", "h2"), ("sw2", "h3")]

    for label, links in [("CHAIN", chain),
                         ("WITH REDUNDANT LINK", chain + [("r1", "sw2")])]:
        print(f"\n== {label} ==")
        for f in run(topo(devs, links)):
            print(f["id"], f["severity"], "-", f["message"])

    print("\n== WHAT IF SW1 FAILS? (chain) ==")
    print(simulate_failure(topo(devs, chain), "sw1"))
    print("\n== SCORES ==")
    print("CHAIN    ", redundancy_score(topo(devs, chain)))
    print("REDUNDANT", redundancy_score(topo(devs, chain + [("r1", "sw2")])))
    loop_devs = [("r1", "router"), ("sw1", "switch"), ("sw2", "switch"),
                 ("sw3", "switch"), ("h1", "host")]
    triangle = [("r1", "sw1"), ("sw1", "sw2"), ("sw2", "sw3"),
                ("sw3", "sw1"), ("sw3", "h1")]
    print("\n== SWITCH TRIANGLE ==")
    for f in run(topo(loop_devs, triangle)):
        print(f["id"], f["severity"], "-", f["message"])

    print("\n== L2 LOOP CHECK ==")
    cases = [("chain", chain),
             ("router triangle", chain + [("r1", "sw2")]),
             ("parallel switch link", chain + [("sw1", "sw2")])]
    for label, links in cases:
        found = [f for f in run(topo(devs, links)) if "Layer 2 loop" in f["message"]]
        print(f"{label:22} -> {len(found)} loop warning(s)")