"""backend/checks/resilience.py  (owner: D)"""
INFRA = {"router", "switch"}


def _build_graph(topology):
    # Keep graph operations local so this check does not require NetworkX.
    g = {"nodes": {}, "adj": {}, "counts": {}}
    for d in topology["devices"]:
        node = d["id"]
        g["nodes"][node] = {"type": d["type"], "name": d.get("name", node)}
        g["adj"][node] = set()
    for link in topology["links"]:
        a, b = link["a"]["device"], link["b"]["device"]
        if a == b or a not in g["nodes"] or b not in g["nodes"]:
            continue
        edge = frozenset((a, b))
        g["adj"][a].add(b)
        g["adj"][b].add(a)
        g["counts"][edge] = g["counts"].get(edge, 0) + 1
    return g


def _parts(graph):
    """Connected components, largest first, deterministic order."""
    unseen = set(graph["adj"])
    components = []
    while unseen:
        start = min(unseen)
        unseen.remove(start)
        pending = [start]
        component = set()
        while pending:
            node = pending.pop()
            component.add(node)
            discovered = graph["adj"][node] & unseen
            unseen.difference_update(discovered)
            pending.extend(discovered)
        components.append(component)
    return sorted(components, key=lambda c: (-len(c), sorted(c)))


def _induced_graph(graph, nodes):
    nodes = set(nodes)
    return {
        "nodes": {n: graph["nodes"][n] for n in nodes},
        "adj": {n: graph["adj"][n] & nodes for n in nodes},
        "counts": {edge: count for edge, count in graph["counts"].items()
                   if edge <= nodes},
    }


def _articulation_points(graph):
    baseline = len(_parts(graph))
    result = []
    for node in graph["adj"]:
        remaining = graph["adj"].keys() - {node}
        if len(_parts(_induced_graph(graph, remaining))) > baseline:
            result.append(node)
    return result


def _bridges(graph):
    baseline = len(_parts(graph))
    for edge, count in graph["counts"].items():
        if count > 1:
            continue
        u, v = tuple(edge)
        reduced = {"adj": {n: set(neighbors)
                           for n, neighbors in graph["adj"].items()}}
        reduced["adj"][u].remove(v)
        reduced["adj"][v].remove(u)
        if len(_parts(reduced)) > baseline:
            yield u, v


def run(topology):
    g = _build_graph(topology)
    name = lambda n: g["nodes"][n]["name"]
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
    infra_nodes = [n for n, attrs in g["nodes"].items()
                   if attrs["type"] in INFRA]
    infra = _induced_graph(g, infra_nodes)

    for node in sorted(_articulation_points(infra)):
        component = next(part for part in _parts(infra) if node in part)
        scope = _induced_graph(infra, component - {node})
        parts = _parts(scope)
        cut_off = sorted(n for p in parts[1:] for n in p)
        add("error", "resilience",
            f"{name(node)} is a single point of failure: if it fails, the network "
            f"splits into {len(parts)} parts and {', '.join(name(n) for n in cut_off)} "
            f"lose connectivity to the main part",
            [node] + cut_off,
            "Add a redundant link or second device so traffic has an alternate path")

    for u, v in _bridges(infra):
        add("warning", "resilience",
            f"Link {name(u)}-{name(v)} is a single point of failure: it is the "
            f"only path between two parts of the network",
            [u, v],
            "Add a second link between these devices or an alternate route")

    # 3. Hosts with a single uplink
    uplinks = {}
    for n, attrs in g["nodes"].items():
        if attrs["type"] == "host" and len(g["adj"][n]) == 1:
            (peer,) = g["adj"][n]
            if g["counts"][frozenset((n, peer))] == 1:
                uplinks.setdefault(peer, []).append(n)
    for peer, hosts in sorted(uplinks.items()):
        names = ", ".join(sorted(name(h) for h in hosts))
        add("info", "resilience",
            f"{names} depend on {name(peer)} as their only connection",
            sorted(hosts) + [peer],
            "Fine for end-user PCs; servers should connect to two switches")

    return findings


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