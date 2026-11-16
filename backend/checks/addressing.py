"""
backend/checks/addressing.py  (owner: C)

NET03 - Addressing engine

Public API
----------
    run(topology: dict) -> list[dict]                  # same entry point as checks/resilience.py
    check_addressing(topology: dict, id_prefix: str = "A") -> list[dict]

Pure function: takes the topology JSON (see SCHEMA.md), returns findings in the
agreed format, plus one extra key, "rule", that the UI/report can group by:

    {"id": "A-001", "severity": "error|warning|info", "category": "addressing",
     "rule": "duplicate_ip", "message": "...", "devices": ["h1", "h2"],
     "suggestion": "..."}

Rules implemented
-----------------
    invalid_ip, invalid_mask        malformed address / non-contiguous mask
    reserved_address                network/broadcast/loopback/multicast/etc. used as host IP
    link_local_address              169.254.0.0/16 used (warning)
    unaddressed_interface           connected interface with no IP (warning)
    duplicate_ip                    same IP on two interfaces anywhere in the design
    host_outside_subnet             host not in the subnet of its L2 segment
    router_link_mismatch            router interface not in the subnet of its link/segment
    invalid_gateway, gateway_mismatch, gateway_is_self, gateway_reserved,
    gateway_unreachable, gateway_not_router, missing_gateway
    overlapping_subnets             two separate segments use overlapping/identical subnets
    capacity_exceeded, capacity_tight

Design decisions (say these out loud in the demo)
-------------------------------------------------
* Switches are transparent. Everything joined by links through switches is ONE
  layer-2 segment, and one segment must be one subnet.
* One design = one addressing plan. Duplicate IPs and overlapping subnets are
  flagged design-wide, even between segments that are not connected to each
  other. To scope them to routed-connected segments only, filter in
  _check_duplicates / _check_overlaps.
* IPv4 only.
"""
from __future__ import annotations

import ipaddress
import itertools
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

CATEGORY = "addressing"
_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}

CAPACITY_WARN_RATIO = 0.8      # warn when a subnet is this full...
CAPACITY_WARN_MIN_USABLE = 6   # ...but only for /29 and larger (a full /30 point-to-point is normal)

Node = Tuple[str, ...]  # ("sw", device_id) | ("if", device_id, iface_name)


# --------------------------------------------------------------------------- #
# Data holders
# --------------------------------------------------------------------------- #
@dataclass
class Iface:
    device_id: str
    device_name: str
    device_type: str
    name: str
    ip: Optional[ipaddress.IPv4Address] = None
    prefix: Optional[int] = None
    network: Optional[ipaddress.IPv4Network] = None
    flagged: bool = False  # already reported as invalid; don't also call it "unaddressed"

    @property
    def label(self) -> str:
        return f"{self.device_name} {self.name}".strip()

    @property
    def cidr(self) -> str:
        return f"{self.ip}/{self.prefix}"


@dataclass
class Segment:
    nodes: List[Node]
    switches: List[str] = field(default_factory=list)   # switch names
    members: List[Iface] = field(default_factory=list)  # interfaces with a valid ip+mask
    unaddressed: List[Iface] = field(default_factory=list)
    ref: Optional[ipaddress.IPv4Network] = None          # the subnet this segment "should" be

    def label(self) -> str:
        if self.switches:
            return "segment " + "+".join(sorted(self.switches))
        names = sorted({m.device_name for m in self.members} | {u.device_name for u in self.unaddressed})
        return "link " + "-".join(names)


class _Collector:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def add(self, rule: str, severity: str, message: str, devices: List[str], suggestion: str = "") -> None:
        uniq: List[str] = []
        for d in devices:
            if d not in uniq:
                uniq.append(d)
        self.items.append(
            {"rule": rule, "severity": severity, "message": message, "devices": uniq, "suggestion": suggestion}
        )

    def finalize(self, prefix: str) -> List[Dict[str, Any]]:
        self.items.sort(key=lambda f: (_SEVERITY_RANK[f["severity"]], f["rule"], f["devices"], f["message"]))
        out = []
        for n, f in enumerate(self.items, 1):
            out.append(
                {
                    "id": f"{prefix}-{n:03d}",
                    "severity": f["severity"],
                    "category": CATEGORY,
                    "rule": f["rule"],
                    "message": f["message"],
                    "devices": f["devices"],
                    "suggestion": f["suggestion"],
                }
            )
        return out


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def parse_prefix(mask: Any) -> int:
    """Accept '255.255.255.0', '/24', '24' or 24. Raise ValueError on anything else."""
    if mask is None or isinstance(mask, bool) or str(mask).strip() == "":
        raise ValueError("mask is missing")
    if isinstance(mask, int):
        prefix = mask
    else:
        s = str(mask).strip().lstrip("/")
        if s.isdigit():
            prefix = int(s)
        else:
            value = int(ipaddress.IPv4Address(s))  # AddressValueError is a ValueError
            inverted = ~value & 0xFFFFFFFF
            if inverted & (inverted + 1):
                raise ValueError(f"{mask} is not a contiguous subnet mask")
            return 32 - inverted.bit_length()
    if not 0 <= prefix <= 32:
        raise ValueError(f"prefix length {prefix} is out of range 0-32")
    return prefix


def _usable_hosts(net: ipaddress.IPv4Network) -> int:
    if net.prefixlen == 32:
        return 1
    if net.prefixlen == 31:
        return 2
    return net.num_addresses - 2


def _prefix_for(count: int) -> int:
    """Longest prefix whose usable host count fits `count` interfaces."""
    for p in range(30, -1, -1):
        if 2 ** (32 - p) - 2 >= count:
            return p
    return 0


def _free_address(net: ipaddress.IPv4Network, used: set) -> Optional[ipaddress.IPv4Address]:
    for host in itertools.islice(net.hosts(), 4096):
        if host not in used:
            return host
    return None


# --------------------------------------------------------------------------- #
# Step 1: parse interfaces and check each one in isolation
# --------------------------------------------------------------------------- #
def _build_interfaces(devices: List[Dict[str, Any]], out: _Collector) -> Dict[Tuple[str, str], Iface]:
    ifaces: Dict[Tuple[str, str], Iface] = {}
    for dev in devices:
        if dev.get("type") == "switch":
            continue  # layer 2 only
        did = dev["id"]
        for raw in dev.get("interfaces") or []:
            it = Iface(
                device_id=did,
                device_name=dev.get("name", did),
                device_type=dev.get("type", "host"),
                name=raw.get("name", ""),
            )
            ifaces[(did, it.name)] = it

            ip_raw = raw.get("ip")
            if ip_raw in (None, ""):
                continue
            try:
                it.ip = ipaddress.IPv4Address(str(ip_raw).strip())
            except ValueError:
                it.flagged = True
                out.add(
                    "invalid_ip", "error",
                    f"{it.label} has an invalid IPv4 address '{ip_raw}'",
                    [did], "Use dotted-decimal notation, e.g. 192.168.1.10",
                )
                continue
            try:
                it.prefix = parse_prefix(raw.get("mask"))
            except ValueError as exc:
                it.flagged = True
                out.add(
                    "invalid_mask", "error",
                    f"{it.label} ({ip_raw}) has an invalid subnet mask: {exc}",
                    [did], "Use a contiguous mask such as 255.255.255.0 (/24)",
                )
                continue
            it.network = ipaddress.IPv4Network(f"{it.ip}/{it.prefix}", strict=False)
    return ifaces


def _check_reserved(ifaces: Dict[Tuple[str, str], Iface], used: set, out: _Collector) -> None:
    for it in ifaces.values():
        if it.ip is None or it.network is None:
            continue
        ip, net = it.ip, it.network
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_reserved:
            out.add(
                "reserved_address", "error",
                f"{it.label} uses {ip}, which cannot be assigned to a host (loopback, multicast, unspecified or reserved)",
                [it.device_id], "Use an address from a private range such as 192.168.0.0/16, 172.16.0.0/12 or 10.0.0.0/8",
            )
        elif it.prefix is not None and it.prefix <= 30 and ip == net.network_address:
            free = _free_address(net, used)
            out.add(
                "reserved_address", "error",
                f"{it.label} uses {ip}, the network address of {net}",
                [it.device_id], f"Use a host address in {net}" + (f", e.g. {free}" if free else ""),
            )
        elif it.prefix is not None and it.prefix <= 30 and ip == net.broadcast_address:
            free = _free_address(net, used)
            out.add(
                "reserved_address", "error",
                f"{it.label} uses {ip}, the broadcast address of {net}",
                [it.device_id], f"Use a host address in {net}" + (f", e.g. {free}" if free else ""),
            )
        elif ip.is_link_local:
            out.add(
                "link_local_address", "warning",
                f"{it.label} uses link-local address {ip} (169.254.0.0/16), which is not routable",
                [it.device_id], "Assign a static address from the subnet's range instead",
            )


def _check_duplicates(ifaces: Dict[Tuple[str, str], Iface], used: set, out: _Collector) -> None:
    by_ip: Dict[ipaddress.IPv4Address, List[Iface]] = defaultdict(list)
    for it in ifaces.values():
        if it.ip is not None:
            by_ip[it.ip].append(it)
    for ip, group in by_ip.items():
        if len(group) < 2:
            continue
        names = " and ".join(g.label for g in group)
        # keep the first holder, suggest changing the rest
        hints = []
        for g in group[1:]:
            if g.network is not None:
                free = _free_address(g.network, used)
                hints.append(f"{g.label} -> {free}" if free else g.label)
        suggestion = "Give each interface a unique address" + (f" (e.g. {'; '.join(hints)})" if hints else "")
        out.add("duplicate_ip", "error", f"Duplicate IP {ip} on {names}", [g.device_id for g in group], suggestion)


# --------------------------------------------------------------------------- #
# Step 2: layer-2 segments (switches are transparent)
# --------------------------------------------------------------------------- #
def _build_segments(
    devices: List[Dict[str, Any]],
    links: List[Dict[str, Any]],
    ifaces: Dict[Tuple[str, str], Iface],
) -> Tuple[List[Segment], Dict[Tuple[str, str], Segment]]:
    by_id = {d["id"]: d for d in devices}
    parent: Dict[Node, Node] = {}

    def find(x: Node) -> Node:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: Node, b: Node) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    def endpoint(ep: Optional[Dict[str, Any]]) -> Optional[Node]:
        if not ep:
            return None
        dev = by_id.get(ep.get("device"))
        if dev is None:
            return None
        if dev.get("type") == "switch":
            return ("sw", dev["id"])
        name = ep.get("iface")
        if name is None:
            declared = [i.get("name") for i in dev.get("interfaces") or []]
            if len(declared) != 1:
                return None
            name = declared[0]
        key = (dev["id"], name)
        if key not in ifaces:  # link names an interface the device never declared
            ifaces[key] = Iface(dev["id"], dev.get("name", dev["id"]), dev.get("type", "host"), name)
        return ("if", dev["id"], name)

    for link in links:
        a, b = endpoint(link.get("a")), endpoint(link.get("b"))
        if a is None or b is None:
            continue
        union(a, b)

    groups: Dict[Node, List[Node]] = defaultdict(list)
    for node in list(parent):
        groups[find(node)].append(node)

    segments: List[Segment] = []
    seg_of: Dict[Tuple[str, str], Segment] = {}
    for nodes in sorted(groups.values(), key=lambda ns: min(str(n) for n in ns)):
        nodes.sort(key=str)
        seg = Segment(nodes=nodes)
        for n in nodes:
            if n[0] == "sw":
                seg.switches.append(by_id[n[1]].get("name", n[1]))
            else:
                it = ifaces[(n[1], n[2])]
                seg_of[(n[1], n[2])] = seg
                (seg.members if it.network is not None else seg.unaddressed).append(it)
        seg.ref = _reference(seg.members)
        segments.append(seg)
    return segments, seg_of


def _reference(members: List[Iface]) -> Optional[ipaddress.IPv4Network]:
    """Majority subnet in the segment; ties prefer a router's subnet, then the lowest network."""
    if not members:
        return None
    counts = Counter(m.network for m in members)
    router_counts = Counter(m.network for m in members if m.device_type == "router")
    return sorted(
        counts,
        key=lambda n: (-counts[n], -router_counts[n], int(n.network_address), n.prefixlen),
    )[0]


# --------------------------------------------------------------------------- #
# Step 3: segment-level checks
# --------------------------------------------------------------------------- #
def _check_unaddressed(segments: List[Segment], out: _Collector) -> None:
    for seg in segments:
        for it in seg.unaddressed:
            if it.flagged:
                continue
            out.add(
                "unaddressed_interface", "warning",
                f"{it.label} is connected ({seg.label()}) but has no IP address",
                [it.device_id], "Assign an IP address and mask, or remove the link",
            )


def _describe(members: List[Iface], limit: int = 3) -> str:
    text = ", ".join(f"{m.label} ({m.cidr})" for m in members[:limit])
    return text + (f" and {len(members) - limit} more" if len(members) > limit else "")


def _check_segment_subnets(segments: List[Segment], used: set, out: _Collector) -> None:
    for seg in segments:
        if len(seg.members) < 2 or seg.ref is None:
            continue
        ref = seg.ref
        ref_members = [m for m in seg.members if m.network == ref]
        for m in seg.members:
            if m.network == ref:
                continue
            same_base = m.network.network_address == ref.network_address
            tail = " (same network address, different mask)" if same_base else ""
            free = _free_address(ref, used)
            e_g = f" (for example {free})" if free else ""
            if m.device_type == "router":
                out.add(
                    "router_link_mismatch", "error",
                    f"{m.label} ({m.cidr}) and {_describe(ref_members)} are on the same {seg.label()} "
                    f"but in different subnets ({m.network} vs {ref}){tail}",
                    [m.device_id] + [r.device_id for r in ref_members if r.device_type == "router"],
                    f"Give {m.label} an address in {ref}{e_g}, or change the other side to match",
                )
            else:
                out.add(
                    "host_outside_subnet", "error",
                    f"{m.label} ({m.cidr}) is outside {ref}, the subnet used by "
                    f"{_describe(ref_members)} on the same {seg.label()}{tail}",
                    [m.device_id],
                    f"Move {m.device_name} into {ref}{e_g}, or connect it to a segment that uses {m.network}",
                )


def _check_overlaps(segments: List[Segment], out: _Collector) -> None:
    refs = [s for s in segments if s.ref is not None]
    for s1, s2 in itertools.combinations(refs, 2):
        n1, n2 = s1.ref, s2.ref
        if not n1.overlaps(n2):
            continue

        def blame(s: Segment) -> List[str]:
            routers = [m.device_id for m in s.members if m.device_type == "router"]
            return routers or [m.device_id for m in s.members]

        if n1 == n2:
            msg = f"Subnet {n1} is used on two separate segments: {s1.label()} and {s2.label()}"
        else:
            msg = f"Subnet {n1} ({s1.label()}) overlaps {n2} ({s2.label()})"
        out.add(
            "overlapping_subnets", "error", msg, blame(s1) + blame(s2),
            f"Re-address {s2.label()} into a range that does not overlap {n1}",
        )


def _check_capacity(segments: List[Segment], out: _Collector) -> None:
    for seg in segments:
        if seg.ref is None:
            continue
        ref = seg.ref
        members = [m for m in seg.members if m.network == ref]
        count, usable = len(members), _usable_hosts(ref)
        ids = [m.device_id for m in members]
        if count > usable:
            out.add(
                "capacity_exceeded", "error",
                f"{ref} ({seg.label()}) has {usable} usable addresses but {count} interfaces are connected",
                ids, f"Use a larger subnet, at least /{_prefix_for(count)}",
            )
        elif usable >= CAPACITY_WARN_MIN_USABLE and count / usable >= CAPACITY_WARN_RATIO:
            out.add(
                "capacity_tight", "warning",
                f"{ref} ({seg.label()}) is nearly full: {count} of {usable} usable addresses in use",
                ids, f"Use a larger subnet (e.g. /{max(ref.prefixlen - 1, 0)}) to leave room for growth",
            )


# --------------------------------------------------------------------------- #
# Step 4: host gateways
# --------------------------------------------------------------------------- #
def _check_gateways(
    devices: List[Dict[str, Any]],
    ifaces: Dict[Tuple[str, str], Iface],
    seg_of: Dict[Tuple[str, str], Segment],
    out: _Collector,
) -> None:
    for dev in devices:
        if dev.get("type") != "host":
            continue
        did, name = dev["id"], dev.get("name", dev["id"])
        mine = [i for i in ifaces.values() if i.device_id == did and i.network is not None]
        gw_raw = dev.get("gateway")

        if gw_raw in (None, ""):
            for it in mine:
                seg = seg_of.get((it.device_id, it.name))
                if seg and any(m.device_type == "router" for m in seg.members):
                    out.add(
                        "missing_gateway", "warning",
                        f"{name} has no default gateway but its {seg.label()} has a router, "
                        f"so {name} can only reach its own subnet",
                        [did], "Set the gateway to the router interface address on this segment",
                    )
                    break
            continue

        try:
            gw = ipaddress.IPv4Address(str(gw_raw).strip())
        except ValueError:
            out.add("invalid_gateway", "error", f"{name} has an invalid gateway '{gw_raw}'", [did],
                    "Use dotted-decimal notation, e.g. 192.168.1.1")
            continue
        if not mine:
            continue

        containing = [i for i in mine if gw in i.network]
        if not containing:
            nets = ", ".join(str(i.network) for i in mine)
            out.add(
                "gateway_mismatch", "error",
                f"{name}'s gateway {gw} is not inside its own subnet {nets}, so the host cannot reach it",
                [did], f"Change the gateway to a router address inside {nets}, or re-address {name}",
            )
            continue

        it = containing[0]
        net = it.network
        if gw == it.ip:
            out.add("gateway_is_self", "error", f"{name}'s gateway {gw} is its own IP address", [did],
                    "Point the gateway at the router interface instead")
        elif it.prefix <= 30 and gw in (net.network_address, net.broadcast_address):
            kind = "network" if gw == net.network_address else "broadcast"
            out.add("gateway_reserved", "error", f"{name}'s gateway {gw} is the {kind} address of {net}", [did],
                    "Use the router interface address")
        else:
            seg = seg_of.get((it.device_id, it.name))
            owners = [m for m in (seg.members if seg else []) if m.ip == gw and m is not it]
            if any(o.device_type == "router" for o in owners):
                continue
            if owners:
                out.add(
                    "gateway_not_router", "warning",
                    f"{name}'s gateway {gw} belongs to {owners[0].label}, which is not a router",
                    [did, owners[0].device_id], "Point the gateway at a router interface",
                )
            else:
                out.add(
                    "gateway_unreachable", "error",
                    f"{name}'s gateway {gw} is not assigned to any router interface on its {seg.label() if seg else 'segment'}",
                    [did], f"Add a router interface with {gw} on this segment, or change the gateway to an existing router address",
                )


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def check_addressing(topology: Dict[str, Any], id_prefix: str = "A") -> List[Dict[str, Any]]:
    """Run every addressing rule. Never mutates `topology`."""
    devices = topology.get("devices") or []
    links = topology.get("links") or []
    out = _Collector()

    ifaces = _build_interfaces(devices, out)
    used = {i.ip for i in ifaces.values() if i.ip is not None}

    _check_reserved(ifaces, used, out)
    _check_duplicates(ifaces, used, out)

    segments, seg_of = _build_segments(devices, links, ifaces)
    _check_unaddressed(segments, out)
    _check_segment_subnets(segments, used, out)
    _check_overlaps(segments, out)
    _check_capacity(segments, out)
    _check_gateways(devices, ifaces, seg_of, out)

    return out.finalize(id_prefix)


def run(topology: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Entry point matching checks/resilience.py: findings are numbered A-001, A-002, ..."""
    return check_addressing(topology, id_prefix="A")


if __name__ == "__main__":  # quick self-test: python -m checks.addressing ../samples/c_addressing_broken.json
    import json
    import sys

    if len(sys.argv) != 2:
        sys.exit("usage: python -m checks.addressing <topology.json>")
    with open(sys.argv[1], encoding="utf-8") as fh:
        results = check_addressing(json.load(fh))
    if not results:
        print("No addressing problems found.")
    for f in results:
        print(f"{f['id']} [{f['severity'].upper():7}] {f['rule']}: {f['message']}")
        print(f"          devices: {', '.join(f['devices'])}")
        if f["suggestion"]:
            print(f"          fix: {f['suggestion']}")
    print(f"\n{len(results)} finding(s)")
