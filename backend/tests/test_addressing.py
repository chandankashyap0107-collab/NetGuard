import copy
import json
import pathlib

import pytest

from checks.addressing import check_addressing, parse_prefix, run

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "samples"


# ----------------------------- builders ----------------------------------- #
def router(id, name, *ifaces):
    return {"id": id, "type": "router", "name": name,
            "interfaces": [{"name": n, "ip": ip, "mask": m} for n, ip, m in ifaces]}


def host(id, name, ip, mask="255.255.255.0", gateway=None, iface="eth0"):
    d = {"id": id, "type": "host", "name": name,
         "interfaces": [{"name": iface, "ip": ip, "mask": mask}]}
    if gateway is not None:
        d["gateway"] = gateway
    return d


def switch(id, name):
    return {"id": id, "type": "switch", "name": name, "interfaces": []}


def L(n, a, b):
    def ep(x):
        return {"device": x[0], "iface": x[1]} if len(x) == 2 else {"device": x[0]}
    return {"id": f"l{n}", "a": ep(a), "b": ep(b)}


def topo(devices, links):
    return {"devices": devices, "links": links}


def rules(findings):
    return {f["rule"] for f in findings}


def lan(extra_hosts=(), router_ip="192.168.1.1"):
    """R1 -- SW1 -- hosts, all in 192.168.1.0/24."""
    devices = [router("r1", "R1", ("g0/0", router_ip, "255.255.255.0")), switch("sw1", "SW1")]
    links = [L(1, ("r1", "g0/0"), ("sw1",))]
    for i, h in enumerate(extra_hosts, start=2):
        devices.append(h)
        links.append(L(i, ("sw1",), (h["id"], "eth0")))
    return topo(devices, links)


# ----------------------------- samples ------------------------------------ #
def test_clean_sample_has_no_findings():
    t = json.loads((SAMPLES / "c_addressing_clean.json").read_text())
    assert check_addressing(t) == []


def test_broken_sample_triggers_expected_rules():
    t = json.loads((SAMPLES / "c_addressing_broken.json").read_text())
    assert rules(check_addressing(t)) == {
        "duplicate_ip", "gateway_mismatch", "gateway_unreachable", "host_outside_subnet",
        "overlapping_subnets", "router_link_mismatch", "capacity_tight", "missing_gateway",
    }


# ----------------------------- contract ----------------------------------- #
def test_finding_shape_and_unique_ids():
    t = json.loads((SAMPLES / "c_addressing_broken.json").read_text())
    findings = check_addressing(t)
    ids = [f["id"] for f in findings]
    assert len(ids) == len(set(ids))
    for f in findings:
        assert set(f) == {"id", "severity", "category", "rule", "message", "devices", "suggestion"}
        assert f["severity"] in {"error", "warning", "info"}
        assert f["category"] == "addressing"
        assert isinstance(f["devices"], list) and f["devices"]


def test_errors_sorted_before_warnings():
    t = json.loads((SAMPLES / "c_addressing_broken.json").read_text())
    sev = [f["severity"] for f in check_addressing(t)]
    assert sev == sorted(sev, key=["error", "warning", "info"].index)


def test_input_is_not_mutated():
    t = json.loads((SAMPLES / "c_addressing_broken.json").read_text())
    before = copy.deepcopy(t)
    check_addressing(t)
    assert t == before


def test_empty_and_minimal_topologies():
    assert check_addressing({}) == []
    assert check_addressing({"devices": [], "links": []}) == []


# ----------------------------- parsing ------------------------------------ #
@pytest.mark.parametrize("mask,prefix", [
    ("255.255.255.0", 24), ("/24", 24), ("24", 24), (24, 24),
    ("255.255.255.255", 32), ("0.0.0.0", 0), ("255.255.255.252", 30),
])
def test_parse_prefix_ok(mask, prefix):
    assert parse_prefix(mask) == prefix


@pytest.mark.parametrize("bad", ["255.0.255.0", "0.0.0.255", "33", "abc", "", None, "255.255.255"])
def test_parse_prefix_rejects(bad):
    with pytest.raises(ValueError):
        parse_prefix(bad)


def test_invalid_ip_and_mask_reported():
    t = lan([host("h1", "PC1", "192.168.1.999"), host("h2", "PC2", "192.168.1.5", mask="255.0.255.0")])
    found = check_addressing(t)
    assert {"invalid_ip", "invalid_mask"} <= rules(found)


def test_cidr_style_mask_accepted():
    t = lan([host("h1", "PC1", "192.168.1.10", mask="/24", gateway="192.168.1.1")])
    assert check_addressing(t) == []


# ----------------------------- per-interface ------------------------------ #
def test_network_and_broadcast_address_rejected():
    t = lan([host("h1", "PC1", "192.168.1.0", gateway="192.168.1.1"),
             host("h2", "PC2", "192.168.1.255", gateway="192.168.1.1")])
    assert [f["rule"] for f in check_addressing(t)].count("reserved_address") == 2


def test_loopback_and_link_local():
    t = lan([host("h1", "PC1", "127.0.0.1"), host("h2", "PC2", "169.254.1.1")])
    r = {f["rule"]: f["severity"] for f in check_addressing(t)}
    assert r["reserved_address"] == "error"
    assert r["link_local_address"] == "warning"


def test_slash31_point_to_point_is_clean():
    t = topo([router("r1", "R1", ("g0/0", "10.0.0.0", "255.255.255.254")),
              router("r2", "R2", ("g0/0", "10.0.0.1", "255.255.255.254"))],
             [L(1, ("r1", "g0/0"), ("r2", "g0/0"))])
    assert check_addressing(t) == []


def test_unaddressed_connected_interface_warns():
    t = lan([{"id": "h1", "type": "host", "name": "PC1", "interfaces": [{"name": "eth0"}]}])
    assert "unaddressed_interface" in rules(check_addressing(t))


# ----------------------------- duplicates --------------------------------- #
def test_duplicate_ip_same_segment():
    t = lan([host("h1", "PC1", "192.168.1.10", gateway="192.168.1.1"),
             host("h2", "PC2", "192.168.1.10", gateway="192.168.1.1")])
    f = [x for x in check_addressing(t) if x["rule"] == "duplicate_ip"]
    assert len(f) == 1 and set(f[0]["devices"]) == {"h1", "h2"}


def test_router_ip_conflicts_with_host():
    t = lan([host("h1", "PC1", "192.168.1.1", gateway="192.168.1.1")])
    assert "duplicate_ip" in rules(check_addressing(t))


# ----------------------------- subnet membership -------------------------- #
def test_host_outside_subnet():
    t = lan([host("h1", "PC1", "192.168.2.10", gateway="192.168.2.1")])
    f = check_addressing(t)
    assert "host_outside_subnet" in rules(f)
    assert [x for x in f if x["rule"] == "host_outside_subnet"][0]["devices"] == ["h1"]


def test_mask_mismatch_same_network_address():
    t = lan([host("h1", "PC1", "192.168.1.10", mask="255.255.255.128", gateway="192.168.1.1")])
    msg = [x for x in check_addressing(t) if x["rule"] == "host_outside_subnet"][0]["message"]
    assert "different mask" in msg


def test_router_misconfigured_blames_the_router_not_three_hosts():
    hosts = [host(f"h{i}", f"PC{i}", f"192.168.1.{10 + i}", gateway="192.168.1.1") for i in range(3)]
    t = lan(hosts, router_ip="10.9.9.1")
    mism = [x for x in check_addressing(t) if x["rule"] in {"router_link_mismatch", "host_outside_subnet"}]
    assert len(mism) == 1 and mism[0]["rule"] == "router_link_mismatch"


def test_router_to_router_link_mismatch():
    t = topo([router("r1", "R1", ("g0/0", "10.0.0.1", "255.255.255.252")),
              router("r2", "R2", ("g0/0", "10.0.1.2", "255.255.255.252"))],
             [L(1, ("r1", "g0/0"), ("r2", "g0/0"))])
    f = [x for x in check_addressing(t) if x["rule"] == "router_link_mismatch"]
    assert len(f) == 1 and set(f[0]["devices"]) == {"r1", "r2"}


def test_two_switches_form_one_segment():
    t = topo([router("r1", "R1", ("g0/0", "192.168.1.1", "255.255.255.0")),
              switch("sw1", "SW1"), switch("sw2", "SW2"),
              host("h1", "PC1", "192.168.1.10", gateway="192.168.1.1"),
              host("h2", "PC2", "192.168.7.10", gateway="192.168.7.1")],
             [L(1, ("r1", "g0/0"), ("sw1",)), L(2, ("sw1",), ("sw2",)),
              L(3, ("sw1",), ("h1", "eth0")), L(4, ("sw2",), ("h2", "eth0"))])
    assert "host_outside_subnet" in rules(check_addressing(t))


# ----------------------------- gateways ----------------------------------- #
def test_gateway_outside_host_subnet():
    t = lan([host("h1", "PC1", "192.168.1.10", gateway="192.168.2.1")])
    assert "gateway_mismatch" in rules(check_addressing(t))


def test_gateway_not_on_any_router():
    t = lan([host("h1", "PC1", "192.168.1.10", gateway="192.168.1.200")])
    assert "gateway_unreachable" in rules(check_addressing(t))


def test_gateway_is_self():
    t = lan([host("h1", "PC1", "192.168.1.10", gateway="192.168.1.10")])
    assert "gateway_is_self" in rules(check_addressing(t))


def test_gateway_is_another_host():
    t = lan([host("h1", "PC1", "192.168.1.10", gateway="192.168.1.11"),
             host("h2", "PC2", "192.168.1.11", gateway="192.168.1.1")])
    assert "gateway_not_router" in rules(check_addressing(t))


def test_gateway_reserved_and_invalid():
    t = lan([host("h1", "PC1", "192.168.1.10", gateway="192.168.1.255"),
             host("h2", "PC2", "192.168.1.11", gateway="not-an-ip")])
    assert {"gateway_reserved", "invalid_gateway"} <= rules(check_addressing(t))


def test_missing_gateway_only_when_a_router_is_present():
    with_router = lan([host("h1", "PC1", "192.168.1.10")])
    assert "missing_gateway" in rules(check_addressing(with_router))
    no_router = topo([switch("sw1", "SW1"), host("h1", "PC1", "192.168.1.10"),
                      host("h2", "PC2", "192.168.1.11")],
                     [L(1, ("sw1",), ("h1", "eth0")), L(2, ("sw1",), ("h2", "eth0"))])
    assert check_addressing(no_router) == []


# ----------------------------- overlaps ----------------------------------- #
def _two_lans(net_a, net_b):
    (ra, ma), (rb, mb) = net_a, net_b
    return topo([router("r1", "R1", ("g0/0", ra, ma), ("g0/1", rb, mb)),
                 switch("sw1", "SW1"), switch("sw2", "SW2")],
                [L(1, ("r1", "g0/0"), ("sw1",)), L(2, ("r1", "g0/1"), ("sw2",))])


def test_partial_overlap():
    t = _two_lans(("192.168.1.1", "255.255.255.0"), ("192.168.1.129", "255.255.255.128"))
    assert "overlapping_subnets" in rules(check_addressing(t))


def test_identical_subnet_on_two_segments():
    t = _two_lans(("192.168.1.1", "255.255.255.0"), ("192.168.1.2", "255.255.255.0"))
    msg = [x for x in check_addressing(t) if x["rule"] == "overlapping_subnets"][0]["message"]
    assert "two separate segments" in msg


def test_adjacent_subnets_do_not_overlap():
    t = _two_lans(("192.168.1.1", "255.255.255.0"), ("192.168.2.1", "255.255.255.0"))
    assert check_addressing(t) == []


# ----------------------------- capacity ----------------------------------- #
def test_capacity_exceeded_slash30_with_three_devices():
    t = topo([router("r1", "R1", ("g0/0", "10.0.0.1", "255.255.255.252")), switch("sw1", "SW1"),
              host("h1", "PC1", "10.0.0.2", "255.255.255.252", gateway="10.0.0.1"),
              host("h2", "PC2", "10.0.0.2", "255.255.255.252", gateway="10.0.0.1")],
             [L(1, ("r1", "g0/0"), ("sw1",)), L(2, ("sw1",), ("h1", "eth0")), L(3, ("sw1",), ("h2", "eth0"))])
    f = [x for x in check_addressing(t) if x["rule"] == "capacity_exceeded"]
    assert len(f) == 1 and "/29" in f[0]["suggestion"]


def test_full_slash30_point_to_point_is_not_flagged():
    t = topo([router("r1", "R1", ("g0/0", "10.0.0.1", "255.255.255.252")),
              router("r2", "R2", ("g0/0", "10.0.0.2", "255.255.255.252"))],
             [L(1, ("r1", "g0/0"), ("r2", "g0/0"))])
    assert check_addressing(t) == []


# ----------------------------- repo convention ---------------------------- #
def test_run_matches_resilience_entry_point_and_id_style():
    t = json.loads((SAMPLES / "c_addressing_broken.json").read_text())
    found = run(t)
    assert found and all(f["id"].startswith("A-") for f in found)
    assert found == check_addressing(t, id_prefix="A")
