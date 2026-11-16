# Topology Schema

## Topology JSON
```json
{
  "devices": [
    {"id": "r1", "type": "router", "name": "R1",
     "interfaces": [{"name": "g0/0", "ip": "192.168.1.1", "mask": "255.255.255.0"}]},
    {"id": "sw1", "type": "switch", "name": "SW1", "interfaces": []},
    {"id": "h1", "type": "host", "name": "PC1",
     "interfaces": [{"name": "eth0", "ip": "192.168.1.10", "mask": "255.255.255.0"}],
     "gateway": "192.168.1.1"}
  ],
  "links": [
    {"id": "l1", "a": {"device": "r1", "iface": "g0/0"}, "b": {"device": "sw1"}},
    {"id": "l2", "a": {"device": "sw1"}, "b": {"device": "h1", "iface": "eth0"}}
  ]
}
```

## Rules
- Device `type` is one of: `router`, `switch`, `host`.
- `ip` and `mask` are strings in dotted format.
- `gateway` exists only on hosts and is optional.
- Link endpoints use `{"device": "id", "iface": "name"}`. `iface` is omitted for switches.

## Finding format
```json
{"id": "F-001", "severity": "error",
 "category": "addressing",
 "message": "Duplicate IP 192.168.1.10 on PC1 and PC2",
 "devices": ["h1", "h2"],
 "suggestion": "Change PC2 to an unused address in 192.168.1.0/24"}
```
- `severity`: `error`, `warning`, or `info`
- `category`: `addressing`, `resilience`, or `structure`