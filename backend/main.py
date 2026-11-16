from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from checks.addressing import check_addressing
from checks.resilience import run as check_resilience

app = FastAPI(title="NetGuard API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/validate")
def validate(topology: dict):
    topo = {
        "devices": topology.get("devices", []),
        "links": topology.get("links", []),
    }
    findings = check_addressing(topo) + check_resilience(topo)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 3))
    return findings