from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="CSBI Scam Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    url: str
    trust_score: int
    risk_level: str
    scam_probability: float
    csbi: float
    reasons: list[str]
    cluster_tag: str | None

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    # STUB — replaced with the real pipeline in Step 6
    return ScanResponse(
        url=req.url,
        trust_score=32,
        risk_level="HIGH",
        scam_probability=0.68,
        csbi=65.0,
        reasons=[
            "Domain registered 3 days ago",
            "Brand impersonation: PayPal",
            "Urgency language detected",
        ],
        cluster_tag="Cluster #4 — fake government-subsidy template",
    )