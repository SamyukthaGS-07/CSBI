from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl

from csbi.pipeline import run_pipeline

app = FastAPI(title="CSBI Scam Detection API")


class ScanRequest(BaseModel):
    url: HttpUrl


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    record = run_pipeline(str(request.url))
    return record.to_dict()
