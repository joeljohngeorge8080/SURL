from pydantic import BaseModel


class ScanRequest(BaseModel):
    url: str


class ScanResponse(BaseModel):
    url: str
    timestamp: str
    engine_version: str
    risk_score: int
    severity: str
    pbh_fingerprint: str
    binary_pattern: str
    analysis: list
