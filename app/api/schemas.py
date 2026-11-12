from pydantic import BaseModel, field_validator
from typing import List


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        v = v.strip()
        scheme, sep, rest = v.partition("://")
        if sep and scheme.lower() in ("http", "https"):
            # Lowercase only the scheme: "HTTPS://x" must not become "https://HTTPS://x".
            v = f"{scheme.lower()}://{rest}"
        else:
            v = f"https://{v}"
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum allowed length of 2048 characters.")
        return v


class DetailedAnalysis(BaseModel):
    indicator: str
    severity: str
    report_paragraph: str
    remediation_strategy: str
    verification_strategy: str


class ScanResponse(BaseModel):
    url: str
    risk_score: int
    severity: str
    transport_risk: int
    phishing_risk: int
    confidence_score: int
    pbh_fingerprint: str
    executive_summary: str
    detailed_analysis: List[DetailedAnalysis]
