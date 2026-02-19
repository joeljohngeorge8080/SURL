from pydantic import BaseModel


class ScanRequest(BaseModel):
    url: str


from typing import List
from pydantic import BaseModel

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
    pbh_fingerprint: str
    executive_summary: str
    detailed_analysis: List[DetailedAnalysis]
