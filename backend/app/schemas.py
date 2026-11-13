from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect for phishing/suspicious characteristics")

class RiskFactor(BaseModel):
    rule: str
    weight: float
    description: str

class HomoglyphAnalysis(BaseModel):
    has_punycode: bool
    confusables_found: List[Dict[str, Any]]
    is_spoofed: bool
    decoded_domain: str

class URLScanResponse(BaseModel):
    id: str
    url: str
    normalized_url: str
    hostname: str
    tld: str
    threat_score: float
    classification: str
    domain_entropy: float
    url_length: int
    homoglyph_analysis: HomoglyphAnalysis
    risk_factors: List[RiskFactor]
    created_at: str

class ScanHistoryItem(BaseModel):
    id: str
    url: str
    hostname: str
    threat_score: float
    classification: str
    domain_entropy: float
    risk_factor_count: int
    created_at: str

class BlocklistRuleCreate(BaseModel):
    pattern: str = Field(..., description="Glob or regex pattern to block")
    reason: str = Field(..., description="Reason for blocking")

class BlocklistRuleResponse(BaseModel):
    id: str
    pattern: str
    reason: str
    created_at: str

class ThreatIntelligenceSummary(BaseModel):
    total_scans: int
    malicious_count: int
    suspicious_count: int
    benign_count: int
    average_threat_score: float
    active_blocklist_rules: int
