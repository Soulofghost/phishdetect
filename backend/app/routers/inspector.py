import uuid
import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from app.database import get_db_connection
from app.schemas import URLScanRequest, URLScanResponse, ScanHistoryItem, ThreatIntelligenceSummary
from app.engine.detector import analyze_url

router = APIRouter(prefix="/inspect", tags=["URL Inspector"])

@router.post("", response_model=URLScanResponse, status_code=201)
def inspect_url(req: URLScanRequest):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # Run heuristic and lexical analysis
    analysis = analyze_url(raw_url)
    scan_id = "scan-" + str(uuid.uuid4())[:8]
    now_iso = datetime.now(timezone.utc).isoformat()

    details_payload = {
        "homoglyph_analysis": analysis["homoglyph_analysis"],
        "risk_factors": analysis["risk_factors"],
        "normalized_url": analysis["normalized_url"],
        "tld": analysis["tld"],
        "url_length": analysis["url_length"]
    }

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (
                id, url, hostname, threat_score, classification,
                domain_entropy, risk_factor_count, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, analysis["url"], analysis["hostname"], analysis["threat_score"],
            analysis["classification"], analysis["domain_entropy"], len(analysis["risk_factors"]),
            json.dumps(details_payload), now_iso
        ))
        conn.commit()

    return URLScanResponse(
        id=scan_id,
        url=analysis["url"],
        normalized_url=analysis["normalized_url"],
        hostname=analysis["hostname"],
        tld=analysis["tld"],
        threat_score=analysis["threat_score"],
        classification=analysis["classification"],
        domain_entropy=analysis["domain_entropy"],
        url_length=analysis["url_length"],
        homoglyph_analysis=analysis["homoglyph_analysis"],
        risk_factors=analysis["risk_factors"],
        created_at=now_iso
    )

@router.get("/history", response_model=List[ScanHistoryItem])
def get_scan_history(
    limit: int = Query(50, ge=1, le=200),
    classification: Optional[str] = None
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT id, url, hostname, threat_score, classification, domain_entropy, risk_factor_count, created_at FROM scans"
        params = []
        if classification:
            query += " WHERE classification = ?"
            params.append(classification.upper())
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        return [
            ScanHistoryItem(
                id=r["id"],
                url=r["url"],
                hostname=r["hostname"],
                threat_score=r["threat_score"],
                classification=r["classification"],
                domain_entropy=r["domain_entropy"],
                risk_factor_count=r["risk_factor_count"],
                created_at=r["created_at"]
            )
            for r in rows
        ]

@router.get("/summary", response_model=ThreatIntelligenceSummary)
def get_summary():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        total = cursor.execute("SELECT count(*) FROM scans").fetchone()[0]
        mal = cursor.execute("SELECT count(*) FROM scans WHERE classification = 'MALICIOUS'").fetchone()[0]
        susp = cursor.execute("SELECT count(*) FROM scans WHERE classification = 'SUSPICIOUS'").fetchone()[0]
        benign = cursor.execute("SELECT count(*) FROM scans WHERE classification = 'BENIGN'").fetchone()[0]
        avg_score_row = cursor.execute("SELECT AVG(threat_score) FROM scans").fetchone()[0]
        avg_score = round(float(avg_score_row), 1) if avg_score_row is not None else 0.0
        rules_count = cursor.execute("SELECT count(*) FROM blocklist").fetchone()[0]

        return ThreatIntelligenceSummary(
            total_scans=total,
            malicious_count=mal,
            suspicious_count=susp,
            benign_count=benign,
            average_threat_score=avg_score,
            active_blocklist_rules=rules_count
        )
