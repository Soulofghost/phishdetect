import os
import pytest
from fastapi.testclient import TestClient

os.environ["PHISHDETECT_DB"] = "test_phishdetect_api.db"

from app.database import init_db
from app.main import app

@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    if os.path.exists("test_phishdetect_api.db"):
        os.remove("test_phishdetect_api.db")
    init_db()
    yield
    if os.path.exists("test_phishdetect_api.db"):
        try:
            os.remove("test_phishdetect_api.db")
        except Exception:
            pass

client = TestClient(app)

def test_health_check():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "PhishDetect" in data["service"]

def test_inspect_urls_api():
    # 1. Benign URL
    benign_res = client.post("/api/v1/inspect", json={"url": "https://docs.python.org/3/"})
    assert benign_res.status_code == 201
    benign_data = benign_res.json()
    assert benign_data["classification"] == "BENIGN"
    assert benign_data["threat_score"] < 25.0

    # 2. Phishing lure URL
    lure_res = client.post("/api/v1/inspect", json={"url": "http://198.51.100.42/secure-account/login?verify=true"})
    assert lure_res.status_code == 201
    lure_data = lure_res.json()
    assert lure_data["threat_score"] >= 40.0
    assert len(lure_data["risk_factors"]) >= 2

def test_scan_history_and_summary():
    history_res = client.get("/api/v1/inspect/history")
    assert history_res.status_code == 200
    history = history_res.json()
    assert len(history) >= 2

    summary_res = client.get("/api/v1/inspect/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["total_scans"] >= 2
    assert "average_threat_score" in summary

def test_blocklist_crud():
    # List initial seeded rules
    res = client.get("/api/v1/blocklist")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) >= 2

    # Add a new blocklist rule
    add_res = client.post("/api/v1/blocklist", json={
        "pattern": "*secure-crypto-wallet*",
        "reason": "Phishing targeting cryptocurrency wallets"
    })
    assert add_res.status_code == 201
    created_rule = add_res.json()
    rule_id = created_rule["id"]

    # Delete the rule
    del_res = client.delete(f"/api/v1/blocklist/{rule_id}")
    assert del_res.status_code == 204
