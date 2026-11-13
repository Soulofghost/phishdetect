import pytest
from app.engine.detector import calculate_shannon_entropy, detect_homoglyphs, analyze_url

def test_shannon_entropy():
    # Low entropy repetitive string
    low_ent = calculate_shannon_entropy("aaaaaaaaaa")
    assert low_ent == 0.0

    # Natural language domain
    domain_ent = calculate_shannon_entropy("wikipedia")
    assert 2.0 <= domain_ent <= 3.5

    # High entropy random string
    random_str = "x9q8m2z1k7v4w6p0"
    high_ent = calculate_shannon_entropy(random_str)
    assert high_ent > 3.8

def test_homoglyph_detection():
    # Test Cyrillic 'a' confusable (\u0430)
    spoofed = "p\u0430ypal.com"
    res = detect_homoglyphs(spoofed)
    assert res["is_spoofed"] is True
    assert len(res["confusables_found"]) >= 1
    assert res["confusables_found"][0]["mimics"] == "a"

    # Test clean ASCII domain
    clean = "github.com"
    clean_res = detect_homoglyphs(clean)
    assert clean_res["is_spoofed"] is False
    assert len(clean_res["confusables_found"]) == 0

def test_analyze_malicious_phishing_url():
    url = "http://paypal-security-update.xyz/login/verify.php?session=update"
    result = analyze_url(url)
    assert result["threat_score"] > 60.0
    assert result["classification"] in ["MALICIOUS", "SUSPICIOUS"]
    rule_names = [r["rule"] for r in result["risk_factors"]]
    assert "BRAND_IMPERSONATION" in rule_names
    assert "HIGH_RISK_TLD" in rule_names
    assert "CREDENTIAL_HARVESTING_PATH" in rule_names

def test_analyze_benign_url():
    url = "https://en.wikipedia.org/wiki/Computer_science"
    result = analyze_url(url)
    assert result["threat_score"] < 25.0
    assert result["classification"] == "BENIGN"
