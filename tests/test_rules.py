import pytest
import rules


def threat(path="/", query="", body=b"", headers=None):
    return [f["id"] for f in rules.inspect(path, query, body, headers or {}) if f["severity"] != "low"]


@pytest.mark.parametrize("query,rule", [
    ("id=1 UNION SELECT 1,2,3", "SQLI-001"),
    ("id=1 OR 1=1", "SQLI-002"),
    ("q=x' or 'a'='a", "SQLI-002"),
    ("q=admin'--", "SQLI-003"),
    ("id=1;SELECT sleep(5)", "SQLI-004"),
    ("q=<script>alert(1)</script>", "XSS-001"),
    ("q=<img src=x onerror=alert(1)>", "XSS-002"),
    ("q=../../etc/passwd", "TRAV-001"),
    ("q=x;cat /etc/passwd", "CMDI-001"),
])
def test_signatures_detected(query, rule):
    assert rule in threat(query=query)


@pytest.mark.parametrize("query", [
    "q=leather+wallet", "q=black or brown wallet", "q=sleep mask", "q=dads' #1 gift",
    "q=2 and 2=4", "q=union station tickets", "q=select a size", "q=price<20",
])
def test_legitimate_queries_not_flagged(query):
    assert threat(query=query) == []


def test_double_encoding_and_comment_tricks():
    assert threat(query="id=1%2520UNION%2520SELECT%25201") != []
    assert threat(query="id=1/**/UNION/**/SELECT/**/1") != []


def test_json_body_is_inspected():
    assert threat(body=b'{"comment": "<script>alert(1)</script>"}') != []


def test_scanner_user_agent_is_low_severity_only():
    found = rules.inspect("/", "", b"", {"user-agent": "sqlmap/1.7"})
    assert [f["id"] for f in found] == ["SCAN-001"] and found[0]["severity"] == "low"


def test_anomaly_score_range_and_ordering():
    calm, odd = rules.anomaly_score("leather wallet"), rules.anomaly_score("';{}$()|`\\" * 40)
    assert 0 <= calm < odd <= 1
