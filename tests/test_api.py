from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_demo_http_contracts_remain_isolated_and_downloadable():
    health = client.get("/api/health")
    demo = client.get("/api/demo")
    report = client.get("/api/demo/report")
    json_export = client.get("/api/demo/export.json")
    sarif_export = client.get("/api/demo/export.sarif")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert demo.status_code == 200
    assert demo.json()["is_demo"] is True
    assert demo.json()["domain"] == "demo.local"
    assert report.status_code == 200
    assert "DONNÉES FICTIVES" in report.text
    assert json_export.headers["content-disposition"] == 'attachment; filename="logialog-demo-audit.json"'
    assert json_export.json()["audit"]["domain"] == "demo.local"
    assert sarif_export.headers["content-disposition"] == 'attachment; filename="logialog-demo-audit.sarif"'
    assert sarif_export.json()["version"] == "2.1.0"


def test_audit_http_contract_rejects_missing_authorization():
    response = client.post(
        "/api/audits",
        json={
            "target": "https://shop.test",
            "authorization_confirmed": False,
            "max_requests": 1,
            "delay_seconds": 1,
        },
    )

    assert response.status_code == 422
    assert "autorisation explicite" in response.text
