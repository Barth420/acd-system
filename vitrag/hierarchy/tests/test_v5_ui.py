"""V5: the lab console is served by the controller, embeddable, and free of external resources / HTML injection."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from controller.app import create_app
from controller.core import Lab
from controller.dockerops import FakeDockerOps

UI = Path(__file__).resolve().parents[1] / "controller" / "ui"


@pytest.fixture()
def client(tmp_path):
    lab = Lab(tmp_path / "c" / "state.json", "http://127.0.0.1:9", FakeDockerOps(), probe=False)
    yield TestClient(create_app(lab))
    lab.close()


def strip(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


def test_ui_is_served_with_every_required_section(client):
    r = client.get("/ui")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    for needle in ('id="graph"', 'id="journeys"', 'id="modes"', 'id="cut"', 'id="restore"', 'id="scenario"', 'id="seed"', 'id="run"',
                   'id="steps"', 'id="traffic-on"', 'id="traffic-off"', 'id="reset"', 'id="actions"', 'id="rotate"'):
        assert needle in r.text, needle
    assert client.get("/ui/app.js").status_code == 200 and client.get("/ui/style.css").status_code == 200
    assert client.get("/ui/secrets").status_code == 404 and list(client.get("/ui/secrets").json()) == ["error"]


def test_ui_can_be_embedded_in_an_iframe(client):
    for path in ("/ui", "/ui/app.js", "/ui/style.css"):
        h = {k.lower(): v for k, v in client.get(path).headers.items()}
        assert "x-frame-options" not in h
        assert "frame-ancestors" not in h.get("content-security-policy", "")


def test_no_external_resources_no_build_step_no_html_injection():
    blob = "\n".join(strip((UI / n).read_text()) for n in ("index.html", "app.js", "style.css"))
    assert set(re.findall(r"https?://[^\s'\"<>)]+", blob)) <= {"http://www.w3.org/2000/svg"}
    assert "cdn" not in blob.lower() and re.findall(r'<script[^>]*src="([^"]+)"', (UI / "index.html").read_text()) == ["/ui/app.js"]
    code = strip((UI / "app.js").read_text())
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert bad not in code, bad
    assert not list(UI.glob("package*.json"))


def test_ui_only_calls_endpoints_the_controller_implements(client):
    js = strip((UI / "app.js").read_text())
    called = set(re.findall(r"(?:api|post)\(\s*[`'\"](/[a-z\-/]+)", js))
    called |= {"/services/x/mode", "/services/x/rotate-credentials", "/scenarios/x/run", "/runs/x/stop"}
    ok = {"/topology", "/state", "/health", "/actions", "/scenarios", "/reset", "/traffic/start", "/traffic/stop", "/edges/cut", "/edges/restore",
          "/runs/", "/scenarios/", "/services/", "/scenarios/x/run", "/services/x/mode", "/services/x/rotate-credentials", "/runs/x/stop"}
    assert {c for c in called if c not in ok} == set()
    for path in ("/topology", "/state", "/actions", "/reset"):
        assert client.request("POST" if path == "/reset" else "GET", path).status_code == 200
