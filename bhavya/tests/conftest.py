"""
tests/conftest.py — Shared pytest fixtures.

Important: TestClient must be used as a context manager to trigger FastAPI's
lifespan events (which init the DB). We also reset the DB to a clean state
for each test session.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session", autouse=True)
def _isolated_db(tmp_path_factory):
    """
    Point the DB at a temp file for the test session so we don't pollute the
    real incidents.db. Done before any pipeline modules are imported.
    """
    tmp_dir = tmp_path_factory.mktemp("acd_db")
    os.environ["ACD_DB_PATH"] = str(tmp_dir / "test_incidents.db")
    yield


@pytest.fixture(scope="session")
def client(_isolated_db):
    """
    Yields a TestClient inside its lifespan context, so startup hooks fire.
    """
    # Import AFTER env var is set
    from pipeline.main import app

    with TestClient(app) as c:
        yield c
