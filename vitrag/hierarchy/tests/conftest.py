from __future__ import annotations

import pytest

import controlstate as cs
from local_stack import LocalStack


@pytest.fixture(scope="session")
def stack():
    with LocalStack() as s:
        yield s


@pytest.fixture()
def lab(stack):
    """The shared local stack, reset to the default control state before each test."""
    cs.write_state(stack.control, cs.default_state())
    yield stack
    cs.write_state(stack.control, cs.default_state())


@pytest.fixture()
def client(stack):
    """A FastAPI TestClient wrapping the real controller against the shared local stack, with two attackers
    bound to distinct loopback addresses (see attacker/agent.py)."""
    from fastapi.testclient import TestClient

    from controller.app import create_app
    from controller.attackers import DirectClient
    from controller.core import Lab
    from controller.dockerops import FakeDockerOps

    cs.write_state(stack.control, cs.default_state())
    attackers = {"attacker-1": DirectClient("127.0.0.2"), "attacker-2": DirectClient("127.0.0.3")}
    lab = Lab(stack.control, stack.gateway, FakeDockerOps(), probe=False, attackers=attackers, sink_url="http://127.0.0.1:1")
    yield TestClient(create_app(lab))
    lab.close()
    cs.write_state(stack.control, cs.default_state())
