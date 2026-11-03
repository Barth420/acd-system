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
