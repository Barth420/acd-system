"""
dockerops.py: the Docker side of actuation.

* "isolated" means more than a flag: the container is detached from ALL its networks (docker network disconnect)
  and re-attached on restore, in addition to the app-level state file.
* The gateway (nginx) cannot read the state file, so the controller regenerates an include and signals a reload.
Real operations need the docker socket; NullDockerOps (no-op) and FakeDockerOps (records calls) serve local runs/tests.
"""

from __future__ import annotations

import logging
from typing import Optional

import controlstate as cs

log = logging.getLogger("controller.docker")

# which docker networks each service sits on (mirrors docker-compose.yml)
NETWORKS: dict[str, list[str]] = {
    "nginx": ["acd-h-attacker-net", "acd-h-net-t0"],
    **{s: ["acd-h-net-t0", "acd-h-net-t1", "acd-h-net-t2"] for s in ("auth_api", "product_api", "order_api", "search_api")},
    **{s: ["acd-h-net-t2"] for s in ("database", "cache", "queue")},
}


class NullDockerOps:
    """No Docker (local-process runs): network operations are no-ops and the caller is told so."""
    real = False

    def disconnect(self, service: str) -> list[str]:
        return []

    def reconnect(self, service: str) -> list[str]:
        return []

    def reload_gateway(self) -> bool:
        return False

    def is_running(self, service: str) -> Optional[bool]:
        return None


class FakeDockerOps(NullDockerOps):
    real = False

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.detached: set[str] = set()

    def disconnect(self, service: str) -> list[str]:
        self.calls.append(("disconnect", service))
        self.detached.add(service)
        return NETWORKS[service]

    def reconnect(self, service: str) -> list[str]:
        self.calls.append(("reconnect", service))
        self.detached.discard(service)
        return NETWORKS[service]

    def reload_gateway(self) -> bool:
        self.calls.append(("reload_gateway",))
        return True

    def is_running(self, service: str) -> Optional[bool]:
        return service not in self.detached


class DockerOps(NullDockerOps):
    real = True

    def __init__(self) -> None:
        import docker
        self._docker = docker
        self.client = docker.from_env()

    def _c(self, service: str):
        return self.client.containers.get(f"acd-h-{service}")

    def disconnect(self, service: str) -> list[str]:
        done = []
        c = self._c(service)
        for n in NETWORKS[service]:
            try:
                self.client.networks.get(n).disconnect(c, force=True)
                done.append(n)
            except self._docker.errors.APIError as e:  # already detached, or network missing
                log.warning("disconnect %s from %s: %s", service, n, e)
        return done

    def reconnect(self, service: str) -> list[str]:
        done = []
        c = self._c(service)
        for n in NETWORKS[service]:
            try:
                self.client.networks.get(n).connect(c, aliases=[service])   # the alias keeps the DNS name = service name
                done.append(n)
            except self._docker.errors.APIError as e:                       # already attached
                log.info("reconnect %s to %s: %s", service, n, e)
        return done

    def reload_gateway(self) -> bool:
        try:
            self._c("nginx").kill(signal="HUP")
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("gateway reload failed: %s", e)
            return False

    def is_running(self, service: str) -> Optional[bool]:
        try:
            c = self._c(service)
            c.reload()
            return c.status == "running" and bool(c.attrs["NetworkSettings"]["Networks"])
        except Exception:  # noqa: BLE001
            return False


def make_dockerops() -> NullDockerOps:
    import os
    mode = os.getenv("ACD_DOCKER", "auto")
    if mode == "off":
        return NullDockerOps()
    try:
        ops = DockerOps()
        ops.client.ping()
        return ops
    except Exception as e:  # noqa: BLE001
        if mode == "on":
            raise
        log.warning("docker unavailable (%s): network isolation disabled, app-level enforcement only", e)
        return NullDockerOps()
