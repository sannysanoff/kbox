#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for the kbox Docker Engine HTTP API frontend."""

import importlib.util
import json
import os
import struct
import tempfile
import threading
import unittest
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCKERD_PATH = os.path.join(REPO_ROOT, "scripts", "kbox-dockerd.py")

spec = importlib.util.spec_from_file_location("kbox_dockerd", DOCKERD_PATH)
kbox_dockerd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kbox_dockerd)


class FakeRpc:
    """In-memory stub for `kbox daemon` JSON-RPC."""

    def __init__(self, log_dir):
        self.calls = []
        self.log_dir = log_dir
        self._ip_seq = 2

    def call(self, payload):
        self.calls.append(payload)
        op = payload.get("op")
        if op == "ping":
            return {"ok": True, "lkl": True}
        if op == "image_import":
            return {"ok": True}
        if op == "container_create":
            ip = f"172.18.0.{self._ip_seq}"
            self._ip_seq += 1
            cid = payload["id"]
            return {
                "ok": True,
                "id": cid,
                "ip": ip,
                "log_path": os.path.join(self.log_dir, f"{cid}.log"),
            }
        if op == "container_start":
            return {"ok": True, "pid": 1234, "ip": "172.18.0.2"}
        if op == "container_inspect":
            return {"ok": True, "state": "running", "pid": 1234, "exit_code": 0}
        if op == "container_wait":
            return {"ok": True, "exit_code": 0}
        if op == "exec_start":
            eid = payload["exec_id"]
            lp = os.path.join(self.log_dir, f"exec-{eid}.log")
            with open(lp, "wb") as f:
                data = b"EXEC_OK\n"
                f.write(struct.pack(">BxxxI", 1, len(data)) + data)
            return {"ok": True, "pid": 1235, "log_path": lp}
        if op == "exec_wait":
            return {"ok": True, "exit_code": 42}
        if op in ("container_stop", "container_kill", "container_rm", "dns_set"):
            return {"ok": True}
        return {"ok": True}


class TestDockerEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_dir = os.path.join(self.tmpdir.name, "state")
        self.log_dir = os.path.join(self.tmpdir.name, "logs")
        self.img_src = os.path.join(self.tmpdir.name, "rootfs")
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(os.path.join(self.img_src, "bin"), exist_ok=True)

        self.rpc = FakeRpc(self.log_dir)
        self.vol_root = os.path.join(self.tmpdir.name, "volumes")
        self.engine = kbox_dockerd.DockerEngineState(
            self.rpc,
            self.state_dir,
            path_maps=[("/host/src", "/mapped/src")],
            config={
                "start_ip": "172.18.0.2",
                "gateway": "172.18.0.1",
                "volumes_root": self.vol_root,
            },
        )
        self.img_id = self.engine.images.import_dir_as_image(
            "alpine:latest", self.img_src
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_image_resolve_variants(self):
        self.assertEqual(self.engine.images.resolve("alpine"), self.img_id)
        self.assertEqual(self.engine.images.resolve("alpine:latest"), self.img_id)
        self.assertEqual(
            self.engine.images.resolve("docker.io/library/alpine:latest"),
            self.img_id,
        )
        self.assertEqual(self.engine.images.resolve(self.img_id[:16]), self.img_id)

    def test_create_container_binds_aliases_ports(self):
        rec = self.engine.create_container(
            "web-1",
            {
                "Image": "alpine:latest",
                "Cmd": ["sh", "-c", "echo ok"],
                "Labels": {"com.docker.compose.service": "web"},
                "HostConfig": {
                    "Binds": ["/host/src/www:/srv:ro"],
                    "PortBindings": {
                        "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}]
                    },
                },
                "NetworkingConfig": {
                    "EndpointsConfig": {
                        "app_net": {"Aliases": ["web", "web-alias"]}
                    }
                },
            },
        )
        self.assertEqual(rec["name"], "web-1")
        self.assertEqual(rec["ip"], "172.18.0.2")
        create_rpc = [c for c in self.rpc.calls if c["op"] == "container_create"][-1]
        self.assertIn("/mapped/src/www:/srv:ro", create_rpc["binds"])
        self.assertIn("web", create_rpc["aliases"])
        self.assertIn("web-alias", create_rpc["aliases"])
        self.assertIn("0.0.0.0:18080:8080", create_rpc["ports"])

    def test_exec_lifecycle_and_http_endpoints(self):
        rec = self.engine.create_container("svc", {"Image": "alpine:latest"})
        self.engine.start_container(rec)

        srv = kbox_dockerd.ThreadingHTTPServer(
            ("127.0.0.1", 0), kbox_dockerd.DockerHandler
        )
        srv.engine = self.engine
        srv.verbose = False
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/_ping") as r:
                self.assertEqual(r.status, 200)
                self.assertEqual(r.read(), b"OK")

            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1.47/containers/{rec['id']}/exec",
                data=json.dumps({"Cmd": ["sh", "-c", "exit 42"]}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as r:
                self.assertEqual(r.status, 201)
                eid = json.loads(r.read().decode())["Id"]

            req2 = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1.47/exec/{eid}/start",
                data=json.dumps({"Detach": False, "Tty": False}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req2) as r:
                self.assertEqual(r.status, 200)
                body = r.read()
                self.assertIn(b"EXEC_OK", body)

            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/v1.47/exec/{eid}/json"
            ) as r:
                self.assertEqual(r.status, 200)
                info = json.loads(r.read().decode())
                self.assertFalse(info["Running"])
                self.assertEqual(info["ExitCode"], 42)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_logs_tail_parameter(self):
        rec = self.engine.create_container("logger", {"Image": "alpine:latest"})
        with open(rec["log_path"], "wb") as f:
            payload = b"line1\nline2\nline3\n"
            f.write(struct.pack(">BxxxI", 1, len(payload)) + payload)

        srv = kbox_dockerd.ThreadingHTTPServer(
            ("127.0.0.1", 0), kbox_dockerd.DockerHandler
        )
        srv.engine = self.engine
        srv.verbose = False
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/containers/{rec['id']}/logs?stdout=1&tail=2"
            ) as r:
                raw = r.read()
                self.assertNotIn(b"line1", raw)
                self.assertIn(b"line2", raw)
                self.assertIn(b"line3", raw)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_config_yaml_prefix32_and_persistent_volumes(self):
        cfg_path = os.path.join(self.tmpdir.name, "kbox-config.yaml")
        custom_vols = os.path.join(self.tmpdir.name, "persist-vols")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(
                "network:\n"
                "  start_ip: 172.24.0.10\n"
                f"volumes:\n  root: {custom_vols}\n"
            )
        cfg = kbox_dockerd.load_kbox_config(cfg_path)
        self.assertEqual(cfg["start_ip"], "172.24.0.10")
        self.assertEqual(cfg["gateway"], "172.24.0.1")
        self.assertEqual(cfg["volumes_root"], os.path.abspath(custom_vols))

        eng1 = kbox_dockerd.DockerEngineState(
            self.rpc, os.path.join(self.tmpdir.name, "s1"), config_path=cfg_path
        )
        eng1.images.import_dir_as_image("alpine:latest", self.img_src)
        rec = eng1.create_container(
            "db-1",
            {
                "Image": "alpine:latest",
                "Labels": {"com.docker.compose.service": "db"},
                "HostConfig": {"Binds": ["pgdata:/var/lib/db"]},
            },
        )
        insp = eng1.container_inspect_json(rec)
        self.assertEqual(insp["NetworkSettings"]["IPPrefixLen"], 32)
        self.assertEqual(insp["NetworkSettings"]["Gateway"], "172.24.0.1")
        self.assertEqual(rec["mounts_json"][0]["Type"], "volume")
        self.assertEqual(rec["mounts_json"][0]["Name"], "pgdata")

        data_file = os.path.join(custom_vols, "pgdata", "_data", "state.txt")
        with open(data_file, "w", encoding="utf-8") as f:
            f.write("DB_ROW_1\n")

        # Simulate full daemon restart: fresh DockerEngineState loads persisted volume.
        eng2 = kbox_dockerd.DockerEngineState(
            self.rpc, os.path.join(self.tmpdir.name, "s2"), config_path=cfg_path
        )
        self.assertIn("pgdata", eng2.volumes)
        self.assertEqual(
            eng2.volumes["pgdata"]["Labels"].get("com.docker.compose.service"),
            "db",
        )
        with open(data_file, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "DB_ROW_1\n")

    def test_port_binding_formats(self):
        # 1. Other services only: expose without PortBindings.
        r1 = self.engine.create_container(
            "svc-expose",
            {
                "Image": "alpine:latest",
                "ExposedPorts": {"8080/tcp": {}},
            },
        )
        c1 = [c for c in self.rpc.calls if c.get("op") == "container_create"][-1]
        self.assertEqual(c1["ports"], [])
        i1 = self.engine.container_inspect_json(r1)
        self.assertEqual(i1["Config"]["ExposedPorts"], {"8080/tcp": {}})
        self.assertEqual(i1["NetworkSettings"]["Ports"], {})

        # 2. Host localhost only: 127.0.0.1:18081:8080.
        r2 = self.engine.create_container(
            "svc-local",
            {
                "Image": "alpine:latest",
                "HostConfig": {
                    "PortBindings": {
                        "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18081"}]
                    }
                },
            },
        )
        c2 = [c for c in self.rpc.calls if c.get("op") == "container_create"][-1]
        self.assertEqual(c2["ports"], ["127.0.0.1:18081:8080"])
        i2 = self.engine.container_inspect_json(r2)
        self.assertEqual(
            i2["NetworkSettings"]["Ports"]["8080/tcp"],
            [{"HostIp": "127.0.0.1", "HostPort": "18081"}],
        )

        # 3. All IPv4 interfaces: 0.0.0.0:18082:8080 and omitted HostIp -> 0.0.0.0.
        r3 = self.engine.create_container(
            "svc-all",
            {
                "Image": "alpine:latest",
                "HostConfig": {
                    "PortBindings": {
                        "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18082"}],
                        "8081/tcp": [{"HostIp": "", "HostPort": "18083"}],
                    }
                },
            },
        )
        c3 = [c for c in self.rpc.calls if c.get("op") == "container_create"][-1]
        self.assertEqual(
            sorted(c3["ports"]),
            ["0.0.0.0:18082:8080", "0.0.0.0:18083:8081"],
        )
        i3 = self.engine.container_inspect_json(r3)
        self.assertEqual(
            i3["NetworkSettings"]["Ports"]["8080/tcp"],
            [{"HostIp": "0.0.0.0", "HostPort": "18082"}],
        )
        self.assertEqual(
            i3["NetworkSettings"]["Ports"]["8081/tcp"],
            [{"HostIp": "0.0.0.0", "HostPort": "18083"}],
        )

    def test_healthcheck_state_and_transitions(self):
        orig_call = self.rpc.call
        exec_rcs = [1, 0, 1, 1]

        def hc_call(payload):
            if payload.get("op") == "exec_wait":
                rc = exec_rcs.pop(0) if exec_rcs else 1
                return {"ok": True, "exit_code": rc}
            return orig_call(payload)

        self.rpc.call = hc_call
        rec = self.engine.create_container(
            "hc-web",
            {
                "Image": "alpine:latest",
                "Healthcheck": {
                    "Test": ["CMD-SHELL", "echo ok"],
                    "Interval": 200_000_000,
                    "Timeout": 1_000_000_000,
                    "Retries": 2,
                },
            },
        )
        rec["health"] = {"Status": "starting", "FailingStreak": 0, "Log": []}
        rec["status"] = "running"

        e1 = self.engine._run_healthcheck_once(rec, ["/bin/sh", "-c", "echo ok"], 1.0)
        self.assertEqual(e1["ExitCode"], 1)
        self.assertEqual(e1["Output"], "EXEC_OK\n")

        # Drive healthy transition and failing streak -> unhealthy via _watch_health logic
        rec["health_stop"].clear()
        hc = rec["healthcheck"]
        self.assertEqual(
            self.engine._healthcheck_cmd(hc["Test"]),
            ["/bin/sh", "-c", "echo ok"],
        )
        self.assertEqual(
            self.engine._healthcheck_cmd(["CMD", "clickhouse-client", "--query", "SELECT 1"]),
            ["clickhouse-client", "--query", "SELECT 1"],
        )

        # Pass check -> healthy
        e2 = self.engine._run_healthcheck_once(rec, ["/bin/sh", "-c", "echo ok"], 1.0)
        self.assertEqual(e2["ExitCode"], 0)
        rec["health"]["Status"] = "healthy"
        insp = self.engine.container_inspect_json(rec)
        self.assertEqual(insp["State"]["Health"]["Status"], "healthy")
        self.assertEqual(insp["Config"]["Healthcheck"]["Retries"], 2)

        # Clean up health_stop
        rec["health_stop"].set()

    def test_rename_container_updates_name_and_dns(self):
        rec = self.engine.create_container("old-name", {"Image": "alpine:latest"})
        with self.engine.lock:
            self.assertEqual(rec["name"], "old-name")
            rec["name"] = "new-name"
        self.assertIs(self.engine.find_container("new-name"), rec)
        insp = self.engine.container_inspect_json(rec)
        self.assertEqual(insp["Name"], "/new-name")


if __name__ == "__main__":
    unittest.main(verbosity=2)
