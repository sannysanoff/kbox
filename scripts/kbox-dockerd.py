#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Docker Engine REST API frontend backed by a single `kbox daemon` LKL instance.

Serves Docker Engine HTTP/1.1 API (compatible with Docker CLI 29.x and
Docker Compose v5.x) over TCP (--host 0.0.0.0:2375) and/or Unix socket.
"""

import argparse
import faulthandler
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import os
import platform
import queue
import re
import secrets
import shutil
import signal
import socket
import struct
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


API_VERSION = "1.47"
MIN_API_VERSION = "1.24"
SERVER_VERSION = "29.0.0-kbox"
DEFAULT_CONFIG_PATH = "~/.config/kbox-config.yaml"
DEFAULT_START_IP = "172.18.0.2"
DEFAULT_GATEWAY_IP = "172.18.0.1"
DEFAULT_VOLUMES_ROOT = "~/.local/share/kbox/volumes"


def _normalize_start_ip(raw):
    val = (raw or "").strip().split("/", 1)[0]
    if not val:
        return None
    parts = val.split(".")
    if len(parts) == 2:
        val = f"{val}.0.2"
    elif len(parts) == 3:
        val = f"{val}.2"
    try:
        addr = ipaddress.IPv4Address(val)
    except ipaddress.AddressValueError:
        return None
    if (int(addr) & 0xff) == 0:
        addr = ipaddress.IPv4Address(int(addr) | 2)
    return str(addr)


def _derive_gateway_ip(start_ip):
    try:
        addr = ipaddress.IPv4Address(start_ip)
    except ipaddress.AddressValueError:
        return DEFAULT_GATEWAY_IP
    h = int(addr)
    cand = (h & 0xffffff00) | 1
    if cand == h:
        cand = (h & 0xffffff00) | 254
    return str(ipaddress.IPv4Address(cand))


def load_kbox_config(config_path=None):
    """Load YAML settings from ~/.config/kbox-config.yaml (no PyYAML required)."""
    cfg = {
        "start_ip": DEFAULT_START_IP,
        "gateway": "",
        "volumes_root": os.path.abspath(os.path.expanduser(DEFAULT_VOLUMES_ROOT)),
        "config_path": "",
    }
    eff = config_path or os.environ.get("KBOX_CONFIG") or os.path.expanduser(DEFAULT_CONFIG_PATH)
    cfg["config_path"] = eff
    if eff and os.path.isfile(eff):
        section = ""
        with open(eff, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.split("#", 1)[0]
                indented = line[:1] in (" ", "\t")
                stripped = line.strip()
                if not stripped or ":" not in stripped:
                    continue
                key, val = stripped.split(":", 1)
                key = key.strip()
                val = val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                    val = val[1:-1]
                if not indented and not val:
                    section = key
                    continue
                if not indented:
                    section = ""
                if (section in ("", "network")) and key in ("start_ip", "start-ip"):
                    norm = _normalize_start_ip(val)
                    if norm:
                        cfg["start_ip"] = norm
                elif (section in ("", "network")) and key in ("gateway", "gateway_ip"):
                    try:
                        cfg["gateway"] = str(ipaddress.IPv4Address(val))
                    except ipaddress.AddressValueError:
                        pass
                elif (section in ("", "volumes")) and key in ("root", "volumes_root", "dir"):
                    if val:
                        cfg["volumes_root"] = os.path.abspath(os.path.expanduser(val))
                elif not section and key == "volumes_root" and val:
                    cfg["volumes_root"] = os.path.abspath(os.path.expanduser(val))
    if not cfg["gateway"]:
        cfg["gateway"] = _derive_gateway_ip(cfg["start_ip"])
    return cfg


NFS_SCHEME = "nfs://"


def is_nfs_source(src):
    """True for a volume source that names a kbox-declared NFS export."""
    return isinstance(src, str) and src.startswith(NFS_SCHEME)


def split_bind_spec(spec):
    """Split docker short syntax SRC:DST[:MODE] into (src, dst, mode).

    The nfs: scheme name carries a colon of its own ("nfs://mounted_here/sub>x"),
    so a naive split on ':' would misread the handle as the source.
    """
    if not isinstance(spec, str):
        return None
    if spec.startswith(NFS_SCHEME):
        i = spec.find(":", len(NFS_SCHEME))
        if i < 0:
            return None
        src, rest = spec[:i], spec[i + 1:]
    else:
        parts = spec.split(":", 2)
        if len(parts) < 2:
            return None
        src, rest = parts[0], ":".join(parts[1:])
    if ":" in rest:
        dst, mode = rest.split(":", 1)
    else:
        dst, mode = rest, ""
    if not dst.startswith("/"):
        return None
    return src, dst, mode


def rfc3339(ts):
    if not ts or ts <= 0:
        return "0001-01-01T00:00:00Z"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class KboxRpcClient:
    """Thread-safe JSON-line RPC client talking to `kbox daemon` Unix socket."""

    def __init__(self, sock_path):
        self.sock_path = sock_path
        self.lock = threading.Lock()

    def call(self, payload):
        data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        # Separate connection per RPC so concurrent wait/start calls never block.
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.sock_path)
        try:
            s.sendall(data)
            buf = bytearray()
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
        finally:
            s.close()
        if not buf:
            raise RuntimeError("empty reply from kbox daemon")
        line = bytes(buf).split(b"\n", 1)[0].decode("utf-8")
        resp = json.loads(line)
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "kbox daemon error"))
        return resp


class EventBus:
    """Pub/sub event stream for Docker `/events`."""

    def __init__(self):
        self.lock = threading.Lock()
        self.subs = []

    def emit(self, typ, action, actor_id, attrs=None):
        ev = {
            "Type": typ,
            "Action": action,
            "Actor": {
                "ID": actor_id,
                "Attributes": attrs or {},
            },
            "scope": "local",
            "time": int(time.time()),
            "timeNano": time.time_ns(),
        }
        with self.lock:
            for q in list(self.subs):
                try:
                    q.put_nowait(ev)
                except queue.Full:
                    pass

    def subscribe(self):
        q = queue.Queue(maxsize=256)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)


class ImageStore:
    """OCI image puller, unpacker, and metadata registry."""

    def __init__(self, state_dir, rpc):
        self.state_dir = state_dir
        self.img_dir = os.path.join(state_dir, "images")
        self.tags_file = os.path.join(state_dir, "tags.json")
        os.makedirs(self.img_dir, exist_ok=True)
        self.rpc = rpc
        self.lock = threading.Lock()
        self.tags = {}
        self._load_tags()

    def _load_tags(self):
        if os.path.exists(self.tags_file):
            try:
                with open(self.tags_file, "r", encoding="utf-8") as f:
                    self.tags = json.load(f)
            except Exception:
                self.tags = {}

    def _save_tags(self):
        tmp = self.tags_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.tags, f, indent=2)
        os.replace(tmp, self.tags_file)

    @staticmethod
    def normalize_ref(name, tag=None):
        if ":" in name and "/" not in name.split(":", 1)[1]:
            repo, t = name.rsplit(":", 1)
        elif tag:
            repo, t = name, tag
        else:
            repo, t = name, "latest"
        return f"{repo}:{t}", repo, t

    def resolve(self, ref):
        with self.lock:
            if ref in self.tags:
                return self.tags[ref]
            norm, _, _ = self.normalize_ref(ref)
            if norm in self.tags:
                return self.tags[norm]
            # Try stripping docker.io/library/
            short = re.sub(r"^(docker\.io/)?(library/)?", "", norm)
            if short in self.tags:
                return self.tags[short]
            # Match by image ID prefix
            clean = ref.removeprefix("sha256:")
            for k, iid in self.tags.items():
                if iid == ref or iid.removeprefix("sha256:").startswith(clean):
                    return iid
        return None

    def tag(self, src, repo, tag=None):
        """Point repo:tag at the image src resolves to (docker tag)."""
        iid = self.resolve(src)
        if not iid:
            return None
        norm, _, _ = self.normalize_ref(repo, tag)
        with self.lock:
            self.tags[norm] = iid
            self._save_tags()
        return norm

    def get_meta(self, img_id):
        meta_path = os.path.join(self.img_dir, img_id.removeprefix("sha256:"), "meta.json")
        if not os.path.exists(meta_path):
            return None
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def ensure_imported(self, img_id):
        short = img_id.removeprefix("sha256:")
        rootfs = os.path.join(self.img_dir, short, "rootfs")
        self.rpc.call({"op": "image_import", "id": short, "src": rootfs})

    def list_images(self):
        res = []
        seen = {}
        with self.lock:
            items = list(self.tags.items())
        for ref, iid in items:
            if iid not in seen:
                meta = self.get_meta(iid)
                if not meta:
                    continue
                seen[iid] = {
                    "Id": iid,
                    "ParentId": "",
                    "RepoTags": [],
                    "RepoDigests": [],
                    "Created": meta.get("created", 0),
                    "Size": meta.get("size", 0),
                    "SharedSize": -1,
                    "VirtualSize": meta.get("size", 0),
                    "Labels": meta.get("config", {}).get("Labels") or {},
                    "Containers": -1,
                }
            if ref not in seen[iid]["RepoTags"]:
                seen[iid]["RepoTags"].append(ref)
        for v in seen.values():
            res.append(v)
        return res

    @staticmethod
    def _target_arch():
        m = platform.machine().lower()
        if m in ("aarch64", "arm64"):
            return "arm64"
        if m in ("x86_64", "amd64"):
            return "amd64"
        return m

    @staticmethod
    def _split_registry(repo):
        parts = repo.split("/")
        if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
            host = "registry-1.docker.io" if parts[0] == "docker.io" else parts[0]
            rest = "/".join(parts[1:])
            if host == "registry-1.docker.io" and "/" not in rest:
                rest = f"library/{rest}"
            return host, rest
        if "/" not in repo:
            return "registry-1.docker.io", f"library/{repo}"
        return "registry-1.docker.io", repo

    def _http_get_with_auth(self, url, headers=None, token_cache=None):
        hdrs = dict(headers or {})
        if token_cache and token_cache.get("token"):
            hdrs["Authorization"] = f"Bearer {token_cache['token']}"
        req = urllib.request.Request(url, headers=hdrs)
        try:
            return urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            www = e.headers.get("WWW-Authenticate", "")
            m_realm = re.search(r'realm="([^"]+)"', www)
            if not m_realm:
                raise
            params = {}
            for k in ("service", "scope"):
                mk = re.search(rf'{k}="([^"]+)"', www)
                if mk:
                    params[k] = mk.group(1)
            tok_url = m_realm.group(1)
            if params:
                tok_url += ("&" if "?" in tok_url else "?") + urllib.parse.urlencode(params)
            treq = urllib.request.Request(tok_url)
            with urllib.request.urlopen(treq, timeout=20) as tresp:
                tdata = json.loads(tresp.read().decode("utf-8"))
            tok = tdata.get("token") or tdata.get("access_token")
            if token_cache is not None:
                token_cache["token"] = tok
            hdrs["Authorization"] = f"Bearer {tok}"
            return urllib.request.urlopen(urllib.request.Request(url, headers=hdrs), timeout=60)

    @staticmethod
    def _extract_layer_tar(tar_bytes, rootfs):
        # Support gzip or uncompressed tar
        if tar_bytes[:2] == b"\x1f\x8b":
            bio = gzip.GzipFile(fileobj=io.BytesIO(tar_bytes))
        else:
            bio = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=bio, mode="r:*") as tf:
            members = tf.getmembers()
            # Handle opaque directories (.wh..wh..opq) and whiteouts (.wh.<file>)
            for m in members:
                rel = m.name.lstrip("./")
                if not rel:
                    continue
                base = os.path.basename(rel)
                parent = os.path.join(rootfs, os.path.dirname(rel))
                if base == ".wh..wh..opq":
                    if os.path.isdir(parent):
                        for entry in os.listdir(parent):
                            ep = os.path.join(parent, entry)
                            if os.path.isdir(ep) and not os.path.islink(ep):
                                shutil.rmtree(ep)
                            else:
                                os.unlink(ep)
                    continue
                if base.startswith(".wh."):
                    target = os.path.join(parent, base[4:])
                    if os.path.lexists(target):
                        if os.path.isdir(target) and not os.path.islink(target):
                            shutil.rmtree(target)
                        else:
                            os.unlink(target)
                    continue

                dest = os.path.normpath(os.path.join(rootfs, rel))
                if not (dest == rootfs or dest.startswith(rootfs + os.sep)):
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                if m.isdir():
                    os.makedirs(dest, exist_ok=True)
                elif m.issym():
                    if os.path.lexists(dest):
                        os.unlink(dest)
                    os.symlink(m.linkname, dest)
                elif m.islnk():
                    link_target = os.path.normpath(os.path.join(rootfs, m.linkname.lstrip("./")))
                    if os.path.lexists(dest):
                        os.unlink(dest)
                    if os.path.exists(link_target):
                        os.link(link_target, dest)
                elif m.isreg():
                    if os.path.lexists(dest):
                        if os.path.isdir(dest) and not os.path.islink(dest):
                            shutil.rmtree(dest)
                        else:
                            os.unlink(dest)
                    src_f = tf.extractfile(m)
                    if src_f is not None:
                        with open(dest, "wb") as out_f:
                            shutil.copyfileobj(src_f, out_f)
                        os.chmod(dest, m.mode & 0o7777)

    def pull(self, from_image, tag="latest", progress_cb=None):
        norm, repo, tag = self.normalize_ref(from_image, tag)
        short_norm = re.sub(r"^(docker\.io/)?(library/)?", "", norm)
        registry, path_repo = self._split_registry(repo)
        scheme = "http" if registry.startswith("localhost") or registry.startswith("127.") else "https"
        base = f"{scheme}://{registry}/v2/{path_repo}"
        token_cache = {}
        accept = ", ".join([
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ])

        if progress_cb:
            progress_cb({"status": f"Pulling from {path_repo}", "id": tag})

        with self._http_get_with_auth(f"{base}/manifests/{tag}", {"Accept": accept}, token_cache) as r:
            manifest = json.loads(r.read().decode("utf-8"))

        # Handle manifest list / OCI index
        if "manifests" in manifest:
            arch = self._target_arch()
            chosen = None
            for m in manifest["manifests"]:
                plat = m.get("platform", {})
                if plat.get("os") == "linux" and plat.get("architecture") == arch:
                    chosen = m["digest"]
                    break
            if not chosen and manifest["manifests"]:
                chosen = manifest["manifests"][0]["digest"]
            with self._http_get_with_auth(f"{base}/manifests/{chosen}", {"Accept": accept}, token_cache) as r:
                manifest = json.loads(r.read().decode("utf-8"))

        cfg_digest = manifest["config"]["digest"]
        with self._http_get_with_auth(f"{base}/blobs/{cfg_digest}", {}, token_cache) as r:
            cfg_bytes = r.read()
        cfg_json = json.loads(cfg_bytes.decode("utf-8"))
        img_id = "sha256:" + hashlib.sha256(cfg_bytes).hexdigest()
        short_id = img_id.removeprefix("sha256:")
        dest_dir = os.path.join(self.img_dir, short_id)
        rootfs = os.path.join(dest_dir, "rootfs")

        if not os.path.exists(os.path.join(dest_dir, "meta.json")):
            stage = dest_dir + ".tmp." + secrets.token_hex(4)
            stage_rootfs = os.path.join(stage, "rootfs")
            os.makedirs(stage_rootfs, exist_ok=True)
            total_size = 0
            for layer in manifest.get("layers", []):
                ldig = layer["digest"]
                if progress_cb:
                    progress_cb({"status": "Pulling fs layer", "id": ldig[7:19]})
                with self._http_get_with_auth(f"{base}/blobs/{ldig}", {}, token_cache) as r:
                    blob = r.read()
                total_size += len(blob)
                if progress_cb:
                    progress_cb({"status": "Extracting", "id": ldig[7:19]})
                self._extract_layer_tar(blob, stage_rootfs)
            meta = {
                "id": img_id,
                "created": int(time.time()),
                "size": total_size,
                "architecture": cfg_json.get("architecture", self._target_arch()),
                "os": cfg_json.get("os", "linux"),
                "config": cfg_json.get("config", {}),
            }
            with open(os.path.join(stage, "meta.json"), "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
            if os.path.exists(dest_dir):
                shutil.rmtree(stage)
            else:
                os.replace(stage, dest_dir)

        with self.lock:
            self.tags[norm] = img_id
            self.tags[short_norm] = img_id
            self._save_tags()

        self.ensure_imported(img_id)
        if progress_cb:
            progress_cb({"status": f"Status: Downloaded newer image for {short_norm}"})
        return img_id

    def import_dir_as_image(self, ref, src_dir, config=None):
        norm, _, _ = self.normalize_ref(ref)
        short_norm = re.sub(r"^(docker\.io/)?(library/)?", "", norm)
        img_id = "sha256:" + hashlib.sha256(norm.encode()).hexdigest()
        short_id = img_id.removeprefix("sha256:")
        dest_dir = os.path.join(self.img_dir, short_id)
        rootfs = os.path.join(dest_dir, "rootfs")
        if not os.path.exists(rootfs):
            os.makedirs(dest_dir, exist_ok=True)
            shutil.copytree(src_dir, rootfs, symlinks=True)
        meta = {
            "id": img_id,
            "created": int(time.time()),
            "size": 0,
            "architecture": self._target_arch(),
            "os": "linux",
            "config": config or {},
        }
        with open(os.path.join(dest_dir, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        with self.lock:
            self.tags[norm] = img_id
            self.tags[short_norm] = img_id
            self._save_tags()
        self.ensure_imported(img_id)
        return img_id


class DockerEngineState:
    """In-memory state for containers, networks, and persistent volumes."""

    def __init__(self, rpc, state_dir, path_maps=None, config_path=None, config=None):
        self.rpc = rpc
        self.state_dir = state_dir
        self.path_maps = path_maps or []
        self.config = config if config is not None else load_kbox_config(config_path)
        self.start_ip = self.config.get("start_ip", DEFAULT_START_IP)
        self.gateway_ip = self.config.get("gateway") or _derive_gateway_ip(self.start_ip)
        self.subnet_cidr = str(ipaddress.IPv4Network(f"{self.gateway_ip}/16", strict=False))
        self.events = EventBus()
        self.images = ImageStore(state_dir, rpc)
        self.lock = threading.Lock()
        self.containers = {}
        self.networks = {
            "kbox-bridge-default": {
                "Name": "bridge",
                "Id": "kbox-bridge-default",
                "Created": rfc3339(time.time()),
                "Scope": "local",
                "Driver": "bridge",
                "EnableIPv6": False,
                "Internal": False,
                "Attachable": False,
                "Ingress": False,
                "IPAM": {
                    "Driver": "default",
                    "Options": None,
                    "Config": [{"Subnet": self.subnet_cidr, "Gateway": self.gateway_ip}],
                },
                "Options": {},
                "Labels": {},
            },
            "kbox-host-default": {
                "Name": "host",
                "Id": "kbox-host-default",
                "Created": rfc3339(time.time()),
                "Scope": "local",
                "Driver": "host",
                "IPAM": {"Driver": "default", "Config": []},
                "Options": {},
                "Labels": {},
            },
            "kbox-none-default": {
                "Name": "none",
                "Id": "kbox-none-default",
                "Created": rfc3339(time.time()),
                "Scope": "local",
                "Driver": "null",
                "IPAM": {"Driver": "default", "Config": []},
                "Options": {},
                "Labels": {},
            },
        }
        self.volumes = {}
        self.execs = {}
        vol_cfg = self.config.get("volumes_root")
        self.vol_root = os.path.abspath(os.path.expanduser(vol_cfg)) if vol_cfg else os.path.join(state_dir, "volumes")
        os.makedirs(self.vol_root, exist_ok=True)
        self._load_persisted_volumes()
        self._next_ephemeral_port = 20000

    @staticmethod
    def _validate_volume_name(vname):
        if (
            not vname
            or vname in (".", "..")
            or "/" in vname
            or "\\" in vname
            or "\0" in vname
        ):
            raise ValueError(f"invalid volume name: {vname!r}")
        return vname

    def _volume_meta_path(self, vname):
        return os.path.join(self.vol_root, vname, "meta.json")

    def _volume_data_dir(self, vname):
        return os.path.join(self.vol_root, vname, "_data")

    def _write_volume_meta(self, vname, vobj):
        meta_path = self._volume_meta_path(vname)
        tmp_path = f"{meta_path}.tmp.{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(vobj, f, indent=2, sort_keys=True)
        os.replace(tmp_path, meta_path)

    def _load_persisted_volumes(self):
        if not os.path.isdir(self.vol_root):
            return
        for entry in sorted(os.listdir(self.vol_root)):
            if entry.startswith("."):
                continue
            vdir = os.path.join(self.vol_root, entry)
            if not os.path.isdir(vdir):
                continue
            data_dir = os.path.join(vdir, "_data")
            meta_path = os.path.join(vdir, "meta.json")
            if not os.path.isdir(data_dir) and not os.path.isfile(meta_path):
                continue
            os.makedirs(data_dir, exist_ok=True)
            vobj = None
            if os.path.isfile(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        vobj = json.load(f)
                except Exception:
                    vobj = None
            if not isinstance(vobj, dict):
                vobj = {
                    "Name": entry,
                    "Driver": "local",
                    "Mountpoint": data_dir,
                    "CreatedAt": rfc3339(os.path.getctime(vdir)),
                    "Labels": {},
                    "Scope": "local",
                    "Options": {},
                }
            else:
                vobj["Name"] = vobj.get("Name") or entry
                vobj["Mountpoint"] = data_dir
                vobj.setdefault("Driver", "local")
                vobj.setdefault("Scope", "local")
                vobj.setdefault("Labels", {})
                vobj.setdefault("Options", {})
                vobj.setdefault("CreatedAt", rfc3339(time.time()))
            self.volumes[entry] = vobj

    def ensure_volume(self, vname, labels=None, options=None, service=None):
        vname = self._validate_volume_name(vname)
        data_dir = self._volume_data_dir(vname)
        os.makedirs(data_dir, exist_ok=True)
        with self.lock:
            existing = self.volumes.get(vname)
            if existing:
                vobj = dict(existing)
                vobj["Mountpoint"] = data_dir
                merged_labels = dict(vobj.get("Labels") or {})
                if labels:
                    merged_labels.update(labels)
                if service and "com.docker.compose.service" not in merged_labels:
                    merged_labels["com.docker.compose.service"] = service
                vobj["Labels"] = merged_labels
                if options:
                    opts = dict(vobj.get("Options") or {})
                    opts.update(options)
                    vobj["Options"] = opts
            else:
                merged_labels = dict(labels or {})
                if service and "com.docker.compose.service" not in merged_labels:
                    merged_labels["com.docker.compose.service"] = service
                vobj = {
                    "Name": vname,
                    "Driver": "local",
                    "Mountpoint": data_dir,
                    "CreatedAt": rfc3339(time.time()),
                    "Labels": merged_labels,
                    "Scope": "local",
                    "Options": dict(options or {}),
                }
            self.volumes[vname] = vobj
            self._write_volume_meta(vname, vobj)
            return dict(vobj)

    def remove_volume(self, vname):
        vname = self._validate_volume_name(vname)
        with self.lock:
            existed = self.volumes.pop(vname, None) is not None
        vdir = os.path.join(self.vol_root, vname)
        if os.path.isdir(vdir):
            shutil.rmtree(vdir, ignore_errors=True)
            existed = True
        return existed

    def map_host_path(self, p):
        for src_prefix, dst_prefix in self.path_maps:
            if p == src_prefix:
                return dst_prefix
            if p.startswith(src_prefix.rstrip("/") + "/"):
                return dst_prefix.rstrip("/") + p[len(src_prefix.rstrip("/")):]
        return p

    def _alloc_ephemeral_port(self):
        p = self._next_ephemeral_port
        self._next_ephemeral_port += 1
        return p

    def find_network(self, key):
        with self.lock:
            if key in self.networks:
                return self.networks[key]
            for n in self.networks.values():
                if n["Name"] == key or n["Id"].startswith(key):
                    return n
        return None

    def find_container(self, key):
        key = key.lstrip("/")
        with self.lock:
            if key in self.containers:
                return self.containers[key]
            for c in self.containers.values():
                if c["name"] == key or c["id"].startswith(key):
                    return c
        return None

    def refresh_container(self, c):
        try:
            st = self.rpc.call({"op": "container_inspect", "id": c["id"]})
            c["status"] = st.get("state", c["status"])
            c["pid"] = st.get("pid", 0)
            c["exit_code"] = st.get("exit_code", 0)
            c["ip"] = st.get("ip", c.get("ip", ""))
            c["started_at"] = st.get("started_at", c.get("started_at", 0))
            c["finished_at"] = st.get("finished_at", c.get("finished_at", 0))
            if st.get("log_path"):
                c["log_path"] = st["log_path"]
            if c["status"] != "running" and c.get("health_stop") is not None:
                c["health_stop"].set()
        except Exception:
            pass

    @staticmethod
    def match_filters(item_id, name, labels, status, filters_json):
        if not filters_json:
            return True
        if isinstance(filters_json, str):
            filters = json.loads(filters_json)
        else:
            filters = filters_json

        if "id" in filters:
            vals = filters["id"]
            if not any(item_id.startswith(v) or item_id == v for v in vals):
                return False
        if "name" in filters:
            vals = filters["name"]
            if not any(v in name or name == v.lstrip("/") for v in vals):
                return False
        if "status" in filters:
            vals = filters["status"]
            if status not in vals:
                return False
        if "label" in filters:
            for expr in filters["label"]:
                if "=" in expr:
                    k, v = expr.split("=", 1)
                    if labels.get(k) != v:
                        return False
                else:
                    if expr not in labels:
                        return False
        return True

    def create_container(self, name, body):
        image_ref = body.get("Image", "")
        img_id = self.images.resolve(image_ref)
        if not img_id:
            raise KeyError(f"No such image: {image_ref}")
        meta = self.images.get_meta(img_id) or {}
        img_cfg = meta.get("config") or {}
        self.images.ensure_imported(img_id)

        cid = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        cname = (name or "").lstrip("/") or f"kbox-{cid[:12]}"

        img_ep = img_cfg.get("Entrypoint") or []
        img_cmd = img_cfg.get("Cmd") or []
        if body.get("Entrypoint") is not None:
            ep = body["Entrypoint"]
            cmd = body.get("Cmd") if body.get("Cmd") is not None else []
        else:
            ep = img_ep
            cmd = body.get("Cmd") if body.get("Cmd") is not None else img_cmd
        full_cmd = list(ep) + list(cmd)
        if not full_cmd:
            full_cmd = ["/bin/sh"]

        # Merge env vars
        env_map = {}
        env_order = []
        for item in list(img_cfg.get("Env") or []) + list(body.get("Env") or []):
            k = item.split("=", 1)[0]
            if k not in env_map:
                env_order.append(k)
            env_map[k] = item
        merged_env = [env_map[k] for k in env_order]

        workdir = body.get("WorkingDir") or img_cfg.get("WorkingDir") or "/"
        hostname = body.get("Hostname") or cname
        labels = dict(img_cfg.get("Labels") or {})
        labels.update(body.get("Labels") or {})

        host_cfg = body.get("HostConfig") or {}
        service_name = labels.get("com.docker.compose.service") or cname
        binds = []
        mounts_json = []
        for b in host_cfg.get("Binds") or []:
            parsed = split_bind_spec(b)
            if parsed is None:
                continue
            raw_src, dst, mode_str = parsed
            ro_flag = "ro" in mode_str.split(",")
            mode = ":ro" if ro_flag else ""
            if is_nfs_source(raw_src):
                # Hard-coded scheme name: the volume lives on an NFS export
                # declared in the kbox config, and the daemon bind-mounts the
                # requested subtree. Passed through verbatim.
                mounts_json.append({
                    "Type": "bind",
                    "Source": raw_src,
                    "Destination": dst,
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
                binds.append(f"{raw_src}:{dst}{mode}")
                continue
            if not raw_src.startswith("/"):
                vobj = self.ensure_volume(raw_src, service=service_name)
                src = vobj["Mountpoint"]
                mounts_json.append({
                    "Type": "volume",
                    "Name": raw_src,
                    "Source": src,
                    "Destination": dst,
                    "Driver": "local",
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
            else:
                src = self.map_host_path(raw_src)
                mounts_json.append({
                    "Type": "bind",
                    "Source": src,
                    "Destination": dst,
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
            binds.append(f"{src}:{dst}{mode}")

        for m in host_cfg.get("Mounts") or []:
            mtype = m.get("Type", "bind")
            src = m.get("Source", "")
            dst = m.get("Target", "")
            if not dst:
                continue
            ro_flag = bool(m.get("ReadOnly"))
            ro = ":ro" if ro_flag else ""
            if is_nfs_source(src):
                mounts_json.append({
                    "Type": "bind",
                    "Source": src,
                    "Destination": dst,
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
                binds.append(f"{src}:{dst}{ro}")
                continue
            if mtype == "volume":
                vname = src or secrets.token_hex(8)
                vobj = self.ensure_volume(vname, service=service_name)
                src = vobj["Mountpoint"]
                mounts_json.append({
                    "Type": "volume",
                    "Name": vname,
                    "Source": src,
                    "Destination": dst,
                    "Driver": "local",
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
            else:
                src = self.map_host_path(src)
                mounts_json.append({
                    "Type": "bind",
                    "Source": src,
                    "Destination": dst,
                    "Mode": "ro" if ro_flag else "rw",
                    "RW": not ro_flag,
                })
            binds.append(f"{src}:{dst}{ro}")

        ports = []
        port_bindings = host_cfg.get("PortBindings") or {}
        mapped_ports_json = {}
        for cport_proto, blist in port_bindings.items():
            cport_str = cport_proto.split("/")[0]
            try:
                cport = int(cport_str)
            except ValueError:
                continue
            out_list = []
            for entry in blist or [{"HostIp": "0.0.0.0", "HostPort": ""}]:
                e = entry or {}
                hip = (e.get("HostIp") or "").strip() or "0.0.0.0"
                hp_str = str(e.get("HostPort") or "").strip()
                hp = (
                    int(hp_str)
                    if hp_str.isdigit() and int(hp_str) > 0
                    else self._alloc_ephemeral_port()
                )
                ports.append(f"{hip}:{hp}:{cport}")
                out_list.append({"HostIp": hip, "HostPort": str(hp)})
            mapped_ports_json[cport_proto] = out_list
        exposed_ports = dict(body.get("ExposedPorts") or {})

        # Collect DNS aliases from NetworkingConfig.EndpointsConfig and Compose labels
        aliases = [cname, cid[:12], hostname]
        svc_label = labels.get("com.docker.compose.service")
        if svc_label and svc_label not in aliases:
            aliases.append(svc_label)

        net_cfg = (body.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}
        attached_nets = {}
        for net_name, ep_cfg in net_cfg.items():
            for al in (ep_cfg or {}).get("Aliases") or []:
                if al and al not in aliases:
                    aliases.append(al)
            attached_nets[net_name] = dict(ep_cfg or {})
        if not attached_nets:
            nmode = host_cfg.get("NetworkMode") or "bridge"
            attached_nets[nmode] = {}

        rpc_resp = self.rpc.call({
            "op": "container_create",
            "id": cid,
            "image": img_id.removeprefix("sha256:"),
            "name": cname,
            "hostname": hostname,
            "workdir": workdir,
            "cmd": full_cmd,
            "env": merged_env,
            "binds": binds,
            "aliases": aliases,
            "ports": ports,
            "host_net": host_cfg.get("NetworkMode") == "host",
        })

        hc = body.get("Healthcheck")
        if hc is None:
            hc = img_cfg.get("Healthcheck")
        hc_test = hc.get("Test") if isinstance(hc, dict) else None
        if not isinstance(hc_test, list) or not hc_test or hc_test == ["NONE"]:
            hc = None

        rec = {
            "id": cid,
            "name": cname,
            "image": image_ref,
            "image_id": img_id,
            "created": int(time.time()),
            "started_at": 0,
            "finished_at": 0,
            "status": "created",
            "pid": 0,
            "exit_code": 0,
            "ip": rpc_resp.get("ip", ""),
            "gateway": rpc_resp.get("gateway", self.gateway_ip),
            "log_path": rpc_resp.get("log_path", f"/tmp/kboxd-logs/{cid}.log"),
            "cmd": cmd,
            "entrypoint": ep,
            "full_cmd": full_cmd,
            "env": merged_env,
            "workdir": workdir,
            "hostname": hostname,
            "labels": labels,
            "tty": bool(body.get("Tty", False)),
            "open_stdin": bool(body.get("OpenStdin", False)),
            "host_config": host_cfg,
            "port_bindings": mapped_ports_json,
            "exposed_ports": exposed_ports,
            "networks": attached_nets,
            "mounts_json": mounts_json,
            "healthcheck": hc,
            "health": None,
            "health_stop": threading.Event(),
        }
        with self.lock:
            self.containers[cid] = rec
        self.events.emit("container", "create", cid, {**labels, "name": cname, "image": image_ref})
        return rec

    def _watch_exit(self, c, gen=None):
        try:
            w = self.rpc.call({"op": "container_wait", "id": c["id"]})
            ec = w.get("exit_code", 0)
        except Exception:
            ec = 137
        # A watcher started by an older run must not overwrite the state of a
        # container that has been restarted since (compose restarts containers
        # in place, and the previous wait returns at that point).
        if gen is not None and c.get("gen") != gen:
            return
        c["status"] = "exited"
        c["exit_code"] = ec
        c["finished_at"] = int(time.time())
        if c.get("health_stop") is not None:
            c["health_stop"].set()
        self.events.emit(
            "container", "die", c["id"],
            {**c["labels"], "name": c["name"], "exitCode": str(ec)},
        )

    @staticmethod
    def _read_multiplexed_output(log_path, limit=4096):
        out = bytearray()
        try:
            with open(log_path, "rb") as f:
                while len(out) < limit:
                    hdr = f.read(8)
                    if len(hdr) < 8:
                        break
                    slen = struct.unpack(">I", hdr[4:8])[0]
                    payload = f.read(slen)
                    out.extend(payload[: max(0, limit - len(out))])
                    if len(payload) < slen:
                        break
        except OSError:
            return ""
        return out.decode("utf-8", errors="replace")

    @staticmethod
    def _healthcheck_cmd(test):
        if not test:
            return None
        kind = test[0]
        if kind == "CMD":
            return list(test[1:])
        if kind == "CMD-SHELL" and len(test) >= 2:
            return ["/bin/sh", "-c", test[1]]
        return list(test)

    def _run_healthcheck_once(self, c, cmd, timeout_s):
        start_ts = time.time()
        ec = 1
        out = ""
        eid = None
        try:
            e = self.create_exec(c, {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True})
            eid = e["id"]
            self.start_exec(e)
            if not e["done_ev"].wait(timeout=timeout_s):
                ec = 1
                out = "healthcheck timed out"
            else:
                ec = int(e.get("exit_code", 1))
                out = self._read_multiplexed_output(e["log_path"])
        except Exception as exc:
            ec = 1
            out = str(exc)
        finally:
            if eid:
                with self.lock:
                    self.execs.pop(eid, None)
        end_ts = time.time()
        return {
            "Start": rfc3339(start_ts),
            "End": rfc3339(end_ts),
            "ExitCode": ec,
            "Output": out,
        }

    def _watch_health(self, c):
        hc = c.get("healthcheck") or {}
        cmd = self._healthcheck_cmd(hc.get("Test") or [])
        if not cmd:
            return
        interval_s = max(0.2, int(hc.get("Interval") or 30_000_000_000) / 1e9)
        timeout_s = max(0.5, int(hc.get("Timeout") or 30_000_000_000) / 1e9)
        retries = max(1, int(hc.get("Retries") or 3))
        start_period_s = max(0.0, int(hc.get("StartPeriod") or 0) / 1e9)
        stop_ev = c["health_stop"]
        started_monotonic = time.monotonic()

        # Run an initial probe promptly so `service_healthy` converges without waiting
        # a full interval when a container comes up fast, then follow configured Interval.
        if stop_ev.wait(timeout=min(1.0, interval_s)):
            return

        while not stop_ev.is_set():
            self.refresh_container(c)
            if c["status"] != "running":
                break
            entry = self._run_healthcheck_once(c, cmd, timeout_s)
            if stop_ev.is_set() or c["status"] != "running":
                break

            with self.lock:
                h = c.get("health")
                if h is None:
                    break
                prev_status = h["Status"]
                log = list(h.get("Log") or [])
                log.append(entry)
                if len(log) > 5:
                    log = log[-5:]
                h["Log"] = log
                if entry["ExitCode"] == 0:
                    h["FailingStreak"] = 0
                    h["Status"] = "healthy"
                else:
                    in_start_period = (time.monotonic() - started_monotonic) < start_period_s
                    if not in_start_period:
                        h["FailingStreak"] = int(h.get("FailingStreak", 0)) + 1
                        if h["FailingStreak"] >= retries:
                            h["Status"] = "unhealthy"
                new_status = h["Status"]

            if new_status != prev_status and new_status in ("healthy", "unhealthy"):
                self.events.emit(
                    "container", f"health_status: {new_status}", c["id"],
                    {**c["labels"], "name": c["name"]},
                )

            wait_s = min(interval_s, 2.0) if new_status == "starting" else interval_s
            if stop_ev.wait(timeout=wait_s):
                break

    def _ensure_mount_sources(self, c):
        """Recreate volume directories that disappeared while the container
        existed. Docker keeps named volumes across container restarts, so a
        missing directory must not turn into a broken mount (the guest then
        dies with "mkdir: cannot create directory ...: No such file or
        directory" and exit 127).
        """
        for m in c.get("mounts_json") or []:
            src = m.get("Source")
            if not src or not os.path.isabs(src):
                continue
            try:
                owned = os.path.commonpath(
                    [os.path.abspath(src), self.vol_root]
                ) == self.vol_root
            except ValueError:
                owned = False
            if owned:
                os.makedirs(src, exist_ok=True)

    def start_container(self, c):
        self._ensure_mount_sources(c)
        resp = self.rpc.call({"op": "container_start", "id": c["id"]})
        c["status"] = "running"
        c["pid"] = resp.get("pid", 0)
        c["ip"] = resp.get("ip", c.get("ip", ""))
        c["started_at"] = int(time.time())
        # A restart must not report the previous run's exit status.
        c["exit_code"] = 0
        c["finished_at"] = 0
        c["gen"] = c.get("gen", 0) + 1
        gen = c["gen"]
        if c.get("healthcheck"):
            c["health"] = {"Status": "starting", "FailingStreak": 0, "Log": []}
            c["health_stop"].clear()
            ht = threading.Thread(target=self._watch_health, args=(c,), daemon=True)
            ht.start()
        self.events.emit("container", "start", c["id"], {**c["labels"], "name": c["name"]})
        t = threading.Thread(target=self._watch_exit, args=(c, gen), daemon=True)
        t.start()

    def create_exec(self, c, body):
        self.refresh_container(c)
        if c["status"] != "running":
            raise RuntimeError(f"Container {c['id']} is not running")
        eid = secrets.token_hex(32)
        cmd = body.get("Cmd") or ["/bin/sh"]
        env = body.get("Env") or []
        workdir = body.get("WorkingDir") or ""
        tty = bool(body.get("Tty", False))
        rec = {
            "id": eid,
            "container_id": c["id"],
            "cmd": cmd,
            "env": env,
            "workdir": workdir,
            "tty": tty,
            "attach_stdout": bool(body.get("AttachStdout", True)),
            "attach_stderr": bool(body.get("AttachStderr", True)),
            "running": False,
            "exited": False,
            "exit_code": 0,
            "pid": 0,
            "log_path": f"/tmp/kboxd-logs/exec-{eid}.log",
            "done_ev": threading.Event(),
        }
        with self.lock:
            self.execs[eid] = rec
        return rec

    def _watch_exec_exit(self, e):
        try:
            w = self.rpc.call({"op": "exec_wait", "exec_id": e["id"]})
            ec = w.get("exit_code", 0)
        except Exception:
            ec = 137
        e["exit_code"] = ec
        e["running"] = False
        e["exited"] = True
        e["done_ev"].set()

    def start_exec(self, e):
        resp = self.rpc.call({
            "op": "exec_start",
            "exec_id": e["id"],
            "container_id": e["container_id"],
            "cmd": e["cmd"],
            "env": e["env"],
            "workdir": e["workdir"],
        })
        e["pid"] = resp.get("pid", 0)
        e["log_path"] = resp.get("log_path", e["log_path"])
        e["running"] = True
        t = threading.Thread(target=self._watch_exec_exit, args=(e,), daemon=True)
        t.start()

    def exec_inspect_json(self, e):
        return {
            "CanRemove": False,
            "DetachKeys": "",
            "ID": e["id"],
            "Running": e["running"],
            "ExitCode": e["exit_code"],
            "ProcessConfig": {
                "privileged": False,
                "user": "",
                "tty": e["tty"],
                "entrypoint": e["cmd"][0] if e["cmd"] else "/bin/sh",
                "arguments": e["cmd"][1:] if len(e["cmd"]) > 1 else [],
            },
            "OpenStdin": False,
            "OpenStderr": e["attach_stderr"],
            "OpenStdout": e["attach_stdout"],
            "ContainerID": e["container_id"],
            "Pid": e["pid"],
        }

    def container_inspect_json(self, c):
        self.refresh_container(c)
        running = c["status"] == "running"
        gw = c.get("gateway") or self.gateway_ip
        nets_out = {}
        for nname, ep in c["networks"].items():
            net_obj = self.find_network(nname)
            nid = net_obj["Id"] if net_obj else "kbox-bridge-default"
            nets_out[nname] = {
                "IPAMConfig": ep.get("IPAMConfig"),
                "Links": ep.get("Links"),
                "Aliases": ep.get("Aliases") or [c["name"], c["id"][:12]],
                "NetworkID": nid,
                "EndpointID": hashlib.sha256(f"{nid}:{c['id']}".encode()).hexdigest()[:16],
                "Gateway": gw,
                "IPAddress": c["ip"],
                "IPPrefixLen": 32,
                "IPv6Gateway": "",
                "GlobalIPv6Address": "",
                "GlobalIPv6PrefixLen": 0,
                "MacAddress": "02:42:ac:12:00:02",
            }
        ports_ns = {}
        for cport_proto, blist in c["port_bindings"].items():
            ports_ns[cport_proto] = blist

        state_out = {
            "Status": c["status"],
            "Running": running,
            "Paused": False,
            "Restarting": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": c["pid"] if running else 0,
            "ExitCode": c["exit_code"],
            "Error": "",
            "StartedAt": rfc3339(c["started_at"]),
            "FinishedAt": rfc3339(c["finished_at"]),
        }
        if c.get("health") is not None:
            with self.lock:
                h = c["health"]
                state_out["Health"] = {
                    "Status": h["Status"],
                    "FailingStreak": h["FailingStreak"],
                    "Log": list(h["Log"]),
                }

        cfg_out = {
            "Hostname": c["hostname"],
            "Domainname": "",
            "User": "",
            "AttachStdin": False,
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": c["tty"],
            "OpenStdin": c["open_stdin"],
            "StdinOnce": False,
            "Env": c["env"],
            "Cmd": c["cmd"],
            "Image": c["image"],
            "WorkingDir": c["workdir"],
            "Entrypoint": c["entrypoint"],
            "ExposedPorts": c.get("exposed_ports") or {},
            "Labels": c["labels"],
        }
        if c.get("healthcheck") is not None:
            cfg_out["Healthcheck"] = c["healthcheck"]

        return {
            "Id": c["id"],
            "Created": rfc3339(c["created"]),
            "Path": c["full_cmd"][0] if c["full_cmd"] else "/bin/sh",
            "Args": c["full_cmd"][1:] if len(c["full_cmd"]) > 1 else [],
            "State": state_out,
            "Image": c["image_id"],
            "Name": "/" + c["name"],
            "RestartCount": 0,
            "Driver": "overlay2",
            "Platform": "linux",
            "Mounts": c["mounts_json"],
            "Config": cfg_out,
            "HostConfig": {
                **c["host_config"],
                "PortBindings": c["port_bindings"],
            },
            "NetworkSettings": {
                "Bridge": "br0",
                "Gateway": gw,
                "IPAddress": c["ip"],
                "IPPrefixLen": 32,
                "Ports": ports_ns,
                "Networks": nets_out,
            },
        }


class DockerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"Docker/{SERVER_VERSION}"

    def log_message(self, fmt, *args):
        if getattr(self.server, "verbose", False):
            sys.stderr.write(f"[dockerd] {self.address_string()} - {fmt % args}\n")

    def _send_docker_headers(self):
        self.send_header("Api-Version", API_VERSION)
        self.send_header("Min-Api-Version", MIN_API_VERSION)
        self.send_header("Ostype", "linux")
        self.send_header("Docker-Experimental", "false")
        self.send_header("Server", f"Docker/{SERVER_VERSION} (linux)")

    def send_json(self, code, obj):
        body = (json.dumps(obj) + "\n").encode("utf-8")
        self.send_response(code)
        self._send_docker_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_empty(self, code, ctype="text/plain"):
        self.send_response(code)
        self._send_docker_headers()
        if code not in (204, 304):
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", "0")
        self.end_headers()

    def _begin_chunked(self, code, ctype):
        self.send_response(code)
        self._send_docker_headers()
        self.send_header("Content-Type", ctype)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _write_chunk(self, data):
        if not data:
            return
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.wfile.write(f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n")
        self.wfile.flush()

    def _end_chunked(self):
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _read_body(self):
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            out = bytearray()
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                sz = int(line.strip().split(b";", 1)[0], 16)
                if sz == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                out.extend(self.rfile.read(sz))
                self.rfile.read(2)
            return bytes(out)
        cl = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(cl) if cl > 0 else b""

    def _read_json(self):
        raw = self._read_body()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _parse_url(self):
        u = urllib.parse.urlparse(self.path)
        clean_path = re.sub(r"^/v\d+\.\d+", "", u.path) or "/"
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        return clean_path, qs

    def do_HEAD(self):
        path, _ = self._parse_url()
        if path == "/_ping":
            self.send_response(200)
            self._send_docker_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "2")
            self.end_headers()
            return
        self.send_empty(404)

    def do_GET(self):
        eng = self.server.engine
        path, qs = self._parse_url()

        if path == "/_ping":
            self.send_response(200)
            self._send_docker_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        if path == "/version":
            arch = "arm64" if platform.machine().lower() in ("aarch64", "arm64") else "amd64"
            self.send_json(200, {
                "Platform": {"Name": "kbox LKL Engine"},
                "Components": [{"Name": "Engine", "Version": SERVER_VERSION, "Details": {"ApiVersion": API_VERSION, "Arch": arch, "Os": "linux"}}],
                "Version": SERVER_VERSION,
                "ApiVersion": API_VERSION,
                "MinAPIVersion": MIN_API_VERSION,
                "Os": "linux",
                "Arch": arch,
                "KernelVersion": "6.8.0-kbox",
            })
            return

        if path == "/info":
            arch = platform.machine()
            with eng.lock:
                total = len(eng.containers)
                running = sum(1 for c in eng.containers.values() if c["status"] == "running")
            self.send_json(200, {
                "ID": "kbox-single-lkl-engine",
                "Containers": total,
                "ContainersRunning": running,
                "ContainersPaused": 0,
                "ContainersStopped": total - running,
                "Images": len(eng.images.list_images()),
                "Driver": "overlay2",
                "OperatingSystem": "kbox LKL (single-kernel namespaces)",
                "OSType": "linux",
                "Architecture": arch,
                "KernelVersion": "6.8.0-kbox",
                "Name": "kboxd",
                "ServerVersion": SERVER_VERSION,
                "NCPU": 1,
                "MemTotal": 1024 * 1024 * 1024,
            })
            return

        if path == "/events":
            self._handle_events(qs)
            return

        if path == "/images/json":
            self.send_json(200, eng.images.list_images())
            return

        m = re.match(r"^/images/(.+)/json$", path)
        if m:
            ref = urllib.parse.unquote(m.group(1))
            iid = eng.images.resolve(ref)
            if not iid:
                self.send_json(404, {"message": f"No such image: {ref}"})
                return
            meta = eng.images.get_meta(iid) or {}
            tags = [k for k, v in eng.images.tags.items() if v == iid]
            self.send_json(200, {
                "Id": iid,
                "RepoTags": tags,
                "Created": rfc3339(meta.get("created", 0)),
                "Architecture": meta.get("architecture", "arm64"),
                "Os": "linux",
                "Size": meta.get("size", 0),
                "Config": meta.get("config", {}),
            })
            return

        if path == "/networks":
            filters = (qs.get("filters") or [None])[0]
            out = []
            with eng.lock:
                nets = list(eng.networks.values())
            for n in nets:
                if eng.match_filters(n["Id"], n["Name"], n.get("Labels") or {}, "", filters):
                    out.append(n)
            self.send_json(200, out)
            return

        m = re.match(r"^/networks/([^/]+)$", path)
        if m:
            n = eng.find_network(urllib.parse.unquote(m.group(1)))
            if not n:
                self.send_json(404, {"message": "network not found"})
                return
            ncopy = dict(n)
            cdict = {}
            with eng.lock:
                clist = list(eng.containers.values())
            for c in clist:
                if n["Name"] in c["networks"] or n["Id"] in c["networks"]:
                    cdict[c["id"]] = {
                        "Name": c["name"],
                        "EndpointID": c["id"][:16],
                        "MacAddress": "02:42:ac:12:00:02",
                        "IPv4Address": f"{c['ip']}/16" if c.get("ip") else "",
                        "IPv6Address": "",
                    }
            ncopy["Containers"] = cdict
            self.send_json(200, ncopy)
            return

        if path == "/volumes":
            with eng.lock:
                vols = list(eng.volumes.values())
            self.send_json(200, {"Volumes": vols, "Warnings": []})
            return

        m = re.match(r"^/volumes/([^/]+)$", path)
        if m:
            vname = urllib.parse.unquote(m.group(1))
            with eng.lock:
                v = eng.volumes.get(vname)
            if not v:
                self.send_json(404, {"message": f"no such volume: {vname}"})
            else:
                self.send_json(200, v)
            return

        if path == "/containers/json":
            show_all = (qs.get("all") or ["0"])[0] in ("1", "true", "True")
            filters = (qs.get("filters") or [None])[0]
            out = []
            with eng.lock:
                clist = list(eng.containers.values())
            for c in clist:
                eng.refresh_container(c)
                if not show_all and c["status"] != "running" and not filters:
                    continue
                if not eng.match_filters(c["id"], c["name"], c["labels"], c["status"], filters):
                    continue
                ports_list = []
                for cport_proto, blist in c["port_bindings"].items():
                    cp = int(cport_proto.split("/")[0])
                    for b in blist:
                        ports_list.append({
                            "IP": b.get("HostIp", "0.0.0.0"),
                            "PrivatePort": cp,
                            "PublicPort": int(b.get("HostPort", 0)),
                            "Type": "tcp",
                        })
                if c["status"] == "running":
                    h = c.get("health")
                    ps_status = f"Up ({h['Status']})" if h else "Up"
                elif c["status"] == "created":
                    ps_status = "Created"
                else:
                    ps_status = f"Exited ({c['exit_code']})"
                out.append({
                    "Id": c["id"],
                    "Names": ["/" + c["name"]],
                    "Image": c["image"],
                    "ImageID": c["image_id"],
                    "Command": " ".join(c["full_cmd"]),
                    "Created": c["created"],
                    "Ports": ports_list,
                    "Labels": c["labels"],
                    "State": c["status"],
                    "Status": ps_status,
                    "HostConfig": {"NetworkMode": next(iter(c["networks"]), "bridge")},
                    "NetworkSettings": {"Networks": {k: {"IPAddress": c["ip"]} for k in c["networks"]}},
                    "Mounts": c["mounts_json"],
                })
            self.send_json(200, out)
            return

        m = re.match(r"^/containers/([^/]+)/json$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            # Report live state: compose polls inspect while waiting for a
            # container to exit, and a cached "running" hides the exit.
            eng.refresh_container(c)
            self.send_json(200, eng.container_inspect_json(c))
            return

        m = re.match(r"^/containers/([^/]+)/logs$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            self._handle_logs(c, qs)
            return

        m = re.match(r"^/exec/([^/]+)/json$", path)
        if m:
            eid = urllib.parse.unquote(m.group(1))
            with eng.lock:
                e = eng.execs.get(eid)
            if not e:
                self.send_json(404, {"message": f"No such exec instance: {eid}"})
                return
            self.send_json(200, eng.exec_inspect_json(e))
            return

        self.send_json(404, {"message": f"page not found: {path}"})

    def do_POST(self):
        eng = self.server.engine
        path, qs = self._parse_url()

        if path == "/images/create":
            from_img = (qs.get("fromImage") or [""])[0]
            tag = (qs.get("tag") or ["latest"])[0]
            if not from_img:
                self.send_json(400, {"message": "fromImage required"})
                return
            self._begin_chunked(200, "application/json")
            try:
                def emit_p(obj):
                    self._write_chunk(json.dumps(obj) + "\n")
                eng.images.pull(from_img, tag, progress_cb=emit_p)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._write_chunk(json.dumps({"error": str(e), "errorDetail": {"message": str(e)}}) + "\n")
            self._end_chunked()
            return

        m = re.match(r"^/images/(.+)/tag$", path)
        if m:
            src = urllib.parse.unquote(m.group(1))
            repo = (qs.get("repo") or [""])[0]
            tag = (qs.get("tag") or [None])[0]
            if not repo:
                self.send_json(400, {"message": "repo required"})
                return
            if eng.images.tag(src, repo, tag) is None:
                self.send_json(404, {"message": f"No such image: {src}"})
                return
            self.send_empty(201)
            return

        if path == "/networks/create":
            body = self._read_json()
            name = body.get("Name", "")
            nid = hashlib.sha256((name + secrets.token_hex(8)).encode()).hexdigest()
            net = {
                "Name": name,
                "Id": nid,
                "Created": rfc3339(time.time()),
                "Scope": "local",
                "Driver": body.get("Driver") or "bridge",
                "EnableIPv6": False,
                "Internal": bool(body.get("Internal", False)),
                "Attachable": bool(body.get("Attachable", True)),
                "Ingress": False,
                "IPAM": {
                    "Driver": "default",
                    "Options": None,
                    "Config": [{"Subnet": eng.subnet_cidr, "Gateway": eng.gateway_ip}],
                },
                "Options": body.get("Options") or {},
                "Labels": body.get("Labels") or {},
            }
            with eng.lock:
                eng.networks[nid] = net
            eng.events.emit("network", "create", nid, {"name": name, "type": net["Driver"]})
            self.send_json(201, {"Id": nid, "Warning": ""})
            return

        m = re.match(r"^/networks/([^/]+)/connect$", path)
        if m:
            n = eng.find_network(urllib.parse.unquote(m.group(1)))
            body = self._read_json()
            c = eng.find_container(body.get("Container", ""))
            if not n or not c:
                self.send_json(404, {"message": "network or container not found"})
                return
            ep_cfg = body.get("EndpointConfig") or {}
            c["networks"][n["Name"]] = ep_cfg
            for al in ep_cfg.get("Aliases") or []:
                if c.get("ip"):
                    eng.rpc.call({"op": "dns_set", "name": al, "ip": c["ip"]})
            self.send_empty(200)
            return

        m = re.match(r"^/networks/([^/]+)/disconnect$", path)
        if m:
            n = eng.find_network(urllib.parse.unquote(m.group(1)))
            body = self._read_json()
            c = eng.find_container(body.get("Container", ""))
            if n and c:
                c["networks"].pop(n["Name"], None)
            self.send_empty(200)
            return

        if path == "/volumes/create":
            body = self._read_json()
            vname = body.get("Name") or secrets.token_hex(16)
            try:
                vobj = eng.ensure_volume(
                    vname,
                    labels=body.get("Labels") or {},
                    options=body.get("DriverOpts") or {},
                )
            except ValueError as e:
                self.send_json(400, {"message": str(e)})
                return
            self.send_json(201, vobj)
            return

        if path == "/containers/create":
            body = self._read_json()
            cname = (qs.get("name") or [""])[0]
            try:
                rec = eng.create_container(cname, body)
                self.send_json(201, {"Id": rec["id"], "Warnings": []})
            except KeyError as e:
                self.send_json(404, {"message": str(e)})
            except Exception as e:
                self.send_json(500, {"message": str(e)})
            return

        m = re.match(r"^/containers/([^/]+)/start$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            try:
                eng.start_container(c)
                self.send_empty(204)
            except Exception as e:
                self.send_json(500, {"message": str(e)})
            return

        m = re.match(r"^/containers/([^/]+)/stop$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            timeout = int((qs.get("t") or ["10"])[0] or "10")
            eng.refresh_container(c)
            if c["status"] != "running":
                self.send_empty(304)
                return
            eng.rpc.call({"op": "container_stop", "id": c["id"], "timeout": timeout})
            if c.get("health_stop") is not None:
                c["health_stop"].set()
            eng.refresh_container(c)
            eng.events.emit("container", "stop", c["id"], {**c["labels"], "name": c["name"]})
            self.send_empty(204)
            return

        m = re.match(r"^/containers/([^/]+)/kill$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            eng.rpc.call({"op": "container_kill", "id": c["id"], "signal": 9})
            self.send_empty(204)
            return

        m = re.match(r"^/containers/([^/]+)/rename$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            new_name = ((qs.get("name") or [""])[0] or "").lstrip("/")
            if not new_name:
                self.send_json(400, {"message": "name query parameter is required"})
                return
            with eng.lock:
                for other in eng.containers.values():
                    if other["id"] != c["id"] and other["name"] == new_name:
                        self.send_json(409, {"message": f"Conflict. The container name \"/{new_name}\" is already in use"})
                        return
                old_name = c["name"]
                c["name"] = new_name
                for net_ep in c["networks"].values():
                    aliases = list(net_ep.get("Aliases") or [])
                    if old_name in aliases:
                        aliases = [new_name if a == old_name else a for a in aliases]
                    elif new_name not in aliases:
                        aliases.append(new_name)
                    net_ep["Aliases"] = aliases
            if c.get("ip"):
                try:
                    eng.rpc.call({"op": "dns_set", "name": new_name, "ip": c["ip"]})
                except Exception:
                    pass
            eng.events.emit(
                "container", "rename", c["id"],
                {**c["labels"], "name": new_name, "oldName": old_name},
            )
            self.send_empty(204)
            return

        m = re.match(r"^/containers/([^/]+)/wait$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            w = eng.rpc.call({"op": "container_wait", "id": c["id"]})
            c["status"] = "exited"
            c["exit_code"] = w.get("exit_code", 0)
            self.send_json(200, {"StatusCode": c["exit_code"], "Error": None})
            return

        m = re.match(r"^/containers/([^/]+)/attach$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            self._handle_attach(c, qs)
            return

        m = re.match(r"^/containers/([^/]+)/exec$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            body = self._read_json()
            try:
                rec = eng.create_exec(c, body)
                self.send_json(201, {"Id": rec["id"]})
            except Exception as exc:
                self.send_json(409, {"message": str(exc)})
            return

        m = re.match(r"^/exec/([^/]+)/start$", path)
        if m:
            eid = urllib.parse.unquote(m.group(1))
            with eng.lock:
                e = eng.execs.get(eid)
            if not e:
                self.send_json(404, {"message": f"No such exec instance: {eid}"})
                return
            body = self._read_json()
            self._handle_exec_start(e, body)
            return

        m = re.match(r"^/(containers|exec)/([^/]+)/resize$", path)
        if m:
            self.send_empty(200)
            return

        self.send_json(404, {"message": f"unsupported POST {path}"})

    def do_DELETE(self):
        eng = self.server.engine
        path, qs = self._parse_url()

        m = re.match(r"^/containers/([^/]+)$", path)
        if m:
            c = eng.find_container(urllib.parse.unquote(m.group(1)))
            if not c:
                self.send_json(404, {"message": "No such container"})
                return
            force = (qs.get("force") or ["0"])[0] in ("1", "true", "True")
            try:
                eng.rpc.call({"op": "container_rm", "id": c["id"], "force": force})
            except Exception as e:
                self.send_json(409, {"message": str(e)})
                return
            with eng.lock:
                eng.containers.pop(c["id"], None)
            if c.get("health_stop") is not None:
                c["health_stop"].set()
            eng.events.emit("container", "destroy", c["id"], {**c["labels"], "name": c["name"]})
            self.send_empty(204)
            return

        m = re.match(r"^/networks/([^/]+)$", path)
        if m:
            n = eng.find_network(urllib.parse.unquote(m.group(1)))
            if not n:
                self.send_json(404, {"message": "network not found"})
                return
            with eng.lock:
                eng.networks.pop(n["Id"], None)
            eng.events.emit("network", "destroy", n["Id"], {"name": n["Name"]})
            self.send_empty(204)
            return

        m = re.match(r"^/volumes/([^/]+)$", path)
        if m:
            vname = urllib.parse.unquote(m.group(1))
            try:
                removed = eng.remove_volume(vname)
            except ValueError as e:
                self.send_json(400, {"message": str(e)})
                return
            if not removed:
                self.send_json(404, {"message": f"no such volume: {vname}"})
                return
            self.send_empty(204)
            return

        m = re.match(r"^/images/(.+)$", path)
        if m:
            self.send_json(200, [{"Untagged": urllib.parse.unquote(m.group(1))}])
            return

        self.send_json(404, {"message": f"unsupported DELETE {path}"})

    @staticmethod
    def _drain_frames(log_path, pos, tty, show_out, show_err, write_fn):
        with open(log_path, "rb") as f:
            f.seek(pos)
            while True:
                hdr = f.read(8)
                if len(hdr) < 8:
                    break
                stype = hdr[0]
                slen = struct.unpack(">I", hdr[4:8])[0]
                payload = f.read(slen)
                if len(payload) < slen:
                    break
                pos += 8 + slen
                if (stype == 1 and show_out) or (stype == 2 and show_err):
                    write_fn(payload if tty else (hdr + payload))
        return pos

    def _stream_log_file(self, log_path, tty, follow, show_out, show_err, write_fn, is_exited_fn, tail=None):
        pos = 0
        if tail is not None and tail != "all":
            try:
                tn = int(tail)
            except ValueError:
                tn = None
            if tn is not None and tn >= 0:
                if tn == 0:
                    if os.path.exists(log_path):
                        pos = os.path.getsize(log_path)
                    if not follow:
                        return
                elif os.path.exists(log_path):
                    frames = []
                    with open(log_path, "rb") as f:
                        while True:
                            hdr = f.read(8)
                            if len(hdr) < 8:
                                break
                            stype = hdr[0]
                            slen = struct.unpack(">I", hdr[4:8])[0]
                            payload = f.read(slen)
                            if len(payload) < slen:
                                break
                            pos += 8 + slen
                            if (stype == 1 and show_out) or (stype == 2 and show_err):
                                frames.append((hdr, payload))
                    lines = []
                    for hdr, pl in frames:
                        for ln in pl.splitlines(keepends=True):
                            lines.append((hdr[0], ln))
                    for stype, ln in lines[-tn:]:
                        if tty:
                            write_fn(ln)
                        else:
                            h = struct.pack(">BxxxI", stype, len(ln))
                            write_fn(h + ln)
                    if not follow:
                        return

        while True:
            if not os.path.exists(log_path):
                if is_exited_fn() or not follow:
                    break
                time.sleep(0.05)
                continue
            pos = self._drain_frames(log_path, pos, tty, show_out, show_err, write_fn)
            if not follow:
                break
            if is_exited_fn():
                pos = self._drain_frames(log_path, pos, tty, show_out, show_err, write_fn)
                break
            time.sleep(0.05)

    def _stream_upgrade_or_chunked(self, log_path, tty, show_out, show_err, is_exited_fn):
        upgrade = self.headers.get("Upgrade", "").lower() == "tcp"
        ctype = "application/vnd.docker.raw-stream" if tty else "application/vnd.docker.multiplexed-stream"

        if upgrade:
            self.send_response(101, "Switching Protocols")
            self._send_docker_headers()
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "tcp")
            self.send_header("Content-Type", ctype)
            self.end_headers()

            def write_raw(b):
                self.wfile.write(b)
                self.wfile.flush()

            try:
                self._stream_log_file(log_path, tty, True, show_out, show_err, write_raw, is_exited_fn)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
        else:
            self._begin_chunked(200, ctype)
            try:
                self._stream_log_file(log_path, tty, True, show_out, show_err, self._write_chunk, is_exited_fn)
            except (BrokenPipeError, ConnectionResetError):
                return
            self._end_chunked()

    def _handle_logs(self, c, qs):
        follow = (qs.get("follow") or ["0"])[0] in ("1", "true", "True")
        show_out = (qs.get("stdout") or ["1"])[0] in ("1", "true", "True")
        show_err = (qs.get("stderr") or ["1"])[0] in ("1", "true", "True")
        tail = (qs.get("tail") or [None])[0]
        ctype = "application/vnd.docker.raw-stream" if c["tty"] else "application/vnd.docker.multiplexed-stream"
        self._begin_chunked(200, ctype)

        def is_exited():
            self.server.engine.refresh_container(c)
            return c["status"] == "exited"

        try:
            self._stream_log_file(c["log_path"], c["tty"], follow, show_out, show_err, self._write_chunk, is_exited, tail=tail)
        except (BrokenPipeError, ConnectionResetError):
            return
        self._end_chunked()

    def _handle_attach(self, c, qs):
        show_out = (qs.get("stdout") or ["1"])[0] in ("1", "true", "True")
        show_err = (qs.get("stderr") or ["1"])[0] in ("1", "true", "True")

        def is_exited():
            self.server.engine.refresh_container(c)
            return c["status"] == "exited"

        self._stream_upgrade_or_chunked(c["log_path"], c["tty"], show_out, show_err, is_exited)

    def _handle_exec_start(self, e, body):
        eng = self.server.engine
        detach = bool(body.get("Detach", False))
        tty = bool(body.get("Tty", e["tty"]))
        e["tty"] = tty
        try:
            eng.start_exec(e)
        except Exception as exc:
            sys.stderr.write(f"[dockerd] exec_start error: {exc}\n")
            sys.stderr.flush()
            self.send_json(500, {"message": str(exc)})
            return

        if detach:
            self.send_empty(200)
            return

        self._stream_upgrade_or_chunked(
            e["log_path"],
            tty,
            e["attach_stdout"],
            e["attach_stderr"],
            lambda: e["exited"],
        )
        e["done_ev"].wait(timeout=2.0)
        try:
            if os.path.exists(e["log_path"]):
                os.unlink(e["log_path"])
        except OSError:
            pass

    def _handle_events(self, qs):
        filters = (qs.get("filters") or [None])[0]
        fobj = json.loads(filters) if filters else {}
        self._begin_chunked(200, "application/json")
        q = self.server.engine.events.subscribe()
        try:
            while True:
                try:
                    ev = q.get(timeout=0.5)
                except queue.Empty:
                    continue
                if fobj:
                    if "type" in fobj and ev["Type"] not in fobj["type"]:
                        continue
                    if "event" in fobj and ev["Action"] not in fobj["event"]:
                        continue
                    if "label" in fobj:
                        attrs = ev.get("Actor", {}).get("Attributes", {})
                        ok = True
                        for expr in fobj["label"]:
                            if "=" in expr:
                                k, v = expr.split("=", 1)
                                if attrs.get(k) != v:
                                    ok = False
                            elif expr not in attrs:
                                ok = False
                        if not ok:
                            continue
                self._write_chunk(json.dumps(ev) + "\n")
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.server.engine.events.unsubscribe(q)


def main():
    ap = argparse.ArgumentParser(description="Docker Engine HTTP server backed by kbox daemon")
    ap.add_argument("--kbox-sock", default="/tmp/kboxd.sock", help="kbox daemon RPC socket")
    ap.add_argument("--listen", default="0.0.0.0:2375", help="TCP listen host:port")
    ap.add_argument("--state-dir", default="/tmp/kbox-dockerd", help="Image/state cache directory")
    ap.add_argument("--config", default=None, help="Path to kbox-config.yaml")
    ap.add_argument("--import-dir", action="append", default=[], help="Pre-import host dir as REF=DIR")
    ap.add_argument("--path-map", action="append", default=[], help="Rewrite bind path HOST_PREFIX:LOCAL_PREFIX")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.state_dir, exist_ok=True)
    rpc = KboxRpcClient(args.kbox_sock)
    for _ in range(50):
        try:
            if rpc.call({"op": "ping"}).get("ok"):
                break
        except Exception:
            time.sleep(0.1)

    path_maps = []
    for pm in args.path_map:
        if ":" in pm:
            s, d = pm.split(":", 1)
            path_maps.append((s, d))

    engine = DockerEngineState(rpc, args.state_dir, path_maps=path_maps, config_path=args.config)

    for imp in args.import_dir:
        if "=" in imp:
            ref, src = imp.split("=", 1)
            engine.images.import_dir_as_image(ref, src)

    host, port_str = args.listen.rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port_str)), DockerHandler)
    srv.engine = engine
    srv.verbose = args.verbose
    sys.stderr.write(f"kbox-dockerd listening on http://{host}:{port_str} -> {args.kbox_sock}\n")
    sys.stderr.flush()
    # SIGUSR1 dumps every thread's Python stack into the log; the only way to
    # see where a wedged request is stuck without a debugger in the image.
    faulthandler.register(signal.SIGUSR1, file=sys.stderr, all_threads=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
