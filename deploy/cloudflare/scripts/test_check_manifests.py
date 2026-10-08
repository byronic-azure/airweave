#!/usr/bin/env python3
"""Self-test for check_manifests.py.

Pins the behaviours a user can rely on: the manifests in the repo pass, the
documented QUIC fallback (``--protocol http2`` on the command, or the env var
``TUNNEL_TRANSPORT_PROTOCOL``) is accepted in both the base Deployment and the
config overlay's patch, an unknown protocol is rejected, and the config overlay
cannot regress to nesting the credentials Secret inside the ConfigMap mount.

Runs with plain python3 (no pytest needed; pytest collects it too):
    python3 deploy/cloudflare/scripts/test_check_manifests.py
validate.sh runs it as the "selftest" check.
"""

from __future__ import annotations

import contextlib
import copy
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_manifests as cm  # noqa: E402

K8S_DIR = Path(__file__).resolve().parent.parent / "k8s"
BASE_SRC = "base/deployment.yaml"
PATCH_SRC = "overlays/config/deployment-patch.yaml"


def load(rel: str) -> dict:
    """Return the single document of a manifest under k8s/."""
    (doc,) = cm.load_docs(K8S_DIR / rel)
    return copy.deepcopy(doc)


def container(doc: dict) -> dict:
    """The cloudflared container of a Deployment (or Deployment patch)."""
    return doc["spec"]["template"]["spec"]["containers"][0]


def with_protocol_flag(doc: dict, value: str) -> dict:
    """Insert ``--protocol VALUE`` before ``run``, as the docs describe."""
    command = container(doc)["command"]
    command[-1:-1] = ["--protocol", value]
    return doc


def test_repo_manifests_pass() -> None:
    with contextlib.redirect_stdout(io.StringIO()):
        assert cm.main([str(K8S_DIR)]) == 0


def test_protocol_flag_accepted_in_base_and_config_patch() -> None:
    assert cm.check_deployment(with_protocol_flag(load(BASE_SRC), "http2"), BASE_SRC) == []
    assert cm.check_config_patch(with_protocol_flag(load(PATCH_SRC), "http2"), PATCH_SRC) == []


def test_protocol_env_accepted_and_validated() -> None:
    doc = load(BASE_SRC)
    container(doc)["env"] = [{"name": cm.PROTOCOL_ENV, "value": "http2"}]
    assert cm.check_deployment(doc, BASE_SRC) == []
    container(doc)["env"] = [{"name": cm.PROTOCOL_ENV, "value": "udp"}]
    assert any(cm.PROTOCOL_ENV in e for e in cm.check_deployment(doc, BASE_SRC))


def test_unknown_protocol_and_other_command_edits_rejected() -> None:
    errors = cm.check_deployment(with_protocol_flag(load(BASE_SRC), "udp"), BASE_SRC)
    assert any("--protocol must be one of" in e for e in errors)
    doc = load(BASE_SRC)
    container(doc)["command"].insert(2, "--edge-ip-version")
    assert any("command must be" in e for e in cm.check_deployment(doc, BASE_SRC))


def test_nested_secret_mount_rejected() -> None:
    doc = load(PATCH_SRC)
    mounts = {m["name"]: m for m in container(doc)["volumeMounts"]}
    mounts["config"]["mountPath"] = "/etc/cloudflared"
    errors = cm.check_config_patch(doc, PATCH_SRC)
    assert any("siblings" in e for e in errors), errors
    assert any("volumeMount 'config'" in e for e in errors), errors


def main() -> int:
    """Run every test_* function; print a one-line summary; non-zero on failure."""
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
    status = "FAIL" if failed else "OK  "
    print(f"{status} test_check_manifests: {len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
