#!/usr/bin/env python3
"""Fail if any NodePort Service manifest lacks `externalTrafficPolicy: Local`.

Usage: python3 deploy/microk8s/check_policy.py [MANIFEST ...]
Defaults to every *.yaml / *.yml file next to this script.
"""

import sys
from pathlib import Path

import yaml

NODE_PORT_RANGE = range(30000, 32768)


def check_service(doc: dict, source: str) -> list[str]:
    """Return policy violations for a single Service document."""
    spec = doc.get("spec") or {}
    if doc.get("kind") != "Service" or spec.get("type") != "NodePort":
        return []
    name = (doc.get("metadata") or {}).get("name", "<unnamed>")
    errors = []
    if spec.get("externalTrafficPolicy") != "Local":
        errors.append(f"{source}: Service {name} must set externalTrafficPolicy: Local")
    for port in spec.get("ports") or []:
        node_port = port.get("nodePort")
        if node_port is not None and node_port not in NODE_PORT_RANGE:
            errors.append(f"{source}: Service {name} nodePort {node_port} outside 30000-32767")
    return errors


def main(argv: list[str]) -> int:
    """Validate the given manifests (or the defaults) and report violations."""
    here = Path(__file__).resolve().parent
    paths = [Path(p) for p in argv] or sorted([*here.glob("*.yaml"), *here.glob("*.yml")])
    errors: list[str] = []
    seen_node_ports: dict[int, str] = {}
    for path in paths:
        for doc in yaml.safe_load_all(path.read_text()):
            if not isinstance(doc, dict):
                continue
            errors += check_service(doc, path.name)
            for port in (doc.get("spec") or {}).get("ports") or []:
                node_port = port.get("nodePort")
                if node_port is None:
                    continue
                owner = f"{path.name}:{doc['metadata']['name']}"
                if node_port in seen_node_ports:
                    errors.append(f"nodePort {node_port} used by {seen_node_ports[node_port]} and {owner}")
                seen_node_ports[node_port] = owner
    for err in errors:
        print(f"FAIL {err}")
    if not errors:
        print(f"OK   {len(seen_node_ports)} NodePort(s) across {len(paths)} manifest(s), all Local")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
