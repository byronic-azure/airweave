#!/usr/bin/env python3
"""Structural checks for the Cloudflare tunnel manifests in deploy/cloudflare/k8s.

Runs without a cluster, kustomize or network: every YAML document is loaded with
``yaml.safe_load_all`` and checked for the keys the tunnel setup depends on. It is
the fallback validate.sh uses when kubectl / kubeconform are unavailable, and a
cheap regression guard (unpinned image, lost security context, an example Secret
that no longer holds a placeholder) when they are present.

Usage: python3 deploy/cloudflare/scripts/check_manifests.py [K8S_DIR]
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

NAMESPACE = "airweave"
PART_OF = "app.kubernetes.io/part-of"
PLACEHOLDER = "REPLACE_WITH_"
CLUSTER_SCOPED = {"Namespace"}
LOCAL_SECRET_FILES = {"tunnel-token.yaml", "tunnel-credentials.yaml"}
MODE_A_ORIGIN = "http://airweave-backend-host.airweave.svc.cluster.local:8001"
MODE_B_ORIGIN = "http://airweave-backend.airweave.svc.cluster.local:8001"
# The ConfigMap and the credentials Secret are mounted as siblings; a Secret
# nested inside the (read-only) ConfigMap mount cannot be created by runc.
CONFIG_PATH = "/etc/cloudflared/config/config.yml"
CREDENTIALS_PATH = "/etc/cloudflared/creds/credentials.json"
# The documented QUIC fallback: "--protocol http2" before "run", or the env var.
PROTOCOLS = ("quic", "http2")
PROTOCOL_ENV = "TUNNEL_TRANSPORT_PROTOCOL"
BASE_COMMAND = [
    "cloudflared",
    "tunnel",
    "--no-autoupdate",
    "--loglevel",
    "info",
    "--metrics",
    "0.0.0.0:2000",
    "run",
]


def load_docs(path: Path) -> list[dict]:
    """Return every mapping document in a YAML file."""
    return [doc for doc in yaml.safe_load_all(path.read_text()) if isinstance(doc, dict)]


def split_protocol(command: list) -> tuple[list, list[str]]:
    """Return ``command`` without an optional ``--protocol <quic|http2>`` pair, plus errors.

    The pair is the documented fallback for networks that block QUIC and may sit
    anywhere before ``run``; an unknown protocol value is an error.
    """
    errors: list[str] = []
    rest: list = []
    i = 0
    while i < len(command):
        if command[i] == "--protocol":
            value = command[i + 1] if i + 1 < len(command) else None
            if value not in PROTOCOLS:
                errors.append(f"--protocol must be one of {', '.join(PROTOCOLS)}, got {value!r}")
            i += 2
            continue
        rest.append(command[i])
        i += 1
    return rest, errors


def check_command(c: dict, expected: list, src: str) -> list[str]:
    """Checks the container command equals ``expected`` apart from an optional --protocol pair."""
    command, errors = split_protocol(c.get("command") or [])
    errors = [f"{src}: {e}" for e in errors]
    if command != expected:
        errors.append(
            f"{src}: command must be {' '.join(expected)}"
            f" (optionally with --protocol {'|'.join(PROTOCOLS)} before run)"
        )
    for env in c.get("env") or []:
        if env.get("name") == PROTOCOL_ENV and env.get("value") not in PROTOCOLS:
            errors.append(f"{src}: env {PROTOCOL_ENV} must be one of {', '.join(PROTOCOLS)}")
    return errors


def check_common(doc: dict, src: str, partial: bool = False) -> list[str]:
    """Checks every object must satisfy: identity, namespace and (unless partial) part-of label.

    Strategic-merge patches are partial documents that inherit labels from the base,
    so only their identity and namespace are checked.
    """
    errors = []
    kind = doc.get("kind")
    meta = doc.get("metadata") or {}
    if not doc.get("apiVersion") or not kind or not meta.get("name"):
        errors.append(f"{src}: apiVersion, kind and metadata.name are required")
        return errors
    if kind not in CLUSTER_SCOPED and meta.get("namespace") != NAMESPACE:
        errors.append(f"{src}: {kind} {meta['name']} must set metadata.namespace: {NAMESPACE}")
    if not partial and (meta.get("labels") or {}).get(PART_OF) != NAMESPACE:
        errors.append(f"{src}: {kind} {meta['name']} must carry {PART_OF}={NAMESPACE}")
    return errors


def check_deployment(doc: dict, src: str) -> list[str]:
    """Checks the full cloudflared Deployment in base/."""
    errors = []
    spec = doc.get("spec") or {}
    if spec.get("replicas") != 1:
        errors.append(f"{src}: replicas must be 1 on a laptop")
    pod = (spec.get("template") or {}).get("spec") or {}
    if (pod.get("securityContext") or {}).get("runAsNonRoot") is not True:
        errors.append(f"{src}: pod securityContext.runAsNonRoot must be true")
    containers = pod.get("containers") or []
    if len(containers) != 1 or containers[0].get("name") != "cloudflared":
        errors.append(f"{src}: expected exactly one container named cloudflared")
        return errors
    errors += check_container(containers[0], src)
    return errors


def check_container(c: dict, src: str) -> list[str]:
    """Checks image pinning, command, probes, resources and hardening of the container."""
    errors = []
    image = c.get("image", "")
    tag = image.rsplit(":", 1)[1] if ":" in image else ""
    if not image.startswith("cloudflare/cloudflared:") or tag in ("", "latest"):
        errors.append(f"{src}: image must be a pinned cloudflare/cloudflared tag, got {image!r}")
    errors += check_command(c, BASE_COMMAND, src)
    for probe in ("livenessProbe", "readinessProbe"):
        http = (c.get(probe) or {}).get("httpGet") or {}
        if http.get("path") != "/ready" or http.get("port") not in ("metrics", 2000):
            errors.append(f"{src}: {probe} must GET /ready on the metrics port (2000)")
    resources = c.get("resources") or {}
    for section in ("requests", "limits"):
        block = resources.get(section) or {}
        if not block.get("cpu") or not block.get("memory"):
            errors.append(f"{src}: resources.{section} must set cpu and memory")
    sec = c.get("securityContext") or {}
    if sec.get("readOnlyRootFilesystem") is not True:
        errors.append(f"{src}: container securityContext.readOnlyRootFilesystem must be true")
    if sec.get("allowPrivilegeEscalation") is not False:
        errors.append(f"{src}: container securityContext.allowPrivilegeEscalation must be false")
    return errors


def check_service(doc: dict, src: str) -> list[str]:
    """Checks the two backend Services by name: ExternalName (mode A) and ClusterIP (mode B)."""
    errors = []
    name = doc["metadata"]["name"]
    spec = doc.get("spec") or {}
    ports = [p.get("port") for p in spec.get("ports") or []]
    if name == "airweave-backend-host":
        if spec.get("type") != "ExternalName" or spec.get("externalName") != "host.docker.internal":
            errors.append(f"{src}: {name} must be type ExternalName -> host.docker.internal")
        if "selector" in spec:
            errors.append(f"{src}: {name} is ExternalName and must not have a selector")
    elif name == "airweave-backend":
        if spec.get("type", "ClusterIP") != "ClusterIP":
            errors.append(f"{src}: {name} must be ClusterIP (no NodePort behind a tunnel)")
        if (spec.get("selector") or {}).get("app") != "airweave-backend":
            errors.append(f"{src}: {name} must select app: airweave-backend")
    else:
        errors.append(f"{src}: unexpected Service {name}")
    if ports != [8001]:
        errors.append(f"{src}: {name} must expose exactly port 8001, got {ports}")
    return errors


def check_secret_example(doc: dict, src: str) -> list[str]:
    """Checks an example Secret still holds placeholders only (never a real value)."""
    errors = []
    if not src.endswith(".example.yaml"):
        errors.append(f"{src}: Secret manifests must be *.example.yaml templates")
    data = doc.get("stringData") or {}
    if not data:
        errors.append(f"{src}: Secret example must use stringData so the placeholder is readable")
    # The message carries nothing from the Secret document (not even a key name), so
    # a validator log line can never contain secret material.
    if any(PLACEHOLDER not in str(value) for value in data.values()):
        errors.append(f"{src}: every stringData value must contain the {PLACEHOLDER} placeholder")
    if "data" in doc:
        errors.append(f"{src}: Secret example must not carry base64 'data'")
    return errors


def check_kustomization(doc: dict, path: Path, src: str) -> list[str]:
    """Checks that everything a kustomization references exists on disk."""
    errors = []
    here = path.parent
    if doc.get("namespace") != NAMESPACE:
        errors.append(f"{src}: kustomization must set namespace: {NAMESPACE}")
    refs = list(doc.get("resources") or [])
    refs += [p.get("path") for p in doc.get("patches") or [] if p.get("path")]
    for gen in doc.get("configMapGenerator") or []:
        refs += gen.get("files") or []
    for ref in refs:
        target = here / ref
        if target.is_dir():
            target = target / "kustomization.yaml"
        if not target.is_file():
            errors.append(f"{src}: references {ref} but {target} does not exist")
    return errors


def container_patch(doc: dict, src: str) -> tuple[dict, dict, list[str]]:
    """Return (container patch, pod spec patch, errors) for a Deployment strategic-merge patch."""
    pod = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
    containers = pod.get("containers") or []
    if len(containers) != 1 or containers[0].get("name") != "cloudflared":
        return {}, pod, [f"{src}: patch must target exactly the container named cloudflared"]
    return containers[0], pod, []


def check_token_patch(doc: dict, src: str) -> list[str]:
    """Checks the token overlay injects TUNNEL_TOKEN from Secret cloudflared-token."""
    container, _, errors = container_patch(doc, src)
    if errors:
        return errors
    envs = {e.get("name"): e for e in container.get("env") or []}
    ref = ((envs.get("TUNNEL_TOKEN") or {}).get("valueFrom") or {}).get("secretKeyRef") or {}
    if ref.get("name") != "cloudflared-token" or ref.get("key") != "TUNNEL_TOKEN":
        errors.append(
            f"{src}: env TUNNEL_TOKEN must come from Secret cloudflared-token/TUNNEL_TOKEN"
        )
    if "command" in container:
        errors.append(f"{src}: token overlay must not override the command")
    return errors


def check_config_patch(doc: dict, src: str) -> list[str]:
    """Checks the config overlay runs with --config and mounts config + credentials as siblings."""
    container, pod, errors = container_patch(doc, src)
    if errors:
        return errors
    errors += check_command(container, BASE_COMMAND[:-1] + ["--config", CONFIG_PATH, "run"], src)
    mounts = {m.get("name"): m for m in container.get("volumeMounts") or []}
    config_mount = (mounts.get("config") or {}).get("mountPath") or ""
    creds_mount = (mounts.get("credentials") or {}).get("mountPath") or ""
    if config_mount != str(Path(CONFIG_PATH).parent):
        errors.append(f"{src}: volumeMount 'config' must mount at {Path(CONFIG_PATH).parent}")
    if creds_mount != str(Path(CREDENTIALS_PATH).parent):
        errors.append(
            f"{src}: volumeMount 'credentials' must mount at {Path(CREDENTIALS_PATH).parent}"
        )
    if config_mount and creds_mount:
        a, b = Path(config_mount), Path(creds_mount)
        if a in b.parents or b in a.parents:
            errors.append(f"{src}: config and credentials mounts must be siblings, not nested")
    volumes = {v.get("name"): v for v in pod.get("volumes") or []}
    if (volumes.get("config") or {}).get("configMap", {}).get("name") != "cloudflared-config":
        errors.append(f"{src}: volume 'config' must come from ConfigMap cloudflared-config")
    creds = (volumes.get("credentials") or {}).get("secret") or {}
    if creds.get("secretName") != "cloudflared-credentials":
        errors.append(f"{src}: volume 'credentials' must come from Secret cloudflared-credentials")
    return errors


def check_tunnel_config(path: Path, src: str) -> list[str]:
    """Checks the cloudflared config.yml: identity, credentials path, ingress rules, catch-all."""
    errors = []
    text = path.read_text()
    cfg = yaml.safe_load(text) or {}
    if not cfg.get("tunnel"):
        errors.append(f"{src}: 'tunnel' (the tunnel UUID) is required")
    if cfg.get("credentials-file") != CREDENTIALS_PATH:
        errors.append(f"{src}: credentials-file must match the Secret mount in the patch")
    rules = cfg.get("ingress") or []
    if len(rules) < 2:
        errors.append(f"{src}: ingress needs at least one hostname rule and the catch-all")
        return errors
    last = rules[-1]
    if last.get("service") != "http_status:404" or "hostname" in last or "path" in last:
        errors.append(f"{src}: the last ingress rule must be the bare catch-all http_status:404")
    for i, rule in enumerate(rules[:-1]):
        if not rule.get("hostname") or not str(rule.get("service", "")).startswith("http://"):
            errors.append(f"{src}: ingress rule #{i} needs a hostname and an http:// service")
    if MODE_A_ORIGIN not in text or MODE_B_ORIGIN not in text:
        errors.append(f"{src}: both the mode A and mode B rules must be present (one commented)")
    return errors


def check_document(doc: dict, path: Path, rel: str) -> list[str]:
    """Dispatch one YAML document to the checks that apply to it."""
    kind = doc.get("kind")
    if kind == "Kustomization":
        return check_kustomization(doc, path, rel)
    errors = check_common(doc, rel, partial=rel.endswith("deployment-patch.yaml"))
    if kind == "Deployment" and rel == "base/deployment.yaml":
        errors += check_deployment(doc, rel)
    elif kind == "Deployment" and rel == "overlays/token/deployment-patch.yaml":
        errors += check_token_patch(doc, rel)
    elif kind == "Deployment" and rel == "overlays/config/deployment-patch.yaml":
        errors += check_config_patch(doc, rel)
    elif kind == "Service":
        errors += check_service(doc, rel)
    elif kind == "Secret":
        errors += check_secret_example(doc, rel)
    elif kind not in ("Namespace", "Deployment"):
        errors.append(f"{rel}: unexpected kind {kind}")
    return errors


def main(argv: list[str]) -> int:
    """Validate every manifest under K8S_DIR (default: ../k8s next to this script)."""
    k8s_dir = Path(argv[0]).resolve() if argv else Path(__file__).resolve().parent.parent / "k8s"
    paths = sorted(p for p in k8s_dir.rglob("*") if p.suffix in (".yaml", ".yml"))
    errors: list[str] = []
    docs = 0
    for path in paths:
        rel = path.relative_to(k8s_dir).as_posix()
        if path.name in LOCAL_SECRET_FILES:
            print(f"note skipping local secret file {rel} (gitignored, not validated)")
            continue
        try:
            if rel == "overlays/config/config.yml":
                errors += check_tunnel_config(path, rel)
                docs += 1
                continue
            loaded = load_docs(path)
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: not valid YAML: {exc}")
            continue
        for doc in loaded:
            errors += check_document(doc, path, rel)
            docs += 1
    for err in errors:
        print(f"FAIL {err}")
    if not errors:
        print(f"OK   {docs} document(s) across {len(paths)} file(s) under {k8s_dir}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
