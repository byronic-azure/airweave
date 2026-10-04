// @ts-check
// The Docker Desktop side: the cloudflared Deployment from k8s/overlays/token,
// fed the tunnel token through a Secret piped to `kubectl apply -f -` (stdin,
// never argv). Pure Node, so it runs the same on macOS, Windows and Linux.

import { join } from "node:path";
import { EdgeError } from "./util.mjs";

export const NAMESPACE = "airweave";

/** In-cluster Service the tunnel routes to, per backend mode. */
export const BACKEND_SERVICE = {
  host: "http://airweave-backend-host.airweave.svc.cluster.local:8001",
  cluster: "http://airweave-backend.airweave.svc.cluster.local:8001",
};

/**
 * @typedef {object} KubeDeps
 * @property {import("./exec.mjs").Runner} run
 * @property {import("./log.mjs").Logger} log
 * @property {string} k8sDir     deploy/cloudflare/k8s
 * @property {string} context
 */

/** @param {KubeDeps} deps @param {string[]} args @param {import("./exec.mjs").RunOptions} [opts] */
const kubectl = (deps, args, opts) => deps.run("kubectl", ["--context", deps.context, ...args], opts);

/**
 * Fails early, with the fix, when kubectl, the context or the cluster is missing.
 * @param {KubeDeps} deps
 */
export async function checkCluster(deps) {
  const ctx = await deps
    .run("kubectl", ["config", "get-contexts", deps.context, "-o", "name"], { allowFailure: true })
    .catch((/** @type {Error} */ err) => {
      throw new EdgeError(`${err.message} (Docker Desktop installs kubectl once Kubernetes is enabled)`);
    });
  if (ctx.code !== 0) {
    throw new EdgeError(
      `kube context "${deps.context}" does not exist. Enable Kubernetes in Docker Desktop ` +
        "(Settings > Kubernetes) or pass --context <name>.",
    );
  }
  const ready = await kubectl(deps, ["get", "--raw", "/readyz", "--request-timeout=15s"], { allowFailure: true });
  if (ready.code !== 0) {
    throw new EdgeError(`the cluster behind context "${deps.context}" is not reachable; is Docker Desktop running?`);
  }
  deps.log.ok(`kube context ${deps.context} is reachable`);
}

/**
 * Applies the namespace, the token Secret and the overlay, then waits for the
 * rollout. A changed token restarts cloudflared, which reads it at start-up only.
 * @param {KubeDeps} deps
 * @param {{ token: string, timeout?: string }} opts
 */
export async function deployConnector(deps, opts) {
  await kubectl(deps, ["apply", "-f", join(deps.k8sDir, "base", "namespace.yaml")]);
  const existed =
    (await kubectl(deps, ["get", "deployment/cloudflared", "-n", NAMESPACE], { allowFailure: true })).code === 0;

  const secret = {
    apiVersion: "v1",
    kind: "Secret",
    metadata: {
      name: "cloudflared-token",
      namespace: NAMESPACE,
      labels: {
        "app.kubernetes.io/name": "cloudflared",
        "app.kubernetes.io/component": "tunnel",
        "app.kubernetes.io/part-of": "airweave",
        "app.kubernetes.io/managed-by": "airweave-edge",
      },
    },
    type: "Opaque",
    stringData: { TUNNEL_TOKEN: opts.token },
  };
  const applied = await kubectl(deps, ["apply", "-f", "-"], { input: JSON.stringify(secret) });
  const secretChanged = !/\bunchanged\b/.test(applied.stdout);
  if (secretChanged) deps.log.update("Secret cloudflared-token (tunnel token)");
  else deps.log.ok("Secret cloudflared-token (tunnel token)");

  const overlay = await kubectl(deps, ["apply", "-k", join(deps.k8sDir, "overlays", "token")]);
  const changed = overlay.stdout.split("\n").filter((l) => /\b(created|configured)\b/.test(l));
  if (changed.length) deps.log.update(`overlay token: ${changed.map((l) => l.trim()).join("; ")}`);
  else deps.log.ok("overlay token: unchanged");

  if (existed && secretChanged) {
    await kubectl(deps, ["rollout", "restart", "deployment/cloudflared", "-n", NAMESPACE]);
    deps.log.update("deployment/cloudflared restarted to pick up the new token");
  }
  const timeout = opts.timeout ?? "180s";
  const status = await kubectl(
    deps,
    ["rollout", "status", "deployment/cloudflared", "-n", NAMESPACE, `--timeout=${timeout}`],
    { allowFailure: true },
  );
  if (status.code !== 0) {
    throw new EdgeError(
      `cloudflared did not become Ready within ${timeout} (readiness is /ready on :2000, which needs a live edge ` +
        "connection). Inspect with:\n" +
        `  kubectl --context ${deps.context} -n ${NAMESPACE} logs deployment/cloudflared --tail=50\n` +
        "Common causes: UDP 7844 (QUIC) blocked on this network (uncomment TUNNEL_TRANSPORT_PROTOCOL=http2 " +
        "in k8s/base/deployment.yaml), or no internet access.",
    );
  }
  deps.log.ok("deployment/cloudflared is Ready (connected to the Cloudflare edge)");
}

/**
 * Mirrors scripts/down.sh -s: the connector, its Services and its Secrets; the
 * namespace stays because it may hold a mode-B backend.
 * @param {KubeDeps} deps
 */
export async function removeConnector(deps) {
  const ns = await kubectl(deps, ["get", "namespace", NAMESPACE], { allowFailure: true }).catch(
    (/** @type {Error} */ err) => {
      throw new EdgeError(`${err.message}; pass --skip-k8s to leave Kubernetes alone`);
    },
  );
  if (ns.code !== 0) {
    deps.log.skip(`namespace ${NAMESPACE} does not exist`);
    return;
  }
  if (!deps.log.dryRun) {
    await kubectl(deps, ["delete", "deployment/cloudflared", "-n", NAMESPACE, "--ignore-not-found"]);
    await kubectl(deps, [
      "delete",
      "service/airweave-backend-host",
      "service/airweave-backend",
      "-n",
      NAMESPACE,
      "--ignore-not-found",
    ]);
    await kubectl(deps, ["delete", "secret", "cloudflared-token", "-n", NAMESPACE, "--ignore-not-found"]);
  }
  deps.log.remove(`cloudflared Deployment, Services and Secret in namespace ${NAMESPACE} (namespace kept)`);
}
