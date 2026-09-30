# Airweave on MicroK8s (NodePort)

NodePort Services that expose Airweave on a MicroK8s node, for access through
Brev **Secure Links** or **TCP/UDP port access**.

## The rule

Every NodePort Service must set `externalTrafficPolicy: Local` **before** its
NodePort is used, and the Secure Link / TCP forward must target the
**NodePort**, not the pod or container port.

```
Secure Link (443) / TCP port  ──►  node:<nodePort>  ──►  pod:<targetPort>
                                    use THIS port        not this one
```

With `Local`, kube-proxy delivers traffic only to pods on the receiving node
and does not SNAT it, so the client source IP is preserved and there is no
extra hop between nodes. On a single-node MicroK8s this is what you want. On
multi-node clusters, a node with no ready pod for the Service drops the traffic,
so point the forward at a node that runs the pod.

## Port map

| Service                | NodePort (use this) | targetPort (container) |
|------------------------|---------------------|------------------------|
| `airweave-backend`     | **30801**           | 8001                   |
| `airweave-frontend`    | **30880**           | 8080                   |
| `airweave-connect`     | **30882**           | 8082                   |

`airweave-temporal-ui` has no authentication, so it is deliberately **ClusterIP
only** (no NodePort). Reach it through a tunnel instead:
`microk8s kubectl port-forward -n airweave svc/airweave-temporal-ui 8088:8088`.

For example, a Secure Link for the API forwards public 443 to destination
`30801`. Forwarding to `8001` would bypass the Service, unless something else
such as `kubectl proxy` (also 8001 by default) is listening there.

## Security

A NodePort listens on **every node interface**, not only the path a Secure Link
uses. Before forwarding traffic:

- Keep 30000–32767 **closed** in the cloud firewall (Brev "Cloud Firewall
  Ports"). Only the Secure Link / TCP forward should reach the NodePorts; do not
  open them to "Anywhere".
- Run the backend with authentication on (`AUTH_ENABLED=true`). A NodePort
  bypasses any control that exists only at the Secure Link.
- Check that each Service has ready endpoints on the node you forward to:
  `microk8s kubectl get endpointslices -n airweave`.

## New Services

```bash
microk8s kubectl create namespace airweave --dry-run=client -o yaml | microk8s kubectl apply -f -
microk8s kubectl apply -f deploy/microk8s/services.yaml
```

The selectors assume Deployments labelled `app: airweave-backend` and so on.
Change them to match your workloads.

## Existing Services

Patch one Service by hand:

```bash
kubectl patch service <service-name> \
  --namespace <namespace> \
  --type=merge \
  --patch '{"spec":{"externalTrafficPolicy":"Local"}}'
```

Or use the script, which patches, reads each change back and prints the
NodePorts to use:

```bash
deploy/microk8s/patch-external-traffic-policy.sh -n airweave                   # Airweave-labelled NodePorts
deploy/microk8s/patch-external-traffic-policy.sh -n airweave airweave-backend  # named Services only
deploy/microk8s/patch-external-traffic-policy.sh -n airweave -A                # every NodePort in the namespace
```

By default it only touches Services labelled
`app.kubernetes.io/part-of=airweave`, so other workloads in a shared namespace
are left alone. It is idempotent and falls back to `microk8s kubectl` when
`kubectl` is not on `PATH`. If any Service fails to patch or does not read back
as `Local`, it names them and exits non-zero. Some Services may already have
changed at that point, so fix the cause and re-run it (safe to repeat) before
forwarding traffic.

## Verify

```bash
python3 deploy/microk8s/check_policy.py     # manifests: Local, valid and unique nodePorts
microk8s kubectl get svc -n airweave \
  -o custom-columns=NAME:.metadata.name,POLICY:.spec.externalTrafficPolicy,NODEPORT:.spec.ports[*].nodePort
```

Use plain `kubectl` instead of `microk8s kubectl` if it is on your `PATH`.
