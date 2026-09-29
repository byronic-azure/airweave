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
| `airweave-temporal-ui` | **30888**           | 8080                   |

For example, a Secure Link for the API forwards public 443 to destination
`30801`. Forwarding to `8001` would bypass the Service, unless something else
such as `kubectl proxy` (also 8001 by default) is listening there.

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

Or patch every NodePort Service in a namespace and print the NodePorts to use:

```bash
deploy/microk8s/patch-external-traffic-policy.sh -n airweave            # all NodePorts
deploy/microk8s/patch-external-traffic-policy.sh -n airweave airweave-backend
```

The script is idempotent and falls back to `microk8s kubectl` when `kubectl`
is not on `PATH`.

## Verify

```bash
python3 deploy/microk8s/check_policy.py     # manifests: Local, valid and unique nodePorts
kubectl get svc -n airweave \
  -o custom-columns=NAME:.metadata.name,POLICY:.spec.externalTrafficPolicy,NODEPORT:.spec.ports[*].nodePort
```
