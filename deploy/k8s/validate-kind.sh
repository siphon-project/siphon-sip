#!/usr/bin/env bash
#
# Kubernetes analogue of deploy/ha-demo/validate.sh: stand the manifests up on a
# local kind cluster, register a contact, **kill a pod**, and prove the pod comes
# back and recovers its registrar binding from Redis — the k8s version of the
# compose failover demo.
#
# Verification uses the admin API (/admin/registrations) over a port-forward (TCP),
# and the REGISTER is sent from an in-cluster Job (SIP/UDP via cluster DNS).
#
# Requirements: kind, kubectl, docker. The siphon image is pulled from a registry
# by default (override with SIPHON_IMAGE); a locally-built image is auto-loaded.
#
#   SIPHON_IMAGE=ghcr.io/siphon-project/siphon-sip:latest ./validate-kind.sh
#   KEEP_CLUSTER=1 ./validate-kind.sh      # don't delete the kind cluster at the end
#
# Exit 0 = the binding survived the pod kill.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${KIND_CLUSTER:-siphon-ha}"
IMAGE="${SIPHON_IMAGE:-ghcr.io/siphon-project/siphon-sip:latest}"
AOR="sip:alice@example.com"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m• %s\033[0m\n' "$*"; }

PF_PID=""
cleanup() {
  set +e
  [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null
  kubectl delete configmap sipcli --ignore-not-found >/dev/null 2>&1
  kubectl delete job sip-register --ignore-not-found >/dev/null 2>&1
  if [[ "${KEEP_CLUSTER:-0}" != "1" ]]; then
    info "deleting kind cluster '$CLUSTER' (KEEP_CLUSTER=1 to keep)"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

for tool in kind kubectl docker; do
  command -v "$tool" >/dev/null || { red "$tool is required"; exit 2; }
done

# --- cluster ------------------------------------------------------------------
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  info "creating kind cluster '$CLUSTER'"
  kind create cluster --name "$CLUSTER" >/dev/null
fi
# kind sets the kubeconfig context on create; select it explicitly to be safe.
kubectl config use-context "kind-$CLUSTER" >/dev/null

# Load a locally-built image into the cluster if it exists locally; otherwise the
# pods pull it from the registry.
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  info "loading local image $IMAGE into kind"
  kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null
fi

# --- deploy -------------------------------------------------------------------
info "applying redis + config + service"
kubectl apply -f "$DIR/redis.yaml" >/dev/null
kubectl apply -f "$DIR/configmap.yaml" >/dev/null
kubectl apply -f "$DIR/service.yaml" >/dev/null

# kind nodes are containers — drop hostNetwork and use cluster networking, and
# substitute the image. (hostNetwork is correct for real SIP ingress; see the
# manifest comments. For an in-cluster test we use ClusterIP + DNS.)
info "applying statefulset (hostNetwork off for kind, image=$IMAGE)"
sed -e '/hostNetwork: true/d' \
    -e '/dnsPolicy: ClusterFirstWithHostNet/d' \
    -e "s#image: ghcr.io/siphon-project/siphon-sip:latest#image: $IMAGE#" \
    "$DIR/statefulset.yaml" | kubectl apply -f - >/dev/null

info "waiting for siphon-0 and siphon-1 to become Ready (readiness = /admin/ready)"
kubectl rollout status statefulset/siphon --timeout=180s >/dev/null

# --- register a contact from inside the cluster (SIP/UDP via cluster DNS) ------
info "REGISTER $AOR via an in-cluster Job targeting siphon-0"
kubectl delete configmap sipcli --ignore-not-found >/dev/null 2>&1
kubectl create configmap sipcli --from-file=sipcli.py="$DIR/../ha-demo/sipcli.py" >/dev/null
kubectl delete job sip-register --ignore-not-found >/dev/null 2>&1
cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: sip-register
spec:
  backoffLimit: 3
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: register
          image: python:3-alpine
          command: ["python", "/cli/sipcli.py", "register",
                    "siphon-0.siphon", "5060", "alice", "siphon-0.siphon", "5060"]
          volumeMounts: [{ name: cli, mountPath: /cli }]
      volumes:
        - name: cli
          configMap: { name: sipcli }
YAML
kubectl wait --for=condition=complete job/sip-register --timeout=60s >/dev/null

verify_binding() { # -> prints HTTP code from /admin/registrations/$AOR on siphon-0
  [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null
  kubectl port-forward pod/siphon-0 19091:9091 >/dev/null 2>&1 &
  PF_PID="$!"
  sleep 2
  curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:19091/admin/registrations/$AOR"
}

info "verifying the binding is present (admin API)"
before="$(verify_binding)"
[[ "$before" == "200" ]] && green "  binding present before kill (HTTP $before)" \
                         || { red "  binding NOT present before kill (HTTP $before)"; exit 1; }

# --- KILL THE POD -------------------------------------------------------------
info "kubectl delete pod siphon-0  (simulating a node failure)"
kubectl delete pod siphon-0 --wait=true >/dev/null
info "waiting for siphon-0 to be recreated and Ready"
kubectl rollout status statefulset/siphon --timeout=180s >/dev/null
kubectl wait --for=condition=ready pod/siphon-0 --timeout=120s >/dev/null

# --- prove recovery -----------------------------------------------------------
info "verifying the binding recovered from Redis (no re-REGISTER)"
after="$(verify_binding)"
if [[ "$after" == "200" ]]; then
  green "==== PASS: siphon-0 recovered $AOR from Redis after the pod was killed ===="
  exit 0
else
  red "==== FAIL: binding missing after pod restart (HTTP $after) ===="
  exit 1
fi
