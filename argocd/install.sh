#!/usr/bin/env bash
# ============================================================
# Grafana Governance Platform — ArgoCD Bootstrap Script
# Chạy 1 lần duy nhất để khởi động toàn bộ hệ thống
#
# Yêu cầu:
#   - kubectl đã kết nối đến cluster
#   - ArgoCD đã cài (namespace: argocd)
#   - Crossplane đã cài (namespace: crossplane-system)
#
# Usage:
#   chmod +x argocd/install.sh
#   ./argocd/install.sh
# ============================================================

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/ducdat18/crossplanetest.git}"
ARGOCD_NS="argocd"
CROSSPLANE_NS="crossplane-system"

echo ""
echo "=========================================="
echo "  Grafana Governance Platform — Bootstrap"
echo "=========================================="
echo ""

# ── Step 1: Patch argocd-cm với custom health checks ──────────
echo "[1/5] Applying ArgoCD custom health checks..."
kubectl apply -f argocd/argocd-cm-patch.yaml
echo "      ✓ argocd-cm patched"

# Restart ArgoCD để load config mới
echo "      Restarting argocd-application-controller..."
kubectl rollout restart deployment argocd-application-controller -n "$ARGOCD_NS" 2>/dev/null || true
kubectl rollout restart deployment argocd-repo-server -n "$ARGOCD_NS" 2>/dev/null || true

# ── Step 2: Tạo AppProject ────────────────────────────────────
echo ""
echo "[2/5] Creating AppProject: grafana-governance..."
kubectl apply -f argocd/project.yaml
echo "      ✓ AppProject created"

# ── Step 3: Cài Crossplane Provider ──────────────────────────
echo ""
echo "[3/5] Installing Crossplane Provider Grafana..."
kubectl apply -f provider/provider.yaml
echo "      Waiting for Provider to be healthy..."
kubectl wait --for=condition=Healthy provider/provider-grafana \
  --timeout=300s 2>/dev/null || {
  echo "      ⚠ Provider not healthy yet, continuing anyway..."
}

# Apply credentials
kubectl apply -f provider/grafana-config.yaml
echo "      ✓ ProviderConfig applied"

# ── Step 4: Bootstrap App-of-Apps ────────────────────────────
echo ""
echo "[4/5] Bootstrapping App-of-Apps..."
# Thay REPO_URL trong file trước khi apply
sed "s|https://github.com/ducdat18/crossplanetest.git|${REPO_URL}|g" \
  argocd/app-of-apps.yaml | kubectl apply -f -
echo "      ✓ Root application created"

# ── Step 5: Verify ───────────────────────────────────────────
echo ""
echo "[5/5] Verifying setup..."
sleep 5

echo ""
echo "  ArgoCD Applications:"
kubectl get applications -n "$ARGOCD_NS" \
  -l app.kubernetes.io/part-of=grafana-governance \
  --no-headers 2>/dev/null | \
  awk '{printf "    %-40s %s/%s\n", $1, $7, $8}' || \
  echo "    (Applications being created, check in 1-2 minutes)"

echo ""
echo "=========================================="
echo "  Bootstrap complete!"
echo ""
echo "  View in ArgoCD UI:"
echo "    kubectl port-forward svc/argocd-server -n argocd 8080:443"
echo "    → https://localhost:8080"
echo "    → Filter by project: grafana-governance"
echo ""
echo "  Get ArgoCD admin password:"
echo "    kubectl get secret argocd-initial-admin-secret -n argocd \\"
echo "      -o jsonpath='{.data.password}' | base64 -d"
echo "=========================================="
