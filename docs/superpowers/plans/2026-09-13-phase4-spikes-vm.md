# Phase 4 Admin Control Plane Implementation Plan — Part 1b: VM Spikes and Gate

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove Coder OAuth2 (S1) and Cilium workspace-id selectors (S4) on the lab VM, then record all spike results and gate Part 2.

**Architecture:** Runs inside the lab VM through `$P/vmssh`. Files are copied with `$P/vmssh "cat > /tmp/x" < file`. Spike files are throwaway.

**Tech Stack:** Coder 2.36.5, Cilium 1.20.1, k3s.

**Spec:** `docs/superpowers/specs/2026-09-13-phase4-admin-control-plane-design.md` · Previous: [Part 1 host spikes](2026-09-13-phase4-admin-control-plane.md)

## Global Constraints

- Envoy image: `envoyproxy/envoy:v1.39.1`. Go image: `golang:1.27`. Module: `github.com/envoyproxy/go-control-plane/envoy@v1.39.0`.
- Host has no Go toolchain and no cluster: Go runs only inside `golang:1.27` containers. Never run k3s/Cilium changes on the host.
- Lab VM access for executors: `P=/tmp/claude-1000/-home-user-code-sandcastle/301b8128-c760-470f-8df4-cc65f4b3b771/scratchpad`, then `$P/vmssh '<cmd>'`. The VM repo is `~/sandcastle`; the Coder CLI is `~/.local/bin/coder`; Coder URL `http://192.168.122.124:30080`.
- Workspaces run in namespace `sandcastle-workspaces`; pods carry label `com.coder.workspace.id`.
- In pipelines under `set -o pipefail`, use `grep ... >/dev/null`, never `grep -q`.
- Spike files are throwaway: scratchpad only, never committed.
- A failed spike stops the plan: record it in the results doc and return to design.

---

### Task 1: Spike S1 — Coder OAuth2 provider on OSS 2.36.5 (VM)

**Interfaces:**
- Produces: the results row S1, and the exact authorize/token request shape (PKCE required or not, parameter names, token response fields, `users/me` roles JSON path) that Part 2's `internal/auth` implements.

- [ ] **Step 1: Enable the experiment (temporary; Part 2 moves it into `platform/coder/values.yaml`)**

```bash
$P/vmssh 'kubectl -n coder set env deploy/coder CODER_EXPERIMENTS=oauth2 && kubectl -n coder rollout status deploy/coder --timeout=5m'
$P/vmssh 'curl -s http://192.168.122.124:30080/api/v2/experiments'
```
Expected: rollout complete; the JSON array contains `"oauth2"`.

- [ ] **Step 2: Write and run the flow script**

Create `$P/p4spike/s1.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
URL=http://192.168.122.124:30080
CODER=$HOME/.local/bin/coder
CB=http://192.168.122.124:30081/callback
TOK=$($CODER tokens create --lifetime 1h --name p4spike-$RANDOM)
H=(-H "Coder-Session-Token: $TOK" -H 'Content-Type: application/json')

app=$(curl -sf "${H[@]}" -X POST -d "{\"name\":\"p4spike-$RANDOM\",\"callback_url\":\"$CB\",\"icon\":\"\"}" $URL/api/v2/oauth2-provider/apps)
echo "app: $app"
ID=$(jq -r .id <<<"$app")
sec=$(curl -sf "${H[@]}" -X POST $URL/api/v2/oauth2-provider/apps/$ID/secrets)
echo "secret keys: $(jq -c 'keys' <<<"$sec")"
SECRET=$(jq -r .client_secret_full <<<"$sec")

VERIFIER=$(openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-64)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
Q="client_id=$ID&response_type=code&redirect_uri=$CB&state=xyz&code_challenge=$CHALLENGE&code_challenge_method=S256"

echo "--- GET authorize (consent page expected)"
curl -s -o /dev/null -w '%{http_code}\n' --cookie "coder_session_token=$TOK" "$URL/oauth2/authorize?$Q"
echo "--- POST authorize (consent)"
loc=$(curl -s -o /dev/null -w '%{redirect_url}' --cookie "coder_session_token=$TOK" -X POST "$URL/oauth2/authorize?$Q")
echo "redirect: $loc"
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$loc")

echo "--- token exchange"
tokjson=$(curl -s -X POST $URL/oauth2/tokens -d grant_type=authorization_code -d code="$CODE" \
  -d client_id="$ID" -d client_secret="$SECRET" -d redirect_uri="$CB" -d code_verifier="$VERIFIER")
echo "token keys: $(jq -c 'keys' <<<"$tokjson")"
AT=$(jq -r .access_token <<<"$tokjson")

echo "--- users/me with bearer"
curl -s -H "Authorization: Bearer $AT" $URL/api/v2/users/me | jq '{username, roles}'

echo "--- cleanup"
curl -s "${H[@]}" -X DELETE $URL/api/v2/oauth2-provider/apps/$ID -o /dev/null -w '%{http_code}\n'
```
Run it:
```bash
chmod +x $P/p4spike/s1.sh && $P/vmssh "cat > /tmp/s1.sh" < $P/p4spike/s1.sh && $P/vmssh 'bash /tmp/s1.sh'
```

Pass criteria:
- App create returns an `id` (not 403 or a license error).
- POST authorize redirects to `$CB?code=...&state=xyz`.
- The token response has `access_token`.
- `users/me` returns `username: "admin"` with `roles` containing `owner`.

Diagnose failures from the body, adjust once, rerun, and record what changed:
- 400 mentioning PKCE: the parameters are wrong.
- 404: wrong path; check `/.well-known/oauth-authorization-server`.

If app creation needs a license, S1 fails → stop and return to design (fallback: DR-4.1 alternative, local admin accounts).

- [ ] **Step 3: Revert the temporary env (Part 2 sets it declaratively)**

```bash
$P/vmssh 'kubectl -n coder set env deploy/coder CODER_EXPERIMENTS- && kubectl -n coder rollout status deploy/coder --timeout=5m'
```

---

### Task 2: Spike S4 — CNP label selectors on Kata workspace pods (VM)

**Interfaces:**
- Produces: the results row S4, and the confirmed selector syntax (`com.coder.workspace.id` vs `k8s:com.coder.workspace.id`) that Part 2's `internal/cilium` renders.

- [ ] **Step 1: Create a workspace and read its ID**

```bash
$P/vmssh '~/.local/bin/coder create p4s4 --template base --use-parameter-defaults --yes >/tmp/p4s4.log 2>&1; tail -2 /tmp/p4s4.log'
$P/vmssh 'kubectl -n sandcastle-workspaces get pods -l com.coder.workspace.name=p4s4 -o jsonpath="{.items[0].metadata.labels.com\.coder\.workspace\.id}"; echo'
```
Expected: a UUID. Call it `WSID`.

- [ ] **Step 2: Baseline — external name refused**

```bash
$P/vmssh 'timeout 300 ~/.local/bin/coder ssh p4s4 -- "getent hosts example.org" && echo RESOLVED || echo REFUSED'
```
Expected: `REFUSED`.

- [ ] **Step 3: Apply an `In` selector CNP**

`$P/p4spike/cnp-in.yaml` (replace `WSID`):
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: p4s4-dns
  namespace: sandcastle-workspaces
spec:
  endpointSelector:
    matchExpressions:
      - {key: com.coder.workspace.id, operator: In, values: ["WSID"]}
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s:k8s-app: kube-dns
      toPorts:
        - ports:
            - {port: "53", protocol: UDP}
            - {port: "53", protocol: TCP}
          rules:
            dns:
              - matchName: example.org
```
```bash
sed -i "s/WSID/$WSID/" $P/p4spike/cnp-in.yaml && $P/vmssh "cat > /tmp/cnp-in.yaml" < $P/p4spike/cnp-in.yaml
$P/vmssh 'kubectl apply -f /tmp/cnp-in.yaml && sleep 5 && timeout 300 ~/.local/bin/coder ssh p4s4 -- "getent hosts example.org" && echo RESOLVED || echo REFUSED'
```
Expected: `RESOLVED`. If `REFUSED`, change the key to `k8s:com.coder.workspace.id`, reapply, and record which form works.

- [ ] **Step 4: Switch to `Exists` + `NotIn [WSID]` (the default-zone form)**

`$P/p4spike/cnp-notin.yaml` is the same file with the selector replaced:
```yaml
  endpointSelector:
    matchExpressions:
      - {key: com.coder.workspace.id, operator: Exists}
      - {key: com.coder.workspace.id, operator: NotIn, values: ["WSID"]}
```
```bash
sed -i "s/WSID/$WSID/" $P/p4spike/cnp-notin.yaml && $P/vmssh "cat > /tmp/cnp-notin.yaml" < $P/p4spike/cnp-notin.yaml
$P/vmssh 'kubectl apply -f /tmp/cnp-notin.yaml && sleep 5 && timeout 300 ~/.local/bin/coder ssh p4s4 -- "getent hosts example.org" && echo RESOLVED || echo REFUSED'
```
Expected: `REFUSED`, because the workspace is now excluded. The `Exists` term keeps unlabeled pods unselected; k8s selector semantics guarantee it, so there is no separate check.

- [ ] **Step 5: Clean up**

```bash
$P/vmssh 'kubectl -n sandcastle-workspaces delete cnp p4s4-dns; ~/.local/bin/coder delete p4s4 --yes >/dev/null 2>&1; echo done'
```

---

### Task 3: Record results and gate

**Files:**
- Create: `docs/superpowers/specs/2026-09-13-phase4-spike-results.md`

- [ ] **Step 1: Write the results doc**

Use exactly this structure, filling each cell from the observed output (verbatim codes and messages):

```markdown
# Phase 4 — Spike Results

Date: 2026-09-13
Spec: [Phase 4 design](2026-09-13-phase4-admin-control-plane-design.md)

| # | Question | Result | Evidence |
|---|---|---|---|
| S1 | Coder OAuth2 provider on OSS 2.36.5 | PASS/FAIL | app create code, redirect, token keys, users/me roles |
| S2 | Per-vhost RBAC + SNI binding | PASS/FAIL | A/B codes, header presence on RBAC and direct_response paths, SNI mismatch result |
| S3 | Listener swap closes open tunnel | PASS/FAIL | close time vs swap time; untouched tunnel state; which resource removal closed it |
| S4 | CNP In / Exists+NotIn on workspace-id label | PASS/FAIL | RESOLVED/REFUSED per step; key form that worked |
| S5 | Envoy ALS to gRPC sink | PASS/FAIL | sample ALS line; RBAC denial flags value |

## Findings that change Part 2

- (one bullet per deviation from the spec, with the 5 W's: who found it, what, when, where, why it matters)

## Config fixes made during spikes

- (one bullet per rejected field and the fix; "none" if none)
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-09-13-phase4-spike-results.md
git commit -m "docs(spec): record phase 4 spike results"
```

- [ ] **Step 3: Gate**

If every row is PASS, report to the owner and write Part 2 (build tasks) from the spec plus the findings. If any row is FAIL, report the failure and the proposed design change, and wait for the owner's decision.
