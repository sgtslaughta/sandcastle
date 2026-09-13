# Phase 3 Containment Core Implementation Plan (part 1 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A workspace reaches only Envoy, kube-dns, Nexus and coderd. Every other packet is dropped by Cilium and, once it leaves the VM, by host nftables, and each attempt is visible.

**Architecture:**
- CiliumNetworkPolicy objects enforce the four-destination rule, with L7 HTTP and DNS rules.
- Envoy is an explicit-proxy egress gate (CONNECT plus an SNI check).
- A Cilium egress gateway sends Envoy and Nexus traffic out a dedicated VM NIC.
- Host nftables drop everything else from the VM.

**Tech Stack:** k3s v1.36.4+k3s1, Cilium 1.20.1, Kata 4.1.0 (`kata-clh-runtime-rs`), Envoy v1.39.1, Nexus 3.96.1, Coder 2.36.5, libvirt, nftables, bash.

**Spec:** `docs/superpowers/specs/2026-09-13-phase3-containment-core-design.md`

**Part 2:** `docs/superpowers/plans/2026-09-13-phase3-containment-core-part2.md` (Tasks 5–9)

## Global Constraints

- Lab runs in the VM (192.168.122.124, user `dev`, interface `ens2`). Never run cluster or CNI changes on the host.
- The only host-modifying scripts: `infra/vm/00-host-libvirt.sh`, `infra/vm/01-host-egress-nft.sh`.
- Host nftables use their own table `inet sandcastle`. Hooks are limited to packets arriving on `virbr0` and `virbr-sce`. Never touch host output traffic or other interfaces.
- The executor has no libvirt group or host sudo. Steps marked **[USER]** are handed to the owner, who pastes output back.
- `infra/vm/sandcastle-vm.sh ip/ssh/run` need libvirt. The executor uses `ssh -i ~/.ssh/id_gen_key -o UserKnownHostsFile=/var/lib/libvirt/images/sandcastle/known_hosts dev@192.168.122.124` plus `rsync -az --delete --exclude .git --exclude .remember -e "ssh <same opts>" ./ dev@192.168.122.124:sandcastle/`. Call this `VMSSH` / `VMSYNC` below.
- Egress network: `sandcastle-egress`, bridge `virbr-sce`, 192.168.130.0/24, host .1, VM `egress0` 192.168.130.10, MAC `52:54:00:5c:00:02`, routing table 130.
- Envoy: namespace `sandcastle-egress`, Deployment and label `app: envoy-egress`, Service `egress`, port 3128. Proxy URL `http://egress.sandcastle-egress.svc.cluster.local:3128`.
- Static allowlist: `example.com` only.
- Nexus docker-hub proxy: repo `docker-hub`, HTTP connector 8082, Service port 8082.
- Workspace image version bumps to `0.2.0` (base and dind).
- Files under 500 lines. Semantic commits end with the attribution lines from the session. Shell scripts pass `bash -n`.
- Every "blocked" assertion is paired with a positive control that proves the target is up.
- Log spike results, bugs found and decisions to open-brain project `c3bcc121-ec02-44f9-8a76-add22f0938a5` in the 5 W's form (Who / What / When / Where / Why).

## File Map

| File | Status | Responsibility |
|---|---|---|
| `infra/vm/egress-net.xml` | create | libvirt egress network definition |
| `infra/vm/sandcastle-vm.sh` | modify | `egress-net` subcommand: define network, attach NIC |
| `infra/vm/01-host-egress-nft.sh` | create | host nft `lock <ip>` / `unlock` / `verify` |
| `infra/bootstrap/netplan-egress.yaml` | create | VM `egress0` static IP plus policy routing |
| `infra/bootstrap/01-k3s-cilium.sh` | modify | Cilium: `bpf.masquerade`, `egressGateway.enabled`, `policyDenyResponse` |
| `infra/bootstrap/04-containment.sh` | create | Phase 3 bootstrap inside the VM |
| `platform/egress/envoy.yaml` | create | Namespace, ConfigMap (Envoy config), Deployment, Service |
| `platform/policy/workspaces.yaml` | create | Workspace CNP (4 destinations) |
| `platform/policy/platform.yaml` | create | CNPs for Envoy, Nexus, coderd egress |
| `platform/policy/egress-gateway.yaml` | create | CiliumEgressGatewayPolicy |
| `platform/nexus/nexus.yaml` | modify | Service port 8082, container port 8082 |
| `platform/nexus/configure.sh` | modify | DockerToken realm, `docker-hub` proxy repo |
| `platform/coder/values.yaml` | modify | `CODER_BLOCK_DIRECT=true` |
| `images/base/Dockerfile` | modify | proxy env |
| `images/build-import.sh` | modify | VERSION 0.2.0 |
| `templates/base/main.tf` | modify | image tags 0.2.0, dind registry mirror args |
| `infra/tests/03-containment.sh` | create | Phase 3 verify suite (VM) |
| `Makefile` | modify | Phase 3 targets |
| `docs/superpowers/specs/2026-09-13-phase3-spike-results.md` | create | Spike findings S1–S6 |
| `README.md`, MVP and Phase 3 specs | modify | status, run steps, spike outcomes |

---

### Task 0: Egress network, VM NIC, Makefile targets, snapshot

**Files:**
- Create: `infra/vm/egress-net.xml`
- Modify: `infra/vm/sandcastle-vm.sh` (add `cmd_egress_net`, a usage line, a case entry)
- Modify: `Makefile` (Phase 3 block)

**Interfaces:**
- Produces: `make vm-egress-net`, `make containment`, `make egress-lock`, `make egress-unlock`, `make verify-containment`, `make verify-host-egress`. Tasks 1, 2 and 8 use them.

- [ ] **Step 1: Write `infra/vm/egress-net.xml`**

```xml
<!-- Egress network for pods the Cilium egress gateway selects (Envoy,
     Nexus, coderd). Host nftables allow forwarding only from this bridge, so
     any packet from the VM's primary NIC toward the outside is a bypass.
     No DHCP: the VM side is static (infra/bootstrap/netplan-egress.yaml). -->
<network>
  <name>sandcastle-egress</name>
  <forward mode='nat'/>
  <bridge name='virbr-sce' stp='on' delay='0'/>
  <ip address='192.168.130.1' netmask='255.255.255.0'/>
</network>
```

- [ ] **Step 2: Add the subcommand to `infra/vm/sandcastle-vm.sh`**

Below the variable block near line 16, add:

```bash
EGRESS_NET="${EGRESS_NET:-sandcastle-egress}"
EGRESS_MAC="${EGRESS_MAC:-52:54:00:5c:00:02}"
```

Before `usage()`, add:

```bash
cmd_egress_net() {
  # Idempotent. The fixed MAC lets netplan in the VM name the NIC egress0.
  v net-info "$EGRESS_NET" >/dev/null 2>&1 || v net-define "$REPO_ROOT/infra/vm/egress-net.xml"
  v net-info "$EGRESS_NET" | grep -q '^Active:.*yes' || v net-start "$EGRESS_NET"
  v net-autostart "$EGRESS_NET"
  if v domiflist "$VM_NAME" | grep -qi "$EGRESS_MAC"; then
    echo "egress NIC already attached"
  else
    v attach-interface "$VM_NAME" network "$EGRESS_NET" --model virtio --mac "$EGRESS_MAC" --live --config
  fi
}
```

In `usage()`, add the line `  egress-net          define the egress network and attach the VM's second NIC`. In `main()`, add `    egress-net) cmd_egress_net "$@" ;;`.

- [ ] **Step 3: Append the Phase 3 block to `Makefile`, and add the new targets to `.PHONY`**

```make
# Phase 3
vm-egress-net: ## one-time: libvirt egress network + second VM NIC
	@$(VM) egress-net

containment: ## cilium egress gateway, envoy gate, network policies (run egress-unlock first)
	@$(VM) snapshot pre-containment
	@$(VM) run infra/bootstrap/04-containment.sh

# The lock is not persistent: a host reboot leaves the lab unlocked, and
# verify-containment fails until egress-lock runs again.
egress-lock:   ## host: drop lab VM traffic except the egress network (sudo)
	@ip=$$($(VM) ip) && sudo infra/vm/01-host-egress-nft.sh lock "$$ip"

egress-unlock: ## host: remove the lock for bootstrap steps (sudo)
	@sudo infra/vm/01-host-egress-nft.sh unlock

verify-containment: ## workspace reaches only its four destinations, denials are visible
	@$(VM) run infra/tests/03-containment.sh

verify-host-egress: ## host: nft table shape and sandcastle-deny log lines (sudo)
	@sudo infra/vm/01-host-egress-nft.sh verify
```

- [ ] **Step 4: Syntax check**

Run: `bash -n infra/vm/sandcastle-vm.sh && make -n vm-egress-net containment egress-lock`
Expected: no errors. The make dry-run prints the commands.

- [ ] **Step 5: [USER] Create the network and NIC, then snapshot**

Hand to the owner:
```
sudo -u "$USER" make vm-egress-net
sudo -u "$USER" infra/vm/sandcastle-vm.sh snapshot pre-containment
sudo -u "$USER" make vm-snapshots
```
Expected: the network is active, the NIC is attached, and `pre-containment` is listed.

- [ ] **Step 6: Verify the NIC from inside the VM**

Run: `VMSSH 'ip -br link | grep -i 52:54:00:5c:00:02 || ip -o link | grep -i 52:54:00:5c:00:02'`
Expected: one interface line (not yet named `egress0`).

- [ ] **Step 7: Commit**

```bash
git add infra/vm/egress-net.xml infra/vm/sandcastle-vm.sh Makefile
git commit -m "feat(vm): add egress network, second vm nic and phase 3 make targets"
```

---

### Task 1: Spike (gates Tasks 2–9)

Throwaway work lives in `/tmp/spike` inside the VM and is never committed. Only the results file is committed. **Stop after this task and show the results to the owner.**

**Files:**
- Create: `infra/bootstrap/netplan-egress.yaml` (kept; the spike proves it)
- Modify: `infra/bootstrap/01-k3s-cilium.sh` (kept; the spike proves it)
- Create: `docs/superpowers/specs/2026-09-13-phase3-spike-results.md`

**Interfaces:**
- Produces: decisions **S1–S6** in the results file. Later tasks branch on them by name.

- [ ] **Step 2: Write `infra/bootstrap/netplan-egress.yaml`**

```yaml
# Second NIC for Cilium egress gateway traffic. No default route in the main
# table: node traffic keeps using ens2. Only packets sourced from the egress IP
# use table 130, whose default route is the egress network's gateway.
network:
  version: 2
  ethernets:
    egress0:
      match:
        macaddress: "52:54:00:5c:00:02"
      set-name: egress0
      dhcp4: false
      addresses: [192.168.130.10/24]
      routes:
        - to: default
          via: 192.168.130.1
          table: 130
      routing-policy:
        - from: 192.168.130.10
          table: 130
```

- [ ] **Step 3: Apply netplan in the VM**

Run:
```
VMSYNC
VMSSH 'sudo install -m 600 sandcastle/infra/bootstrap/netplan-egress.yaml /etc/netplan/60-sandcastle-egress.yaml && sudo netplan apply && ip -br addr show egress0 && ip rule | grep 130 && ip route show table 130 && curl -s --interface 192.168.130.10 -m 10 -o /dev/null -w "%{http_code}\n" https://example.com'
```
Expected: `egress0 UP 192.168.130.10/24`, rule `from 192.168.130.10 lookup 130`, default route via 192.168.130.1, HTTP `200`. The ssh session must survive, because `ens2` is unchanged.

- [ ] **Step 4: Add the Cilium values to `infra/bootstrap/01-k3s-cilium.sh`**

In the `helm upgrade --install cilium` command, add these three lines after `--set socketLB.hostNamespaceOnly=true \`:

```bash
  --set bpf.masquerade=true \
  --set egressGateway.enabled=true \
  --set policyDenyResponse=icmp \
```

Append this paragraph to the comment block that follows the helm command:

```bash
#
# Phase 3 containment: egressGateway needs bpf.masquerade and kube-proxy
# replacement. It gives Envoy, Nexus and coderd a dedicated egress IP, so host
# nftables can drop everything else the VM sends. policyDenyResponse=icmp
# (experimental) turns a silent policy drop into an immediate "unreachable"
# for the workspace; a bypass then fails fast instead of hanging.
```

Before the `step "waiting for node Ready"` line, add:

```bash
# Agents read cilium-config only at start; a changed value needs a restart.
kubectl -n kube-system rollout restart ds/cilium deploy/cilium-operator
kubectl -n kube-system rollout status ds/cilium --timeout=5m
```

Run: `bash -n infra/bootstrap/01-k3s-cilium.sh`. Expected: no output.

- [ ] **Step 5: Run the Cilium upgrade in the VM**

Run: `VMSYNC && VMSSH 'cd sandcastle && infra/bootstrap/01-k3s-cilium.sh && kubectl -n kube-system exec ds/cilium -- cilium-dbg status --verbose | grep -iE "masquerading|devices|egress"'`
Expected: the helm upgrade succeeds; `Masquerading: BPF`; Devices include `ens2` and `egress0`. If `egress0` is missing, add `--set devices='{ens2,egress0}'` to the helm command, re-run, and record this in S1.

- [ ] **Step 6: Spike S1, egress gateway with a Kata pod**

Write `/tmp/spike/s1.yaml` in the VM:
```yaml
apiVersion: v1
kind: Namespace
metadata: {name: spike}
---
apiVersion: v1
kind: Pod
metadata: {name: kata-egress, namespace: spike, labels: {spike: egress}}
spec:
  runtimeClassName: kata-clh-runtime-rs
  containers:
    - name: c
      image: sandcastle/base:0.1.0
      imagePullPolicy: Never
      command: ["sleep", "3600"]
---
apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata: {name: spike-egress}
spec:
  selectors:
    - podSelector:
        matchLabels:
          io.kubernetes.pod.namespace: spike
          spike: egress
  destinationCIDRs: ["0.0.0.0/0"]
  excludedCIDRs: ["10.42.0.0/16", "10.43.0.0/16", "192.168.122.0/24"]
  egressGateway:
    nodeSelector:
      matchLabels: {kubernetes.io/os: linux}
    egressIP: 192.168.130.10
```
Run: `VMSSH 'kubectl apply -f /tmp/spike/s1.yaml && kubectl -n spike wait --for=condition=Ready pod/kata-egress --timeout=5m && kubectl -n spike exec kata-egress -- curl -s -m 10 -o /dev/null -w "%{http_code}\n" https://example.com'`
Then **[USER]** on the host, while the owner re-runs that curl: `sudo timeout 20 tcpdump -ni virbr-sce 'tcp port 443' -c 5`
Expected **pass**: HTTP 200, and tcpdump shows packets from `192.168.130.10`. **Fail**: no packets on `virbr-sce` (the traffic left via `virbr0`) or the curl fails. Record S1 = `gateway-ok` or `fallback-vm-allowlist`, with the evidence.

- [ ] **Step 7: Spike S2, L7 HTTP and DNS policy on a Kata pod, including websocket**

Write `/tmp/spike/s2.yaml`:
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: spike-l7, namespace: spike}
spec:
  endpointSelector: {matchLabels: {spike: egress}}
  egress:
    - toEndpoints:
        - matchLabels: {io.kubernetes.pod.namespace: kube-system, k8s-app: kube-dns}
      toPorts:
        - ports: [{port: "53", protocol: UDP}, {port: "53", protocol: TCP}]
          rules:
            dns:
              - matchPattern: "*.cluster.local"
              - matchPattern: "*.*.cluster.local"
              - matchPattern: "*.*.*.cluster.local"
              - matchPattern: "*.*.*.*.cluster.local"
    - toEndpoints:
        - matchLabels: {io.kubernetes.pod.namespace: coder, app.kubernetes.io/name: coder}
      toPorts:
        - ports: [{port: "8080", protocol: TCP}]
          rules:
            http:
              - {method: GET, path: "/api/v2/buildinfo"}
              - {path: "/derp.*"}
```
Run:
```
VMSSH 'kubectl apply -f /tmp/spike/s2.yaml; sleep 5; P="kubectl -n spike exec kata-egress --"
$P curl -s -m 10 -o /dev/null -w "buildinfo %{http_code}\n" http://coder.coder.svc.cluster.local/api/v2/buildinfo
$P curl -s -m 10 -o /dev/null -w "users %{http_code}\n" http://coder.coder.svc.cluster.local/api/v2/users
$P curl -s -m 10 -o /dev/null -w "derp-ws %{http_code}\n" -H "Connection: Upgrade" -H "Upgrade: derp" http://coder.coder.svc.cluster.local/derp
$P getent hosts nexus.sandcastle-mirror.svc.cluster.local; echo "svc rc=$?"
$P getent hosts example.com; echo "external rc=$?"
kubectl -n kube-system exec ds/cilium -- hubble observe --since 1m --namespace spike -o compact | tail -20'
```
Expected **pass**: buildinfo `200`, users `403`, derp-ws `101` (or a non-403 from coderd, showing the upgrade passed the proxy), svc rc=0 **even through the search-list expansion**, external rc≠0, Hubble shows `http-request DROPPED` for `/api/v2/users` and a DNS refusal for `example.com`. Record S2 = `l7-ok` or `fallback-envoy-fronts-coderd`, and S6 = the DNS patterns that worked (if `*` does not span labels, keep the explicit multi-label list above).

- [ ] **Step 8: Spike S3, ICMP deny response**

Run: `VMSSH 'P="kubectl -n spike exec kata-egress --"; s=$(date +%s%N); $P curl -s -m 15 -o /dev/null http://1.1.1.1; echo rc=$? ms=$(( ($(date +%s%N)-s)/1000000 ))'`
Expected **pass**: rc≠0 and ms < 3000. **Fail**: ms ≈ 15000 (a timeout). If it fails, add to the S2 policy
```yaml
  ingress:
    - icmps:
        - fields: [{type: 3, family: IPv4}]
```
plus an `ingress` entry allowing all other traffic the pod already had, re-apply, and re-run. Record S3 = `icmp-fast`, `icmp-needs-ingress-rule` or `timeout-only`.

- [ ] **Step 9: Spike S4, Envoy two-stage CONNECT and SNI**

Copy the Envoy config from part 2, Task 6, Step 1 (the `envoy.yaml` key only) to `/tmp/spike/envoy.yaml` on the **host**, then validate:
Run: `docker run --rm -v /tmp/spike:/cfg:ro envoyproxy/envoy:v1.39.1 --mode validate -c /cfg/envoy.yaml`
Expected: `configuration '/cfg/envoy.yaml' OK`.
Then run it on the host: `docker run --rm -d --name spike-envoy -p 13128:3128 -v /tmp/spike:/cfg:ro envoyproxy/envoy:v1.39.1 -c /cfg/envoy.yaml`, and check:
```
curl -s -o /dev/null -w "allowed %{http_code}\n" -x http://127.0.0.1:13128 https://example.com
curl -s -v -x http://127.0.0.1:13128 https://github.com 2>&1 | grep -iE "CONNECT tunnel failed|x-sandcastle-denied"
curl -s -o /dev/null -w "http-denied %{http_code}\n" -x http://127.0.0.1:13128 http://neverssl.com/
curl -s -m 10 -o /dev/null -w "sni-mismatch %{http_code}\n" -x http://127.0.0.1:13128 --connect-to github.com:443:example.com:443 https://github.com; echo rc=$?
docker logs spike-envoy 2>&1 | tail -5; docker rm -f spike-envoy
```
Expected **pass**: allowed `200`; a `CONNECT tunnel failed, response 403` line plus an `x-sandcastle-denied:` header line; http-denied `403`; sni-mismatch rc≠0 with no 200; JSON access-log lines. If the allowed CONNECT hangs (Envoy waits for upstream bytes before sending 200 while tls_inspector waits for the ClientHello), record S4 = `authority-only`: apply the part 2 Task 6 "S4 = authority-only fallback". Otherwise S4 = `two-stage-ok`.

- [ ] **Step 10: Spike S5, Coder agent paths and address**

Create a throwaway workspace from the current template and capture every HTTP flow its pod makes to coderd:
```
VMSSH 'C=$HOME/.local/bin/coder; $C create spike-agent --template base --use-parameter-defaults --yes >/tmp/spike/create.log 2>&1
kubectl -n kube-system exec ds/cilium -- hubble observe --since 10m --namespace sandcastle-workspaces --to-port 30080 -o compact | tail -5
kubectl -n kube-system exec ds/cilium -- hubble observe --since 10m --namespace sandcastle-workspaces --to-namespace coder -o compact | tail -5'
```
Apply an L7 visibility policy to the workspace namespace that allows everything but parses HTTP to coderd (`/tmp/spike/s5.yaml`):
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: spike-visibility, namespace: sandcastle-workspaces}
spec:
  endpointSelector: {}
  egress:
    - toEntities: [all]
    - toEntities: [host, remote-node]
      toPorts:
        - ports: [{port: "30080", protocol: TCP}]
          rules: {http: [{}]}
    - toEndpoints:
        - matchLabels: {io.kubernetes.pod.namespace: coder}
      toPorts:
        - ports: [{port: "8080", protocol: TCP}]
          rules: {http: [{}]}
```
Run: `VMSSH 'kubectl apply -f /tmp/spike/s5.yaml; C=$HOME/.local/bin/coder; $C restart spike-agent --yes >/dev/null; for i in $(seq 60); do $C ssh spike-agent -- true && break; sleep 5; done; $C ssh spike-agent -- "curl -s localhost:13337/healthz"; kubectl -n kube-system exec ds/cilium -- hubble observe --since 10m --namespace sandcastle-workspaces --protocol http -o json | jq -r ".flow | [.destination.namespace // .destination_names[0] // \"host\", .l7.http.method, (.l7.http.url|sub(\"^https?://[^/]+\";\"\"))] | @tsv" | sort | uniq -c'`
Expected: a list of method/path pairs, and whether the destination is the `coder` pod (`toEndpoints`) or the `host` entity on 30080 (the NodePort was not translated before policy). Record S5 as two things: `coder-address` = `pod-8080` or `host-30080`, and a `coder-paths` list turned into regexes (collapse UUIDs to `[^/]+`). Clean up: `VMSSH 'kubectl delete -f /tmp/spike/s5.yaml; $HOME/.local/bin/coder delete spike-agent --yes'`.

Also run: `VMSSH 'kubectl -n coder exec deploy/coder -- coder server --help | grep -iA2 "block-direct"'`. Expected: the flag exists with env `CODER_BLOCK_DIRECT`. Record it under S5.

- [ ] **Step 11: Clean up the spike cluster objects**

Run: `VMSSH 'kubectl delete -f /tmp/spike/s2.yaml -f /tmp/spike/s1.yaml --ignore-not-found'`
Expected: namespace `spike` and the egress gateway policy are deleted.

- [ ] **Step 12: Write `docs/superpowers/specs/2026-09-13-phase3-spike-results.md`**

Structure (fill each row with observed output, not expectations):
```markdown
# Phase 3 Spike Results

Date: 2026-09-13 · Who: Claude (executor), owner (host steps) · Where: lab VM + GAME-01

| ID | Question | Result | Evidence | Consequence for build |
|---|---|---|---|---|
| S1 | Egress gateway with Kata | gateway-ok / fallback-vm-allowlist | tcpdump line, devices line | ... |
| S2 | L7 HTTP on Kata incl. websocket | l7-ok / fallback-envoy-fronts-coderd | status codes, hubble lines | ... |
| S3 | ICMP deny response | icmp-fast / icmp-needs-ingress-rule / timeout-only | rc, ms | ... |
| S4 | Envoy two-stage CONNECT+SNI | two-stage-ok / authority-only | curl output | ... |
| S5 | Coder agent address + paths | pod-8080 / host-30080; path regex list | hubble uniq -c table | ... |
| S6 | DNS patterns | pattern list | getent results | ... |
```
Then log each row to open-brain with `log_context` (entry_type `note`, tags `phase3`, `spike`) in 5 W's form.

- [ ] **Step 13: Commit and STOP for owner review**

```bash
git add infra/bootstrap/netplan-egress.yaml infra/bootstrap/01-k3s-cilium.sh docs/superpowers/specs/2026-09-13-phase3-spike-results.md
git commit -m "feat(substrate): enable cilium egress gateway and record phase 3 spike results"
```
Show the owner the results table. Do not start Task 2 until the owner approves. If any row fell back, update the Phase 3 spec section it affects before continuing.

---

### Task 2: Host egress lock script

**Files:**
- Create: `infra/vm/01-host-egress-nft.sh`

**Interfaces:**
- Consumes: `make egress-lock` / `egress-unlock` / `verify-host-egress` (Task 0).
- Produces: log prefix `sandcastle-deny ` (`verify` greps for it).

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Second enforcement layer, on the host: the lab VM may send traffic out only
# from its egress network (Cilium egress gateway IP), and only to 80/443.
# Anything from the VM's primary NIC leaving the host, or reaching host
# services other than libvirt's DHCP/DNS, is logged "sandcastle-deny" and
# dropped. That is what a workspace packet looks like if Cilium failed.
#
# Scope is deliberately narrow: our own table, input/forward hooks only, and
# every rule matches iifname virbr0 or virbr-sce. Host output traffic and
# other interfaces are never matched, so this cannot strand the host the way
# the first Cilium install did. Not persistent across host reboots
# (ponytail: re-run make egress-lock; verify-containment fails while unlocked).
#
# usage: sudo 01-host-egress-nft.sh lock <vm-primary-ip> | unlock | verify
set -euo pipefail

TABLE=sandcastle
LAB_BR=virbr0
EGRESS_BR=virbr-sce

[[ $EUID -eq 0 ]] || { echo "needs sudo" >&2; exit 1; }

lock() {
  local vm_ip="$1"
  [[ "$vm_ip" =~ ^192\.168\.122\.[0-9]+$ ]] || { echo "unexpected VM IP '$vm_ip'" >&2; exit 1; }
  ip link show "$EGRESS_BR" >/dev/null 2>&1 || { echo "$EGRESS_BR missing — run make vm-egress-net" >&2; exit 1; }
  # "table; delete table; table {...}" replaces the table atomically and
  # idempotently in one transaction.
  nft -f - <<EOF
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
  chain input {
    type filter hook input priority filter - 10; policy accept;
    iifname "$LAB_BR" ip saddr $vm_ip ct state established,related accept
    iifname "$LAB_BR" ip saddr $vm_ip udp dport { 53, 67 } accept
    iifname "$LAB_BR" ip saddr $vm_ip tcp dport 53 accept
    iifname "$EGRESS_BR" ct state established,related accept
    iifname { "$LAB_BR", "$EGRESS_BR" } limit rate 20/second burst 40 packets log prefix "sandcastle-deny " level warn
    iifname { "$LAB_BR", "$EGRESS_BR" } drop
  }
  chain forward {
    type filter hook forward priority filter - 10; policy accept;
    # Public destinations only: an allowlisted name resolving to the LAN or an
    # enclave range must not become a route (DNS rebinding).
    iifname "$EGRESS_BR" ip saddr 192.168.130.10 ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } tcp dport { 80, 443 } accept
    iifname { "$LAB_BR", "$EGRESS_BR" } limit rate 20/second burst 40 packets log prefix "sandcastle-deny " level warn
    iifname { "$LAB_BR", "$EGRESS_BR" } drop
  }
}
EOF
  echo "locked: VM $vm_ip may leave the host only via $EGRESS_BR (tcp 80/443)"
}

unlock() {
  nft delete table inet "$TABLE" 2>/dev/null && echo "unlocked" || echo "already unlocked"
}

verify() {
  local fail=0 hooks
  nft list table inet "$TABLE" >/dev/null 2>&1 && echo "  ok    table inet $TABLE present" || { echo "  FAIL  table inet $TABLE missing (unlocked)"; exit 1; }
  hooks=$(nft list table inet "$TABLE" | awk '/hook/ {print $4}' | sort -u | tr '\n' ' ')
  [[ "$hooks" == "forward input " ]] && echo "  ok    hooks: $hooks" || { echo "  FAIL  unexpected hooks: $hooks"; fail=1; }
  # Every rule line (not table/chain/type/brace) must match a lab bridge.
  if nft list table inet "$TABLE" | grep -vE '^\s*(table|chain|type|\}|$)' | grep -vq iifname; then
    echo "  FAIL  a rule does not match on a lab bridge"; fail=1
  else
    echo "  ok    every rule is scoped to $LAB_BR/$EGRESS_BR"
  fi
  journalctl -k --since "-30 min" --no-pager | grep -q 'sandcastle-deny' \
    && echo "  ok    sandcastle-deny log lines in the last 30 min" \
    || { echo "  FAIL  no sandcastle-deny log lines in the last 30 min (run make verify-containment first)"; fail=1; }
  exit "$fail"
}

case "${1:-}" in
  lock)   lock "${2:?usage: lock <vm-primary-ip>}" ;;
  unlock) unlock ;;
  verify) verify ;;
  *)      echo "usage: $0 lock <vm-ip> | unlock | verify" >&2; exit 2 ;;
esac
```

- [ ] **Step 2: Syntax and ruleset check (no host change)**

Run: `bash -n infra/vm/01-host-egress-nft.sh && sed -n '/^table inet \$TABLE {/,/^}/p' infra/vm/01-host-egress-nft.sh | sed 's/\$TABLE/sandcastle/; s/\$LAB_BR/virbr0/g; s/\$EGRESS_BR/virbr-sce/g; s/\$vm_ip/192.168.122.124/g' > /tmp/claude-nft-check.nft && nft -c -f /tmp/claude-nft-check.nft 2>&1 | tail -3; echo rc=$?`
Expected: `bash -n` passes. `nft -c` may need root; if it prints a permission error, hand `sudo nft -c -f /tmp/claude-nft-check.nft` to the owner (check mode applies nothing). Expected: rc=0.

- [ ] **Step 3: [USER] Lock, observe, unlock**

Hand to the owner:
```
sudo -u "$USER" make egress-lock
ssh -i ~/.ssh/id_gen_key -o UserKnownHostsFile=/var/lib/libvirt/images/sandcastle/known_hosts dev@192.168.122.124 'curl -s -m 5 -o /dev/null -w "primary %{http_code}\n" https://example.com; curl -s -m 10 --interface 192.168.130.10 -o /dev/null -w "egress %{http_code}\n" https://example.com; getent hosts example.com'
sudo journalctl -k --since "-5 min" | grep sandcastle-deny | tail -3
sudo -u "$USER" make egress-unlock
```
Expected: ssh still works (established traffic, and host output is untouched); `primary 000`; `egress 200`; `getent` resolves (DNS to dnsmasq allowed); deny log lines show `SRC=192.168.122.124`.

- [ ] **Step 4: Commit**

```bash
git add infra/vm/01-host-egress-nft.sh
git commit -m "feat(vm): add host nftables egress lock for the lab vm"
```

---

### Task 3: Nexus docker-hub proxy

**Files:**
- Modify: `platform/nexus/nexus.yaml` (Service ports, container ports)
- Modify: `platform/nexus/configure.sh` (realm plus repo, before `step "done"`)

**Interfaces:**
- Produces: `http://nexus.sandcastle-mirror.svc.cluster.local:8082` serving the Docker Registry v2 API anonymously (Tasks 4 and 5).

- [ ] **Step 1: Write a failing check**

Run: `VMSSH 'kubectl -n sandcastle-mirror run curlcheck --rm -i --restart=Never --image=sandcastle/base:0.1.0 --image-pull-policy=Never --overrides="{\"spec\":{\"runtimeClassName\":\"kata-clh-runtime-rs\"}}" -- curl -s -m 10 -o /dev/null -w "%{http_code}\n" http://nexus.sandcastle-mirror.svc.cluster.local:8082/v2/'`
Expected: `000` (the port is not served).

- [ ] **Step 2: Add port 8082 to `platform/nexus/nexus.yaml`**

In the Service `ports:`, add:
```yaml
    - name: docker-hub
      port: 8082
      targetPort: 8082
```
Change the container `ports:` to:
```yaml
          ports:
            - containerPort: 8081
            - containerPort: 8082 # docker-hub proxy HTTP connector (configure.sh)
```

- [ ] **Step 3: Add the realm and repo to `platform/nexus/configure.sh`**

Before `step "done"`, add:
```bash
step "docker bearer token realm"
# Anonymous docker pulls fail without the DockerToken realm: the Docker client
# always runs the token flow, even when no credentials are configured.
curl -fsS --fail-with-body -u "admin:$ADMIN_PW" \
  -X PUT -H 'Content-Type: application/json' \
  -d '["NexusAuthenticatingRealm","DockerToken"]' \
  "$NEXUS_URL/service/rest/v1/security/realms/active"

step "docker-hub proxy"
# DinD sidecars use this as --registry-mirror. A registry mirror must be served
# at the root of a host:port, so the repo gets its own HTTP connector (8082)
# rather than a /repository/ path.
create_repo "docker-hub" "docker/proxy" '{
  "name": "docker-hub",
  "online": true,
  "storage": {"blobStoreName": "default", "strictContentTypeValidation": true},
  "proxy": {"remoteUrl": "https://registry-1.docker.io", "contentMaxAge": 1440, "metadataMaxAge": 1440},
  "negativeCache": {"enabled": true, "timeToLive": 1440},
  "httpClient": {"blocked": false, "autoBlock": true},
  "docker": {"v1Enabled": false, "forceBasicAuth": false, "httpPort": 8082},
  "dockerProxy": {"indexType": "HUB", "cacheForeignLayers": false}
}'
```
Add `echo "docker: http://nexus.sandcastle-mirror.svc.cluster.local:8082 (registry mirror)"` to the done block.

- [ ] **Step 4: Apply and configure (lock must be off)**

Run:
```
bash -n platform/nexus/configure.sh && VMSYNC && VMSSH 'cd sandcastle && kubectl apply -f platform/nexus/nexus.yaml && kubectl -n sandcastle-mirror rollout status statefulset/nexus --timeout=15m && (kubectl -n sandcastle-mirror port-forward svc/nexus 18081:8081 >/tmp/pf.log 2>&1 & echo $! >/tmp/pf.pid; sleep 3; platform/nexus/configure.sh; kill $(cat /tmp/pf.pid))'
```
Expected: `ok docker-hub created`. The realms PUT returns 204 with no output.

- [ ] **Step 5: Re-run the Step 1 check, then pull a manifest**

Run the Step 1 command again. Expected: `401` or `200` (the registry answers; 401 is the token challenge).
Run: `VMSSH 'kubectl -n sandcastle-mirror run curlcheck --rm -i --restart=Never --image=sandcastle/base:0.1.0 --image-pull-policy=Never --overrides="{\"spec\":{\"runtimeClassName\":\"kata-clh-runtime-rs\"}}" -- sh -c "t=\$(curl -s \"http://nexus.sandcastle-mirror.svc.cluster.local:8082/v2/token?scope=repository:library/busybox:pull\" | jq -r .token); curl -s -o /dev/null -w \"%{http_code}\n\" -H \"Authorization: Bearer \$t\" -H \"Accept: application/vnd.oci.image.index.v1+json\" http://nexus.sandcastle-mirror.svc.cluster.local:8082/v2/library/busybox/manifests/1.36"'`
Expected: `200`.

- [ ] **Step 6: Commit**

```bash
git add platform/nexus/nexus.yaml platform/nexus/configure.sh
git commit -m "feat(mirror): add nexus docker-hub proxy for dind registry mirror"
```

---

### Task 4: Workspace images and template (proxy env, registry mirror, 0.2.0)

**Files:**
- Modify: `images/base/Dockerfile` (the `ENV` line near line 51)
- Modify: `images/build-import.sh:9`
- Modify: `templates/base/main.tf` (dev image line 205, dind image line 238, dind args line 252)
- Modify: `platform/coder/values.yaml` (env list)

**Interfaces:**
- Consumes: the Envoy proxy URL (Global Constraints) and the Nexus :8082 mirror (Task 3).
- Produces: images `sandcastle/base:0.2.0` and `sandcastle/dind:0.2.0`, a pushed `base` template.

- [ ] **Step 1: Write a failing check**

Run: `VMSSH 'sudo k3s ctr -n k8s.io images ls -q | grep -F sandcastle/base:0.2.0'`
Expected: no output, rc=1.

- [ ] **Step 2: Add the proxy env to `images/base/Dockerfile`**

Replace `ENV DOCKER_HOST=unix:///run/dind/docker.sock` with:
```dockerfile
# Everything external goes through the egress gate; in-cluster names (Nexus,
# coderd) go direct. Lowercase variants too: curl reads only http_proxy for
# plain HTTP, and tools disagree on which case they honor. A tool that ignores
# these gets no route at all (platform/policy/workspaces.yaml).
ENV DOCKER_HOST=unix:///run/dind/docker.sock \
    HTTP_PROXY=http://egress.sandcastle-egress.svc.cluster.local:3128 \
    HTTPS_PROXY=http://egress.sandcastle-egress.svc.cluster.local:3128 \
    NO_PROXY=.cluster.local,localhost,127.0.0.1 \
    http_proxy=http://egress.sandcastle-egress.svc.cluster.local:3128 \
    https_proxy=http://egress.sandcastle-egress.svc.cluster.local:3128 \
    no_proxy=.cluster.local,localhost,127.0.0.1
```

- [ ] **Step 3: Bump the version in `images/build-import.sh`**

Change `VERSION="${VERSION:-0.1.0}"` to `VERSION="${VERSION:-0.2.0}"`.

- [ ] **Step 4: Update `templates/base/main.tf`**

- Change the dev `image = "sandcastle/base:0.1.0"` to `"sandcastle/base:0.2.0"`.
- Change the dind `image = "sandcastle/dind:0.1.0" # ...` to `"sandcastle/dind:0.2.0" # ...`.
- Replace the dind `args = [...]` line and add a comment above it:
```hcl
          # Image pulls go to the Nexus docker-hub proxy: with Phase 3 egress
          # policy, Docker Hub itself is unreachable from the workspace.
          args = [
            "dockerd",
            "--host=unix:///run/dind/docker.sock",
            "--group=1000",
            "--registry-mirror=http://nexus.sandcastle-mirror.svc.cluster.local:8082",
            "--insecure-registry=nexus.sandcastle-mirror.svc.cluster.local:8082",
          ]
```
Run: `terraform -chdir=templates/base fmt -check || terraform -chdir=templates/base fmt`. Expected: the file is formatted.

- [ ] **Step 5: Add `CODER_BLOCK_DIRECT` to `platform/coder/values.yaml`**

After the `CODER_TELEMETRY_ENABLE` entry, add:
```yaml
    # DERP relay only. Direct tailnet paths would make every workspace try
    # STUN/UDP to the outside; with egress denied those attempts are noise
    # that trains people to ignore drop alerts.
    - name: CODER_BLOCK_DIRECT
      value: "true"
```
(If spike S5 found no such env, record that instead and skip this step.)

- [ ] **Step 6: [USER] Build and import (host docker plus VM ssh), push the template**

Hand to the owner:
```
sudo -u "$USER" make image
sudo -u "$USER" make template
```
Expected: `sandcastle/base:0.2.0 imported`, `sandcastle/dind:0.2.0 imported`, the template pushes.

- [ ] **Step 7: Re-run the Step 1 check**

Expected: prints `docker.io/sandcastle/base:0.2.0` (or without the `docker.io/` prefix).

- [ ] **Step 8: Commit**

```bash
git add images/base/Dockerfile images/build-import.sh templates/base/main.tf platform/coder/values.yaml
git commit -m "feat(workspace): route workspace egress through proxy and dind pulls through nexus"
```

Continue with part 2: `docs/superpowers/plans/2026-09-13-phase3-containment-core-part2.md`.
