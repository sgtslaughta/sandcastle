# Sandcastle Security Logic

Why each security control exists, what else we could have done, and why we
chose what we did. It also covers the known gaps, what to monitor, and how
the design grows from a single-node lab to an enterprise deployment.

Status: covers Phases 1–4 (v0.4.0). Last updated 2026-09-13.

## The claim being defended

> A hostile or runaway AI agent with root inside its workspace cannot reach
> anything it was not granted, and every attempt is visible within seconds.

"Visible" is a separate requirement from "blocked". Every escape test asserts
both (C-SUP-7).

## Threat model in one table

| Actor | Starting position | Goal | Primary defenses |
|---|---|---|---|
| Runaway agent | Root in one workspace | Reach the internet, other workspaces, the cluster, or enclaves while "helping" | Network containment (02), isolation (01), expiry and revocation (03) |
| Hostile or prompt-injected agent | Root in one workspace, knows it is contained | Escape, exfiltrate, persist, or social-engineer access | All of the above, plus human-confirmed requests (C-ADM-2) and detection (05) |
| Compromised platform pod | Code execution in Envoy, Nexus, coderd, or admin | Widen access, tamper with evidence | Platform pod policies (C-NET-9), least privilege (C-ADM-13), append-only audit (C-ADM-10) |
| Malicious or careless insider | Coder account, possibly admin | Grant themselves broad access, hide it | Required expiry (C-ADM-5), self-approval flagged in audit, audit grants (C-ADM-10) |
| Supply chain | Poisoned upstream package or image | Code running in every workspace | Single mirror (C-SUP-1), pinned images (C-SUP-4); a known gap (05) |

Out of scope for the MVP: stealing data by copying it from the screen by hand,
and physical access to hosts.

## Defense layers

```
 agent (root) ─┬─ Kata microVM boundary ............... 01-isolation (C-ISO-1..7)
               ├─ admission policy: only Kata, no host access
               ├─ Cilium: exactly 4 destinations ...... 02-network (C-NET-1..5, 9, 12)
               ├─ Envoy: CONNECT + SNI per host ....... 02-network (C-NET-6..8)
               │    └─ per-workspace grants over xDS .. 03-admin-plane (C-ADM-1..15)
               ├─ egress gateway + host nftables ...... 02-network (C-NET-10, 11)
               └─ mirror-only packages ................ 04-supply-chain-ops (C-SUP-1..8)
```

Every destination leaving the cluster is denied by two independent layers:
Cilium inside the node, and host nftables outside it (an AWS Network Firewall
in enterprise deployments).

## Documents

| File | Contents |
|---|---|
| [01-isolation.md](01-isolation.md) | Workspace runtime and cluster isolation: Kata, gVisor, admission policy, no Kubernetes credentials, DinD, platform pod hardening |
| [02-network.md](02-network.md) | The four-destination rule, L7 request rules for coderd and Nexus, DNS limits, the Envoy two-stage proxy, identity, egress gateway, host lock |
| [03-admin-plane.md](03-admin-plane.md) | sandcastle-admin: identity, request and approval flow, zones, grant expiry, revocation, fail-closed behavior, audit, web security, least privilege |
| [04-supply-chain-ops.md](04-supply-chain-ops.md) | Package mirror, image handling, template control, bootstrap egress toggle, verification suites |
| [05-gaps-and-monitoring.md](05-gaps-and-monitoring.md) | Known and possible gaps, attack vectors to watch, monitoring signals, verification coverage |
| [06-external-controls-roadmap.md](06-external-controls-roadmap.md) | External controls, future enhancements, reducing admin workload |
| [07-enterprise-scale.md](07-enterprise-scale.md) | AWS air-gapped reference architecture, sizing for 50/500/5000 users, HA changes (CloudNativePG, leader election, xDS mTLS) |

## How to read a control entry

Every control in 01–04 has the same five parts:
1. **Threat mitigated**: who attacks, and what they could do without the control.
2. **Control**: what it does, where it lives, how it was verified.
3. **Alternatives considered**: a table of pros, cons, cost, and the risk each option adds.
4. **Why this control**: the reasoning, with decision-record IDs.
5. **Residual risk**: what remains, with links to 05.

## Evidence

| Suite | Proves | Result at v0.4.0 |
|---|---|---|
| `infra/tests/01-isolation-substrate.sh` | Kata/gVisor runtimes; the workspace runs its own kernel | pass |
| `infra/tests/02-dx-baseline.sh` | Admission refuses unsafe pods; developer tooling works through the mirror | pass |
| `infra/tests/03-containment.sh` | 15 escape paths blocked **and** visible; normal work causes no stray blocked packets | pass (34 checks) |
| `infra/tests/04-admin.sh` | Grants for one workspace only; approval under 5 s; revocation closes open tunnels; expiry; fail-closed; append-only audit | pass (38 checks) |
| `make admin-test`, `make admin-smoke` | Policy, xDS, Cilium, store, auth, and web logic; a real Envoy accepts the generated config | pass |

A whole-branch final review (Opus) found 3 Important, 1 recommended and 8
minor issues after the Phase 4 build; the fix wave (`503662f..2604add`)
closed all but two, which are tracked as gaps (G-15, G-16) in
[05-gaps-and-monitoring.md](05-gaps-and-monitoring.md). Details: the
"Implementation findings" section of the
[Phase 4 spec](../superpowers/specs/2026-09-13-phase4-admin-control-plane-design.md).

Source decisions: [MVP design](../superpowers/specs/2026-09-13-sandcastle-mvp-design.md),
[Phase 3](../superpowers/specs/2026-09-13-phase3-containment-core-design.md) (DR-3.x),
[Phase 4](../superpowers/specs/2026-09-13-phase4-admin-control-plane-design.md) (DR-4.x).
