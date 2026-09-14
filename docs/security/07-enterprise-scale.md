# 07 — Pathway to Enterprise Scale on AWS

This file describes how sandcastle grows from the single-node lab (one KVM VM,
k3s, host nftables) to 50, 500, and 5000 users in an air-gapped AWS VPC,
commercial or GovCloud. It covers the reference architecture, sizing, the HA
changes each component needs, the limits that bite at each tier, an ordered
migration with gates, and the risks that scale itself adds. It is a plan, not a
build: nothing here is verified in the lab unless it says so. Back to
[README.md](../../README.md). Gaps referenced here are tracked in
[05-gaps-and-monitoring.md](05-gaps-and-monitoring.md).

Sources: `docs/superpowers/specs/2026-09-13-sandcastle-mvp-design.md`
("Production deltas", phases 5–8), the Phase 3 and Phase 4 design specs
(DR-3.2, DR-3.5, DR-3.8, DR-4.6..4.10), `platform/admin/admin.yaml`,
`platform/egress/envoy.yaml`, `admin/internal/xds/build.go`,
`admin/cmd/sandcastle-admin/main.go`.

## 1. Scope and assumptions

| Assumption | Value used in this file | Why / how to validate |
|---|---|---|
| Workspaces per user | 1 persistent, 1.2 peak (some users run two) | Validate with pilot Coder metrics (`coderd` workspace build counts) |
| Concurrency ratio (active workspaces / users) | 0.6 at peak; 0.3 off-peak | Developer tools with idle autostop; replace with pilot data |
| Workspace size | 4 vCPU / 8 GiB standard; 2 vCPU / 4 GiB small; 8 vCPU / 16 GiB large (desktop, heavy builds) | Mix assumed 20 / 70 / 10 % (small / standard / large) |
| Kata overhead per pod | ~0.3–0.5 GiB guest kernel, agent and Cloud Hypervisor; DinD `/var/lib/docker` disk on the node | Measure on the target AMI; lab numbers are nested (L2) and not representative |
| CPU overcommit | 2:1 vCPU on workspace nodes | Dev workloads are bursty; watch steal time |
| Memory overcommit | None (1:1) | Kata guest memory is committed at boot; ballooning is not relied on |
| Phases 5–8 | Brokers, detection, desktop, red team built before tier 500 | MVP spec phases; the migration gates depend on them |

### Virtualization substrate

Kata with Cloud Hypervisor (`kata-clh-runtime-rs`) needs `/dev/kvm`. On AWS
that means `*.metal` instances, or the newer non-metal instance families that
expose nested virtualization. The lab already runs Kata nested (MVP spec, "Lab
host boundary"), but nested guests pay boot and memory overhead and add a
hypervisor layer to the trust chain. This plan uses metal.

| Option | Pros | Cons / trade-offs | Recommendation |
|---|---|---|---|
| Kata + Cloud Hypervisor on `*.metal` | Same runtime as the lab; verified suites carry over; virtio-fs, hotplug | Metal capacity is lumpy and slow to launch (minutes); large failure unit (30–60 workspaces per node) | Default |
| Kata + Firecracker on `*.metal` | Smaller VMM attack surface; faster boot; lower per-VM memory | Needs the devmapper snapshotter; no virtio-fs or device hotplug; DinD sidecar and memory-medium emptyDir must be re-verified (Phase 2 findings); separate RuntimeClass and admission change | Evaluate in a pilot spike; adopt only if the containment and DX suites pass unchanged |
| Nested virtualization on non-metal instances | Finer-grained sizing; faster scale-out | Extra hypervisor layer; performance cost; family and region support varies (verify in GovCloud) | Fallback when metal capacity is short |
| gVisor only (no `/dev/kvm`) | Runs on any instance | Strictly weaker than Kata (MVP spec, "Second isolation layer") | Not for sensitive workspaces |

### Kubernetes distribution and node OS

| Option | Pros | Cons / trade-offs |
|---|---|---|
| EKS with managed node groups on metal | Managed control plane across 3 AZs; managed node groups accept `*.metal` types; IAM integration (Pod Identity / IRSA) | Cilium must replace `aws-node` and `kube-proxy` (supported, but adds bootstrap steps); EKS version cadence forces upgrades; API endpoint must be private-only |
| Self-managed RKE2 or k3s on EC2 | Closest to the lab (k3s); full control of versions; FIPS-validated RKE2 builds help GovCloud programs | You operate etcd, control-plane HA, certificate rotation and upgrades |
| **Choice** | EKS for tiers 500 and 5000; either for the pilot. RKE2 if the accreditation program requires control-plane ownership or FIPS builds EKS cannot show | |

| Node OS | Use for | Notes |
|---|---|---|
| Ubuntu (EKS-optimized, Canonical) or Amazon Linux 2023 | Kata workspace nodes | `kata-deploy` installs host binaries and edits containerd config; this needs a mutable host |
| Bottlerocket | Platform nodes (coderd, admin, Envoy, observability) | Immutable root and API-driven config reduce drift; Kata on Bottlerocket would need a custom variant, so it is not used for workspace nodes |

## 2. Reference architecture (air-gapped VPC)

"Air-gapped" here means no internet gateway and no NAT gateway in any
sandcastle VPC. Every packet that leaves a workspace VPC goes through a
Transit Gateway to an inspection VPC owned by the network team. Whether that
inspection VPC has any path beyond the corporate network is an enterprise
decision outside sandcastle; in the strictest form the only "external"
destinations are on-premises services over Direct Connect, and packages arrive
through an airlock into the artifact registry.

### Accounts and OUs

| OU / account | Contents | Owner |
|---|---|---|
| Security OU: `log-archive` | S3 Object Lock buckets (audit export, VPC Flow Logs, CloudTrail) | Security |
| Security OU: `security-tooling` | Security Hub and GuardDuty delegated admin, Detective, Config aggregator | Security |
| Infrastructure OU: `network` | Transit Gateway, inspection VPC with AWS Network Firewall, Route 53 Resolver rules and DNS Firewall, egress proxy fleet | Network team (the "different team" of the MVP invariant) |
| Infrastructure OU: `artifacts` | ECR (pull-through cache or airlock-fed repos), Artifactory or Nexus HA, airlock scanning | Platform + security |
| Workloads OU: `sandcastle-prod` / `sandcastle-pilot` | EKS cluster, CNPG, coderd, sandcastle-admin, Envoy, observability | Platform |
| Enclaves OU: one account per enclave | Enclave services, exposed only as PrivateLink endpoint services to the data-broker | Enclave owners |

SCPs on the Workloads OU deny `ec2:CreateInternetGateway`,
`ec2:CreateNatGateway`, `ec2:AttachInternetGateway`, VPC peering, and public
IP assignment. This makes "no internet gateway" a guardrail, not a
convention.

### VPC layout (workload account, per AZ, 3 AZs)

| Subnet | Size (per AZ) | Contents | Route table |
|---|---|---|---|
| `workspace` | /18 (tier 5000), /20 (tier 500) | Kata metal nodes and workspace pod IPs (Cilium ENI or cluster-pool IPAM) | Local only; no route to TGW. Workspaces reach platform subnets only, through Cilium policy. Node-local Envoy traffic exits via Cilium egress gateway nodes in `platform` |
| `platform` | /22 | Platform nodes: coderd, admin, Envoy gateway pods, CNPG, Nexus/Artifactory | Local; `0.0.0.0/0` → TGW (inspection VPC) |
| `endpoints` | /24 | Interface VPC endpoints | Local |
| `ingress` | /24 | Internal NLB / ALB for Coder and admin UI | Local; corporate CIDRs → TGW |
| `broker` | /24 | data-broker and cred-broker; PrivateLink interface endpoints to enclaves | Local only |

Enclave VPCs are never attached to the Transit Gateway route domain that the
workload VPC uses. The data-broker reaches each enclave through a PrivateLink
interface endpoint; there is no routed path from any workspace subnet to any
enclave CIDR, and VPC Flow Logs plus Network Firewall alert rules page on any
attempt (MVP invariant).

### Egress: replacing host nftables

The lab's second enforcement layer is host nftables outside the VM, allowing
only the Cilium egress-gateway IP to forward (DR-3.2, C-NET-10, C-NET-11). In
AWS the equivalent independent layer is owned by the network account:

| Lab component | AWS replacement | Notes |
|---|---|---|
| Host nftables lock (`infra/vm/01-host-egress-nft.sh`) | AWS Network Firewall in the inspection VPC: stateful rules allowing only egress-proxy source IPs, TLS SNI / HTTP Host domain allowlist, drop-and-alert default | Different account, different team, different API: a Cilium or cluster-admin compromise cannot change it |
| Cilium egress gateway IP | Dedicated egress-proxy subnet IPs (or Cilium egress gateway nodes with fixed ENI IPs) | See section 4 for egress gateway HA |
| Envoy in-cluster (per-workspace policy) | Unchanged: Envoy DaemonSet stays the per-workspace decision point | Network Firewall cannot see workspace identity (traffic is SNATed); it enforces the union allowlist only |
| Egress proxy fleet (optional) | Squid or Envoy ASG in the inspection VPC as a second, enterprise-owned proxy hop | Gives the network team its own logs and allowlist; costs another hop |
| libvirt DNS | Route 53 Resolver (VPC `.2`) with DNS Firewall rule groups: allow `cluster.local`-forwarded names and approved internal zones, block everything else | Backs C-NET-4 at the VPC level; CoreDNS forwards to Resolver |

### Required VPC endpoints

| Endpoint | Type | Needed by |
|---|---|---|
| `com.amazonaws.<region>.s3` | Gateway | ECR layers, CNPG barman-cloud backups, Loki chunks, audit export |
| `ecr.api`, `ecr.dkr` | Interface | Node image pulls (replaces `imagePullPolicy: Never` imports, C-SUP-4) |
| `sts` | Interface | EKS Pod Identity / IRSA token exchange |
| `kms` | Interface | EBS, S3, Secrets Manager encryption; CNPG backup encryption |
| `logs` | Interface | CloudWatch Logs (control-plane logs, Network Firewall alerts) |
| `ssm`, `ssmmessages`, `ec2messages` | Interface | Node break-glass access without SSH or bastions |
| `ec2` | Interface | Cilium ENI IPAM, Karpenter/cluster-autoscaler, EBS CSI |
| `elasticloadbalancing` | Interface | AWS Load Balancer Controller |
| `eks`, `eks-auth` | Interface | Node join, Pod Identity |
| `secretsmanager` | Interface | External Secrets Operator |
| `autoscaling` | Interface | Managed node groups / cluster-autoscaler |
| `guardduty-data` (if runtime monitoring) | Interface | GuardDuty agent (verify regional availability) |

The EKS API endpoint is private-only. Endpoint policies restrict S3 and ECR
to the organization's accounts (`aws:ResourceOrgID`), which closes the
"exfil through a public bucket via the gateway endpoint" path.

### Artifacts, identity, secrets, audit

| Concern | Lab | Enterprise |
|---|---|---|
| Package mirror (C-SUP-1) | Nexus 3.96.1 CE, one pod, internet upstream | Artifactory or Nexus Pro in HA (3 nodes, shared S3 blobstore, external Postgres) fed by the airlock; no internet upstream. ECR pull-through cache for OCI where the upstream is reachable from the artifacts account; airlock-pushed ECR repos otherwise |
| Node images | Built on host, imported to containerd | Built in CI outside workspaces, signed (cosign/Notation), pushed to ECR; admission verifies signatures |
| Coder and admin UI | NodePort 30080 / 30081 on the lab net | Internal ALB (TLS, ACM private CA certificate) in the `ingress` subnets, reachable only from corporate CIDRs via TGW |
| Human identity (C-ADM-1) | Coder local users; Coder OAuth2 provider for admin | Corporate IdP (IAM Identity Center, Okta, or Entra ID) via OIDC into Coder; admin keeps Coder as its OAuth2 provider, so roles derive from IdP groups synced to Coder |
| Secrets (C-ADM-15) | Generated in-cluster, Kubernetes Secrets | AWS Secrets Manager + External Secrets Operator; KMS customer-managed keys; rotation for DB and OAuth client secrets |
| Encryption | Lab disk | KMS CMKs for EBS, S3, EKS secrets envelope encryption, CNPG backups |
| Audit (C-ADM-10) | Append-only `audit` table | Same table, plus a periodic exporter to S3 with Object Lock (compliance mode) in `log-archive` |
| Detection | Hubble, Envoy logs; Falco in Phase 6 | Plus GuardDuty (EKS audit log and runtime monitoring), Security Hub, VPC Flow Logs, Network Firewall alert logs, CloudTrail org trail |

GuardDuty EKS Runtime Monitoring runs its agent on the node. It sees the host
kernel and runc pods; it does not see processes inside a Kata guest. It covers
platform nodes and the Kata node hosts, not workspace interiors, which stay
with in-guest Falco (MVP Phase 6). Verify agent support for the chosen node OS
and for GovCloud before relying on it.

### Commercial vs GovCloud

| Topic | Commercial | GovCloud (US) |
|---|---|---|
| Compliance | FedRAMP Moderate / High in selected regions | FedRAMP High, ITAR, CJIS, DoD SRG IL4/IL5 workloads; US-person operator requirements |
| Service availability | Broadest | Lags commercial; check each service in section 2 (ECR pull-through cache, GuardDuty runtime monitoring, IAM Identity Center features, managed Prometheus/Grafana) on the AWS regional services list before design sign-off |
| Instance types | Full metal range | Fewer metal families and less capacity per AZ; newest generations arrive later |
| Pricing | Baseline | Commonly 10–30 % higher for EC2 and many services; validate per SKU |
| Accounts | Standard Organizations | GovCloud accounts are separate partitions (`aws-us-gov`) linked to a commercial payer; ARNs and endpoints differ, so IaC must be partition-aware |
| Marketplace / third-party | Wide | Narrower; confirm Artifactory/Nexus Pro and Okta connectivity options |

## 3. Sizing per tier

Density rule: a `m7i.metal-24xl` (96 vCPU, 384 GiB) keeps ~10 % for the host,
kubelet, Cilium and Kata shims, leaving ~345 GiB. With the section 1 mix
(average ~8.4 GiB guest + ~0.4 GiB overhead) that is **~35–40 workspaces**; plan
**30** to leave room for bin-packing loss and rolling node replacement. CPU
at 2:1 overcommit (~190 vCPU-equivalents) is not the binding limit. A
`m7i.metal-48xl` (192 vCPU, 768 GiB) holds roughly twice that. Alternatives
when capacity is short: `m6i.metal` (128 vCPU, 512 GiB), `r7i.metal-24xl`
(96 vCPU, 768 GiB, memory-heavy mixes), `c7i.metal-24xl` (96 vCPU, 192 GiB,
only for small workspaces).

Capacity for AZ loss: with 3 AZs, workspace nodes are sized so that losing one
AZ still holds peak (N × 1.5 for tier 500 and 5000). The pilot accepts reduced
capacity during an AZ outage.

### Workspace and platform compute

| Item | Pilot (50 users) | Department (500) | Enterprise (5000) |
|---|---|---|---|
| Peak active workspaces | ~30 (plan 40) | ~300 | ~3000 |
| Workspace nodes | 3 × `m7i.metal-24xl` (1 per AZ) | 15 × `m7i.metal-24xl` (5 per AZ) | 75–85 × `m7i.metal-48xl` (25–28 per AZ) |
| Workspace pool autoscaling | Fixed | Cluster-autoscaler, min = peak, On-Demand Capacity Reservations for the base | Karpenter or cluster-autoscaler with ODCRs for the base; separate pools per workspace size |
| Platform nodes | 3 × `m7i.2xlarge` | 6 × `m7i.4xlarge` | 12–18 × `m7i.4xlarge`, split into `platform`, `data` (CNPG) and `observability` node groups |
| Control plane | EKS (or 3 × RKE2 servers `m7i.xlarge`) | EKS | EKS; ask AWS for control-plane scaling review at >100 metal nodes |
| Envoy egress | DaemonSet on workspace nodes, 1 pod each (3) | DaemonSet (15) | DaemonSet (75–85); per-pod CPU limit raised; no HPA needed per node, see note |
| sandcastle-admin | 2 (leader + standby) | 3 (1 leader, 2 standby / UI) | 3 leader-eligible + 3–6 stateless UI replicas (HPA on CPU) |
| coderd | 2 replicas | 3 replicas | 5–8 replicas (HPA) |
| Coder external provisioners | 2 | 4–6 | 15–25 (build bursts at shift start) |
| Egress proxy fleet (network account) | Optional | 2 per AZ, ASG | 3–4 per AZ, ASG, scaled on connections |

Envoy note: a DaemonSet with node-local traffic (section 4) sizes Envoy with
its node. An HPA does not apply to a DaemonSet; if Envoy moves to dedicated
gateway nodes instead, use a Deployment with HPA on CPU and active connections.

### Data services

| Item | Pilot (50) | Department (500) | Enterprise (5000) |
|---|---|---|---|
| Coder Postgres (CNPG) | 3 instances (1 primary + 2 replicas across AZs), `m7i.large`-class requests (2 vCPU / 8 GiB), gp3 50 GiB | 3 instances, 4 vCPU / 16 GiB, gp3 200 GiB, 6k IOPS | 3 instances, 8–16 vCPU / 64 GiB, io2 500 GiB–1 TiB; PgBouncer pooler (CNPG `Pooler`) |
| Admin Postgres (CNPG) | 3 instances, 1 vCPU / 2 GiB, gp3 20 GiB | 3 instances, 2 vCPU / 8 GiB, gp3 50 GiB | 3 instances, 4 vCPU / 16 GiB, gp3 200 GiB; denial write rate is the driver (section 5) |
| Backups | barman-cloud to S3 (gateway endpoint), daily base + continuous WAL, 14-day PITR | Same, 30-day PITR | Same, 35-day PITR; cross-region copy if the DR plan requires it |
| Artifact registry | Nexus Pro or Artifactory, 2 nodes, S3 blobstore | 3 nodes, S3 blobstore, CNPG or RDS backend | 3–5 nodes, S3 blobstore, dedicated DB; separate read-only replicas for workspace pulls |
| Observability | Loki (simple scalable, S3), Prometheus (1 replica), Grafana, Hubble Relay | Loki (S3, 3 read / 3 write), Prometheus HA pair or Amazon Managed Prometheus, Hubble Relay with flow export to Loki | Loki microservices (S3), Mimir or AMP, Hubble flow export filtered to drops and L7 denials only |

### Order-of-magnitude monthly cost

**Order-of-magnitude estimates, dated 2026-09, commercial region, On-Demand
list prices, before Savings Plans. Validate every line with the AWS Pricing
Calculator before any budget request.** Savings Plans or Reserved Instances
typically cut the compute share by a third or more. GovCloud: add the
uplift from section 2 (commonly 10–30 %).

| Cost driver | Pilot (50) | Department (500) | Enterprise (5000) |
|---|---|---|---|
| Workspace metal nodes | ~$10k | ~$50k | ~$500k–600k |
| Platform + data nodes, EBS | ~$2k | ~$8k | ~$30k–50k |
| Network Firewall, VPC endpoints, TGW attachments, NLB/ALB | ~$2k–4k | ~$4k–8k | ~$15k–40k (data processing dominates) |
| Artifact registry licences and storage | ~$1k–5k | ~$5k–15k | ~$20k–50k |
| Logs, metrics, S3, GuardDuty, Security Hub, Flow Logs | ~$1k–3k | ~$5k–15k | ~$30k–80k |
| **Total range** | **~$15k–25k / month** | **~$70k–100k / month** | **~$0.6M–0.8M / month** |

Per user this is roughly $300–500 (pilot) down to $120–160
(enterprise) per month, dominated by metal compute. The biggest levers are the
concurrency ratio, idle autostop, and memory per workspace, not platform
services.

## 4. HA modifications

| Component | Lab state (file) | Enterprise change | Why |
|---|---|---|---|
| Coder Postgres | Single StatefulSet `postgres:17.6`, 5 GiB (`platform/coder/postgres.yaml`) | CNPG `Cluster`, 3 instances with pod anti-affinity across AZs; `minSyncReplicas: 1`, `maxSyncReplicas: 1` (quorum sync to one standby); barman-cloud backups to S3 with KMS; scheduled base backups; PITR; `Pooler` (PgBouncer) at tier 5000 | A single Postgres pod is a Coder outage and data-loss point; sync replica across AZs gives RPO ≈ 0 for one AZ loss; PITR recovers from bad migrations and operator error |
| Admin Postgres | StatefulSet in `platform/admin/admin.yaml` (spec DR-4.7 names a separate `postgres.yaml`; code keeps it in `admin.yaml`) | Separate CNPG cluster in `sandcastle-admin` ns, same sync + backup pattern; keep the app/owner role split (C-ADM-10) via CNPG `managed.roles`; audit export job to S3 Object Lock | Policy and audit data are the most sensitive state; DR-4.7 separation stays; Object Lock makes audit tamper-evident even against a DB superuser |
| sandcastle-admin writer | 1 replica, `Recreate`; comment: "rebuild loop and denial throttle assume a single writer" (`platform/admin/admin.yaml`) | Active/standby via a Kubernetes `coordination.k8s.io` Lease (client-go `leaderelection`). Only the leader runs the rebuild loop, expiry ticker (30 s), one-minute resync, CNP reconciler, and ALS denial ingest/throttle | Two writers would race CNP apply/prune and double-count denials; the throttle is in-memory per process. Lease failover is ~15 s with default timings; running Envoys keep their last snapshot meanwhile (DR-4.6) |
| sandcastle-admin UI | Same process, NodePort 30081 | Split mode flag: stateless UI replicas behind the internal ALB, any replica serves pages; writes go to Postgres and trigger the leader via `LISTEN/NOTIFY` or a DB change poll | UI availability should not depend on the leader; sessions are HMAC cookies (C-ADM-11), so no sticky sessions are needed if all replicas share the session key |
| xDS serving | ADS on :18000 in the single admin; one Envoy node ID `sandcastle-egress` (`admin/internal/xds/build.go`) | Option A (preferred): every admin replica builds the snapshot from the same DB state + pod informer and serves ADS; snapshot version derived from a DB revision counter so replicas agree. Option B: leader-only ADS, Envoy bootstrap lists all admin endpoints and reconnects on failover | A: no xDS gap on leader loss. B: simpler but a failover means ADS reconnect; Envoy keeps serving the last snapshot either way. All Envoys sharing one node ID is fine (`IDHash` cache serves one snapshot to many streams) until per-node snapshots are needed (section 5) |
| xDS / ALS transport | Plaintext gRPC, :18000 limited to Envoy pods by CNP (Phase 4 threat table, "ponytail") | mTLS both ways: cert-manager with a private CA (ACM PCA issuer) or SPIRE issuing SPIFFE SVIDs; admin verifies Envoy SVID, Envoy verifies admin SVID | On many nodes, "only the Envoy pod can reach :18000" rests on Cilium identity across nodes; a spoofed xDS server is total egress control, so authenticate the channel |
| Envoy egress | Deployment, 1 replica (DR-3.8), 100m / 128 Mi | DaemonSet on workspace nodes; Service `internalTrafficPolicy: Local` so workspaces use their node's Envoy; PodDisruptionBudget `maxUnavailable: 1`; `--drain-time-s 5 --drain-strategy immediate` kept; readiness requires a received snapshot | Node-local traffic keeps source IPs intact and avoids cross-AZ data charges; a failed Envoy affects one node's workspaces, not the fleet |
| Cilium | Single-node, `operator.replicas=1` (Phase 3 finding) | `operator.replicas=2`; Hubble Relay HA; for multiple clusters (per-AZ or per-region blast-radius cells) use Cluster Mesh with shared identities; KVStoreMesh at scale | Multi-node operator HA; cells limit blast radius at tier 5000 (section 7) |
| Coder | 1 coderd, built-in provisioner | Multiple coderd replicas; external provisioner daemons in a separate namespace with their own identity; DERP served by coderd replicas behind the internal NLB. Verify licensing first: multi-replica coderd and external provisioners are listed as Coder Premium features, not OSS 2.36.5 (owner decision: licence, or single coderd with fast restart) | Provisioner isolation keeps Terraform credentials out of coderd; replicas remove the workspace-access single point of failure |
| Egress gateway (C-NET-10) | Cilium `CiliumEgressGatewayPolicy`, one VM NIC | OSS Cilium egress gateway selects one gateway node per policy, with no built-in failover of the egress IP; loss of that node drops platform egress until reselection. Enterprise: route platform egress through the network account's Network Firewall + proxy fleet (multi-AZ, managed HA), and keep the Cilium egress gateway only to give Network Firewall a stable, attributable source, using one policy per AZ | Network Firewall is the independent layer; do not let OSS egress gateway failover semantics define platform availability |
| Topology | One node | `topologySpreadConstraints` (`topology.kubernetes.io/zone`, `maxSkew: 1`) on coderd, admin, CNPG, registry, Loki; workspace pools per AZ; Coder template pins a workspace to its volume's AZ (EBS is AZ-scoped) | Survive an AZ loss; avoid a restarted workspace landing in an AZ without its disk |
| Workspace identity (C-NET-8, DR-3.5) | Pod source IP → workspace ID; RBAC principals are `/32` IPs | Tier 500: keep source IP, Envoy node-local, Cilium anti-spoofing. Tier 5000: move to identity-based authorization, either Envoy RBAC on a header set by a node-local Cilium L7 policy carrying the Cilium identity, or SPIFFE SVIDs via an in-guest agent that cannot read its own key (harder under Kata). Zone membership becomes a principal, not a list of IPs | IP lists scale with workspace count and churn on every pod event (section 5); identities scale with zones |

## 5. Scaling limits to watch

The admin design rebuilds everything on every change: "read rows + current pod
IPs → build xDS snapshot and desired CNPs → push/apply" (Phase 4 spec,
Architecture), coalescing pod events for 200 ms and resyncing every minute
(`admin/cmd/sandcastle-admin/main.go`). That is correct and simple at lab size.
These are the numbers that change first.

| Limit | Mechanism in code | Pilot (50) | Department (500) | Enterprise (5000) | Mitigation |
|---|---|---|---|---|---|
| Tunnel churn from listener renames | SNI listener name = `sha256(host, port, sorted IP set)` (`admin/internal/xds/build.go` `hashName`). Any workspace start or stop in a zone changes the IP set of every zone-wide host, renaming its listener and draining **all** open tunnels to that host after 5 s | Rare; tolerable | Pod events every few minutes: users see periodic TLS resets on zone hosts | Constant resets; effectively breaks long-lived tunnels | Rename only on IP **removal**, and split zone-rule listeners from grant listeners; at tier 5000 use zone principals (section 4) so the IP set is not in the name. Must be fixed before tier 500 |
| xDS snapshot size | One vhost per host with one `/32` principal per IP, plus one internal listener and cluster per host | Small (KBs) | Zone hosts × ~300 IPs: hundreds of KB | 50 zone hosts × 3000 IPs = 150k principals: tens of MB per push, to every Envoy | Delta xDS (go-control-plane supports incremental), per-node snapshots with only local pods' IPs (natural fit with node-local Envoy DaemonSet), identity principals |
| Full rebuild cost | Every UI action, expiry, pod event, and the 1-minute resync reads all rows and all pods | ms | tens of ms | Seconds of CPU per rebuild; rebuilds overlap during shift-start pod storms | Measure p99 rebuild time as a metric; debounce longer under load; incremental per-node builds |
| Listener churn in Envoy | Draining listeners hold memory and connections for the drain time | None | Low | Many listeners draining at once on each Envoy | Same as tunnel churn; cap concurrent drains; monitor `listener_manager.total_listeners_draining` |
| CNP count and selector size | One CNP per zone with DNS rules (`In` list of workspace IDs) plus one per workspace with DNS grants (`admin/internal/cilium`) | Tens | Hundreds; `In` lists of hundreds of IDs | Thousands of CNPs; default-zone `NotIn` list with thousands of IDs; identity recomputation on each change | Label workspaces with their zone (admin-managed label or namespace per zone) so selectors are `zone=X` and constant size; watch Cilium `policy_regeneration_time` and BPF policy map pressure |
| Hubble and Envoy log volume | Hubble flows, Envoy stdout + ALS per request | Fine on defaults | Filter Hubble export to drops, L7 denials, and DNS denials | Allowed-flow logs dominate cost; noise-budget signatures (C-NET-13) × 3000 workspaces | Export only denials and security events; sample allowed flows; keep per-workspace rollups; budget log cost per tier (section 3) |
| Postgres write rate from denials | ALS upsert into `denials`, ≤ 1 update/s per (workspace, host, port), 200 rows per workspace cap | Negligible | A misbehaving agent adds up to 1 write/s per distinct key | 3000 workspaces × several hot keys = thousands of writes/s during an incident | Batch upserts per second per leader; per-workspace write budget; alert on denial rate (it is also a detection signal) |
| IP reuse window | Grants follow Running pods; exposure window = rebuild latency (~1 s in the lab, C-ADM-9) | ~1 s | Seconds | Rebuild latency grows with size; Cilium ENI IPAM may reuse IPs quickly | Track rebuild latency SLO; delay IP release (Cilium IPAM cool-down) beyond p99 rebuild time; identity-based principals remove the issue |
| Coder provisioning | Terraform runs per workspace start | Built-in provisioner OK | External provisioners required | Start storms at shift change; Postgres connection count | Provisioner pool HPA, prebuilt workspaces, PgBouncer |
| Metal node launch time | New `*.metal` nodes take several minutes to boot | n/a | Scale-out lags demand | Morning ramp needs pre-scaled capacity | Scheduled scaling ahead of shift start; ODCRs |

## 6. Migration path

Each stage must pass its gate before the next begins. "Suites" are the
existing scripts in `infra/tests/` (01 substrate, 02 DX, 03 containment 35/35,
04 admin 39/39) adapted for AWS; adapted means host-lock checks become
Network Firewall checks and VM snapshots become infrastructure-as-code redeploys.

| # | Stage | Work | Gate (all must pass) |
|---|---|---|---|
| 0 | Lab complete | Finish MVP Phases 5–8 (brokers, detection, desktop, red team) in the VM | All phase suites green under the host lock; red-team suite (Phase 8) reports blocked **and** alerted for every PoC |
| 1 | IaC foundation | Accounts, SCPs (no IGW/NAT), TGW, inspection VPC with Network Firewall, Resolver DNS Firewall, endpoints, KMS, log-archive with Object Lock | Automated check: no route to an IGW/NAT in any workload route table; SCP denies tested; DNS Firewall blocks a test domain; Flow Logs arrive |
| 2 | Pilot cluster (50) | EKS or RKE2, Cilium replacing aws-node/kube-proxy, metal node group with kata-deploy, platform node group; ECR images signed; Artifactory/Nexus HA fed by airlock | `01-isolation-substrate.sh` and `02-dx-baseline.sh` adapted and green on metal; Firecracker spike recorded (adopt or reject) |
| 3 | Pilot containment + admin | Envoy DaemonSet with node-local policy; CNPG for both databases; admin with Lease leader election; xDS mTLS; External Secrets; Coder behind internal ALB with corporate OIDC | `03-containment.sh` and `04-admin.sh` adapted and green, including: Envoy restarted with admin down fails closed; revoke closes an open tunnel within the Phase 4 bound; workspace → Network Firewall direct path dropped and alerted; kill the admin leader → standby takes the Lease and a grant applies within the Phase 4 target |
| 4 | Pilot operation | 50 users for at least one release cycle; measure concurrency ratio, density, rebuild latency, denial rate, log cost | Red-team suite green in AWS; CNPG failover drill (primary deleted, RPO 0, Coder recovers); PITR restore drill; AZ failure game day; cost within the pilot range or re-estimated |
| 5 | Fix scale blockers | Listener-rename scoping, zone-label CNP selectors, batched denial writes, per-node or delta xDS (section 5) | Load test at 2× the department target (600 synthetic workspaces): no tunnel resets on unrelated pod events; p99 rebuild within the Phase 4 target; all suites still green |
| 6 | Department (500) | Scale node groups per section 3; external provisioners; Loki/Prometheus HA; ODCRs; GuardDuty + Security Hub wired to paging | Suites + red team green; AZ loss game day holds peak; on-call runbooks exercised (admin failover, CNPG failover, Network Firewall rule rollback) |
| 7 | Identity and cells | Identity-based principals (Cilium identity or SPIFFE) replace IP lists; split into cells (for example one cluster per AZ pair or per business unit) joined by Cluster Mesh or kept independent with one admin per cell | Suites green per cell; cross-cell isolation test (workspace in cell A cannot use a grant from cell B); admin compromise drill limited to one cell |
| 8 | Enterprise (5000) | Scale cells; Karpenter; scheduled pre-scaling; audit export and retention at volume | Load test at 1.2× peak per cell; red team green per cell; cost review against section 3 with Savings Plans in place |

## 7. Risks introduced by scaling

| Risk | Why scale adds it | Mitigation | Residual |
|---|---|---|---|
| Larger blast radius of sandcastle-admin | One admin decides egress for thousands of workspaces; a compromise or a bad rule edit opens egress fleet-wide. The lab threat table already names it the highest-value target | Cells with one admin each; two-person approval for zone-rule changes above a size threshold; Network Firewall allowlist as the independent cap (admin cannot grant what the firewall drops); Object Lock audit; admin RBAC stays scoped (C-ADM-13) | Within a cell, admin compromise still equals that cell's egress up to the firewall allowlist. See [05-gaps-and-monitoring.md](05-gaps-and-monitoring.md) |
| Shared Envoy fleet | Envoy terminates CONNECT for every workspace on a node; an Envoy CVE or a crafted request affects many users; all Envoys run the same snapshot | Node-local DaemonSet limits a crash to one node; fast patch pipeline for Envoy; fuzz the xDS builder; Envoy runs non-root, read-only, no service account token | An exploitable Envoy bug crosses workspace trust boundaries on that node |
| Cross-AZ data transfer cost | Workspace pulls from a registry or Envoy in another AZ, CNPG sync replication, Loki replication, and coderd DERP relaying all charge per GB across AZs | Node-local Envoy; AZ-local registry read replicas and `trafficDistribution: PreferClose` Services; keep DERP relays per AZ; watch the Cost and Usage Report by `usage_type` `DataTransfer-Regional-Bytes` | CNPG sync replication must cross AZs by design |
| Metal capacity availability | `*.metal` supply per AZ is limited, especially in GovCloud and for new generations; a failed node needs a full metal host to replace | ODCRs for the base; multiple metal families per node group (m7i, m6i, r7i); Karpenter with family fallbacks; nested-virt non-metal fallback pool documented but gated | A regional capacity shortage delays scale-out and can block AZ-loss recovery |
| Large failure unit per node | 30–60 workspaces die with one metal host; kernel or Kata upgrades need node drains of many live workspaces | PDB-aware, one-node-at-a-time rolling upgrades in off-hours; workspace persistence on EBS so a restart loses only running processes | User disruption during host maintenance |
| Control-plane load | Pod informer across thousands of pods, CNP churn, Coder provisioning storms all hit the API server | Label-scoped informers, constant-size selectors (section 5), provisioner rate limits, EKS control-plane scaling review | API throttling during incident-driven mass restarts |
| Detection blind spots grow | GuardDuty and host eBPF do not see inside Kata guests; more workspaces means more in-guest telemetry to trust | In-guest Falco relay (MVP Phase 6) with a tamper-resistant channel; alert on missing telemetry heartbeat per workspace | A guest that silences its own telemetry is detected by absence, not by content |
| Operational drift across accounts | Network Firewall rules, SCPs, and cluster policy are owned by different teams; changes can diverge from sandcastle zones | Policy-as-code in one repo with CI tests that compare the firewall allowlist to the union of zone rules; drift alarms | Deliberate out-of-band edits during incidents |
| GovCloud-specific lag | Services and instance types arrive later; some features in this design may be unavailable | Partition-aware IaC; a per-service availability check as a stage-1 gate | Design substitutions (for example self-managed Prometheus instead of AMP) add operational load |
