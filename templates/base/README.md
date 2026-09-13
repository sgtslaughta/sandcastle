# base template

`dev` container (`sandcastle/base:0.1.0`, code-server) + `dind` sidecar, both
in one Kata Cloud Hypervisor VM, PVC at `/home/coder`.

- `runtime_class_name = "kata-clh-runtime-rs"` — the VM boundary, also
  admission-enforced; set here for correctness by construction.
- `automount_service_account_token = false` — no API access from a
  workspace; any attempt should alert, not silently work.
- `image_pull_policy = "Never"` — no registry yet; imported directly into
  k3s's containerd (`images/build-import.sh`).
- DinD `privileged` applies inside the Kata guest only. The Docker API is a
  unix socket on a volume shared with `dev` (`/run/dind/docker.sock`); it has
  no TCP listener for any pod on the cluster network to reach.
- `/var/lib/docker` is a sparse ext4 image loop-mounted by `sandcastle/dind`
  (`images/dind`): overlayfs rejects Kata's virtio-fs volumes as an upper layer.

Push:
```
coder templates push base -d templates/base --variable namespace=sandcastle-workspaces --yes
```
