.PHONY: preflight vm-host vm vm-ssh vm-console vm-snapshots vm-revert vm-destroy cluster kata verify-substrate platform image template verify-dx vm-egress-net containment egress-lock egress-unlock verify-containment verify-host-egress policy

VM := infra/vm/sandcastle-vm.sh

# Phase 0
preflight:  ## check this host can run the sandcastle lab VM (read-only)
	@infra/tests/00-host-preflight.sh

vm-host:    ## one-time host setup: install libvirt/KVM (needs sudo)
	@infra/vm/00-host-libvirt.sh

vm:         ## create and boot the lab VM
	@$(VM) create

vm-ssh:     ## ssh into the lab VM
	@$(VM) ssh

vm-console: ## attach to the lab VM's serial console
	@$(VM) console

vm-snapshots: ## list lab VM snapshots
	@$(VM) snapshots

vm-revert:  ## revert the lab VM to snapshot NAME=...
	@if [ -z "$(NAME)" ]; then echo "usage: make vm-revert NAME=<snapshot>" >&2; exit 1; fi
	@$(VM) revert $(NAME)

vm-destroy: ## undefine the lab VM and its storage (needs confirmation)
	@$(VM) destroy

# Phase 1
cluster:    ## k3s + cilium inside the VM, kube-proxy replaced
	@$(VM) snapshot pre-cilium
	@$(VM) run infra/bootstrap/00-prereqs.sh
	@$(VM) run infra/bootstrap/01-k3s-cilium.sh
	@$(VM) kubeconfig

kata:       ## kata-clh-runtime-rs + gvisor runtime classes inside the VM
	@$(VM) snapshot pre-kata
	@$(VM) run infra/bootstrap/02-kata-gvisor.sh

# verify-substrate must run inside the VM: it compares the Kata pod's kernel
# to the kernel of the machine running the test. Run from the host, a runc
# fallback pod would report the VM's kernel, differ from the host's, and
# falsely pass.
verify-substrate: ## prove the workspace kernel is not the VM's kernel
	@$(VM) run infra/tests/01-isolation-substrate.sh

# Phase 2
platform:   ## coder + postgres + nexus + workspace admission policy, inside the VM
	@$(VM) snapshot pre-platform
	@$(VM) run infra/bootstrap/03-platform.sh

image:      ## build the base workspace image on the host and import it into the VM
	@images/build-import.sh

template:   ## push the base Coder template
	@$(VM) run '$$HOME/.local/bin/coder templates push base -d templates/base --variable namespace=sandcastle-workspaces --yes'

verify-dx:  ## workspace works through the mirror; admission refuses non-kata pods
	@$(VM) run infra/tests/02-dx-baseline.sh

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

policy:     ## re-apply network policies, e.g. after editing platform/policy/workspace-dns-allow.yaml
	@$(VM) run 'kubectl apply -f platform/policy/'

verify-containment: ## workspace reaches only its four destinations, denials are visible
	@$(VM) run infra/tests/03-containment.sh

verify-host-egress: ## host: nft table shape and sandcastle-deny log lines (sudo)
	@sudo infra/vm/01-host-egress-nft.sh verify

# Go runs in a container: the host and VM have no toolchain. Runs as the
# caller's uid so go.sum and build output stay user-owned.
GOCACHE_DIR := $(HOME)/.cache/sandcastle-go
GO_RUN = mkdir -p $(GOCACHE_DIR) && docker run --rm -u $$(id -u):$$(id -g) \
	-e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
	-v $(GOCACHE_DIR):/cache -v $(CURDIR)/admin:/src -w /src $(GO_DOCKER_ARGS) golang:1.27

admin-go:   ## run a go command for sandcastle-admin, e.g. make admin-go ARGS='mod tidy'
	$(GO_RUN) go $(ARGS)

admin-test: ## sandcastle-admin tests with a throwaway postgres (docker)
	@docker network create sc-admin-test >/dev/null 2>&1 || true
	@docker rm -f sc-admin-testdb >/dev/null 2>&1 || true
	@docker run -d --name sc-admin-testdb --network sc-admin-test -e POSTGRES_PASSWORD=test postgres:17.6 >/dev/null
	@$(GO_RUN) go test -p 1 ./...; s=$$?; docker rm -f sc-admin-testdb >/dev/null; exit $$s

# -p 1: store and web tests share one Postgres server and its roles.
admin-test: GO_DOCKER_ARGS = --network sc-admin-test -e ADMIN_TEST_DSN=postgres://postgres:test@sc-admin-testdb:5432/postgres?sslmode=disable

admin-smoke: ## real envoy v1.39.1 accepts sandcastle-admin xds (docker)
	admin/hack/smoke.sh
