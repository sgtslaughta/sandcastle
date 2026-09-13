.PHONY: preflight vm-host vm vm-ssh vm-console vm-snapshots vm-revert vm-destroy cluster kata verify-substrate platform image template verify-dx

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
