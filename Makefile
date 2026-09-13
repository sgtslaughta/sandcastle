.PHONY: preflight prereqs cluster kata verify-substrate

# Phase 0
preflight:  ## check this host can run the reference implementation (read-only)
	@infra/tests/00-host-preflight.sh

prereqs:    ## install kubectl, helm, terraform (needs sudo)
	@infra/bootstrap/00-prereqs.sh

# Phase 1
cluster:    ## k3s + cilium, kube-proxy replaced (needs sudo)
	@infra/bootstrap/01-k3s-cilium.sh

kata:       ## kata-clh + gvisor runtime classes (needs sudo)
	@infra/bootstrap/02-kata-gvisor.sh

verify-substrate: ## prove the workspace kernel is not the host kernel
	@infra/tests/01-isolation-substrate.sh
