.PHONY: preflight prereqs

# Phase 0
preflight:  ## check this host can run the reference implementation (read-only)
	@infra/tests/00-host-preflight.sh

prereqs:    ## install kubectl, helm, terraform (needs sudo)
	@infra/bootstrap/00-prereqs.sh
