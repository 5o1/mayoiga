.PHONY: build check test verify-no-wireguard

GOCACHE ?= /tmp/mayoiga-go-build-$(shell id -u)

build: ## Build the self-contained binary
	@mkdir -p bin
	@CGO_ENABLED=0 GOCACHE="$(GOCACHE)" go build -trimpath -buildvcs=false -o bin/mayoiga ./cmd/mayoiga

check: ## Check documentation graph and forbidden runtime packages
	@python3 scripts/check_graph.py
	@$(MAKE) verify-no-wireguard

verify-no-wireguard:
	@mkdir -p bin
	@CGO_ENABLED=0 GOCACHE="$(GOCACHE)" go build -trimpath -buildvcs=false -o bin/mayoiga.verify ./cmd/mayoiga
	@if go tool nm >/dev/null 2>&1; then \
		! go tool nm bin/mayoiga.verify | grep -F 'xray-core/proxy/wireguard'; \
	elif command -v nm >/dev/null 2>&1; then \
		! nm bin/mayoiga.verify | grep -F 'xray-core/proxy/wireguard'; \
	else \
		echo "no nm implementation available" >&2; exit 1; \
	fi
	@rm -f bin/mayoiga.verify

test: check ## Run all tests
	@GOCACHE="$(GOCACHE)" go test -buildvcs=false ./...
