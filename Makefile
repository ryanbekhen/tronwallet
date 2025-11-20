# Makefile for tronwallet
# Targets:
#  - make test           -> run unit tests (excludes example/generate)
#  - make cover          -> run tests with coverage and write coverage.out
#  - make check-coverage -> fail if coverage < COVERAGE_THRESHOLD (default 80)
#  - make ci             -> fmt, vet, test, cover, check-coverage
#  - make fmt            -> go fmt ./...
#  - make vet            -> go vet ./...
#  - make clean          -> remove coverage artifacts

COVERAGE_THRESHOLD ?= 80

# collect packages, excluding the example/generate package
PACKAGES := $(shell go list ./... | grep -v '/example/generate' || true)

.PHONY: all test cover check-coverage ci fmt vet clean
all: ci

fmt:
	@echo "==> go fmt"
	go fmt ./...

vet:
	@echo "==> go vet"
	go vet ./...

test:
	@echo "==> go test packages: $(PACKAGES)"
	@echo "Note: 'example/generate' is excluded from the default test run"
	go test -v $(PACKAGES)

cover:
	@echo "==> go test (with coverage) packages: $(PACKAGES)"
	@echo "Note: 'example/generate' is excluded from the default coverage run"
	go test -v -covermode=atomic -coverprofile=coverage.out $(PACKAGES)
	@echo "Wrote coverage.out"

check-coverage: cover
	@echo "==> checking coverage against threshold $(COVERAGE_THRESHOLD)%"
	@PCT=$$(go tool cover -func=coverage.out | awk '/total:/ {print $$3}' | sed 's/%//'); \
	PCT_INT=$${PCT%.*}; \
	echo "Total coverage: $${PCT}%"; \
	if [ $${PCT_INT} -lt $(COVERAGE_THRESHOLD) ]; then \
		echo "Coverage $$PCT% is below threshold $(COVERAGE_THRESHOLD)%" 1>&2; exit 1; \
	fi

ci: fmt vet check-coverage
	@echo "CI: all checks passed"

clean:
	@echo "==> cleaning"
	rm -f coverage.out coverage.html
