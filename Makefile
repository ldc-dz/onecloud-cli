GO       ?= go
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG      := github.com/ldc-dz/onecloud-cli/internal/cli
LDFLAGS  := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)
TARGETS  := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build test vet cross notices notices-check vuln clean

all: vet test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ocd ./cmd/ocd

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# Cross-compile every release target (Linux CI proves they build; Windows and
# macOS are checked by hand before a release, see README).
cross:
	@set -e; for t in $(TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  echo "build $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/ocd_$${os}_$${arch}$$ext ./cmd/ocd; \
	done

# Regenerate NOTICE and THIRD_PARTY_NOTICES.md from the modules linked into
# the binary for every release target. Both files ship in each release
# archive; `make test` fails when they are out of date, when a linked module
# has no license file, or when a license is not a reviewed one.
notices:
	$(GO) run ./tools/notices

notices-check:
	$(GO) run ./tools/notices -check

# Known vulnerabilities reachable from ocd, in its modules and in the Go
# toolchain that runs the build. Run it before a release and after a Go or
# dependency update.
GOVULNCHECK ?= golang.org/x/vuln/cmd/govulncheck@v1.9.0
vuln:
	$(GO) run $(GOVULNCHECK) ./...

clean:
	rm -rf bin dist
