GO_SRCS := $(shell find . -type f -name '*.go' -a ! \( -name 'zz_generated*' -o -name '*_test.go' \))
GO_TESTS := $(shell find . -type f -name '*_test.go')
TAG_NAME = $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
TAG_NAME_DEV = $(shell git describe --tags --abbrev=0 2>/dev/null)
VERSION_CORE = $(shell echo $(TAG_NAME)')
VERSION_CORE_DEV = $(shell echo $(TAG_NAME_DEV)')
GIT_COMMIT = $(shell git rev-parse --short=7 HEAD)
VERSION = $(or $(and $(TAG_NAME),$(VERSION_CORE)),$(and $(TAG_NAME_DEV),$(VERSION_CORE_DEV)-dev),$(GIT_COMMIT))

ifeq ($(gow),)
gow := $(shell go env GOPATH)/bin/gow
endif

ifeq ($(golint),)
golint := $(shell go env GOPATH)/bin/golangci-lint
endif

.PHONY: bin/auth-htmx
bin/auth-htmx: $(GO_SRCS)
	go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./main.go

.PHONY: run
run:
	go run ./main.go

.PHONY: watch
watch:
	gow -e=go,mod,html,tmpl,env,local run ./main.go

.PHONY: lint
lint: $(golint)
	$(golint) run ./...

.PHONY: clean
clean:
	rm -rf bin/

$(gow):
	go install github.com/mitranim/gow@latest

$(golint):
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: version
version:
	@echo VERSION_CORE=${VERSION_CORE}
	@echo VERSION_CORE_DEV=${VERSION_CORE_DEV}
	@echo VERSION=${VERSION}
