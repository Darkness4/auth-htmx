GO_SRCS := $(shell find . -type f -name '*.go' -a ! \( -name 'zz_generated*' -o -name '*_test.go' \))
GO_TESTS := $(shell find . -type f -name '*_test.go')
TAG_NAME = $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
TAG_NAME_DEV = $(shell git describe --tags --abbrev=0 2>/dev/null)
VERSION_CORE = $(shell echo $(TAG_NAME))
VERSION_CORE_DEV = $(shell echo $(TAG_NAME_DEV))
GIT_COMMIT = $(shell git rev-parse --short=7 HEAD)
VERSION = $(or $(and $(TAG_NAME),$(VERSION_CORE)),$(and $(TAG_NAME_DEV),$(VERSION_CORE_DEV)-dev),$(GIT_COMMIT))

gow := $(shell which gow)
ifeq ($(gow),)
gow := $(shell go env GOPATH)/bin/gow
endif

golint := $(shell which golangci-lint)
ifeq ($(golint),)
golint := $(shell go env GOPATH)/bin/golangci-lint
endif

migrate := $(shell which migrate)
ifeq ($(migrate),)
migrate := $(shell go env GOPATH)/bin/migrate
endif

sqlc := $(shell which sqlc)
ifeq ($(sqlc),)
sqlc := $(shell go env GOPATH)/bin/sqlc
endif

.PHONY: bin/auth-htmx
bin/auth-htmx: $(GO_SRCS)
	go build -ldflags "-s -w -X main.version=${VERSION}" -o "$@" ./main.go

.PHONY: run
run:
	go run ./main.go

.PHONY: watch
watch: $(gow)
	$(gow) -e=go,mod,html,tmpl,env,local run ./main.go

.PHONY: lint
lint: $(golint)
	$(golint) run ./...

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: sql
sql: $(sqlc)
	$(sqlc) generate

.PHONY: migration
migration: $(migrate)
	$(migrate) create -seq -ext sql -dir db/migrations $(MIGRATION_NAME)

.PHONY: up
up: $(MIGRATIONS) $(migrate)
	$(migrate) -path database/migrations -database sqlite3://db.sqlite3?x-no-tx-wrap=true up

.PHONY: drop
drop: $(migrate)
	$(migrate) -path database/migrations -database sqlite3://db.sqlite3?x-no-tx-wrap=true drop -f

$(migrate):
	go install -tags 'sqlite3' github.com/golang-migrate/migrate/v4/cmd/migrate

$(gow):
	go install github.com/mitranim/gow@latest

$(golint):
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

$(sqlc):
	go install github.com/sqlc-dev/sqlc/cmd/sqlc

.PHONY: version
version:
	@echo VERSION_CORE=${VERSION_CORE}
	@echo VERSION_CORE_DEV=${VERSION_CORE_DEV}
	@echo VERSION=${VERSION}
