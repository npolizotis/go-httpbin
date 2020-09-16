.PHONY: clean deploy deps image imagepush lint run stagedeploy test testci testcover

# The version that will be used in docker tags (e.g. to push a
# go-httpbin:latest image use `make imagepush VERSION=latest)`
VERSION        ?= $(shell git rev-parse --short HEAD)

# Override these values to deploy to a different App Engine project
GCLOUD_PROJECT ?= httpbingo
GCLOUD_ACCOUNT ?= mccutchen@gmail.com

# Built binaries will be placed here
DIST_PATH  	  ?= dist

# Default flags used by the test, testci, testcover targets
COVERAGE_PATH ?= coverage.txt
COVERAGE_ARGS ?= -covermode=atomic -coverprofile=$(COVERAGE_PATH)
TEST_ARGS     ?= -race

# Tool dependencies
TOOL_BIN_DIR     ?= $(shell go env GOPATH)/bin
TOOL_GOLINT      := $(TOOL_BIN_DIR)/golint
TOOL_STATICCHECK := $(TOOL_BIN_DIR)/staticcheck

GO_SOURCES = $(wildcard **/*.go) $(wildcard **/*/*.go)

GENERATED_ASSETS_PATH := httpbin/assets/assets_vfsdata.go

# =============================================================================
# build
# =============================================================================
.PHONY: build
build: $(DIST_PATH)/go-httpbin

$(DIST_PATH)/go-httpbin : assets $(GO_SOURCES)
	mkdir -p $(DIST_PATH)
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(DIST_PATH)/go-httpbin ./cmd/go-httpbin

.PHONY: assets 
assets: $(GENERATED_ASSETS_PATH)

buildtests:
	CGO_ENABLED=0 go test -ldflags="-s -w" -v -c -o $(DIST_PATH)/go-httpbin.test ./httpbin

clean:
	rm -rf $(DIST_PATH) $(COVERAGE_PATH) $(GENERATED_ASSETS_PATH)

$(GENERATED_ASSETS_PATH):  static/*
	go run -tags=dev  cmd/assets_generate.go && mv -f  assets_vfsdata.go httpbin/assets/


# =============================================================================
# test & lint
# =============================================================================
test:
	go test $(TEST_ARGS) ./...

# Test command to run for continuous integration, which includes code coverage
# based on codecov.io's documentation:
# https://github.com/codecov/example-go/blob/b85638743b972bd0bd2af63421fe513c6f968930/README.md
testci:
	go test $(TEST_ARGS) $(COVERAGE_ARGS) ./...

testcover: testci
	go tool cover -html=$(COVERAGE_PATH)

lint: $(TOOL_GOLINT) $(TOOL_STATICCHECK)
	test -z "$$(gofmt -d -s -e .)" || (echo "Error: gofmt failed"; gofmt -d -s -e . ; exit 1)
	go vet ./...
	$(TOOL_GOLINT) -set_exit_status ./...
	$(TOOL_STATICCHECK) ./...


# =============================================================================
# deploy & run locally
# =============================================================================
deploy: build
	gcloud --account=$(GCLOUD_ACCOUNT) app deploy --quiet --project=$(GCLOUD_PROJECT) --version=$(VERSION) --promote

stagedeploy: build
	gcloud --account=$(GCLOUD_ACCOUNT) app deploy --quiet --project=$(GCLOUD_PROJECT) --version=$(VERSION) --no-promote

run: build
	$(DIST_PATH)/go-httpbin


# =============================================================================
# docker images
# =============================================================================
image:
	docker build -t mccutchen/go-httpbin:$(VERSION) .

imagepush: image
	docker push mccutchen/go-httpbin:$(VERSION)


# =============================================================================
# dependencies
#
# Deps are installed outside of working dir to avoid polluting go modules
# =============================================================================
deps:  $(TOOL_GOLINT) $(TOOL_STATICCHECK)

$(TOOL_GOLINT):
	cd /tmp && go get -u golang.org/x/lint/golint

$(TOOL_STATICCHECK):
	cd /tmp && go get -u honnef.co/go/tools/cmd/staticcheck
