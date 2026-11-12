BINARY := chezmoi-sops
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build test lint fmt vet clean install

all: lint test build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/chezmoi-sops

test:
	go test ./...

lint:
	go vet ./...
	gofmt -l . | (! grep .)

fmt:
	gofmt -w .

install:
	go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/chezmoi-sops

clean:
	rm -rf $(BINARY) dist/
