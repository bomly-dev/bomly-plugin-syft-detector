BINARY ?= bomly-plugin-syft-detector

.PHONY: test build

test:
	go test ./...

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)
