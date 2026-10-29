GO ?= go

.PHONY: build test check fmt clean
build:
	$(GO) build -trimpath -buildvcs=false -o bin/agent-doctor ./cmd/agent-doctor

test:
	$(GO) test -race ./...

check:
	$(GO) vet ./...
	$(GO) test -race ./...
	@test -z "$$($(GO) fmt ./...)" || (echo "Go formatting changed files; review and rerun"; exit 1)

fmt:
	$(GO) fmt ./...

clean:
	$(GO) clean ./...
