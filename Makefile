.PHONY: fmt test build run

fmt:
	gofmt -w $$(find cmd internal -name '*.go')

test:
	go test ./...

build:
	go build -o bin/server ./cmd/server
	go build -o bin/admin ./cmd/admin

run:
	go run ./cmd/server
