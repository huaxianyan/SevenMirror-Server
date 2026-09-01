.PHONY: fmt test build run

fmt:
	gofmt -w $$(find cmd internal -name '*.go')

test:
	go test ./...

build:
	go build -o bin/server ./cmd/server
	go build -o bin/admin ./cmd/admin
	go build -o bin/admin-web ./cmd/admin-web

run:
	go run ./cmd/server
