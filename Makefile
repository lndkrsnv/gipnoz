.PHONY: all build client server proto clean vet lint test ci

BINARY_DIR := bin

all: proto build

build: client server

client:
	go build -o $(BINARY_DIR)/gipnoz-client ./cmd/gipnoz-client

server:
	go build -o $(BINARY_DIR)/gipnoz-server ./cmd/gipnoz-server

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		internal/proto/gipnoz.proto

test:
	go test ./...

ci: vet test build

clean:
	rm -rf $(BINARY_DIR)

vet:
	go vet ./...

lint:
	golangci-lint run ./...
