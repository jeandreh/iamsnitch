GOOS := $(shell uname -s | tr "[A-Z]" "[a-z]")

all: build test

test: generate
	go test ./... -coverprofile .cover.out

internal/mocks:
	go install github.com/golang/mock/mockgen@v1.6.0
	go generate ./...

generate: internal/mocks

coverage: test
	@go tool cover -html .cover.out

build: generate
	@mkdir -p bin
	CGO_ENABLED="1" GOARCH="amd64" go build -o "bin/iamsnitch-$(GOOS)-amd64"

clean: 
	rm -f .snitch.db
	rm -f .cover.out
	rm -rf bin
	rm -rf internal/mocks

docker-%:
	docker-compose run $*

x-build:
	@mkdir -p bin
	docker pull karalabe/xgo-latest
	go get github.com/karalabe/xgo
	xgo --targets=linux/amd64,darwin/amd64 --dest bin github.com/jeandreh/iamsnitch