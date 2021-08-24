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
	@echo "Cross-compiling iamsnitch for platforms linux/amd64 and darwin/amd64"
	@docker run --rm \
		-v ${PWD}/bin:/build \
		-e OUT=iamsnitch-xgo \
		-e TARGETS="linux/amd64 darwin-10.10/amd64" \
		karalabe/xgo-latest:latest github.com/jeandreh/iamsnitch