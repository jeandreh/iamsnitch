OS_LIST:=linux darwin

all: build test

test: generate
	go test ./... -coverprofile .cover.out

internal/mocks:
	go generate ./...

generate: internal/mocks

coverage: test
	@go tool cover -html .cover.out

build: generate
	@mkdir -p bin
	$(foreach os, $(OS_LIST), \
		$(shell GOARCH=amd64 GOOS=$(os) go build -o bin/iamsnitch-$(os)-amd64) \
	)
	@echo "artifacts written to ./bin"
	@ls bin

clean: 
	rm -f .snitch.db
	rm -f .cover.out
	rm -rf bin
	rm -rf internal/mocks

docker-%:
	docker-compose run $*