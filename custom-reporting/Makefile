require-%:
	@ if [ "$(shell command -v ${*} 2> /dev/null)" = "" ]; then \
		echo "[$*] not found"; \
		exit 1; \
	fi

lint-project:
	@echo ">> checking code format"
	@fmtRes=$$(gofmt -l .); \
	if [ ! -z "$${fmtRes}" ]; then \
	  echo "format check failed"; echo "$${fmtRes}"; \
	  exit 1; \
	fi

.PHONY: test
test: require-go
	go test -v ./...  -tags ${TAGS}

.PHONY: lint
lint: require-go lint-project

.PHONY: fmt
fmt:
	@gofmt -l -w $(shell find . -type f -name '*.go' -not -path "./vendor/*")
	@echo "Formatted all project go files"

.PHONY: build-linux
build-linux: require-go
	mkdir -p build
	env CGO_ENABLED=0 env GOOS=linux GOARCH=amd64 go build -o ./build ./...

.PHONY: build-mac
build-mac: require-go
	mkdir -p build
	env CGO_ENABLED=0 env GOOS=darwin GOARCH=amd64 go build -o ./build ./...

.PHONY: build-windows
build-windows: require-go
	mkdir -p build
	env CGO_ENABLED=0 env GOOS=windows GOARCH=amd64 go build -o ./build ./...

.PHONY: build-local
build-local: require-go
	mkdir -p build
	env CGO_ENABLED=0 go build -o ./build ./...