GOX_OS := linux darwin windows freebsd openbsd solaris
TEST_ARGS :=

.PHONY: build
build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -o bin ./...

.PHONY: fmt
fmt:
	gofmt -w acme

.PHONY: clean
clean:
	rm -rf build/*

.PHONY: test
test:
	@CGO_ENABLED=0 go test $(TEST_ARGS) ./acme

.PHONY: testacc
testacc: build
	@CGO_ENABLED=0 go test $(TEST_ARGS) ./test

.PHONY: website
website:
	$(MAKE) -C website build

.PHONY: preview
preview:
	$(MAKE) -C website website

.PHONY: all
all:
	CGO_ENABLED=0 gox -os='$(GOX_OS)' -arch='386 amd64 arm arm64' -osarch='!darwin/arm !darwin/386' -output 'bin/{{.OS}}_{{.Arch}}/acme-plugin' ./cmd/acme
	CGO_ENABLED=0 gox -os='$(GOX_OS)' -arch='386 amd64 arm arm64' -osarch='!darwin/arm !darwin/386' -output 'bin/{{.OS}}_{{.Arch}}/sidecar' ./cmd/sidecar

.PHONY: archives
archives: all
	for arch in ./bin/*; do zip --junk-paths $$arch.zip $$arch/*; done
	sha256sum ./bin/*.zip > ./build/vault-acme_SHA256SUMS
