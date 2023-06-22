VERSION 0.6
FROM golang:1.20
WORKDIR /vault-acme

vault:
   FROM hashicorp/vault:1.14 
   SAVE ARTIFACT /bin/vault

deps:
    RUN go install github.com/letsencrypt/pebble/...@HEAD
    COPY --dir ./acme/sidecar/ ./acme/sidecar
    COPY go.mod go.sum ./
    RUN go mod download
    SAVE ARTIFACT go.mod AS LOCAL go.mod
    SAVE ARTIFACT go.sum AS LOCAL go.sum
    SAVE ARTIFACT ~/go/bin/pebble

build:
    FROM +deps
    RUN mkdir ./bin
    COPY --dir ./cmd .
    COPY --dir ./acme .

    RUN CGO_ENABLED=0 go build -o bin ./...
    SAVE ARTIFACT bin/acme /acme AS LOCAL bin/acme
    SAVE ARTIFACT bin/sidecar /sidecar AS LOCAL bin/sidecar

test:
    FROM +deps
    COPY --dir ./test .
    COPY --dir ./cmd .
    COPY --dir ./acme .
    RUN CGO_ENABLED=0 go test ./acme

testacc:
    FROM +deps
    ENV PATH=$PATH:~/go/bin
    COPY +vault/vault /usr/bin
    COPY +build/acme bin/acme
    COPY --dir ./test .
    RUN CGO_ENABLED=0 go test ./test

release:
    FROM +deps
    # ARG GOX_OS='linux darwin windows freebsd openbsd solaris'
    ARG GOX_OS='linux'
    RUN go install github.com/mitchellh/gox@HEAD
    RUN apt update && apt install zip -y
    COPY --dir ./cmd .
    COPY --dir ./acme .
    RUN CGO_ENABLED=0 gox -os="$GOX_OS" -arch='amd64' -osarch='!darwin/arm !darwin/386' -output 'bin/{{.OS}}_{{.Arch}}/acme-plugin' ./cmd/acme
    RUN CGO_ENABLED=0 gox -os="$GOX_OS" -arch='amd64' -osarch='!darwin/arm !darwin/386' -output 'bin/{{.OS}}_{{.Arch}}/sidecar' ./cmd/sidecar
    RUN for arch in ./bin/*; do zip --junk-paths $arch.zip $arch/*; done
    RUN sha256sum ./bin/*.zip > ./bin/vault-acme_SHA256SUMS

    SAVE ARTIFACT ./bin /release AS LOCAL ./bin
