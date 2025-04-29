.PHONY:	test imports
SHELL := /bin/bash

VERSION?=$(shell git rev-parse HEAD )

IMAGE = quay.io/fortnox/gitmachinecontroller

build:
	CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.BuildTime=$(shell date +%FT%T%z) -X main.Version=${VERSION} -X main.BuildCommit=$(shell git rev-parse HEAD)" -o gmc ./cmd/gmc
	sha256sum gmc | awk '{print $$1}' > binary-checksum

docker: build
	docker build --pull --rm -t $(IMAGE):$(VERSION) .

push: docker
	docker push $(IMAGE):$(VERSION)

test: imports
	go test -v ./...

imports: SHELL:=/bin/bash
imports:
	go install golang.org/x/tools/cmd/goimports@latest
	ASD=$$(goimports -l . 2>&1); test -z "$$ASD" || (echo "Code is not formatted correctly according to goimports!  $$ASD" && exit 1)

