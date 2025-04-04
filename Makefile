.PHONY:	test imports
SHELL := /bin/bash

VERSION?=0.0.1-local

IMAGE = quay.io/fortnox/gitmachinecontroller

build:
	CGO_ENABLED=0 GOOS=linux go build -o gmc ./cmd/gmc

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

