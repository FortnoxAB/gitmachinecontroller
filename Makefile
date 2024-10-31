.PHONY:	test imports
SHELL := /bin/bash

test: imports
	go test -v ./...

imports: SHELL:=/bin/bash
imports:
	go install golang.org/x/tools/cmd/goimports@latest
	ASD=$$(goimports -l . 2>&1); test -z "$$ASD" || (echo "Code is not formatted correctly according to goimports!  $$ASD" && exit 1)

