.PHONY: init dep build deploy

init:
	go get -u github.com/golang/dep/cmd/dep

dep:
	dep ensure -v

build-local:
	go build -o bin/cloud-iam-policy-checker ./cmd/local
