.PHONY: test build

test:
	go test ./...

build: test
	docker build --tag lattots/salpa .
