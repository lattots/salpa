.PHONY: test build

test:
	go test ./internal/...
	go test ./public/...

build: test
	docker build --tag lattots/salpa .
