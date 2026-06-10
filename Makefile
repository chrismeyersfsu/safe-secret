.PHONY: build test lint vet clean

BINARY := safe-secret

build:
	go build -o $(BINARY) .

test:
	go test -race -count=1 ./...

lint: vet
	golangci-lint run ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
