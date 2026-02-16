FROM golang:trixie

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source files
COPY ./cmd ./cmd
COPY ./public ./public
COPY ./internal ./internal

# Build runnable binary from source
RUN go build -o /bin/salpa-server ./cmd/server.go
