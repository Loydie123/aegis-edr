FROM golang:1.22 AS builder
RUN apt-get update && apt-get install -y libyara-dev pkg-config gcc
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

FROM debian:stable-slim
RUN apt-get update && apt-get install -y libyara4 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/bin/aegis /usr/local/bin/aegis
COPY --from=builder /app/bin/aegisd /usr/local/bin/aegisd
COPY configs/ /etc/aegis/
ENTRYPOINT ["/usr/local/bin/aegisd"]
