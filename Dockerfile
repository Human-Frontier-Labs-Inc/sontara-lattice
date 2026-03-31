FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sontara-lattice .

FROM alpine:latest
RUN apk add --no-cache ca-certificates openssh-client
COPY --from=builder /sontara-lattice /usr/local/bin/claude-peers
ENTRYPOINT ["claude-peers"]
