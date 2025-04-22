FROM golang:1.23-alpine AS builder

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app
COPY go.mod go.sum ./
RUN apk update && apk add --no-cache git && go mod download && apk del git
COPY . .
RUN go build -o auth ./cmd/auth

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/auth .
EXPOSE 8080
CMD ["./auth"]