FROM golang:1.23-alpine AS builder

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

RUN apk update && apk add --no-cache git

WORKDIR /app
COPY go.mod ./
RUN go mod download
RUN apk del git 
COPY . .
RUN go build -o auth ./cmd/auth

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/auth .
EXPOSE 8080
CMD ["./auth"]