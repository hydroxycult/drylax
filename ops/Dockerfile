FROM golang:1.23-alpine AS builder
WORKDIR /app
RUN apk add --no-cache gcc musl-dev ca-certificates
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s -extldflags '-static'" -tags netgo -o drylax cmd/drylax/main.go
RUN addgroup -g 10001 drylax && adduser -D -u 10001 -G drylax drylax
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=10001:10001 /app/drylax /app/drylax
WORKDIR /app
USER 10001:10001
ENV PORT=8080 DATABASE_PATH=/data/drylax.db LOG_LEVEL=info ENVIRONMENT=production
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/app/drylax", "-health"]
ENTRYPOINT ["/app/drylax"]
