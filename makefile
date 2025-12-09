.PHONY: run test build clean docker-build lint test-coverage install-tools help
run:
\t@ENVIRONMENT=development LOG_LEVEL=debug go run cmd/drylax/main.go
test:
\t@go test -v -race ./...
test-coverage:
\t@go test -v -race -coverprofile=coverage.out ./...
\t@go tool cover -html=coverage.out -o coverage.html
\t@echo "Coverage report generated: coverage.html"
build:
\t@CGO_ENABLED=1 go build -o bin/drylax cmd/drylax/main.go
clean:
\t@rm -rf bin/ coverage.out coverage.html
docker-build:
\t@docker build -t drylax .
docker-run:
\t@docker run -p 8080:8080 -v $(PWD)/data:/data drylax
lint:
\t@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
\t@golangci-lint run ./...
security:
\t@echo "Running security scans..."
\t@which gosec > /dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
\t@gosec -fmt=json -out=gosec-report.json ./...
\t@echo "Running vulnerability check..."
\t@which govulncheck > /dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest
\t@govulncheck ./...
fuzz:
\t@echo "Running fuzz tests..."
\t@go test -fuzz=FuzzCreatePaste -fuzztime=30s ./test/
\t@go test -run=TestIDGenerationProperty -count=1000 ./test/
\t@go test -run=TestRateLimiterProperty ./test/
install-tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "Tools installed successfully"

# Stress Testing Targets
stress-quick:
	@echo "Running quick stress tests (5 minutes)..."
	@go test ./test -short -v -timeout=10m

stress-load:
	@echo "Running load tests..."
	@go test ./test -run=TestLoad -v -timeout=30m

stress-security:
	@echo "Running security adversarial tests..."
	@go test ./test -run=TestSecurity -v -timeout=20m

stress-chaos:
	@echo "Running chaos engineering tests..."
	@go test ./test -run=TestChaos -v -timeout=15m

stress-concurrency:
	@echo "Running concurrency tests with race detector..."
	@go test ./test -run=TestConcurrency -race -count=100 -v -timeout=30m

stress-all:
	@echo "Running FULL stress test suite (45+ minutes)..."
	@go test ./test -v -timeout=60m -coverprofile=stress_coverage.out
	@go tool cover -html=stress_coverage.out -o stress_coverage.html
	@echo "Stress test coverage: stress_coverage.html"

stress-race:
	@echo "Running all tests with race detector..."
	@go test ./test -race -v -timeout=30m

help:
	@echo "Available targets:"
	@echo "  run              - Run the application in development mode"
	@echo "  test             - Run tests"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  build            - Build the binary"
	@echo "  clean            - Remove build artifacts"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-run       - Run Docker container"
	@echo "  lint             - Run linter"
	@echo "  security         - Run security scans"
	@echo "  fuzz             - Run fuzz tests"
	@echo "  install-tools    - Install development tools"

	@echo "  stress-quick     - Quick stress tests (5 min)"
	@echo "  stress-load      - Load/performance tests only"
	@echo "  stress-security  - Security adversarial tests only"
	@echo "  stress-chaos     - Chaos engineering tests only"
	@echo "  stress-concurrency - Concurrency + race tests"
	@echo "  stress-all       - Full stress test suite (45+ min)"
	@echo "  stress-race      - All tests with race detector"
	@echo "  help             - Show this help message"
