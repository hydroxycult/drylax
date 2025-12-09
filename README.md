# Drylax - Secure Ephemeral Paste Service

Drylax is a secure, self-hosted pastebin for sharing temporary text with strong encryption and automatic expiration.

## What Does This Do?

Drylax allows you to:
- Share text snippets that automatically delete after a set time
- Encrypt all content with AES-256-GCM encryption
- Control who can delete pastes using secure tokens
- Run your own private pastebin server

**Important:** "Self-hosted" means you run the server yourself. When run on `localhost`, it's only accessible from your computer. To share pastes with others, you must deploy Drylax on a server with a public IP or domain.

See the [Deployment Guide](docs/deployment.md) for instructions on making Drylax publicly accessible.

## Quick Start for Beginners

### What You'll Need

Before starting, you need to have these programs installed on your computer:

1. **Go (version 1.24 or newer)**
   - Go to https://go.dev/dl/
   - Download the installer for your operating system
   - Run the installer
   - To verify: Open your terminal/command prompt and type `go version`

2. **Git**
   - Go to https://git-scm.com/downloads
   - Download the installer for your operating system
   - Run the installer with default settings
   - To verify: Open your terminal/command prompt and type `git --version`

3. **SQLite** (usually already installed)
   - On Windows: Download from https://www.sqlite.org/download.html
   - On Mac: Already included
   - On Linux: Run `sudo apt-get install sqlite3` (Ubuntu/Debian)

### Installation Steps

**Step 1: Download the Code**

Open your terminal (Mac/Linux) or Command Prompt (Windows) and run:

```bash
git clone https://github.com/hydroxycult/drylax.git
cd drylax
```

**Step 2: Set Up Configuration**

Copy the example configuration file:

```bash
cp .env.example .env
```

Edit the `.env` file with a text editor. You must change these values:

- `PEPPER`: Replace with a random 32-character string
- `KMS_LOCAL_KEY`: Replace with a random base64-encoded 32-byte key

To generate random values, you can use:

```bash
# Generate PEPPER (any 32 characters)
openssl rand -hex 16

# Generate KMS_LOCAL_KEY (base64 encoded)
openssl rand -base64 32
```

**Step 3: Install Dependencies**

```bash
go mod download
```

**Step 4: Run the Server**

```bash
go run cmd/drylax/main.go
```

You should see output indicating the server started. The API will be available at `http://localhost:8080`.

### Using the API

**Create a Paste**

```bash
curl -X POST http://localhost:8080/pastes \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello, World!", "duration": "1h"}'
```

This returns a paste ID and deletion token.

**Retrieve a Paste**

```bash
curl http://localhost:8080/pastes/{paste-id}
```

**Delete a Paste**

```bash
curl -X DELETE http://localhost:8080/pastes/{paste-id} \
  -H "X-Deletion-Token: {deletion-token}"
```

## Configuration

All settings are in the `.env` file. Key settings include:

- `PORT`: Which port the server listens on (default: 8080)
- `DATABASE_PATH`: Where to store the SQLite database
- `MAX_PASTE_SIZE`: Maximum size of pastes in bytes
- `ARGON2_TIME`: Password hashing iterations (higher = more secure but slower)

See `docs/configuration.md` for complete details.

## Security Features

- **End-to-End Encryption**: All paste content is encrypted at rest
- **Secure Token Generation**: Deletion tokens use cryptographically secure random generation
- **Rate Limiting**: Protection against abuse and DoS attacks
- **SQL Injection Protection**: Parameterized queries throughout
- **IP Hashing**: Client IPs hashed before storage for privacy

## Testing

### Running Tests

To run all tests:

```bash
go test ./...
```

To run specific test suites:

```bash
# Unit tests
go test ./pkg/...
go test ./svc/...

# Integration tests
go test ./test/...
```

Test results are documented [here](results/).

## Deployment

For production deployment:

1. Use a reverse proxy (nginx/Caddy) for HTTPS
2. Set up proper firewall rules
3. Use a production-grade KMS (Vault/AWS KMS) instead of local keys
4. Enable all security features in `.env`
5. Set appropriate rate limits

See [this](docs/deployment.md) for detailed instructions.

## Architecture

Drylax uses a layered architecture:

- **API Layer**: HTTP handlers and routing
- **Service Layer**: Business logic
- **Database Layer**: Data persistence (SQLite)
- **KMS Layer**: Encryption key management
- **Cache Layer**: LRU cache for performance

See [this](docs/architecture.md) for technical details.

## Troubleshooting

**Server won't start**
- Check that port 8080 is not already in use
- Verify `.env` file exists and has correct values
- Check logs for specific error messages

**Database errors**
- Ensure write permissions in the directory where database is stored
- Check disk space availability

**Performance issues**
- Increase `HASHER_WORKER_COUNT` if CPU has many cores
- Adjust `LRU_CACHE_SIZE` based on available memory
- Consider using Redis for caching in production

## API Documentation

Complete API reference is available [here](docs/api.md).

## License

See LICENSE file for details.

## Support

For issues or questions, please open an issue on GitHub.
