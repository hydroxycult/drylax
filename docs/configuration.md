# Configuration Guide

This document explains all configuration options for Drylax.

## Configuration File

Drylax uses environment variables loaded from a `.env` file. Copy `.env.example` to `.env` and customize the values.

## Required Configuration

These settings must be configured before running Drylax:

### PEPPER
**Type:** String (exactly 32 bytes)  
**Required:** Yes  
**Example:** `PEPPER=0123456789ABCDEF0123456789ABCDEF`

A secret key used in password hashing. Must be exactly 32 bytes. Generate using:
```bash
openssl rand -hex 16
```

**Security:** Never commit this value to version control. Change it will invalidate all existing deletion tokens.

### KMS_LOCAL_KEY
**Type:** Base64-encoded string (32 bytes before encoding)  
**Required:** Yes (if not using Vault/AWS KMS)  
**Example:** `KMS_LOCAL_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`

Encryption key for protecting paste content. Generate using:
```bash
openssl rand -base64 32
```

**Security:** Never commit this value. Changing it will make existing pastes unreadable.

## Server Configuration

### PORT
**Type:** Integer  
**Default:** 8080  
**Example:** `PORT=8080`

The port number the HTTP server listens on.

### ENVIRONMENT
**Type:** String  
**Values:** `production`, `development`, `test`  
**Default:** `production`  
**Example:** `ENVIRONMENT=production`

The runtime environment. Affects logging verbosity and some security defaults.

### LOG_LEVEL
**Type:** String  
**Values:** `debug`, `info`, `warn`, `error`  
**Default:** `info`  
**Example:** `LOG_LEVEL=info`

Minimum log level to output. Use `debug` for troubleshooting, `error` for production.

## Database Configuration

### DATABASE_PATH
**Type:** File path  
**Default:** `./drylax.db`  
**Example:** `DATABASE_PATH=/var/lib/drylax/pastes.db`

Path to the SQLite database file. Directory must be writable.

### CONTEXT_TIMEOUT
**Type:** Duration  
**Default:** `60s`  
**Example:** `CONTEXT_TIMEOUT=30s`

Maximum time for database operations before timeout.

### DB_MAX_OPEN_CONNS
**Type:** Integer  
**Default:** `25`  
**Example:** `DB_MAX_OPEN_CONNS=50`

Maximum number of open database connections. Increase for high traffic.

### DB_MAX_IDLE_CONNS
**Type:** Integer  
**Default:** `5`  
**Example:** `DB_MAX_IDLE_CONNS=10`

Maximum number of idle connections to keep open.

### DB_QUERY_TIMEOUT
**Type:** Duration  
**Default:** `10s`  
**Example:** `DB_QUERY_TIMEOUT=5s`

Maximum time for individual database queries.

## Worker Pool Configuration

### HASHER_WORKER_COUNT
**Type:** Integer  
**Default:** `128`  
**Example:** `HASHER_WORKER_COUNT=256`

Number of worker goroutines for password hashing. Increase if you have many CPU cores and handle high traffic.

**Testing Note:** Automated tests temporarily use 256 workers to handle concurrent test load.

### WORKER_POOL_SIZE
**Type:** Integer  
**Default:** `1000`  
**Example:** `WORKER_POOL_SIZE=2000`

Size of the general worker pool. Increase for high concurrency.

### MAX_WORKER_LOAD
**Type:** Integer  
**Default:** `5000`  
**Example:** `MAX_WORKER_LOAD=10000`

Maximum number of pending tasks before rejecting new requests.

## Argon2 Password Hashing

### ARGON2_TIME
**Type:** Integer  
**Default:** `4`  
**Example:** `ARGON2_TIME=4`

Number of iterations for Argon2 hashing. Higher values are more secure but slower. Minimum: 4.

**Testing Note:** Automated tests temporarily use 1 iteration for faster execution while still validating functionality.

### ARGON2_MEMORY
**Type:** Integer (KiB)  
**Default:** `65536` (64 MB)  
**Example:** `ARGON2_MEMORY=131072`

Memory usage for Argon2 in KiB. Higher values are more secure but require more RAM. Minimum: 131072 (128 MB).

**Testing Note:** Automated tests temporarily use 8192 (8 MB) to reduce memory footprint in CI environments.

### ARGON2_PARALLELISM
**Type:** Integer  
**Default:** `4`  
**Example:** `ARGON2_PARALLELISM=8`

Number of parallel threads for Argon2. Should match available CPU cores.

### ARGON2_KEYLEN
**Type:** Integer  
**Default:** `32`  
**Example:** `ARGON2_KEYLEN=32`

Output length of Argon2 hash in bytes. Do not change unless you know what you're doing.

## Rate Limiting

### RATE_LIMIT_RPM
**Type:** Integer  
**Default:** `60`  
**Example:** `RATE_LIMIT_RPM=120`

Maximum requests per minute per IP address.

### RATE_LIMIT_BURST
**Type:** Integer  
**Default:** `10`  
**Example:** `RATE_LIMIT_BURST=20`

Maximum burst size for rate limiting (number of requests allowed in quick succession).

### RATE_LIMIT_CONSERVATIVE
**Type:** Integer  
**Default:** `30`  
**Example:** `RATE_LIMIT_CONSERVATIVE=60`

Conservative rate limit applied to certain operations.

## Cache Configuration

### LRU_CACHE_SIZE
**Type:** Integer  
**Default:** `1000`  
**Example:** `LRU_CACHE_SIZE=10000`

Number of paste entries to keep in memory cache. Increase for better performance with high traffic.

## Paste Settings

### MAX_PASTE_SIZE
**Type:** Integer (bytes)  
**Default:** `10485760` (10 MB)  
**Example:** `MAX_PASTE_SIZE=5242880`

Maximum allowed paste size in bytes.

### DELETION_TOKEN_EXPIRY
**Type:** Duration  
**Default:** `24h`  
**Example:** `DELETION_TOKEN_EXPIRY=48h`

How long deletion tokens remain valid after paste creation.

### TOKEN_REPLAY_TTL
**Type:** Duration  
**Default:** `1h`  
**Example:** `TOKEN_REPLAY_TTL=2h`

Time window for replay attack detection on deletion tokens.

### TTL_PRESETS
**Type:** Comma-separated durations  
**Default:** `5m,1h,24h,168h`  
**Example:** `TTL_PRESETS=30m,2h,12h,24h,72h`

Available expiration durations users can select. Format: `Xm` (minutes), `Xh` (hours).

## KMS Configuration

### KMS Provider Selection

Drylax supports multiple Key Management Service providers. Configure one of:

**Local Key (Simplest)**
```bash
KMS_LOCAL_KEY=<base64-encoded-key>
```

**HashiCorp Vault**
```bash
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=<your-token>
VAULT_MOUNT=transit
VAULT_KEY_NAME=drylax-dek
```

**AWS KMS**
```bash
AWS_REGION=us-east-1
AWS_KMS_KEY_ID=<key-arn>
# AWS credentials via environment or IAM role
```

### KMS_FAIL_CLOSED
**Type:** Boolean  
**Default:** `true`  
**Example:** `KMS_FAIL_CLOSED=true`

If true, server refuses to start if KMS is unavailable. Set to false only for development.

## Security Best Practices

1. **Never commit .env to version control**
   - Add `.env` to `.gitignore`
   - Use `.env.example` as template

2. **Generate strong random keys**
   - Use `openssl rand` commands provided
   - Never reuse keys across environments

3. **Rotate keys periodically**
   - Plan for key rotation (requires data migration)
   - Keep old keys until all data using them expires

4. **Use production KMS in production**
   - Local keys are convenient but less secure
   - Use Vault or AWS KMS for production deployments

5. **Set appropriate rate limits**
   - Adjust based on expected traffic
   - Monitor for abuse patterns

## Performance Tuning

### For High Traffic

- Increase `HASHER_WORKER_COUNT` (match CPU cores)
- Increase `LRU_CACHE_SIZE` (more memory usage)
- Increase `DB_MAX_OPEN_CONNS`
- Consider Redis for distributed caching

### For Low Memory

- Decrease `LRU_CACHE_SIZE`
- Decrease `ARGON2_MEMORY` (but keep above minimum)
- Decrease `WORKER_POOL_SIZE`

### For Better Security

- Increase `ARGON2_TIME` and `ARGON2_MEMORY`
- Enable stricter rate limits
- Use production KMS provider
- Set `KMS_FAIL_CLOSED=true`

## Validation

Configuration is validated at startup. The server will not start if:

- Required values are missing
- Values are below minimum thresholds
- Values have invalid formats
- KMS is unavailable (when `KMS_FAIL_CLOSED=true`)

Check logs for specific validation errors.
