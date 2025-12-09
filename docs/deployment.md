# Deployment Guide

This guide covers deploying Drylax in production environments for public access.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Production Deployment](#production-deployment)
- [Security Hardening](#security-hardening)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required

- **Go 1.23+** - For building from source
- **SQLite 3** - Database engine (built-in with CGO)
- **Linux/Unix server** - For production deployment
- **Public IP or domain** - To make the service accessible

### Optional

- **Redis** - For distributed rate limiting and token tracking
- **Nginx/Caddy** - Reverse proxy with TLS termination
- **Docker** - For containerized deployment
- **systemd** - For service management

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/hydroxycult/drylax.git
cd drylax
```

### 2. Generate Secrets

```bash
# Generate 32-byte pepper for password hashing
openssl rand -hex 16

# Generate base64-encoded KMS key
openssl rand -base64 32

# Generate deletion token secret
openssl rand -base64 32
```

### 3. Configure Environment

Create `.env` from the example:

```bash
cp .env.test .env
```

Edit `.env` and set the generated secrets:

```bash
# Cryptographic secrets (REQUIRED)
PEPPER=<output from openssl rand -hex 16>
KMS_LOCAL_KEY=<output from openssl rand -base64 32>
DELETION_TOKEN_KEY=<output from openssl rand -base64 32>

# Server configuration
PORT=8080
ENVIRONMENT=production
DATABASE_PATH=/var/lib/drylax/drylax.db

# Rate limiting
RATE_LIMIT_RPM=60
RATE_LIMIT_BURST=20
```

### 4. Build and Run

```bash
# Build the binary
make build

# Run the server
./bin/drylax
```

## Installation Methods

### Method 1: Binary Deployment (Recommended)

**Build:**

```bash
make build
```

The binary will be created at `bin/drylax`.

**Install system-wide:**

```bash
sudo cp bin/drylax /usr/local/bin/
sudo chmod +x /usr/local/bin/drylax
```

**Create data directory:**

```bash
sudo mkdir -p /var/lib/drylax
sudo chown drylax:drylax /var/lib/drylax
```

### Method 2: Docker Deployment

**Build the Docker image:**

```bash
make docker-build
```

**Run with Docker:**

```bash
docker run -d \
  --name drylax \
  -p 8080:8080 \
  -v /var/lib/drylax:/data \
  -e PEPPER="your-32-byte-pepper" \
  -e KMS_LOCAL_KEY="your-base64-encoded-key" \
  -e DELETION_TOKEN_KEY="your-base64-deletion-key" \
  -e DATABASE_PATH=/data/drylax.db \
  drylax:latest
```

**Using docker-compose:**

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  drylax:
    build: ./ops
    ports:
      - "8080:8080"
    volumes:
      - drylax-data:/data
    environment:
      - PEPPER=${PEPPER}
      - KMS_LOCAL_KEY=${KMS_LOCAL_KEY}
      - DELETION_TOKEN_KEY=${DELETION_TOKEN_KEY}
      - DATABASE_PATH=/data/drylax.db
      - PORT=8080
      - ENVIRONMENT=production
      - LOG_LEVEL=info
      - RATE_LIMIT_RPM=60
      - RATE_LIMIT_BURST=20
    restart: unless-stopped
    healthcheck:
      test: ["/app/drylax", "-health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

volumes:
  drylax-data:
```

Run:

```bash
docker-compose up -d
```

### Method 3: systemd Service

Create `/etc/systemd/system/drylax.service`:

```ini
[Unit]
Description=Drylax Secure Pastebin
After=network.target

[Service]
Type=simple
User=drylax
Group=drylax
WorkingDirectory=/var/lib/drylax
EnvironmentFile=/etc/drylax/drylax.env
ExecStart=/usr/local/bin/drylax
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/drylax
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

**Create configuration directory:**

```bash
sudo mkdir -p /etc/drylax
sudo cp .env /etc/drylax/drylax.env
sudo chmod 600 /etc/drylax/drylax.env
sudo chown drylax:drylax /etc/drylax/drylax.env
```

**Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable drylax
sudo systemctl start drylax
sudo systemctl status drylax
```

## Configuration

### Essential Settings

See [configuration.md](configuration.md) for complete options. Key settings for production:

```bash
# Server
PORT=8080
ENVIRONMENT=production
ALLOWED_ORIGINS=https://paste.example.com

# Database
DATABASE_PATH=/var/lib/drylax/drylax.db
DB_MAX_OPEN_CONNS=25
DB_MAX_IDLE_CONNS=10

# Workers
HASHER_WORKER_COUNT=256
WORKER_POOL_SIZE=1000

# Rate Limiting
RATE_LIMIT_RPM=60
RATE_LIMIT_BURST=20
RATE_LIMIT_CONSERVATIVE=30
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12

# Paste Defaults
DEFAULT_PASTE_DURATION=1h
MAX_PASTE_DURATION=168h
MAX_PASTE_SIZE=524288

# Security
IP_HASH_ROTATION_INTERVAL=24h
TOKEN_REPLAY_TTL=5m
```

### Redis Configuration (Optional)

For distributed deployments or enhanced rate limiting:

```bash
REDIS_URL=redis://localhost:6379
REDIS_MAX_RETRIES=3
REDIS_POOL_SIZE=10
```

Redis is used for:
- Distributed rate limiting across multiple instances
- Deletion token replay prevention
- Future caching enhancements

## Production Deployment

### 1. Reverse Proxy Setup

#### Nginx Configuration

Create `/etc/nginx/sites-available/drylax`:

```nginx
upstream drylax {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name paste.example.com;

    # TLS configuration
    ssl_certificate /etc/letsencrypt/live/paste.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/paste.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Client limits
    client_max_body_size 1M;
    client_body_timeout 10s;
    client_header_timeout 10s;

    # Proxy configuration
    location / {
        proxy_pass http://drylax;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://drylax;
        access_log off;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name paste.example.com;
    return 301 https://$server_name$request_uri;
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/drylax /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### Caddy Configuration

Create `Caddyfile`:

```
paste.example.com {
    reverse_proxy localhost:8080
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
    }
}
```

### 2. TLS Certificate

#### Using Let's Encrypt (Certbot)

```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d paste.example.com
```

#### Using Caddy (Automatic)

Caddy automatically obtains and renews certificates. No manual setup required.

### 3. Firewall Configuration

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS (for reverse proxy)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Application port (if not using reverse proxy)
# sudo ufw allow 8080/tcp

# Enable firewall
sudo ufw enable
```

## Security Hardening

### System User

Create a dedicated user with minimal privileges:

```bash
sudo useradd -r -s /bin/false -d /var/lib/drylax drylax
sudo mkdir -p /var/lib/drylax
sudo chown drylax:drylax /var/lib/drylax
sudo chmod 700 /var/lib/drylax
```

### File Permissions

```bash
# Configuration file (contains secrets)
sudo chmod 600 /etc/drylax/drylax.env
sudo chown drylax:drylax /etc/drylax/drylax.env

# Database directory
sudo chmod 700 /var/lib/drylax
sudo chown drylax:drylax /var/lib/drylax

# Binary
sudo chmod 755 /usr/local/bin/drylax
sudo chown root:root /usr/local/bin/drylax
```

### SQLite Hardening

The application automatically enables:
- WAL (Write-Ahead Logging) mode
- Foreign key constraints
- Busy timeout handling
- Secure delete on cleanup

Database file permissions should be `600`:

```bash
sudo chmod 600 /var/lib/drylax/drylax.db
```

### Rate Limiting

Configure aggressive rate limits in production:

```bash
RATE_LIMIT_RPM=60          # 60 requests per minute
RATE_LIMIT_BURST=20        # Allow bursts up to 20
RATE_LIMIT_CONSERVATIVE=30 # Conservative limit for sensitive operations
```

Use Redis for distributed rate limiting:

```bash
REDIS_URL=redis://localhost:6379
```

### IP Privacy

Drylax hashes IP addresses before storage:

```bash
IP_HASH_ROTATION_INTERVAL=24h  # Rotate hash salt every 24 hours
```

Trusted proxies must be configured:

```bash
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

## Monitoring

### Health Checks

Drylax provides a health check endpoint:

```bash
curl http://localhost:8080/health
```

Returns HTTP 200 if healthy, with JSON response:

```json
{
  "status": "healthy",
  "database": "ok",
  "timestamp": "2025-12-10T00:00:00Z"
}
```

### Logging

Drylax uses structured JSON logging. Configure log level:

```bash
LOG_LEVEL=info  # debug, info, warn, error
```

View logs:

```bash
# systemd
sudo journalctl -u drylax -f

# Docker
docker logs -f drylax
```

### Metrics

Drylax exposes metrics on `/metrics` (Prometheus format):

- Request counts and latencies
- Rate limit hits
- Database operation metrics
- Worker pool utilization

### Performance Monitoring

Monitor these key metrics:

```bash
# Database size
du -h /var/lib/drylax/drylax.db

# Memory usage
ps aux | grep drylax

# Open connections
lsof -i :8080
```

### Automated Monitoring

Example Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'drylax'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# backup-drylax.sh

BACKUP_DIR="/var/backups/drylax"
DB_PATH="/var/lib/drylax/drylax.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/drylax_$TIMESTAMP.db'"
find "$BACKUP_DIR" -name "drylax_*.db" -mtime +7 -delete
```

Add to cron:

```bash
0 2 * * * /usr/local/bin/backup-drylax.sh
```

### Recovery

```bash
# Stop the service
sudo systemctl stop drylax

# Restore from backup
sudo cp /var/backups/drylax/drylax_20251210_020000.db /var/lib/drylax/drylax.db
sudo chown drylax:drylax /var/lib/drylax/drylax.db
sudo chmod 600 /var/lib/drylax/drylax.db

# Start the service
sudo systemctl start drylax
```

## Troubleshooting

### Common Issues

#### Database Locked

**Symptom:** Error "database is locked"

**Solution:** Check for long-running transactions or multiple processes accessing the database. WAL mode should prevent this in most cases.

```bash
# Check for locks
lsof /var/lib/drylax/drylax.db

# Force WAL checkpoint
sqlite3 /var/lib/drylax/drylax.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

#### High Memory Usage

**Symptom:** Increasing memory consumption

**Solution:** Reduce worker counts or cache size:

```bash
HASHER_WORKER_COUNT=128  # Reduce from 256
LRU_CACHE_SIZE=500       # Reduce from 1000
```

#### Rate Limit Errors

**Symptom:** Users getting 429 Too Many Requests

**Solution:** Adjust rate limits or add Redis:

```bash
RATE_LIMIT_RPM=120       # Increase limit
REDIS_URL=redis://localhost:6379  # Enable distributed limiting
```

#### KMS Errors

**Symptom:** "no KMS providers available"

**Solution:** Ensure KMS_LOCAL_KEY is set:

```bash
# Check environment
sudo -u drylax env | grep KMS_LOCAL_KEY

# Generate new key if missing
openssl rand -base64 32
```

### Debug Mode

Enable debug logging:

```bash
LOG_LEVEL=debug
ENVIRONMENT=development
```

Restart the service and check logs:

```bash
sudo systemctl restart drylax
sudo journalctl -u drylax -f
```

### Performance Testing

Run stress tests:

```bash
# Quick stress test
make stress-quick

# Full stress test suite
make stress-all

# Security tests
make stress-security
```

## Scaling

### Horizontal Scaling

Drylax can run multiple instances behind a load balancer when using Redis:

1. **Enable Redis** for distributed rate limiting
2. **Use external Redis** (not localhost)
3. **Configure shared database** (or use read replicas with SQLite replication)
4. **Set up load balancer** (Nginx, HAProxy, or cloud LB)

Example load balancer config:

```nginx
upstream drylax_cluster {
    least_conn;
    server 10.0.1.10:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8080 max_fails=3 fail_timeout=30s;
}
```

### Vertical Scaling

Increase worker counts based on CPU cores:

```bash
HASHER_WORKER_COUNT=$(nproc)
WORKER_POOL_SIZE=$(($(nproc) * 100))
```

## Maintenance

### Update Process

```bash
# Pull latest code
git pull origin main

# Build new binary
make build

# Stop service
sudo systemctl stop drylax

# Update binary
sudo cp bin/drylax /usr/local/bin/

# Start service
sudo systemctl start drylax
```

### Database Maintenance

```bash
# Vacuum database (reclaim space)
sqlite3 /var/lib/drylax/drylax.db "VACUUM;"

# Analyze for query optimization
sqlite3 /var/lib/drylax/drylax.db "ANALYZE;"

# Check integrity
sqlite3 /var/lib/drylax/drylax.db "PRAGMA integrity_check;"
```

### Log Rotation

Create `/etc/logrotate.d/drylax`:

```
/var/log/drylax/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 drylax drylax
    sharedscripts
    postrotate
        systemctl reload drylax
    endscript
}
```

## Additional Resources

- [Configuration Guide](configuration.md) - Complete configuration reference
- [Security Documentation](security.md) - Security architecture and threat model
- [API Documentation](api.md) - HTTP API reference
- [Architecture Overview](architecture.md) - System design and components

## Support

For issues and questions:
- GitHub Issues: https://github.com/hydroxycult/drylax/issues
- Security issues: See [security.md](security.md#reporting-vulnerabilities)
