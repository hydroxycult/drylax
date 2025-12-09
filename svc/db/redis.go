package db

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"drylax/cfg"
	"drylax/pkg/domain"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"os"
	"time"
)

type Redis struct {
	client  *redis.Client
	timeout time.Duration
}

func NewRedis(url string, cfg *cfg.Cfg) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, errors.Wrap(err, "parse redis url")
	}
	opt.PoolSize = 50
	opt.MinIdleConns = 10
	opt.PoolTimeout = 4 * time.Second
	opt.ConnMaxIdleTime = 5 * time.Minute
	opt.MaxRetries = 3
	opt.MinRetryBackoff = 8 * time.Millisecond
	opt.MaxRetryBackoff = 512 * time.Millisecond
	if cfg.RedisTLS {
		tlsConfig, err := buildRedisTLSConfig()
		if err != nil {
			return nil, errors.Wrap(err, "failed to build Redis TLS config")
		}
		opt.TLSConfig = tlsConfig
	}
	if cfg.RedisUsername != "" {
		opt.Username = cfg.RedisUsername
	}
	if cfg.RedisPassword.Value() != "" {
		opt.Password = cfg.RedisPassword.Value()
	}
	client := redis.NewClient(opt)
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		return nil, errors.Wrap(err, "ping redis")
	}
	return &Redis{
		client:  client,
		timeout: cfg.RedisTimeout,
	}, nil
}
func buildRedisTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	redisHostname := os.Getenv("REDIS_HOSTNAME")
	if redisHostname == "" {
		return nil, fmt.Errorf("REDIS_HOSTNAME must be set when REDIS_TLS=true")
	}
	tlsConfig.ServerName = redisHostname
	certPath := os.Getenv("REDIS_TLS_CA_CERT")
	if certPath != "" {
		caCert, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read Redis CA cert: %w", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append Redis CA cert to pool")
		}
		tlsConfig.RootCAs = certPool
	} else {
		systemPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system cert pool: %w", err)
		}
		tlsConfig.RootCAs = systemPool
	}
	env := os.Getenv("ENVIRONMENT")
	if env != "production" {
		devCertPath := os.Getenv("REDIS_TLS_DEV_CA")
		if devCertPath != "" {
			devCert, err := os.ReadFile(devCertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read dev CA cert: %w", err)
			}
			if tlsConfig.RootCAs == nil {
				tlsConfig.RootCAs = x509.NewCertPool()
			}
			if !tlsConfig.RootCAs.AppendCertsFromPEM(devCert) {
				return nil, fmt.Errorf("failed to append dev CA cert")
			}
		}
	}
	return tlsConfig, nil
}
func (r *Redis) CachePaste(ctx context.Context, p *domain.Paste, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	data, err := json.Marshal(p)
	if err != nil {
		return errors.Wrap(err, "marshal paste")
	}
	return errors.Wrap(r.client.Set(ctx, "paste:"+p.ID, data, ttl).Err(), "set paste")
}
func (r *Redis) GetPaste(ctx context.Context, id string) (*domain.Paste, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	data, err := r.client.Get(ctx, "paste:"+id).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "get paste")
	}
	var p domain.Paste
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, errors.Wrap(err, "unmarshal paste")
	}
	return &p, nil
}
func (r *Redis) Delete(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if err := r.client.Del(ctx, "paste:"+id).Err(); err != nil {
		return errors.Wrap(err, "delete paste")
	}
	return nil
}
func (r *Redis) RateLimit(ctx context.Context, key string, limit int, window time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	script := redis.NewScript(`
		local current = redis.call("GET", KEYS[1])
		if current == false then
			current = 0
		else
			current = tonumber(current)
		end
		if current >= tonumber(ARGV[2]) then
			return current
		end
		local new_val = redis.call("INCR", KEYS[1])
		if new_val == 1 then
			redis.call("PEXPIRE", KEYS[1], ARGV[1])
		end
		return new_val
	`)
	usage, err := script.Run(ctx, r.client, []string{key}, int(window.Milliseconds()), limit).Int()
	if err != nil {
		return 0, errors.Wrap(err, "rate limit lua")
	}
	return usage, nil
}
func (r *Redis) MarkUsed(ctx context.Context, tokenHash string, ttl time.Duration) error {
	if tokenHash == "" {
		return errors.New("token hash cannot be empty")
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	key := "used_token:" + tokenHash
	return r.client.Set(ctx, key, "1", ttl).Err()
}
func (r *Redis) IsUsed(ctx context.Context, tokenHash string) (bool, error) {
	if tokenHash == "" {
		return false, errors.New("token hash cannot be empty")
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	key := "used_token:" + tokenHash
	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}
func (r *Redis) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}
