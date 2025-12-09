package main

import (
"context"
"drylax/cfg"
"drylax/metrics"
"drylax/pkg/kms"
"drylax/svc/api"
"drylax/svc/auth"
"drylax/svc/cache"
"drylax/svc/db"
"drylax/svc/lim"
"drylax/svc/svc"
"drylax/svc/util"
"encoding/base64"
"fmt"
"net/http"
_ "net/http/pprof"
"os"
"os/signal"
"syscall"
"time"
)

func main() {
if len(os.Args) > 1 && os.Args[1] == "-health" {
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()
dbPath := os.Getenv("DATABASE_PATH")
if dbPath == "" {
dbPath = "drylax.db"
}

sqlDB, err := db.NewSQLite(dbPath)
if err != nil {
os.Exit(1)
}
defer sqlDB.Close()

pingCtx, pingCancel := context.WithTimeout(ctx, 1*time.Second)
defer pingCancel()
if err := sqlDB.DB().PingContext(pingCtx); err != nil {
os.Exit(1)
}
os.Exit(0)
}

c, err := cfg.Load()
if err != nil {
util.Fatal().Err(err).Msg("failed to load configuration")
os.Exit(1)
}

if err := cfg.Validate(c); err != nil {
util.Fatal().Err(err).Msg("invalid configuration")
os.Exit(1)
}
defer c.Wipe()
util.InitLog(c.LogLevel, c.Environment == "development")
util.Info().Msg("starting drylax API")
fmt.Printf("ALLOWED_ORIGINS = %v (count: %d)\n", c.AllowedOrigins, len(c.AllowedOrigins))
metrics.Init()
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

kmsAdapter, err := kms.NewAdapter(ctx)
if err != nil {
util.Fatal().Err(err).Msg("failed to initialize KMS adapter")
os.Exit(1)
}

var pepper []byte
if c.PepperFromKMS {
pepperB64, err := kmsAdapter.GetSecret(ctx, "ARGON2_PEPPER")
if err != nil {
util.Fatal().Err(err).Msg("CRITICAL: failed to load pepper from KMS")
os.Exit(1)
}
pepper, err = base64.StdEncoding.DecodeString(pepperB64)
if err != nil {
util.Fatal().Err(err).Msg("CRITICAL: invalid pepper format")
os.Exit(1)
}
} else {
if c.Pepper.Value() == "" {
util.Fatal().Msg("CRITICAL: PEPPER environment variable must be set when PEPPER_FROM_KMS=false.")
os.Exit(1)
}
pepper = []byte(c.Pepper.Value())
}
if len(pepper) < 32 {
util.Wipe(pepper)
util.Fatal().Int("length", len(pepper)).Msg("CRITICAL: pepper too short, must be >= 32 bytes")
os.Exit(1)
}

tokenSecretB64, err := kmsAdapter.GetSecret(ctx, "DELETION_TOKEN_SECRET")
if err != nil {
util.Wipe(pepper)
util.Fatal().Err(err).Msg("failed to load deletion token secret")
os.Exit(1)
}
tokenSecret, err := base64.StdEncoding.DecodeString(tokenSecretB64)
if err != nil {
util.Wipe(pepper)
util.Fatal().Err(err).Msg("invalid token secret format")
os.Exit(1)
}
if err := util.InitDeletionTokenKey(tokenSecret); err != nil {
util.Wipe(tokenSecret)
util.Wipe(pepper)
util.Fatal().Err(err).Msg("failed to init deletion token key")
os.Exit(1)
}
util.Wipe(tokenSecret)
util.SetTokenReplayTTL(c.TokenReplayTTL)

sqlDB, err := db.NewSQLiteWithConfig(c.DatabasePath, c.DBMaxOpenConns, c.DBMaxIdleConns, c.DBQueryTimeout)
if err != nil {
util.Wipe(pepper)
util.Fatal().Err(err).Msg("failed to initialize database")
os.Exit(1)
}
defer sqlDB.Close()
util.Info().Str("path", c.DatabasePath).Msg("database initialized")

var rdb *db.Redis
if c.RedisURL != "" {
rdb, err = db.NewRedis(c.RedisURL, c)
if err != nil {
if c.Environment == "production" {
util.Fatal().Err(err).Msg("CRITICAL: Redis required in production")
os.Exit(1)
}
util.Warn().Err(err).Msg("redis unavailable (dev mode)")
} else {
util.Info().Msg("redis connected")
util.SetUsedTokenTracker(rdb)
util.Info().Msg("deletion token tracker enabled")
}
}
if rdb != nil {
defer rdb.Close()
}

lruCache, err := cache.NewLRU(c.LRUCacheSize)
if err != nil {
util.Fatal().Err(err).Msg("failed to create LRU cache")
os.Exit(1)
}
util.Info().Int("size", c.LRUCacheSize).Msg("LRU cache initialized")

hasher, err := auth.NewHasher(c.Argon2Time, c.Argon2Memory, c.Argon2Parallelism, pepper)
if err != nil {
util.Wipe(pepper)
util.Fatal().Err(err).Msg("failed to initialize hasher")
os.Exit(1)
}
if err := hasher.Start(c.HasherWorkerCount); err != nil {
util.Fatal().Err(err).Msg("failed to start hasher")
os.Exit(1)
}
defer hasher.Stop()
util.Info().Int("workers", c.HasherWorkerCount).Msg("hasher initialized")

if err := util.InitIPHasher(pepper, c.IPHashRotationInterval); err != nil {
util.Wipe(pepper)
util.Fatal().Err(err).Msg("failed to initialize IP hasher")
os.Exit(1)
}
defer util.StopIPHasher()
util.Info().Dur("rotation_interval", c.IPHashRotationInterval).Msg("IP hasher initialized")

pasteSvc := svc.NewPaste(sqlDB, lruCache, rdb, hasher, kmsAdapter, c)
util.Info().Int("workers", c.WorkerPoolSize).Msg("paste service initialized")

limiter := lim.New(c.RateLimit.RPM, c.RateLimit.Burst, c.RateLimit.ConservativeLimit, rdb, c.TrustedProxies)
defer limiter.Stop()
util.Info().
Int("rpm", c.RateLimit.RPM).
Int("burst", c.RateLimit.Burst).
Strs("trusted_proxies", c.TrustedProxies).
Msg("rate limiter initialized")

server := api.NewServer(c, pasteSvc, limiter, sqlDB, rdb)

quitWAL := make(chan struct{})
go db.StartWALMaintenance(sqlDB.DB(), quitWAL)
util.Info().Msg("WAL maintenance worker started")

if err := svc.StartCleaner(ctx, sqlDB, 10*time.Minute); err != nil {
util.Error().Err(err).Msg("failed to start cleaner")
} else {
util.Info().Msg("Expired paste cleanup worker started")
}

go func() {
util.Info().Msg("starting pprof server on :6060")
if err := http.ListenAndServe(":6060", nil); err != nil {
util.Warn().Err(err).Msg("pprof server failed")
}
}()

util.Info().Str("port", c.Port).Str("environment", c.Environment).Msg("server starting")
go func() {
if err := server.Start(); err != nil {
util.Fatal().Err(err).Msg("server failed")
os.Exit(1)
}
}()
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
<-sigCh
util.Info().Msg("shutting down gracefully...")
shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
defer shutdownCancel()
if err := server.Shutdown(shutdownCtx); err != nil {
util.Error().Err(err).Msg("server shutdown error")
}
close(quitWAL)
walDone := make(chan struct{})
go func() {
time.Sleep(5 * time.Second)
close(walDone)
}()
select {
case <-walDone:
util.Info().Msg("WAL maintenance stopped")
case <-time.After(6 * time.Second):
util.Warn().Msg("WAL maintenance did not stop gracefully")
}
cancel()
pasteSvc.Shutdown()
util.Info().Msg("Shutdown complete")
}
