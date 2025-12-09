package kms
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	vault "github.com/hashicorp/vault/api"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrProviderUnavailable = errors.New("kms provider unavailable")
	ErrDecryptionFailed    = errors.New("decryption failed")
	ErrRequiresPrimary     = errors.New("KMS_REQUIRE_PRIMARY is enabled, cannot use fallback provider")
)
type EncryptionContext map[string]string

type Provider interface {
	Encrypt(ctx context.Context, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ctx context.Context, ciphertext []byte) (plaintext []byte, err error)
	EncryptWithContext(ctx context.Context, plaintext []byte, encContext []byte) (ciphertext []byte, err error)
	DecryptWithContext(ctx context.Context, ciphertext []byte, encContext []byte) (plaintext []byte, err error)
	GetSecret(ctx context.Context, key string) (value string, err error)
}
type Adapter struct {
	primary        Provider
	fallback       Provider
	failClosed     bool
	requirePrimary bool
}

func NewAdapter(ctx context.Context) (*Adapter, error) {
	requirePrimary := strings.ToLower(os.Getenv("KMS_REQUIRE_PRIMARY")) == "true"
	var primary, fallback Provider
	if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
		if vp, err := newVaultProvider(ctx); err == nil {
			primary = vp
		}
	}
	if primary == nil {
		if awsRegion := os.Getenv("AWS_REGION"); awsRegion != "" {
			if ap, err := newAWSProvider(ctx); err == nil {
				primary = ap
			}
		}
	}
	if !requirePrimary && primary == nil {
		if envKey := os.Getenv("KMS_LOCAL_KEY"); envKey != "" {
			ep, err := newEnvProvider(envKey)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize env provider: %w", err)
			}
			fallback = ep
		}
	}
	if primary == nil && fallback == nil {
		if requirePrimary {
			return nil, fmt.Errorf("KMS_REQUIRE_PRIMARY=true but no primary provider available (checked Vault, AWS KMS)")
		}
		return nil, fmt.Errorf("no KMS providers available (checked Vault, AWS KMS, env)")
	}
	failClosed := os.Getenv("KMS_FAIL_CLOSED") != "false" 
	return &Adapter{
		primary:        primary,
		fallback:       fallback,
		failClosed:     failClosed,
		requirePrimary: requirePrimary,
	}, nil
}

func (a *Adapter) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return a.EncryptWithContext(ctx, plaintext, nil)
}
func (a *Adapter) EncryptWithContext(ctx context.Context, plaintext []byte, encContext EncryptionContext) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	contextBytes := serializeEncryptionContext(encContext)
	if a.primary != nil {
		ciphertext, err := a.primary.EncryptWithContext(ctx, plaintext, contextBytes)
		if err == nil {
			return ciphertext, nil
		}
		if a.requirePrimary {
			return nil, fmt.Errorf("primary KMS encrypt failed (KMS_REQUIRE_PRIMARY=true): %w", err)
		}
		if a.failClosed {
			return nil, fmt.Errorf("kms encrypt failed (fail-closed): %w", err)
		}
	}
	if a.fallback != nil {
		return a.fallback.EncryptWithContext(ctx, plaintext, contextBytes)
	}
	return nil, ErrProviderUnavailable
}
func (a *Adapter) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return a.DecryptWithContext(ctx, ciphertext, nil)
}
func (a *Adapter) DecryptWithContext(ctx context.Context, ciphertext []byte, encContext EncryptionContext) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	contextBytes := serializeEncryptionContext(encContext)
	if a.primary != nil {
		plaintext, err := a.primary.DecryptWithContext(ctx, ciphertext, contextBytes)
		if err == nil {
			return plaintext, nil
		}
		if a.requirePrimary {
			return nil, fmt.Errorf("primary KMS decrypt failed (KMS_REQUIRE_PRIMARY=true): %w", err)
		}
		if a.failClosed {
			return nil, fmt.Errorf("kms decrypt failed (fail-closed): %w", err)
		}
	}
	if a.fallback != nil {
		return a.fallback.DecryptWithContext(ctx, ciphertext, contextBytes)
	}
	return nil, ErrProviderUnavailable
}
func serializeEncryptionContext(ctx EncryptionContext) []byte {
	if len(ctx) == 0 {
		return nil
	}
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(ctx[k])
		buf.WriteByte(';')
	}
	return buf.Bytes()
}
func (a *Adapter) GetSecret(ctx context.Context, key string) (string, error) {
	if a.primary != nil {
		val, err := a.primary.GetSecret(ctx, key)
		if err == nil && val != "" {
			return val, nil
		}
		if a.requirePrimary {
			return "", fmt.Errorf("primary KMS GetSecret failed (KMS_REQUIRE_PRIMARY=true): %w", err)
		}
		if a.failClosed {
			return "", fmt.Errorf("get secret failed (fail-closed): %w", err)
		}
	}
	if a.fallback != nil {
		return a.fallback.GetSecret(ctx, key)
	}
	return "", ErrProviderUnavailable
}

type vaultProvider struct {
	client     *vault.Client
	mountPath  string
	keyID      string
	secretPath string
}
func newVaultProvider(ctx context.Context) (*vaultProvider, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = os.Getenv("VAULT_ADDR")
	cfg.Timeout = 5 * time.Second
	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if tokenFile := os.Getenv("VAULT_TOKEN_FILE"); tokenFile != "" {
		tokenBytes, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read VAULT_TOKEN_FILE: %w", err)
		}
		token := strings.TrimSpace(string(tokenBytes))
		client.SetToken(token)
		token = ""
	} else if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
	}
	healthCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = client.Sys().HealthWithContext(healthCtx)
	if err != nil {
		return nil, fmt.Errorf("vault health check failed: %w", err)
	}
	return &vaultProvider{
		client:     client,
		mountPath:  getEnvOrDefault("VAULT_MOUNT_PATH", "transit"),
		keyID:      getEnvOrDefault("VAULT_KEY_ID", "drylax-master"),
		secretPath: getEnvOrDefault("VAULT_SECRET_PATH", "secret/data/drylax"),
	}, nil
}
func (v *vaultProvider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return v.EncryptWithContext(ctx, plaintext, nil)
}

func (v *vaultProvider) EncryptWithContext(ctx context.Context, plaintext []byte, encContext []byte) ([]byte, error) {
	path := fmt.Sprintf("%s/encrypt/%s", v.mountPath, v.keyID)
	data := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}
	if len(encContext) > 0 {
		data["context"] = base64.StdEncoding.EncodeToString(encContext)
	}
	secret, err := v.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, err
	}
	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, errors.New("vault: ciphertext not found")
	}
	return []byte(ciphertext), nil
}

func (v *vaultProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return v.DecryptWithContext(ctx, ciphertext, nil)
}

func (v *vaultProvider) DecryptWithContext(ctx context.Context, ciphertext []byte, encContext []byte) ([]byte, error) {
	path := fmt.Sprintf("%s/decrypt/%s", v.mountPath, v.keyID)
	data := map[string]interface{}{
		"ciphertext": string(ciphertext),
	}
	if len(encContext) > 0 {
		data["context"] = base64.StdEncoding.EncodeToString(encContext)
	}
	secret, err := v.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, err
	}
	plaintextB64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, errors.New("vault: plaintext not found")
	}
	return base64.StdEncoding.DecodeString(plaintextB64)
}

func (v *vaultProvider) GetSecret(ctx context.Context, key string) (string, error) {
	path := fmt.Sprintf("%s/%s", v.secretPath, key)
	secret, err := v.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", err
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", errors.New("vault: invalid secret format")
	}
	value, ok := data["value"].(string)
	if !ok {
		return "", errors.New("vault: value not found")
	}
	return value, nil
}

type awsProvider struct {
	kmsClient *kms.Client
	smClient  *secretsmanager.Client
	keyID     string
}

func newAWSProvider(ctx context.Context) (*awsProvider, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(os.Getenv("AWS_REGION")),
	)
	if err != nil {
		return nil, err
	}
	return &awsProvider{
		kmsClient: kms.NewFromConfig(cfg),
		smClient:  secretsmanager.NewFromConfig(cfg),
		keyID:     getEnvOrDefault("KMS_MASTER_KEY_ID", "alias/drylax-master"),
	}, nil
}
func (a *awsProvider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return a.EncryptWithContext(ctx, plaintext, nil)
}

func (a *awsProvider) EncryptWithContext(ctx context.Context, plaintext []byte, encContext []byte) ([]byte, error) {
	input := &kms.EncryptInput{
		KeyId:     &a.keyID,
		Plaintext: plaintext,
	}
	if len(encContext) > 0 {
		input.EncryptionContext = map[string]string{
			"context": base64.StdEncoding.EncodeToString(encContext),
		}
	}
	result, err := a.kmsClient.Encrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("aws kms encrypt failed: %w", err)
	}
	return result.CiphertextBlob, nil
}

func (a *awsProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return a.DecryptWithContext(ctx, ciphertext, nil)
}

func (a *awsProvider) DecryptWithContext(ctx context.Context, ciphertext []byte, encContext []byte) ([]byte, error) {
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}
	if len(encContext) > 0 {
		input.EncryptionContext = map[string]string{
			"context": base64.StdEncoding.EncodeToString(encContext),
		}
	}
	result, err := a.kmsClient.Decrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("aws kms decrypt failed: %w", err)
	}
	return result.Plaintext, nil
}
func (a *awsProvider) GetSecret(ctx context.Context, key string) (string, error) {
	result, err := a.smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &key,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", key, err)
	}
	if result.SecretString == nil {
		return "", errors.New("secret is binary, not string")
	}
	return *result.SecretString, nil
}

type envProvider struct {
	aead cipher.AEAD
}

func newEnvProvider(key string) (*envProvider, error) {
	if key == "" {
		return nil, fmt.Errorf("KMS_LOCAL_KEY environment variable is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("KMS_LOCAL_KEY must be base64-encoded: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("KMS_LOCAL_KEY must be exactly 32 bytes when decoded (got %d bytes)", len(decoded))
	}
	block, err := aes.NewCipher(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return &envProvider{aead: aead}, nil
}
func (e *envProvider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return e.EncryptWithContext(ctx, plaintext, nil)
}

func (e *envProvider) EncryptWithContext(ctx context.Context, plaintext []byte, encContext []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return e.aead.Seal(nonce, nonce, plaintext, encContext), nil
}

func (e *envProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	return e.DecryptWithContext(ctx, ciphertext, nil)
}

func (e *envProvider) DecryptWithContext(ctx context.Context, ciphertext []byte, encContext []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]
	return e.aead.Open(nil, nonce, encrypted, encContext)
}
func (e *envProvider) GetSecret(ctx context.Context, key string) (string, error) {
	val, exists := os.LookupEnv(key)
	if !exists {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	return val, nil
}
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}
func AEADSeal(plaintext, dek []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}
func AEADOpen(ciphertext, dek []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}
func EncryptDEKWithKMS(ctx context.Context, adapter *Adapter, dek []byte) ([]byte, error) {
	return adapter.Encrypt(ctx, dek)
}
func DecryptDEKWithKMS(ctx context.Context, adapter *Adapter, encryptedDEK []byte) ([]byte, error) {
	return adapter.Decrypt(ctx, encryptedDEK)
}
func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
