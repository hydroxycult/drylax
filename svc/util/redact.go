package util

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strings"
)

var (
	tokenPattern  = regexp.MustCompile(`[A-Za-z0-9_-]{40,}`)
	secretPattern = regexp.MustCompile(`(?i)(password|token|secret|key|pepper)=([^\s&]+)`)
	ipPattern     = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
)

func RedactPasteContent(content string) string {
	if len(content) == 0 {
		return ""
	}
	if len(content) <= 20 {
		return "[REDACTED]"
	}
	return content[:10] + "...[REDACTED]..." + content[len(content)-10:]
}
func RedactToken(token string) string {
	if len(token) == 0 {
		return ""
	}
	if len(token) <= 8 {
		return "[TOKEN-REDACTED]"
	}
	return token[:4] + "..." + token[len(token)-4:] + "[REDACTED]"
}
func RedactSecret(s string) string {
	return secretPattern.ReplaceAllString(s, "$1=[REDACTED]")
}
func RedactIP(ip string) string {
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		hash := sha256.Sum256([]byte(ip))
		return "hash:" + hex.EncodeToString(hash[:8])
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		ipv4[3] = 0
		return ipv4.String()
	}
	if ipv6 := parsed.To16(); ipv6 != nil {
		for i := 4; i < 16; i++ {
			ipv6[i] = 0
		}
		return ipv6.String()
	}
	hash := sha256.Sum256([]byte(ip))
	return "hash:" + hex.EncodeToString(hash[:8])
}
func RedactSensitive(key, val string) string {
	lower := strings.ToLower(key)
	isSensitive := strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "key")
	if !isSensitive {
		return val
	}
	if len(val) <= 3 {
		return "***"
	}
	return val[:2] + "***" + val[len(val)-2:]
}
func RedactLogLine(line string) string {
	line = tokenPattern.ReplaceAllString(line, "[TOKEN-REDACTED]")
	line = secretPattern.ReplaceAllString(line, "$1=[REDACTED]")
	return line
}
