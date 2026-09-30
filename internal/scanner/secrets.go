package scanner

import (
	"math"
	"strings"
)

// DangerousFile describes a file whose very presence warrants a review.
type DangerousFile struct {
	Path     string
	Reason   string
	Severity Severity
}

var sensitiveNameExact = map[string]string{
	".env":        "committed environment file",
	"credentials": "credential file",
	".npmrc":      "npm auth token store",
	".pypirc":     "PyPI auth token store",
	"id_rsa":      "SSH private key",
	"id_dsa":      "SSH private key",
	"id_ecdsa":    "SSH private key",
	"id_ed25519":  "SSH private key",
	"keystore":    "Java keystore",
	"secring.gpg": "GPG secret keyring",
}

var sensitiveExt = map[string]string{
	".pem":      "PEM private key or certificate",
	".key":      "key material",
	".pfx":      "PKCS#12 key bundle",
	".p12":      "PKCS#12 key bundle",
	".jks":      "Java keystore",
	".keystore": "Java keystore",
	".ppk":      "PuTTY private key",
	".p8":       "Apple private key",
}

// ClassifySensitiveFile reports whether a file path is a likely secret carrier
// based purely on its name (never its contents). Files ending in an obvious
// example/template variant are ignored to reduce false positives.
func ClassifySensitiveFile(p string) (reason string, severity Severity, ok bool) {
	base := strings.ToLower(pathBase(p))
	// Ignore documented templates like .env.example, secrets.sample, key.pub.
	for _, suffix := range []string{".example", ".sample", ".template", ".dist", ".md", ".pub", ".txt"} {
		if strings.HasSuffix(base, suffix) {
			return "", "", false
		}
	}
	if r, ok := sensitiveNameExact[base]; ok {
		return r, SeverityHigh, true
	}
	if strings.HasPrefix(base, ".env.") {
		return "environment file variant", SeverityHigh, true
	}
	// Reasonable extensions map.
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		if r, ok := sensitiveExt[base[i:]]; ok {
			return r, SeverityHigh, true
		}
	}
	return "", "", false
}

// ShannonEntropy computes the Shannon entropy (bits per symbol) of s.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	n := 0
	for _, r := range s {
		freq[r]++
		n++
	}
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// HighEntropyValue reports whether a value looks like a random secret based on
// length and Shannon entropy. Thresholds are intentionally conservative; this
// is a review hint, not a verdict.
func HighEntropyValue(v string) bool {
	v = strings.Trim(v, `"'`+"`")
	if len(v) < 20 {
		return false
	}
	// Reject obvious non-secrets.
	if strings.ContainsAny(v, " /\\") {
		return false
	}
	return ShannonEntropy(v) >= 4.0
}

// ScanTextForSecretAssignments scans (bounded) text line by line for
// NAME=value style secret assignments and returns the offending variable names
// with their 1-based line numbers.
type SecretHit struct {
	Name string
	Line int
}

// ScanSecretAssignments inspects a bounded text blob for secret-looking
// assignments. Callers should cap the input size.
func ScanSecretAssignments(content string) []SecretHit {
	var hits []SecretHit
	for i, raw := range strings.Split(content, "\n") {
		name, ok := LooksLikeSecretAssignment(raw)
		if !ok {
			continue
		}
		hits = append(hits, SecretHit{Name: name, Line: i + 1})
	}
	return hits
}
