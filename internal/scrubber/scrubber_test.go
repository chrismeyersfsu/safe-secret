package scrubber

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"testing"
)

func TestScrub_Literal(t *testing.T) {
	secret := []byte("mysecret")
	scrubber := New([][]byte{secret})

	body := []byte("This is mysecret in plain text")
	result, scrubResults := scrubber.Scrub(body)

	expected := []byte("This is [REDACTED] in plain text")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %s, got %s", expected, result)
	}

	if len(scrubResults) == 0 {
		t.Fatal("expected scrub results, got none")
	}

	found := false
	for _, r := range scrubResults {
		if r.Encoding == "literal" && r.Count == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected literal encoding with count 1 in results: %v", scrubResults)
	}
}

func TestScrub_Base64(t *testing.T) {
	secret := []byte("mysecret")
	encoded := base64.StdEncoding.EncodeToString(secret)
	scrubber := New([][]byte{secret})

	body := []byte("Encoded: " + encoded)
	result, scrubResults := scrubber.Scrub(body)

	expected := []byte("Encoded: [REDACTED]")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %s, got %s", expected, result)
	}

	found := false
	for _, r := range scrubResults {
		if r.Encoding == "base64" && r.Count == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected base64 encoding with count 1 in results: %v", scrubResults)
	}
}

func TestScrub_URLEncoded(t *testing.T) {
	secret := []byte("my secret")
	encoded := url.QueryEscape(string(secret))
	scrubber := New([][]byte{secret})

	body := []byte("URL: " + encoded)
	result, scrubResults := scrubber.Scrub(body)

	expected := []byte("URL: [REDACTED]")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %s, got %s", expected, result)
	}

	found := false
	for _, r := range scrubResults {
		if r.Encoding == "urlencode" && r.Count == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected urlencode encoding with count 1 in results: %v", scrubResults)
	}
}

func TestScrub_Hex(t *testing.T) {
	secret := []byte("mysecret")
	encoded := hex.EncodeToString(secret)
	scrubber := New([][]byte{secret})

	body := []byte("Hex: " + encoded)
	result, scrubResults := scrubber.Scrub(body)

	expected := []byte("Hex: [REDACTED]")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %s, got %s", expected, result)
	}

	found := false
	for _, r := range scrubResults {
		if r.Encoding == "hex" && r.Count == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected hex encoding with count 1 in results: %v", scrubResults)
	}
}

func TestScrub_MultipleSecrets(t *testing.T) {
	secret1 := []byte("secret1")
	secret2 := []byte("secret2")
	scrubber := New([][]byte{secret1, secret2})

	body := []byte("secret1 and secret2 are here")
	result, scrubResults := scrubber.Scrub(body)

	expected := []byte("[REDACTED] and [REDACTED] are here")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %s, got %s", expected, result)
	}

	if len(scrubResults) < 2 {
		t.Errorf("expected at least 2 scrub results, got %d: %v", len(scrubResults), scrubResults)
	}
}

func TestScrub_CorrectCounts(t *testing.T) {
	secret := []byte("test")
	scrubber := New([][]byte{secret})

	body := []byte("test test test")
	result, scrubResults := scrubber.Scrub(body)

	expected := []byte("[REDACTED] [REDACTED] [REDACTED]")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %s, got %s", expected, result)
	}

	found := false
	for _, r := range scrubResults {
		if r.Encoding == "literal" && r.Count == 3 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected literal encoding with count 3 in results: %v", scrubResults)
	}
}

func TestScrub_NoMatches(t *testing.T) {
	secret := []byte("secret")
	scrubber := New([][]byte{secret})

	body := []byte("no matches here")
	result, scrubResults := scrubber.Scrub(body)

	if !bytes.Equal(result, body) {
		t.Errorf("expected unchanged body, got %s", result)
	}

	if len(scrubResults) != 0 {
		t.Errorf("expected no scrub results, got %v", scrubResults)
	}
}

func TestNew_EmptySecrets(t *testing.T) {
	scrubber := New([][]byte{})

	body := []byte("nothing to scrub")
	result, scrubResults := scrubber.Scrub(body)

	if !bytes.Equal(result, body) {
		t.Errorf("expected unchanged body, got %s", result)
	}

	if len(scrubResults) != 0 {
		t.Errorf("expected no scrub results, got %v", scrubResults)
	}
}

func TestNew_EmptySecretValue(t *testing.T) {
	scrubber := New([][]byte{[]byte(""), []byte("real")})

	body := []byte("real secret here")
	result, _ := scrubber.Scrub(body)

	expected := []byte("[REDACTED] secret here")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %s, got %s", expected, result)
	}
}
