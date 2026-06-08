package placeholder

import (
	"errors"
	"testing"
)

func TestScanSingleNamePlaceholder(t *testing.T) {
	data := []byte("Authorization: Bearer __SAFE_SECRET__NAME__API_TOKEN")
	matches := Scan(data)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if matches[0].Qualifier != "NAME" {
		t.Errorf("expected qualifier NAME, got %s", matches[0].Qualifier)
	}
	if matches[0].Identifier != "API_TOKEN" {
		t.Errorf("expected identifier API_TOKEN, got %s", matches[0].Identifier)
	}
	if matches[0].Start != 22 {
		t.Errorf("expected start 22, got %d", matches[0].Start)
	}
}

func TestScanSingleIDPlaceholder(t *testing.T) {
	data := []byte("Secret: __SAFE_SECRET__ID__abc-def-123")
	matches := Scan(data)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if matches[0].Qualifier != "ID" {
		t.Errorf("expected qualifier ID, got %s", matches[0].Qualifier)
	}
	if matches[0].Identifier != "abc-def-123" {
		t.Errorf("expected identifier abc-def-123, got %s", matches[0].Identifier)
	}
}

func TestScanMixedPlaceholders(t *testing.T) {
	data := []byte("NAME: __SAFE_SECRET__NAME__DB_PASS and ID: __SAFE_SECRET__ID__12ab-34cd")
	matches := Scan(data)

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	if matches[0].Qualifier != "NAME" || matches[0].Identifier != "DB_PASS" {
		t.Errorf("first match incorrect: %+v", matches[0])
	}
	if matches[1].Qualifier != "ID" || matches[1].Identifier != "12ab-34cd" {
		t.Errorf("second match incorrect: %+v", matches[1])
	}
}

func TestScanNoPlaceholders(t *testing.T) {
	data := []byte("No placeholders here")
	matches := Scan(data)

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestReplaceSubstitutesSecret(t *testing.T) {
	data := []byte("Token: __SAFE_SECRET__NAME__MY_TOKEN")
	lookup := func(qualifier, identifier string) ([]byte, []string, error) {
		if qualifier == "NAME" && identifier == "MY_TOKEN" {
			return []byte("secret-value-xyz"), []string{"example.com"}, nil
		}
		return nil, nil, errors.New("not found")
	}

	output, results := Replace(data, "example.com", lookup)

	expected := "Token: secret-value-xyz"
	if string(output) != expected {
		t.Errorf("expected %q, got %q", expected, string(output))
	}

	if len(results) != 1 || !results[0].Replaced {
		t.Errorf("expected 1 replaced result, got %+v", results)
	}
}

func TestReplaceLeavesPlaceholderWhenHostBlocked(t *testing.T) {
	data := []byte("Token: __SAFE_SECRET__NAME__MY_TOKEN")
	lookup := func(qualifier, identifier string) ([]byte, []string, error) {
		return []byte("secret-value"), []string{"allowed.com"}, nil
	}

	output, results := Replace(data, "blocked.com", lookup)

	if string(output) != string(data) {
		t.Errorf("expected placeholder to remain, got %q", string(output))
	}

	if len(results) != 1 || results[0].Replaced {
		t.Errorf("expected 1 blocked result, got %+v", results)
	}
	if results[0].Reason != "host_blocked" {
		t.Errorf("expected reason host_blocked, got %s", results[0].Reason)
	}
}

func TestReplaceHandlesMultiplePlaceholdersBackToFront(t *testing.T) {
	data := []byte("A: __SAFE_SECRET__NAME__FIRST and B: __SAFE_SECRET__NAME__SECOND")
	lookup := func(qualifier, identifier string) ([]byte, []string, error) {
		if identifier == "FIRST" {
			return []byte("value1"), []string{"example.com"}, nil
		}
		if identifier == "SECOND" {
			return []byte("value2"), []string{"example.com"}, nil
		}
		return nil, nil, errors.New("not found")
	}

	output, results := Replace(data, "example.com", lookup)

	expected := "A: value1 and B: value2"
	if string(output) != expected {
		t.Errorf("expected %q, got %q", expected, string(output))
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results[0].Replaced || !results[1].Replaced {
		t.Errorf("expected both replaced, got %+v", results)
	}
}

func TestReplaceHandlesLookupError(t *testing.T) {
	data := []byte("Token: __SAFE_SECRET__NAME__MISSING")
	lookup := func(qualifier, identifier string) ([]byte, []string, error) {
		return nil, nil, errors.New("lookup failed")
	}

	output, results := Replace(data, "example.com", lookup)

	if string(output) != string(data) {
		t.Errorf("expected placeholder to remain on error, got %q", string(output))
	}

	if len(results) != 1 || results[0].Replaced {
		t.Errorf("expected 1 not_found result, got %+v", results)
	}
	if results[0].Reason != "not_found" {
		t.Errorf("expected reason not_found, got %s", results[0].Reason)
	}
}

func TestNameIdentifierCharacterClass(t *testing.T) {
	data := []byte("__SAFE_SECRET__NAME__VALID_NAME_123 extra")
	matches := Scan(data)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if matches[0].Identifier != "VALID_NAME_123" {
		t.Errorf("expected VALID_NAME_123, got %s (should stop at first non-matching char)", matches[0].Identifier)
	}
}

func TestIDIdentifierCharacterClass(t *testing.T) {
	data := []byte("__SAFE_SECRET__ID__abc-123-def extra")
	matches := Scan(data)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if matches[0].Identifier != "abc-123-def" {
		t.Errorf("expected abc-123-def, got %s (should stop at first non-matching char)", matches[0].Identifier)
	}
}
