package secrets

import (
	"errors"
	"sync"
	"testing"
)

func TestNewInMemoryStore_Valid(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1"}},
		{Name: "secret2", ID: "id2", Value: []byte("value2"), AllowedHosts: []string{"host2"}},
	}

	store, err := NewInMemoryStore(entries)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if store.Count() != 2 {
		t.Errorf("expected count 2, got %d", store.Count())
	}
}

func TestNewInMemoryStore_DuplicateNames(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1"}},
		{Name: "secret1", ID: "id2", Value: []byte("value2"), AllowedHosts: []string{"host2"}},
	}

	store, err := NewInMemoryStore(entries)
	if err == nil {
		t.Fatal("expected error for duplicate names, got nil")
	}

	if store != nil {
		t.Error("expected nil store on error")
	}

	if !containsString(err.Error(), "secret1") {
		t.Errorf("error should list duplicate name 'secret1', got: %v", err)
	}
}

func TestLookupByName_Found(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1"}},
	}

	store, _ := NewInMemoryStore(entries)
	entry, err := store.LookupByName("secret1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entry.Name != "secret1" {
		t.Errorf("expected name 'secret1', got %s", entry.Name)
	}

	if string(entry.Value) != "value1" {
		t.Errorf("expected value 'value1', got %s", string(entry.Value))
	}
}

func TestLookupByName_NotFound(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1"}},
	}

	store, _ := NewInMemoryStore(entries)
	entry, err := store.LookupByName("nonexistent")

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	if entry != nil {
		t.Error("expected nil entry when not found")
	}
}

func TestLookupByID_Found(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1"}},
	}

	store, _ := NewInMemoryStore(entries)
	entry, err := store.LookupByID("id1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if entry.ID != "id1" {
		t.Errorf("expected ID 'id1', got %s", entry.ID)
	}

	if string(entry.Value) != "value1" {
		t.Errorf("expected value 'value1', got %s", string(entry.Value))
	}
}

func TestLookupByID_NotFound(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1"}},
	}

	store, _ := NewInMemoryStore(entries)
	entry, err := store.LookupByID("nonexistent")

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	if entry != nil {
		t.Error("expected nil entry when not found")
	}
}

func TestAllHosts_Deduplicates(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1", "host2"}},
		{Name: "secret2", ID: "id2", Value: []byte("value2"), AllowedHosts: []string{"host2", "host3"}},
	}

	store, _ := NewInMemoryStore(entries)
	hosts := store.AllHosts()

	if len(hosts) != 3 {
		t.Errorf("expected 3 unique hosts, got %d: %v", len(hosts), hosts)
	}

	hostSet := make(map[string]bool)
	for _, host := range hosts {
		hostSet[host] = true
	}

	expectedHosts := []string{"host1", "host2", "host3"}
	for _, expected := range expectedHosts {
		if !hostSet[expected] {
			t.Errorf("expected host %s in result", expected)
		}
	}
}

func TestCount(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1"}},
		{Name: "secret2", ID: "id2", Value: []byte("value2"), AllowedHosts: []string{"host2"}},
		{Name: "secret3", ID: "id3", Value: []byte("value3"), AllowedHosts: []string{"host3"}},
	}

	store, _ := NewInMemoryStore(entries)

	if store.Count() != 3 {
		t.Errorf("expected count 3, got %d", store.Count())
	}
}

func TestConcurrentReadSafety(t *testing.T) {
	entries := []SecretEntry{
		{Name: "secret1", ID: "id1", Value: []byte("value1"), AllowedHosts: []string{"host1"}},
		{Name: "secret2", ID: "id2", Value: []byte("value2"), AllowedHosts: []string{"host2"}},
	}

	store, _ := NewInMemoryStore(entries)

	var wg sync.WaitGroup
	goroutines := 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, _ = store.LookupByName("secret1")
			_, _ = store.LookupByID("id2")
			_ = store.AllHosts()
			_ = store.Count()
		}()
	}

	wg.Wait()
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
