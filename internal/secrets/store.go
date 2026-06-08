package secrets

import (
	"errors"
	"fmt"
	"sync"
)

var ErrNotFound = errors.New("secret not found")

type SecretEntry struct {
	Name         string
	ID           string
	Value        []byte
	AllowedHosts []string
}

type SecretStore interface {
	LookupByName(name string) (*SecretEntry, error)
	LookupByID(id string) (*SecretEntry, error)
	AllHosts() []string
	Count() int
}

type InMemoryStore struct {
	mu     sync.RWMutex
	byName map[string]*SecretEntry
	byID   map[string]*SecretEntry
}

func NewInMemoryStore(entries []SecretEntry) (*InMemoryStore, error) {
	byName := make(map[string]*SecretEntry)
	byID := make(map[string]*SecretEntry)

	var duplicates []string
	for i := range entries {
		entry := &entries[i]
		if _, exists := byName[entry.Name]; exists {
			duplicates = append(duplicates, entry.Name)
		}
		byName[entry.Name] = entry
		byID[entry.ID] = entry
	}

	if len(duplicates) > 0 {
		return nil, fmt.Errorf("duplicate secret names: %v", duplicates)
	}

	return &InMemoryStore{
		byName: byName,
		byID:   byID,
	}, nil
}

func (s *InMemoryStore) LookupByName(name string) (*SecretEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.byName[name]
	if !exists {
		return nil, ErrNotFound
	}

	return copyEntry(entry), nil
}

func (s *InMemoryStore) LookupByID(id string) (*SecretEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.byID[id]
	if !exists {
		return nil, ErrNotFound
	}

	return copyEntry(entry), nil
}

func (s *InMemoryStore) AllHosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hostSet := make(map[string]struct{})
	for _, entry := range s.byName {
		for _, host := range entry.AllowedHosts {
			hostSet[host] = struct{}{}
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}

	return hosts
}

func (s *InMemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.byName)
}

func copyEntry(entry *SecretEntry) *SecretEntry {
	valueCopy := make([]byte, len(entry.Value))
	copy(valueCopy, entry.Value)

	hostsCopy := make([]string, len(entry.AllowedHosts))
	copy(hostsCopy, entry.AllowedHosts)

	return &SecretEntry{
		Name:         entry.Name,
		ID:           entry.ID,
		Value:        valueCopy,
		AllowedHosts: hostsCopy,
	}
}
