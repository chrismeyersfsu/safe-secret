package bitwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chrismeyersfsu/safe-secret/internal/secrets"
)

type Client struct {
	cliPath    string
	timeout    time.Duration
	folderName string
	session    string
}

type BWItem struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	FolderID string   `json:"folderId"`
	Login    *BWLogin `json:"login"`
}

type BWLogin struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	URIs     []BWURI `json:"uris"`
}

type BWURI struct {
	URI   string `json:"uri"`
	Match *int   `json:"match"`
}

type BWFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type BWStatus struct {
	Status    string `json:"status"`
	UserEmail string `json:"userEmail"`
}

func NewClient(cliPath string, timeout time.Duration, folderName, session string) *Client {
	return &Client{
		cliPath:    cliPath,
		timeout:    timeout,
		folderName: folderName,
		session:    session,
	}
}

func (c *Client) CheckSession(ctx context.Context) error {
	out, err := c.runBW(ctx, "status")
	if err != nil {
		return fmt.Errorf("bw status: %w", err)
	}

	var status BWStatus
	if err := json.Unmarshal(out, &status); err != nil {
		return fmt.Errorf("parse bw status: %w", err)
	}

	if status.Status != "unlocked" {
		return fmt.Errorf("vault is %s, must be unlocked", status.Status)
	}

	return nil
}

func (c *Client) FindFolderID(ctx context.Context) (string, error) {
	out, err := c.runBW(ctx, "list", "folders")
	if err != nil {
		return "", fmt.Errorf("bw list folders: %w", err)
	}

	var folders []BWFolder
	if err := json.Unmarshal(out, &folders); err != nil {
		return "", fmt.Errorf("parse folders: %w", err)
	}

	for _, f := range folders {
		if f.Name == c.folderName {
			return f.ID, nil
		}
	}

	return "", fmt.Errorf("folder %q not found in Bitwarden vault", c.folderName)
}

func (c *Client) ListItems(ctx context.Context, folderID string) ([]BWItem, error) {
	out, err := c.runBW(ctx, "list", "items", "--folderid", folderID)
	if err != nil {
		return nil, fmt.Errorf("bw list items: %w", err)
	}

	var items []BWItem
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("parse items: %w", err)
	}

	return items, nil
}

func (c *Client) LoadSecrets(ctx context.Context) ([]secrets.SecretEntry, error) {
	folderID, err := c.FindFolderID(ctx)
	if err != nil {
		return nil, err
	}

	items, err := c.ListItems(ctx, folderID)
	if err != nil {
		return nil, err
	}

	return ParseItems(items)
}

func ParseItems(items []BWItem) ([]secrets.SecretEntry, error) {
	var entries []secrets.SecretEntry

	for _, item := range items {
		if item.Login == nil {
			continue
		}
		if item.Login.Password == "" {
			continue
		}

		hosts := ExtractHosts(item.Login.URIs)

		entries = append(entries, secrets.SecretEntry{
			Name:         item.Name,
			ID:           item.ID,
			Value:        []byte(item.Login.Password),
			AllowedHosts: hosts,
		})
	}

	return entries, nil
}

func ExtractHosts(uris []BWURI) []string {
	seen := make(map[string]bool)
	var hosts []string

	for _, u := range uris {
		parsed, err := url.Parse(u.URI)
		if err != nil || parsed.Hostname() == "" {
			continue
		}

		hostname := parsed.Hostname()

		if u.Match == nil || *u.Match == 0 {
			base := baseDomain(hostname)
			if !seen[base] {
				seen[base] = true
				hosts = append(hosts, base)
			}
		} else {
			if !seen[hostname] {
				seen[hostname] = true
				hosts = append(hosts, hostname)
			}
		}
	}

	return hosts
}

func baseDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (c *Client) runBW(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.cliPath, args...)

	env := os.Environ()
	env = append(env, "BW_SESSION="+c.session)
	cmd.Env = env

	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("%s: %s", err, string(exitErr.Stderr))
		}
		return nil, err
	}

	return out, nil
}
