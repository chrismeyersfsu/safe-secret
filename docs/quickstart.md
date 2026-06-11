# Quickstart

## Prerequisites

- Go 1.25+ (for building from source)

## Install

```bash
git clone https://github.com/chrismeyersfsu/safe-secret.git
cd safe-secret
go build -o safe-secret .
```

## Generate Config

```bash
./safe-secret config init -o ~/.config/safe-secret/config.yaml
```

This creates a config with sensible defaults:
- Proxy listens on `0.0.0.0:8080`
- Health endpoint on `127.0.0.1:8081/healthz`
- ECDSA P-256 certificates

## Start the Proxy

```bash
./safe-secret start
```

Verify it's running:

```bash
./safe-secret status
# or
curl http://127.0.0.1:8081/healthz
```

## Configure Your Application

Point your application at the proxy:

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```

For HTTPS, trust the generated CA certificate (default: `/etc/safe-secret/ca/rootCA.pem`):

```bash
# System-wide (Fedora/RHEL)
sudo cp /etc/safe-secret/ca/rootCA.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust

# Or per-request
curl --cacert /etc/safe-secret/ca/rootCA.pem https://api.github.com/user
```

## Use Placeholders

Replace secrets in your requests with placeholders:

```bash
# By name
curl -H "Authorization: Bearer __SAFE_SECRET__NAME__GITHUB_TOKEN" \
  https://api.github.com/user

# By ID (UUID)
curl -d '{"key": "__SAFE_SECRET__ID__a1b2c3d4-e5f6-7890-abcd-ef1234567890"}' \
  https://api.example.com/auth
```

The proxy replaces placeholders with real secrets only if the destination host is in the secret's allowlist.

## Health Check

```bash
curl -s http://127.0.0.1:8081/healthz | jq .
```

```json
{
  "status": "healthy",
  "cached_secrets": 2,
  "mitm_hosts": ["api.github.com", "gitlab.com"],
  "uptime_seconds": 42.5
}
```

## Next Steps

- [Configuration reference](configuration.md) for all options
- [Architecture overview](architecture.md) for how it works under the hood
