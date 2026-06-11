# safe-secret

Transport-layer HTTP/HTTPS proxy that keeps secrets out of user-space process memory.

Instead of passing API keys and tokens directly to applications, safe-secret intercepts outbound HTTP(S) requests and injects secrets only when the destination matches an allowlist. Responses are scrubbed to prevent secret leakage.

## Quickstart

```bash
# Build
go build -o safe-secret .

# Generate default config
./safe-secret config init -o ~/.config/safe-secret/config.yaml

# Start the proxy
./safe-secret start

# In another terminal, use the proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Placeholders are replaced with real secrets transparently
curl -H "Authorization: Bearer __SAFE_SECRET__NAME__GITHUB_TOKEN" https://api.github.com/user
```

## How It Works

1. Applications use placeholder tokens (`__SAFE_SECRET__NAME__<NAME>` or `__SAFE_SECRET__ID__<UUID>`) in request headers and bodies
2. safe-secret intercepts the request, looks up the real secret, and verifies the destination host is allowed
3. The placeholder is replaced with the real secret before forwarding
4. Responses are scrubbed to remove any echoed secrets (literal, base64, URL-encoded, hex)

## Documentation

- [Quickstart Guide](docs/quickstart.md)
- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)

## Development

```bash
make build      # Build binary
make test       # Run tests
make vet        # Run go vet
make clean      # Remove binary
```

## License

See [LICENSE](LICENSE).
