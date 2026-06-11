# Configuration

safe-secret loads configuration with this precedence (highest to lowest):

1. CLI flags (`--config`)
2. Environment variables (`SAFE_SECRET_*`)
3. User config (`~/.config/safe-secret/config.yaml`)
4. System config (`/etc/safe-secret/config.yaml`)
5. Built-in defaults

## Generate Default Config

```bash
safe-secret config init              # Print to stdout
safe-secret config init -o config.yaml  # Write to file
```

## Validate Config

```bash
safe-secret config validate
```

## Dump Effective Config

```bash
safe-secret config dump
```

## Reference

### proxy

| Key | Default | Description |
|-----|---------|-------------|
| `listen` | `0.0.0.0:8080` | Proxy listen address |
| `max_idle_conns_per_host` | `100` | Max idle connections per upstream host |

### tls

| Key | Default | Description |
|-----|---------|-------------|
| `ca_cert_path` | `/etc/safe-secret/ca/rootCA.pem` | CA certificate path |
| `ca_key_path` | `/etc/safe-secret/ca/rootCA-key.pem` | CA private key path |
| `cert_algorithm` | `ecdsa-p256` | Certificate algorithm (`ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096`) |

### placeholders

| Key | Default | Description |
|-----|---------|-------------|
| `prefix` | `__SAFE_SECRET__` | Placeholder prefix |

### bitwarden

| Key | Default | Description |
|-----|---------|-------------|
| `cli_path` | `bw` | Path to Bitwarden CLI |
| `cli_timeout` | `60` | CLI command timeout (seconds) |
| `session_key_timeout` | `28800` | Session key validity (seconds, default 8h) |
| `folder_name` | `safe-secret` | Bitwarden folder to read secrets from |
| `refresh_interval` | `1800` | Secret refresh interval (seconds, default 30m) |

### keyring

| Key | Default | Description |
|-----|---------|-------------|
| `session_key_description` | `safe-secret:bw-session` | Kernel keyring session key name |
| `cache_name_prefix` | `safe-secret:cache:name:` | Keyring cache prefix for name lookups |
| `cache_id_prefix` | `safe-secret:cache:id:` | Keyring cache prefix for ID lookups |
| `cache_ttl` | `43200` | Keyring cache TTL (seconds, default 12h) |

### pools

| Key | Default | Description |
|-----|---------|-------------|
| `secret_buffer_size` | `4096` | Secret buffer size (bytes) |
| `secret_buffer_count` | `64` | Number of secret buffers |
| `scrub_buffer_size` | `65536` | Scrub buffer size (bytes) |
| `scrub_buffer_count` | `16` | Number of scrub buffers |

### scrubbing

| Key | Default | Description |
|-----|---------|-------------|
| `skip_content_types` | `[application/octet-stream, image/*, video/*, audio/*]` | Content types to skip scrubbing |
| `encodings` | `[literal, base64, urlencode, hex]` | Encodings to detect when scrubbing |
| `max_response_buffer` | `10MB` | Max response body size to scrub |

### logging

| Key | Default | Description |
|-----|---------|-------------|
| `output` | `journal` | Log output (`journal`, `file`, `stdout`) |
| `level` | `info` | Log level |
| `format` | `jsonl` | Log format |
| `include_path` | `true` | Include request path in logs |
| `file.path` | `/var/log/safe-secret/audit.jsonl` | Log file path |
| `file.max_size_mb` | `100` | Max log file size |
| `file.max_backups` | `3` | Max rotated log files |
| `file.max_age_days` | `30` | Max log file age |

### health

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable health endpoint |
| `listen` | `127.0.0.1:8081` | Health endpoint address (must be localhost) |
| `path` | `/healthz` | Health endpoint path |

## Environment Variables

All config keys can be set via environment variables with the prefix `SAFE_SECRET_` and dots/dashes replaced by underscores:

```bash
SAFE_SECRET_PROXY_LISTEN=0.0.0.0:9090
SAFE_SECRET_TLS_CERT_ALGORITHM=rsa-4096
SAFE_SECRET_HEALTH_ENABLED=false
```
