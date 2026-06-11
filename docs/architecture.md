# Architecture

## Threat Model

safe-secret defends against supply-chain attacks and compromised IDE extensions that exfiltrate secrets from process memory. Secrets never enter user-space application memory -- they exist only in the proxy process.

```
Application                    safe-secret proxy                 Upstream
+-----------+                 +------------------+              +----------+
| Uses      |  placeholder    | Intercept req    |  real secret | API      |
| placeholder| ------------> | Lookup secret    | -----------> | server   |
| tokens    |                 | Verify host      |              |          |
|           | <-------------- | Scrub response   | <----------- |          |
+-----------+   [REDACTED]    +------------------+   raw resp   +----------+
```

## Request Flow

1. Application sends HTTP(S) request through the proxy (`HTTP_PROXY`/`HTTPS_PROXY`)
2. For HTTPS: proxy checks if the host has secrets in the store
   - **Yes**: MITM the connection (generate host cert signed by proxy CA)
   - **No**: plain CONNECT tunnel, no interception
3. Scan request headers and body for `__SAFE_SECRET__NAME__<NAME>` or `__SAFE_SECRET__ID__<UUID>` placeholders
4. For each placeholder:
   - Look up the secret by name or ID
   - Check if the destination host is in the secret's allowlist
   - **Allowed**: replace placeholder with real secret value
   - **Blocked**: leave placeholder intact, audit log
5. Forward request to upstream
6. Scan response body for injected secret values (literal, base64, URL-encoded, hex)
7. Replace any matches with `[REDACTED]`
8. Return sanitized response to application

## Package Structure

```
cmd/                    CLI commands (cobra)
  root.go               Root command, global flags
  start.go              Start proxy + health server
  status.go             Query health endpoint
  doctor.go             Environment validation
  config_*.go           Config management subcommands
  version.go            Version output

internal/
  config/               Viper-based config (YAML, env, CLI precedence)
  proxy/                goproxy MITM proxy, request/response handlers
  placeholder/          Regex scanning and back-to-front replacement
  secrets/              SecretStore interface, InMemoryStore
  scrubber/             Multi-encoding response scrubbing
  certgen/              ECDSA P-256 CA certificate generation
  audit/                Structured JSON audit logging (slog)
  health/               Health endpoint (JSON status, uptime, secret count)
```

## Key Design Decisions

**Selective MITM**: Only HTTPS connections to hosts with known secrets are intercepted. All other HTTPS traffic tunnels through as a plain CONNECT proxy with no certificate generation or inspection.

**Per-secret host allowlist**: Each secret has an explicit list of allowed destination hosts. A GitHub token can only be injected into requests to `api.github.com`, not to arbitrary hosts. This prevents exfiltration even if an attacker controls the request URL.

**Multi-encoding scrubbing**: Response scrubbing checks for the secret value in literal, base64, URL-encoded, and hex forms. This catches APIs that echo back credentials in different encodings.

**Header and body scanning**: Placeholders are supported in both request headers (e.g., `Authorization: Bearer __SAFE_SECRET__NAME__API_KEY`) and request bodies. Structural headers (`Host`, `Content-Length`, `Transfer-Encoding`, `Content-Encoding`) are skipped.

**Back-to-front replacement**: Placeholders in the body are replaced from the end of the buffer backward, so byte offsets of earlier placeholders remain valid during replacement.
