# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a gRPC-based tunneling proxy system written in Lua using the `silly` framework. It provides:
- Forward proxy modes (SOCKS5, TLS SNI interception, fixed port forwarding)
- Reverse proxy capability (bidirectional tunneling from client to server)
- AES-128-CBC encryption for authentication
- Comprehensive Prometheus metrics and Loki logging integration
- Grafana dashboards for monitoring

**Architecture Pattern**: Client-server model where the client acts as a local proxy and creates bidirectional gRPC streams to the server, which connects to the actual destination. Reverse proxying allows the server to forward connections back through the tunnel to services behind the client.

## Key Components

### Core Files

- `tunnel.proto` - gRPC service definition with streaming and unary RPCs:
  - `Connect`: Forward tunneling (client → server → target) - bidirectional streaming
  - `Listen`: Reverse tunneling (server → client → local service) - bidirectional streaming
  - `KeepAlive`: Latency monitoring (client sends timestamp, server echoes) - unary RPC

- `client_grpc.lua` - Client-side implementation with three proxy modes:
  - SOCKS5 proxy on port 1080
  - TLS SNI transparent proxy on port 443
  - Fixed proxy (e.g., port 993 → imap.gmail.com:993)
  - Reverse proxy agents that register with server for reverse tunneling

- `server_grpc.lua` - Server-side implementation:
  - gRPC server on port 443
  - Connects to actual target destinations
  - Reverse proxy listeners (ports 3100, 9090) that match waiting agents by port

- `common.conf` - Environment configuration file loaded by both client and server

### Monitoring Stack

- `config.client.alloy` / `config.server.alloy` - Grafana Alloy configurations for log and metrics collection
- Prometheus metrics exposed on port 9001 (both client and server)
- Loki for centralized log aggregation
- Grafana dashboards provisioned in `tunnel-monitoring.json` and `tunnel-logs.json`

### Docker Deployment

- `Dockerfile.client` / `Dockerfile.server` - Based on `ghcr.io/findstr/silly:alpine`
- `docker.client.yml` - Client-side stack (includes Loki, Prometheus, Grafana)
- `docker.server.yml` - Server-side stack (minimal, tunnels metrics/logs back to client)
- `.github/workflows/docker.yml` - Builds and pushes both client and server images to GHCR

## Development Commands

### Running Locally

```bash
# Start client stack (includes monitoring)
docker-compose -f docker.client.yml up -d

# Start server stack
docker-compose -f docker.server.yml up -d

# View client logs
docker logs -f tunnel-client

# View server logs
docker logs -f tunnel-server

# Stop everything
docker-compose -f docker.client.yml down
docker-compose -f docker.server.yml down
```

### Building Docker Images

```bash
# Build client image
docker build -f Dockerfile.client -t ghcr.io/findstr/tunnel:latest-client .

# Build server image
docker build -f Dockerfile.server -t ghcr.io/findstr/tunnel:latest-server .
```

### Testing

```bash
# Test SOCKS5 proxy
curl -x socks5://127.0.0.1:1080 https://example.com

# Test SNI proxy
curl --resolve example.com:443:127.0.0.1 https://example.com

# Check metrics
curl http://localhost:9001/metrics

# Access Grafana dashboards
# http://localhost:3000 (user: findstr, password: findstr)
```

### Configuration

Set these environment variables in `common.conf` or docker-compose files:

- `KEY` - 16-byte AES-128 encryption key (required)
- `SERVER` - Server address for client (e.g., `server.example.com:443`)
- `SOCKS5` - SOCKS5 listen address (default: `0.0.0.0:1080`)
- `ENABLE_REVERSE_PROXY` - Enable reverse proxy agents (set to `true` to enable, `false` or empty to disable)

**Note**: When running tunnel-client standalone (not in docker-compose), you can disable reverse proxy by setting `ENABLE_REVERSE_PROXY=false` or leaving it unset.

## Architecture Details

### Encryption & Authentication

The client encrypts the target domain using AES-128-CBC with a random IV:
1. Generate random 16-byte IV
2. Prepend "tunnel://" to target address
3. Encrypt with AES-128-CBC using shared key
4. Base64 encode IV + ciphertext
5. Send in first gRPC request's `domain` field

The server decrypts and verifies:
1. Base64 decode
2. Extract IV (first 16 bytes) and ciphertext
3. Decrypt with AES-128-CBC
4. Verify "tunnel://" prefix to authenticate

### Stream Flow

**Forward Proxy (Connect RPC)**:
1. Client accepts local connection (SOCKS5/SNI/fixed)
2. Opens bidirectional gRPC stream to server
3. Sends encrypted target in first message
4. Forks two tasks:
   - Read from local → write to stream (with padding)
   - Read from stream → write to local
5. Server connects to actual target and relays data

**Reverse Proxy (Listen RPC)**:
1. Client opens gRPC stream and sends target port
2. Coroutine waits in `wait_pool` indexed by port
3. Server accepts connection on reverse proxy listener (e.g., port 3100)
4. Finds waiting agent for that port in pool
5. Wakes agent coroutine with the TCP connection
6. Bidirectional data relay begins

**KeepAlive (Unary RPC)**:
1. Client sends timestamp every 1 second
2. Server echoes timestamp back immediately
3. Client calculates round-trip latency
4. Latency reported as `tunnel_latency_ms` gauge metric

### Metrics

Both client and server export identical Prometheus metrics:
- `tunnel_grpc_streams_*` - Stream lifecycle tracking
- `tunnel_connections_*` - Connection counts by proxy type and port
- `tunnel_connection_bytes_*` - Bandwidth by direction
- `tunnel_domain_*` - Per-domain traffic (limited to top 100 domains)
- `tunnel_reverse_pool_*` - Reverse proxy agent pool status
- `tunnel_errors_*` - Error counters by type
- `tunnel_latency_ms` - Tunnel round-trip latency (client-side KeepAlive)

Access via HTTP endpoint at `:9001/metrics`

### Grafana Alloy Collection

**Client-side** (`config.client.alloy`):
- Scrapes tunnel-client:9001 metrics → local Prometheus
- Collects tunnel-client logs → local Loki
- All monitoring data stays in client intranet

**Server-side** (`config.server.alloy`):
- Scrapes tunnel-server:9001 metrics → sends to tunnel-server:9090 (reverse tunnel to client Prometheus)
- Collects tunnel-server logs → sends to tunnel-server:3100 (reverse tunnel to client Loki)
- Monitoring data tunneled back to client infrastructure

## Code Patterns

### Task Forking

The `silly.task.fork()` pattern is used extensively to create concurrent tasks:
- One task reads from local conn and writes to gRPC stream
- Another task reads from stream and writes to local conn
- Critical: Metrics decrement happens in only one task to avoid double-counting

### Connection Limiting

Both client and server call `conn:limit(1 * 1024 * 1024)` to set 1MB read buffer limits.

### Random Padding

All gRPC messages include random padding (0-512 bytes) in the `pad` field to obfuscate traffic patterns.

### Metrics Cardinality Control

Domain labels are limited to top 100 using `domain_tracker` table and `should_track_domain()` helper to prevent unbounded cardinality.

### DNS Resolution

Client uses `dns.lookup(host, dns.A)` to resolve container names (e.g., "loki:3100") before connecting.

## Port Mapping

**Client**:
- 1080: SOCKS5 proxy
- 443: TLS SNI proxy
- 993: Fixed IMAP proxy (→ imap.gmail.com:993)
- 9001: Prometheus metrics

**Server**:
- 443: gRPC tunnel listener
- 3100: Reverse proxy for Loki (tunneled back to client)
- 9090: Reverse proxy for Prometheus (tunneled back to client)
- 9001: Prometheus metrics

**External Mapping** (in docker-compose):
- Client: 9000:443 (not typically needed, client is internal)
- Server: 9000:443 (external access to gRPC tunnel)
- Grafana: 3000:3000 (dashboard access)

## Important Notes

- The server must be accessible at the address configured in `SERVER` env var
- Both client and server must share the same `KEY` (16 bytes)
- Reverse proxy agents automatically reconnect if stream closes
- Pool size must be sufficient (currently 1 agent per reverse port)
- All gRPC streams are bidirectional and handle both read and write concurrently
- The monitoring stack runs entirely on client side, with server metrics tunneled back
