# Sandboxed Agentic Tools (MCP Server on Spin)

A high-performance, sandboxed Model Context Protocol (MCP) server written in Rust and executed as a WebAssembly component using [Spin](https://spinframework.dev).

## Exposed Tools

### `calculate_hash`

Computes the deterministic cryptographic SHA-256 checksum of the provided text data.

**Input Schema**:
```json
{
  "data": "Text payload to hash"
}
```
**Output**:
```json
{
  "sha256": "eeed4e41a4a2ca2ae378df140dbe1eea73bcc8ca3ca34cb5cd1c64089bf2b52d"
}
```

### `redact_secrets`

Scans untrusted text and redacts sensitive patterns (API keys, bearer tokens, passwords, and email addresses) before the agent logs or forwards data.

**Input Schema**:
```json
{
  "text": "Payload containing potential credentials"
}
```

**Output**:
```json
{
  "sanitized": "Text with secrets replaced by [REDACTED] and [REDACTED_EMAIL]"
}
```

### Building and Running
```bash
# Build the Wasm component
spin build

# Start the Spin HTTP server
spin up
```
The server listens on `http://127.0.0.1:3000`.

---

## Testing the Tools

### Inspect Available Tools

```bash
curl -X POST http://127.0.0.1:3000 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list"
  }'
```

### Execute `calculate_hash` 

```bash
curl -X POST http://127.0.0.1:3000 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "calculate_hash",
      "arguments": {
        "data": "Hello, Spin!"
      }
    }
  }'
```

### Execute `redact_secrets`

```bash
curl -X POST http://127.0.0.1:3000 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "redact_secrets",
      "arguments": {
        "text": "Contact alice@example.com with api_key=sk-secret123"
      }
    }
  }'
```

## Connecting to Claude Desktop / MCP Clients

Add this server to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sandboxed-tools": {
      "command": "curl",
      "args": [
        "-s",
        "-X", "POST",
        "http://127.0.0.1:3000",
        "-H", "Content-Type: application/json",
        "-d"
      ]
    }
  }
}
```