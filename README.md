# encproxy

encproxy is an OpenAI-compatible proxy for routing chat completion requests to verified confidential inference providers.

It keeps plaintext providers out of confidential routing, normalizes model names for failover, and only exposes models that pass the local confidentiality policy.

## Features

- `POST /v1/chat/completions`
- `GET /v1/models`
- `GET /v1/confidentiality`
- API key authorization
- SQLite-backed provider, model, attestation, and usage state
- Provider failover across matching confidential models
- Attestation refresh for supported providers

## Quick Start

```sh
cp encproxy.example.toml encproxy.toml
go run . -config encproxy.toml -init
go run . -config encproxy.toml
```

Provider API keys are read from environment variables:

```sh
export TINFOIL_API_KEY=...
export PPQ_API_KEY=...
export REDPILL_API_KEY=...
export NANOGPT_API_KEY=...
export NEAR_API_KEY=...
export CHUTES_API_KEY=...
export PRIVATEMODE_API_KEY=...
```

Fetch provider models:

```sh
go run . -config encproxy.toml -fetch-models
```

Run tests:

```sh
go test ./...
```

## Configuration

Use `encproxy.example.toml` as the starting point. Keep `encproxy.toml`, `.env`, SQLite databases, and built binaries out of Git.

By default, the proxy is configured for confidential-only serving. Model listing and routing use an explicit policy so known non-confidential hosted model families are not exposed.
