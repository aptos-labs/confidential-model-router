# Confidential Inference Router

Tinfoil's model router is the entry point for confidential inference. It terminates TLS (optionally with [EHBP](https://docs.tinfoil.sh/resources/ehbp)), reads the model name from an OpenAI-compatible request, and forwards the request to a verified secure enclave serving that model.

## How it works

For each request the router:

1. Authenticates the caller and checks rate limits with the control plane
2. Resolves the requested model (or picks one for `model: "auto"`) to a healthy enclave
3. Runs any server-side tools the request asked for (web search, PII check)
4. Streams the enclave's response back to the client

## Synchronous video

`POST /v1/videos/sync` requires `multipart/form-data` with exactly one nonempty text `model` field naming a configured model. The multipart bytes, Content-Type boundary, and Authorization are forwarded unchanged. Forms allow at most 128 parts, and the model field is limited to 256 bytes. The 64 MiB request limit applies to POST bodies.

Invalid forms return an OpenAI-style 400 error, unsupported media types 415, non-POST methods 405 (`Allow: POST`), oversized POST bodies 413, and unknown models 404. Non-POST requests to the exact `/v1/videos/sync` path return 405 before any body-size check. This selects a configured model; it does not validate video capability.

Video admission uses the same control-plane route context as other inference requests. A rejected quota decision returns 429. A demotion also returns 429, because the multipart body has no trusted priority field to rewrite. Configured priority skips that demotion and overload shedding, and it is not copied into the form. Client `priority` parts, including files, return 400. Admitted bodies, Content-Type, and Authorization are forwarded unchanged.

Video parser regressions run with `go test . -run 'TestVideo'`. Focused integration coverage runs with `go test -tags routertest . -run 'TestVideoRouter'`.

Client-facing behavior is documented at [docs.tinfoil.sh](https://docs.tinfoil.sh):

- [Models](https://docs.tinfoil.sh/models/overview)
- [Reasoning](https://docs.tinfoil.sh/guides/reasoning)
- [Web search](https://docs.tinfoil.sh/guides/web-search)
- [Tool calling](https://docs.tinfoil.sh/guides/tool-calling)
- [Direct API access](https://docs.tinfoil.sh/sdk/direct-api-access)

## Architecture Overview

- **[main.go](main.go)**: Request handling, model resolution, and forwarding to enclaves
- **[autoroute/](autoroute/)**: Model and reasoning-effort selection for `model: "auto"`
- **[route_context.go](route_context.go)**: Admission and rate-limit decisions from the control plane
- **[toolruntime/](toolruntime/)**: Server-side tool loops (web search)
- **[billing/](billing/)**: Usage reporting

Pool selection and overload settings are described in [Routing](docs/routing.md).

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
