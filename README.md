# Confidential Inference Router

Tinfoil's model router is the entry point for confidential inference. It terminates TLS (optionally with [EHBP](https://docs.tinfoil.sh/resources/ehbp)), reads the model name from an OpenAI-compatible request, and forwards the request to a verified secure enclave serving that model.

## License and Aptos Labs modifications

This repository is Aptos Labs' modified version of
[tinfoilsh/confidential-model-router](https://github.com/tinfoilsh/confidential-model-router),
released under the GNU Affero General Public License v3 (see `LICENSE`).
Aptos Labs runs it as `router.inference.aptoslabs.com`.

**Source offer (AGPL-3.0 section 13).** Every router response carries the
`X-Source-Code` and `X-License` headers. `GET /source` (also `/`) and `GET /health`
return the license and the URL of the Corresponding Source of the running build.
For builds published with an `aptos-<commit>` version, that URL is the exact
source commit: `https://github.com/aptos-labs/confidential-model-router/tree/<commit>`.

Aptos Labs modifications, carried onto current upstream:

| Date | Change | Files |
|---|---|---|
| 2026-09-11 | Route synchronous video multipart requests (`/v1/videos/sync`) without rewriting bodies | `main.go`, `video_sync.go`, `video_sync_test.go`, `video_sync_handler_test.go`, `manager/router_video_test_support.go` |
| 2026-09-11 | Test preservation of multimodal SSE metadata and final audio chunks | `tokencount/omni_stream_test.go` |
| 2026-09-12 | Enforce rate and priority admission for video requests | `main.go`, `video_sync_handler_test.go` |
| 2026-10-05 | AGPL-3.0 source offer (headers, `/source`, `/`, `/health` fields); license file and label in the image | `main.go`, `source_offer.go`, `source_offer_test.go`, `source_offer_router_test.go`, `Dockerfile`, `README.md` |

The full history is in this repository's git log.

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

## Backend inference authentication

A model can opt into a backend-only bearer credential in runtime YAML:

```yaml
models:
  private-model:
    repo: owner/model
    enclaves: [inference.example.com:443]
    backend_auth_env: PRIVATE_MODEL_BACKEND_TOKEN
```

Inject `PRIVATE_MODEL_BACKEND_TOKEN` into the router process using your deployment's
secret mechanism. Its value is the **raw token**, without a `Bearer ` prefix.
Do not put the token in YAML, command-line arguments, or source control. Startup
fails before attestation if a referenced variable is unset, empty, surrounded by
whitespace, longer than 512 bytes, or not printable ASCII; errors identify the
model and variable, not the token. The model must name at least one enclave.

Credentials are snapshotted once at startup, scoped to the configured model and
exact HTTPS host (including an explicit port). A different model sharing a host,
a different host/port, or plaintext HTTP does not receive this credential. Restart
with updated configuration/environment to rotate tokens or authorize new hosts;
runtime configuration refresh does not expand the startup credential snapshot.
Omitting `backend_auth_env` preserves the caller authorization.

The credential replaces only the outbound `Authorization` on proxied inference
and internal model dispatches. The incoming customer's identity remains the
source for billing, route-context lookup, and admission. Client-supplied
original-identity headers are not trusted.

Internal inference requests for opted-in models do not follow redirects, even to
the same origin; they return the 3xx response to the caller. The reverse proxy
also returns redirects without following them. This avoids replaying the backend
token at redirect destinations. Backend metrics polling continues to use its
separate `--metrics-api-key` / `METRICS_API_KEY` monitoring credential; it never
uses `backend_auth_env`. This option does not alter attestation or TLS pinning.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
