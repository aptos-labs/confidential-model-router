# Confidential Inference Router

Tinfoil's confidential inference model router terminates TLS connections (optionally with EHBP), inspects the model name, and directs it to a verified secure inference enclave.

## License and Aptos Labs modifications

This repository is Aptos Labs' modified version of
[tinfoilsh/confidential-model-router](https://github.com/tinfoilsh/confidential-model-router),
released under the GNU Affero General Public License v3 (see `LICENSE`).
Aptos Labs runs it as `router.inference.aptoslabs.com`.

**Source offer (AGPL-3.0 section 13).** Every router response carries the
`X-Source-Code` and `X-License` headers. `GET /source` (also `/`) and `GET /health`
return the license and the URL of the Corresponding Source of the running build.
For builds published by the `Publish Aptos router image` workflow, that URL is the
exact source commit: `https://github.com/aptos-labs/confidential-model-router/tree/<commit>`.

Aptos Labs modifications, based on upstream `v0.0.142`:

| Date | Change | Files |
|---|---|---|
| 2026-09-11 | Route synchronous video multipart requests (`/v1/videos/sync`) without rewriting bodies | `main.go`, `video_sync.go`, `video_sync_test.go`, `video_sync_handler_test.go`, `manager/router_video_test_support.go` |
| 2026-09-11 | Test preservation of multimodal SSE metadata and final audio chunks | `tokencount/omni_stream_test.go` |
| 2026-09-12 | Enforce rate and priority admission for video requests | `main.go`, `video_sync_handler_test.go` |
| 2026-10-05 | AGPL-3.0 source offer (headers, `/source`, `/`, `/health` fields); license file and label in the image | `main.go`, `source_offer.go`, `source_offer_test.go`, `source_offer_router_test.go`, `video_sync_handler_test.go`, `Dockerfile`, `README.md` |

The full history is in this repository's git log.

## Request bodies

The router accepts OpenAI-compatible bodies on `/v1/chat/completions` and `/v1/responses`. A few Tinfoil-specific top-level fields are recognized and stripped before the body is forwarded to the model enclave:

- `code_execution_options` — activates the code-execution tool profile. When code execution is requested, this object carries the per-request credentials (`accessToken`, `encryptionKey`, `containerAuthToken`).
- `web_search_options` — activates the web-search tool profile.
- `pii_check_options` — activates the PII safety check.

`POST /v1/videos/sync` requires `multipart/form-data` with exactly one nonempty
text `model` field naming a configured model. Surrounding whitespace, duplicate
selectors (including file parts named `model`), encoded selectors, and malformed
forms are rejected. The selector is required even on a model subdomain; forwarded
host headers cannot override it. The multipart bytes, Content-Type boundary, and
Authorization are forwarded unchanged. Forms allow at most 128 parts total
(including files and the model field), and the model field is limited to 256 bytes,
not characters. Exceeding either cap returns 400. The existing 64 MiB request limit
applies to POST bodies.
Invalid forms return an OpenAI-style 400 error, unsupported media types 415,
non-POST methods 405 (`Allow: POST`), oversized POST bodies 413, and unknown models
404. Non-POST requests to the exact `/v1/videos/sync` path return 405 before any
body-size check, even for oversized bodies. Other endpoints retain their existing
body-size limits.

Video admission uses the control-plane route context for the caller's org and
configured priority. As on JSON inference requests, configured-priority callers
are exempt from per-key RPM limits and overload shedding; this is an admission
exemption only, not a multipart priority injection. Other callers use the shared
per-key (OAuth subject for access tokens), per-model minute counters and receive
429 with a rounded-up `Retry-After` at the configured hard limit. Since video has
no trusted queue-priority transport, the soft limit also returns 429 instead of
silently skipping demotion or rewriting the form as JSON. Failed route-context
lookups grant no priority exemption. Client-supplied multipart `priority` parts
(including files) return 400, even for configured-priority callers. Admitted
multipart bodies and their Content-Type and Authorization remain unchanged.

This selects a configured model; it does not validate video capability (the model
configuration has no endpoint allowlist or capability field). Rejecting configured
but video-incompatible models is a follow-up, not implemented in this draft.

Video parser regressions run with `go test . -run 'TestVideo'`. Focused integration
coverage runs with `go test -tags routertest . -run 'TestVideoRouter'`; that tag
only enables an in-memory manager fixture, avoiding attestation and background
services while exercising the real handler, model selection, and reverse proxy.
This is a review draft, not a deployment-readiness claim.

## Tool Calling

Client side tool calling is handled by the client. Server-side tools currently supported: **web search** and **code execution**.

To handle prompting, we add some instructions about how to call each tool in the system prompt, and we have a short description in each tool.

_vLLM handles putting the system prompt + the tool prompts together, using internal templates built for the specific models._
