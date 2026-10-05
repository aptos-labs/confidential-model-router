# Modified by Aptos Labs on 2026-10-05: ship the AGPL-3.0 license text and an OCI license
# label in the runtime image. Licensed under the GNU AGPL v3.

FROM golang:1.26.6-alpine3.23@sha256:e57c41c1d5864341031181b0db34b9a537bb5773eb6428e4e5bdaea0f9135406 AS builder

WORKDIR /app

ARG VERSION

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION}" \
    -o proxy

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

WORKDIR /app

COPY --from=builder /app/proxy .
COPY --from=builder /app/LICENSE /usr/share/licenses/confidential-model-router/LICENSE

LABEL org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.source="https://github.com/aptos-labs/confidential-model-router"

EXPOSE 8089

ENTRYPOINT ["./proxy"]
