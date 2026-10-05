# Modified by Aptos Labs on 2026-10-05: ship the AGPL-3.0 license text and an OCI license
# label in the runtime image. Licensed under the GNU AGPL v3.

FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder

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
