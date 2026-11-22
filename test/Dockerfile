# Test fixtures only: the mock provider, the load drivers and the integration client.
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie AS builder

ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/ ./test/mock-anthropic ./test/sniflood ./test/latbench ./test/streamcheck

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

COPY --from=builder /out/ /usr/bin/

USER 65532:65532
