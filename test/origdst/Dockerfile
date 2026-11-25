# The integration test's original-destination stand-in: the BPF program and its loader.
# Test fixture only; it runs privileged.
FROM debian:trixie-slim AS bpf
RUN apt-get update && apt-get install -y --no-install-recommends clang libbpf-dev && rm -rf /var/lib/apt/lists/*
COPY test/origdst/bpf/origdst.bpf.c /src/origdst.bpf.c
# The object is BPF bytecode, the same for every platform this is built on.
RUN clang -O2 -g -Wall -Werror -target bpf -I"/usr/include/$(uname -m)-linux-gnu" -c /src/origdst.bpf.c -o /origdst.bpf.o

FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie AS builder
ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /work
ARG TARGETOS TARGETARCH
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/origdst ./test/origdst

# The root variant: loading a program and attaching it to a cgroup needs root.
FROM gcr.io/distroless/static-debian13@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a
COPY --from=builder /out/origdst /usr/bin/origdst
COPY --from=bpf /origdst.bpf.o /bpf/origdst.bpf.o
ENTRYPOINT ["origdst"]
