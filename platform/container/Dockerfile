# syntax=docker/dockerfile:1.7
# Reproducible OCI image for seck-reader (Approach C sandbox).
# distroless/cc gives us libc + libstdc++ without a shell, busybox,
# curl, or any other userland tooling. Pinned by digest.
FROM gcr.io/distroless/cc-debian12@sha256:1a0c87f51637e90f6e34da3f0ba1a39a36b71fdbf69b9d61a5b2f1c8f8cf3027 AS base

# Bring in ONLY the two binaries we need. Both built externally so we
# can apply the same RUSTFLAGS / SOURCE_DATE_EPOCH as the host build.
COPY --chmod=0555 ./seck-reader      /usr/bin/seck-reader
COPY --chmod=0555 ./llama-cli        /usr/bin/llama-cli
COPY --chmod=0444 ./seccomp.bpf.toml /etc/seck/seccomp.bpf.toml
COPY --chmod=0444 ./landlock.toml    /etc/seck/landlock.toml

USER 65534:65534
ENTRYPOINT ["/usr/bin/seck-reader", "--protocol-version=1"]
