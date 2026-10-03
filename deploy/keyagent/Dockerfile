# SVX key agent container image. Build from the repository root:
#
#   docker build -f deploy/keyagent/Dockerfile -t svx-keyagent .
#
# The runtime image has no shell or package manager and runs as an
# unprivileged user (UID 65532). See docs/key-agent.md.

# Latest stable Rust (the workspace needs 1.88+).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p svx-keyagent \
 && strip target/release/svx-keyagent

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/svx-keyagent /usr/local/bin/svx-keyagent
USER 65532:65532
ENV SVX_KEYAGENT_CONFIG=/etc/svx/agent.toml
EXPOSE 9443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["/usr/local/bin/svx-keyagent", "healthcheck", "--addr", "127.0.0.1:9443"]
ENTRYPOINT ["/usr/local/bin/svx-keyagent"]
CMD ["serve"]
