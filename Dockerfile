# One static-ish binary on a distroless base: the gateway needs no shell,
# package manager or interpreter at run time.
FROM rust:1.98.1-bookworm AS build
WORKDIR /source
COPY . .
RUN cargo build --release --locked --bin gateway && mkdir -p /state/reqlog

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /source/target/release/gateway /usr/local/bin/gateway
# Where captured requests are kept when capture is on; a volume mounted here
# takes this owner, so the unprivileged gateway can write to it.
COPY --from=build --chown=65532:65532 /state /var/lib/gateway
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["serve", "/etc/gateway/gateway.toml"]
