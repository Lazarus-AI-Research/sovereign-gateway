# One static-ish binary on a distroless base: the gateway needs no shell,
# package manager or interpreter at run time.
FROM rust:1.98.1-bookworm AS build
WORKDIR /source
COPY . .
RUN cargo build --release --locked --bin gateway

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /source/target/release/gateway /usr/local/bin/gateway
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]
CMD ["serve", "/etc/gateway/gateway.toml"]
