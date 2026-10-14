# syntax=docker/dockerfile:1
FROM golang:1.27.1-bookworm@sha256:8d48e12ec56735e9358640898b9d9b9fcca110612ed8a5567438c0a1baa24e66 AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download && go mod verify
COPY backend/ ./
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/bytelocker ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/bytelocker-admin ./cmd/admin && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/bytelocker-healthcheck ./cmd/healthcheck
RUN mkdir -p /runtime/data && chmod 0700 /runtime/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /usr/local/bin/
COPY --from=build --chown=10001:10001 /runtime/data /data
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/bytelocker"]
CMD ["-data-dir", "/data", "-api-address", "127.0.0.1:8080", "-health-address", "127.0.0.1:8081"]
