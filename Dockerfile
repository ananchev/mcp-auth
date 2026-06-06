# Build
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/mcp-auth ./cmd/server

# Run
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-auth /mcp-auth
# Refresh-token store persists here — mount a volume at /data.
VOLUME ["/data"]
EXPOSE 8092
ENTRYPOINT ["/mcp-auth"]
