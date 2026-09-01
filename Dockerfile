FROM --platform=$BUILDPLATFORM golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG SOURCE_REVISION
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY protocol ./protocol
RUN test -n "$SOURCE_REVISION" \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/server ./cmd/server \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/admin ./cmd/admin \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/huaxianyan/SevenMirror-Server" \
      org.opencontainers.image.revision="$SOURCE_REVISION"
COPY --chown=nonroot:nonroot --from=build /out /app
WORKDIR /app
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/server"]
