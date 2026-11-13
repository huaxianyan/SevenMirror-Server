FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
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
