FROM golang:1.25.13-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY protocol ./protocol
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/admin ./cmd/admin \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --chown=nonroot:nonroot --from=build /out /app
WORKDIR /app
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/server"]
