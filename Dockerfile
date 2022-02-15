#Build
FROM --platform=$BUILDPLATFORM golang:latest AS build

WORKDIR /build
COPY . .

RUN go mod download && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /app -ldflags "-s -w" main.go

# Deploy
FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian11

WORKDIR /
COPY --from=build /app /

USER nonroot:nonroot

ENTRYPOINT ["/app"]