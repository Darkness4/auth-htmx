# ---
FROM --platform=$BUILDPLATFORM registry-1.docker.io/library/alpine:latest as certs
RUN apk update && apk add --no-cache ca-certificates

# ---
FROM --platform=$BUILDPLATFORM registry-1.docker.io/library/golang:1.21.5 as builder
WORKDIR /build/
COPY go.mod go.sum ./
RUN go mod download

ARG TARGETOS TARGETARCH VERSION
COPY . /build/

RUN --mount=type=cache,target=/root/.cache/go-build \
  --mount=type=cache,target=/go/pkg \
  CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -ldflags "-s -w -X main.version=${VERSION}" -o /out/auth-htmx ./main.go

# ---
FROM registry-1.docker.io/library/busybox:1.36.1

ARG TARGETOS TARGETARCH

ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-$TARGETARCH /tini
RUN chmod +x /tini

RUN mkdir /app
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app

COPY --from=builder /out/auth-htmx .
COPY --from=certs /etc/ssl/certs /etc/ssl/certs

RUN chown -R app:app .
USER app

EXPOSE 3000

ENTRYPOINT ["/tini", "--", "/app/auth-htmx"]
