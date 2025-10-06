#LABEL authors="SinKa"

# Multi-stage build with Alpine for smaller image
FROM golang:1.25-alpine AS builder

# Install build dependencies - use edge repo for newer vips version
RUN apk add --no-cache \
    gcc \
    g++ \
    musl-dev \
    pkgconfig

# Install newer vips from edge repository (contains vips 8.15+)
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    vips-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build with static linking for Alpine
RUN CGO_ENABLED=1 GOOS=linux go build -o /app/service .

# Runtime stage
FROM alpine:latest

# Install only runtime vips library from edge
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    vips \
    libheif \
    imagemagick \
    ca-certificates

WORKDIR /app

COPY --from=builder /app/service /app/service


# use unprivileged user
RUN useradd -u 1000 -m app || true
USER 1000

EXPOSE 8080
CMD ["/app/service"]
