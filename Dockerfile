# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY . .

RUN go mod tidy

RUN go build -o server ./cmd/main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/server .

# Run the application
CMD ["./server", "-config", "config/config.yaml"] 