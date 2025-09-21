# Build stage
FROM rust:1.90 as builder

WORKDIR /app
COPY . .

# Build the signalling server from workspace root
RUN cargo build --release --bin signalling-server

# Runtime stage
FROM debian:bookworm-slim

# Install dependencies for runtime
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /app/target/release/signalling-server /usr/local/bin/signalling-server

# Create a non-root user and log directory
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/logs && \
    chown appuser:appuser /app/logs

USER appuser
WORKDIR /app/logs

EXPOSE 2794

CMD ["signalling-server"]
