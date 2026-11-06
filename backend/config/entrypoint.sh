#!/bin/sh
set -e

# Configuration comes from environment variables (see .env.example), read by
# services/config.py on top of the defaults in /app/config/config.yaml, which is
# part of the image. Nothing needs to be mounted, and nothing is written back
# into the config file.
PORT="${PORT:-7000}"
echo "Starting uvicorn on port ${PORT}..."

exec uvicorn main:app \
  --host 0.0.0.0 \
  --port "$PORT"
