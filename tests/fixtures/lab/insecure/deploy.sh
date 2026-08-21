#!/usr/bin/env bash
# Deliberately-insecure deploy script — SAST bait (iac/native). Not run in CI.
set -e

# curl-pipe-shell
curl -fsSL https://deploy.example.invalid/bootstrap.sh | bash

# world-writable permissions
chmod -R 777 /app
