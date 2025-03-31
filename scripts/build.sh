#!/bin/bash
set -euo pipefail

docker build -f Dockerfile.builder_register -t local_builder_register:latest .