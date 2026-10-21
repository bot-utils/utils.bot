#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build/image
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o build/image/bootstrap ./cmd/csv-prototype
cp Dockerfile build/image/Dockerfile
docker build --network=none -t utils-bot-csv-prototype:local build/image
go build -trimpath -o build/csv-prototype ./cmd/csv-prototype
