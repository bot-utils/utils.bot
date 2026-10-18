#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build/payment
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -tags lambda.norpc -ldflags='-s -w' -o build/payment/bootstrap ./cmd/payment
