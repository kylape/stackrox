#!/usr/bin/bash

mkdir -p content/amd64
mkdir -p content/arm64
cd content

# x86
curl https://go.dev/dl/go1.24.4.linux-amd64.tar.gz -L > amd64/go.tar.gz
curl https://dl.min.io/client/mc/release/linux-amd64/mc -L > amd64/mc
chmod +x amd64/mc

# arm
curl https://go.dev/dl/go1.24.4.linux-arm64.tar.gz -L > arm64/go.tar.gz
curl https://dl.min.io/client/mc/release/linux-arm64/mc -L > arm64/mc
chmod +x arm64/mc

arch_dir=amd64
case "$(uname -m)" in
    amd64)
        arch_dir=amd64 ;;
    aarch64)
        arch_dir=arm64 ;;
    *)
        echo "Unsupported architecture"
        exit 1 ;;
esac

# This assumes the bundle has alread been placed here by hand for now at least
$arch_dir/mc alias set minio http://minio:9000 minioadmin minioadmin
$arch_dir/mc get minio/bundle/bundle.zip .
