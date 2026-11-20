#!/usr/bin/env bash
# 构建自建镜像（在 fork 仓库根目录执行）
# 用法: deploy/build.sh [tag]
set -euo pipefail

TAG="${1:-0.24.7-jiral.1}"
VERSION="${TAG%%-*}"

cd "$(dirname "$0")/.."
echo "building mcp-atlassian-jiral:${TAG} (VERSION=${VERSION})"
docker build --build-arg "VERSION=${VERSION}" -t "mcp-atlassian-jiral:${TAG}" .
docker image inspect "mcp-atlassian-jiral:${TAG}" --format 'built {{.Id}} {{.Size}} bytes'