#!/usr/bin/env bash
# 清理过期附件（默认保留 30 天）
# 用法: ./cleanup.sh [days] [data-dir]
set -euo pipefail

DAYS="${1:-30}"
DIR="${2:-$HOME/docker/jira-mcp/data}"

[ -d "$DIR" ] || { echo "目录不存在: $DIR" >&2; exit 1; }

echo "清理 $DIR 下修改时间超过 ${DAYS} 天的文件"
find "$DIR" -type f -mtime "+${DAYS}" -print -delete | sed 's/^/  removed /'
find "$DIR" -mindepth 1 -type d -empty -delete
du -sh "$DIR"