#!/usr/bin/env bash
# 把某台机器上的 opencode 配置切到远程 jira MCP（幂等，自动备份）
# 用法: ./register-opencode.sh [mcp-url]
set -euo pipefail

URL="${1:-http://192.168.4.50:8789/mcp}"
CFG="${HOME}/.config/opencode/opencode.json"

[ -f "$CFG" ] || { echo "找不到 $CFG（该机器没装 opencode）" >&2; exit 1; }

cp "$CFG" "$CFG.bak.$(date +%s)"

python3 - "$CFG" "$URL" <<'PY'
import json, sys, pathlib
cfg_path, url = sys.argv[1], sys.argv[2]
p = pathlib.Path(cfg_path)
cfg = json.loads(p.read_text())
mcp = cfg.setdefault("mcp", {})

# 保留本地条目做回滚，但停用，避免同名工具重复
if "mcp-atlassian" in mcp:
    mcp["mcp-atlassian"]["enabled"] = False

mcp["jira"] = {
    "type": "remote",
    "url": url,
    "timeout": 300000,
    "enabled": True,
}
p.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
print(f"ok: jira -> {url}")
PY

python3 -c "import json,sys;json.load(open(sys.argv[1]));print('json valid')" "$CFG"
echo "重启 opencode 后生效（配置只在启动时读取）"