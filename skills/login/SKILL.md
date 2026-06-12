---
description: Start Mamoraku Secret device login and save local config.
allowed-tools: Bash
---

# Mamoraku Secret Login

This skill performs a two-phase device login. Execute each phase in order.

## Phase 1 — Get the verification URL

Run this command to call the start API and save the device code locally:

```bash
python3 - <<'EOF'
import json, sys, urllib.request
from pathlib import Path

API = "https://mamoraku-secret-api-954273464710.us-central1.run.app"
req = urllib.request.Request(
    f"{API}/v1/auth/device/start",
    data=json.dumps({"client": "claude_code", "plugin_version": "0.3.0", "runtime_version": "0.1.0", "os": "linux"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=15) as r:
    resp = json.loads(r.read())

pending = Path.home() / ".mamoraku-secret" / "pending_login.json"
pending.parent.mkdir(parents=True, exist_ok=True)
pending.write_text(json.dumps(resp))

print(f"verification_url: {resp['verification_url']}")
print(f"user_code: {resp['user_code']}")
print(f"expires_in: {resp['expires_in']}s")
EOF
```

After this command succeeds, show the `verification_url` to the user and instruct them to:
1. Open the URL in their browser
2. Log in with Google if prompted
3. Click **承認する** on the device approval page
4. Come back and say "承認しました" or similar

Wait for the user to confirm approval before proceeding to Phase 2.

## Phase 2 — Poll for completion

After the user confirms they approved, run:

```bash
PENDING="$HOME/.mamoraku-secret/pending_login.json"
if [ ! -f "$PENDING" ]; then
  echo "pending_login.json が見つかりません。もう一度 /mamoraku-secret:login を実行してください。" >&2
  exit 1
fi
DEVICE_CODE=$(python3 -c "import json; print(json.load(open('$PENDING'))['device_code'])")

if command -v mamoraku-secret >/dev/null 2>&1; then
  mamoraku-secret login --device-code "$DEVICE_CODE" --max-wait 60
else
  echo "mamoraku-secret が見つかりません。/reload-plugins 後に再実行してください。" >&2
  exit 1
fi

rm -f "$PENDING"
```

If login succeeds, report "ログイン完了しました。" to the user.
If it fails with timeout, ask the user to run `/mamoraku-secret:login` again.
