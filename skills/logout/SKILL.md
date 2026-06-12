---
description: Log out of Mamoraku Secret by removing local auth credentials.
allowed-tools: Bash
---

# Mamoraku Secret Logout

ローカルに保存されている認証情報を削除してログアウトします。

```bash
python3 - <<'EOF'
from pathlib import Path

app_dir = Path.home() / ".mamoraku-secret"
removed = []

for name in ("config.json", "pending_login.json"):
    f = app_dir / name
    if f.exists():
        f.unlink()
        removed.append(name)

if removed:
    print("削除しました: " + ", ".join(removed))
else:
    print("削除対象のファイルが見つかりませんでした（すでにログアウト済みか未ログイン）。")
EOF
```

コマンドが成功したら「ログアウトしました。」と報告してください。
