---
description: Help the user continue after Secret Protector asks for confirmation or blocks a secret-like tool call.
disable-model-invocation: true
allowed-tools: Bash
---

# Secret Protector Continue

Use this when the user wants to continue after a Secret Protector warning.

Tell the user:

1. If Claude Code showed a native confirmation prompt, choose approve only after confirming the value is safe.
2. If the operation was blocked, offer 3 choices:
   - このセッションで承認: `mamoraku-secret continue $ARGUMENTS`
   - この値を今後も承認: `mamoraku-secret continue $ARGUMENTS --whitelist`
   - キャンセルして修正してから再実行.
   - Promptブロックでは `1` / `2` / `3` の単独入力でも選択可能.
3. Then retry the original request.

Never reveal or repeat the secret value.
If the user provided a Finding ID, use it as `$ARGUMENTS`.
