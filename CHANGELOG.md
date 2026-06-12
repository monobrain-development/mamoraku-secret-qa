# Changelog

## 0.3.0 — 2026-06-12

### Added

- Claude Code plugin パッケージング（marketplace 配布対応）
- `UserPromptSubmit` / `PreToolUse` / `PostToolUse` フックによるシークレット検出
- デバイスログインスキル（`/mamoraku-secret:login`）
- ログアウトスキル（`/mamoraku-secret:logout`）
- ステータス確認スキル（`/mamoraku-secret:status`）
- ブロック後の続行スキル（`/mamoraku-secret:continue`）
- フィードバックスキル（`/mamoraku-secret:feedback`）
- 一時停止スキル（`/mamoraku-secret:pause`）
- ローカルホワイトリスト（HMAC フィンガープリントによる完全一致）
- セッション承認フロー
- ML リランカー（xgboost）による誤検知抑制
- 30+ プロバイダー対応の正規表現ルール
- `xgboost` / `numpy` が未インストールの場合の graceful fallback
