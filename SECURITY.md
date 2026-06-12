# Security Policy

## Reporting a Vulnerability

セキュリティ上の脆弱性を発見した場合は、Issue ではなく以下のメールアドレスへ非公開でご報告ください。

Email: info@monobrain.jp

報告時には以下を含めてください：

- 影響を受けるバージョン
- 再現手順
- 期待される動作と実際の動作
- シークレット値を**必ず削除・マスクした**ログや出力

## Data Handling

Mamoraku Secret は Claude Code セッション内でシークレット検出をローカルで行います。

バグ報告や Issue の本文・添付ファイルに、実際の API キー・トークン・認証情報・秘密鍵を含めないでください。

## Network Access

ログインしていない状態では、ネットワーク通信は行いません。

ログイン後は、以下の目的で Mamoraku Secret API と通信する場合があります：

- デバイス認証（Google OAuth）
- ルールセットの同期
- 検出イベントの記録

ローカルデータは以下に保存されます：

```
~/.mamoraku-secret/
  config.json
  findings.jsonl
  whitelist.json
  device_secret
```
