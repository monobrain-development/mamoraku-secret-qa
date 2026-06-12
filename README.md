# Mamoraku Secret

Mamoraku Secret は、Claude Code セッション中の APIキー・トークン・認証情報・秘密鍵などの誤送信を防ぐためのシークレット検出プラグインです。

ユーザー入力・Bash実行・ファイル書き込み・ツール実行結果をフックで監視し、検出時にはブロック、セッション承認、ローカルホワイトリスト登録を選べます。

## インストール

マーケットプレイスを追加:

```bash
/plugin marketplace add mamoraku/mamoraku-secret
```

プラグインをインストール:

```bash
/plugin install mamoraku-secret@mamoraku-secret
```

リロード:

```bash
/reload-plugins
```

動作確認:

```bash
/mamoraku-secret:status
```

### CLI でのインストール

```bash
claude plugin marketplace add mamoraku/mamoraku-secret
claude plugin install mamoraku-secret@mamoraku-secret
```

### ローカル開発

```bash
git clone https://github.com/monobrain-development/mamoraku-secret-qa.git
cd REPO
claude --plugin-dir .
```

## スキル一覧

| スキル | 説明 |
|---|---|
| `/mamoraku-secret:login` | Google OAuth でログイン |
| `/mamoraku-secret:logout` | ログアウト（ローカル認証情報を削除） |
| `/mamoraku-secret:status` | 検出状況・ログイン状態を確認 |
| `/mamoraku-secret:continue` | ブロック後にセッション承認して続行 |
| `/mamoraku-secret:feedback` | 検出結果にフィードバック（誤検知報告など） |
| `/mamoraku-secret:pause` | 検出を一時停止 / 再開 |

## 検出時の操作

シークレットが検出されると以下の3択が提示されます。

```
1) このセッションで承認: mamoraku-secret continue <finding_id> --session-key <key>
2) この値を今後も承認: mamoraku-secret continue <finding_id> --whitelist
3) キャンセルして修正
```

Claude Code のプロンプトに `1` / `2` / `3` を入力するだけでも選択できます。

## 依存関係

コア検出機能は Python 標準ライブラリのみで動作します。

ML リランカー（誤検知抑制）を有効にするには追加インストールが必要です:

```bash
pip install -r requirements.txt
```

`numpy` または `xgboost` が未インストールの場合、ML リランカーは無効になり、正規表現・エントロピー検出のみで動作します。

## ネットワークアクセスとローカルデータ

ログインしていない状態ではネットワーク通信は行いません。ローカルデータはすべて以下に保存されます：

```
~/.mamoraku-secret/
  config.json        # ログイン設定
  findings.jsonl     # 検出ログ
  whitelist.json     # ホワイトリスト
  device_secret      # デバイス識別子
```

ログイン後は、ルールセット同期・イベント記録のために Mamoraku Secret API と通信します。

## 対応プロバイダー（抜粋）

GitHub · AWS · GitLab · Slack · Stripe · OpenAI · Anthropic · Google · Firebase · Twilio · SendGrid · Discord · Telegram · Shopify · Notion · Linear · npm · Mailchimp · Databricks · Cloudflare · Azure · JWT · PEM秘密鍵 · その他

## アンインストール

```bash
/plugin uninstall mamoraku-secret@mamoraku-secret
```

CLI:

```bash
claude plugin uninstall mamoraku-secret@mamoraku-secret
```

ローカルデータを保持したままアンインストール:

```bash
claude plugin uninstall mamoraku-secret@mamoraku-secret --keep-data
```

## 動作モードのカスタマイズ

| 変数 | デフォルト | 説明 |
|---|---|---|
| `SP_DEMO_TOOL_ACTION` | `deny` | ツール実行前の検出時の動作（`ask` / `deny` / `alert`） |
| `SP_DEMO_PROMPT_ACTION` | `block` | ユーザー入力検出時の動作 |

## ライセンス

MIT — 詳細は [LICENSE](LICENSE) を参照してください。
