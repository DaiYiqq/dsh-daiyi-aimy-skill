# dsh-daiyi-aimy-skill

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README.en.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <b>日本語</b>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="package.json"><img alt="Node" src="https://img.shields.io/badge/node-%5E22.19%20%7C%7C%20%3E%3D24-brightgreen.svg"></a>
  <a href="package.json"><img alt="DSH" src="https://img.shields.io/badge/DSH-%3E%3D0.2.0--rc.1-6f42c1.svg"></a>
  <img alt="dependencies" src="https://img.shields.io/badge/runtime%20deps-0-success.svg">
  <a href="https://github.com/zxz0119/aimy-sikll"><img alt="upstream" src="https://img.shields.io/badge/upstream-aimy--sikll%20v2.0.0-orange.svg"></a>
</p>

> **DeepSeek Harness 向けの、認可スコープ内での偵察と Web 脆弱性検出：8 つのネイティブツール + 8 つのスキル、既定で拒否（deny-by-default）、検出のみ。**

`dsh-daiyi-aimy-skill` は、[zxz0119/aimy-sikll](https://github.com/zxz0119/aimy-sikll)（Python CLI、v2.0.0）から再開発した **DeepSeek Harness (DSH) の Cordis プラグイン**です。上流のコマンドラインスクリプトを常駐型のネイティブツールに作り替え、さらに上流にはなかったものを追加しました。それが **認可スコープゲート**で、スコープが登録されていなければネットワーク系ツールは一切実行されません。

- 形態: ESM の Cordis プラグイン、**実行時のサードパーティ依存はゼロ**（`node:` 組み込みのみ）。
- ホスト: DSH `>=0.2.0-rc.1 <0.3.0`、Node `^22.19 || >=24`。
- バージョン: `3.0.0`、MIT、著者 戴亿。

## 機能

| 機能 | 説明 |
|---|---|
| **8 つのモデル呼び出し可能ツール** | スコープ、偵察、ポート、ディレクトリファジング、クロール、Web スキャン、JWT 監査、レポート |
| **既定で拒否（deny-by-default）** | すべてのネットワーク対象は `aimy_scope` を通じて登録する必要があります。未登録の対象はヒント付きで拒否されます |
| **認可記録と監査** | 各スコープエントリには書面による認可メモ（8 文字以上）と任意の有効期限が必要で、変更は監査ログに記録されます |
| **12 の検出 + 3 の偵察モジュール** | 検出: sqli / xss / cmdi / ssti / ssrf / nosqli / lfi / cors / jwt / graphql / proto-pollution / headers、偵察: crawler / param-miner / tech-fingerprint。ポートとディレクトリの探査はツール層にあります |
| **単一のネットワーク出口** | すべてのリクエストは `lib/http.js` のガード付きプローブを通ります。リクエストごとのスコープ検査、予算、タイムアウト、ボディ上限、リダイレクトの再検査 |
| **8 つの中国語スキル** | 認可スコープ、偵察ワークフロー、Web トリアージ、認証と JWT、API と GraphQL、レポート、初心者モード、熟練者モード |
| **3 つのレポート形式** | Markdown / JSON / SARIF、既定で機微情報をマスク |
| **実行時依存ゼロ** | `requests` なし、サードパーティ HTTP クライアントなし。ホストが `dsh-tools` と `dsh-skill` を提供します |
| **検出のみ** | リバースシェル、デシリアライズ攻撃チェーン、SSRF ピボット、OOB コールバック、WAF バイパスはありません |
| **UI パネルなし** | ツール、スキル、レポートファイルのみで、グラフィカルなインターフェースはありません |

## インストール

前提条件: DSH デスクトップ（`>=0.2.0-rc.1 <0.3.0`）と Node `^22.19 || >=24`。ビルド手順も実行時依存もありません。

### オプション A: DSH プラグインマネージャー（推奨）

DSH デスクトップの **設定 → プラグイン**を開き、プラグインマネージャーから次のいずれかをインストールします。

- **ローカルディレクトリ**: このリポジトリ（`package.json` と `cordis.patch.yml` を含みます）を指定します。
- **git リポジトリ**: `https://github.com/DaiYiqq/dsh-daiyi-aimy-skill`。

インストール後、プラグインマネージャーの reconcile がこのパッケージの `dsh.bundle.patch` を読み取り、`cordis.patch.yml` の挿入エントリ（`id: daiyi-aimy-skill`）をプロファイルに追加します。

### オプション B: 手動でのプラグインディレクトリ配置

1. このディレクトリを DSH のプラグインディレクトリ（例: `~/.dsh/plugins/dsh-daiyi-aimy-skill`）に置きます。
2. プロファイルの `package.json` の dependencies に追加します。

   ```json
   {
     "dsh-daiyi-aimy-skill": "file:~/dsh/plugins/dsh-daiyi-aimy-skill"
   }
   ```

   > `file:` より後ろの部分は、あなたのマシン上の**絶対パス**である必要があります。上記の `~/...` は例示です。
3. プロファイルのディレクトリで `pnpm install` を実行します。
4. DSH を再起動／再読み込みします。このパッケージは `dsh.bundle.patch` を宣言しているため、プラグインマネージャーの reconcile がパッケージ名を `dsh.profile.bundles` に追加します。

読み込まれると、セッションは 8 つの `aimy_*` ツールと 8 つの `aimy-*` スキルを公開します。

## クイックスタート（5 行）

```text
// Step 1: register the authorized scope — without it every network tool refuses
aimy_scope(action="add", target="example.com", authorization="Client authorization letter #A-1024, scope: example.com", expiresInHours=72)
aimy_recon(target="https://example.com")
aimy_crawl(target="https://example.com/", maxPages=10)
aimy_web_scan(target="https://example.com/search?q=test", checks=["xss", "sqli"])
aimy_report(action="report", format="md", outputPath="reports/example-com.md")
```

ツール呼び出し結果の完全な例（一部省略）:

```json
{
  "target": "https://example.com/search?q=test",
  "checks": ["xss", "sqli"],
  "skipped": [],
  "params": [{ "name": "q", "location": "query", "sample": "test" }],
  "findings": [
    {
      "module": "xss",
      "checkId": "xss-reflected",
      "title": "Reflected XSS (HTML context)",
      "severity": "high",
      "confidence": "high",
      "url": "https://example.com/search?q=test",
      "param": "q",
      "payload": "aimy1337<script>alert(1)</script>",
      "evidence": "Parameter q was reflected verbatim in an HTML context; the payload appeared unencoded in the response (200).",
      "cwe": "CWE-79",
      "remediation": "Apply context-aware HTML/attribute/JS encoding, allowlist filtering, and CSP as defense in depth."
    }
  ],
  "requests": 9,
  "notes": ["runId=run-1a2b3c4d", "mode=rookie"]
}
```

> 上記の検出結果はフィールドの形を示すための例にすぎず、`example.com` にこの問題があると主張するものではありません。実際の出力は対象と設定によって異なります。

## ツール

| ツール | 用途 | スコープが必要 |
|---|---|---|
| `aimy_scope` | 認可スコープの追加／一覧／削除／クリア、対象のドライラン | いいえ（これがゲート本体です） |
| `aimy_recon` | DNS、HTTP ベースライン、セキュリティヘッダー、技術フィンガープリント、robots.txt | はい |
| `aimy_port_scan` | TCP コネクトによるポート探査（ハンドシェイクのみ）、危険ポートの検出 | はい |
| `aimy_dir_fuzz` | ソフト 404 ベースラインを用いたパス列挙と機微パスの検出 | はい |
| `aimy_crawl` | 同一オリジンクロール: ページ、リンク、フォーム、パラメータ、JS エンドポイント | はい |
| `aimy_web_scan` | 1 つの URL に対して Web チェック群（12 種類のチェック）を実行 | はい |
| `aimy_jwt_audit` | オフライン JWT 監査: alg、弱いシークレット、クレーム、外部鍵ソース | いいえ（ローカルのみ） |
| `aimy_report` | 集計、検出結果の一覧、Markdown / JSON / SARIF のエクスポート | いいえ |

パラメータの詳細表、戻り値の形、エラーコード、制限: [docs/TOOLS.md](docs/TOOLS.md)（中国語）。

## スキル

| スキル | 読み込むタイミング |
|---|---|
| `aimy-authorized-scope` | セッション開始時、対象の変更／拡張時、または `NO_SCOPE` / `NO_MATCH` / `EXPIRED` / `PRIVATE_BLOCKED` の結果が出たとき |
| `aimy-recon-workflow` | スコープ登録済みで、アセットマップ（ホスト、ポート、ディレクトリ、ページ、パラメータ、技術情報）が必要なとき |
| `aimy-web-vuln-triage` | パラメータ付き URL があり、Web の検出結果が本物かどうか、深刻度はどれくらいかを判断する必要があるとき |
| `aimy-auth-and-jwt` | ログイン状態、Bearer トークン、JWT、セッションやオブジェクトレベルの認可についての疑問があるとき |
| `aimy-api-and-graphql` | `/api`、`/graphql`、`/swagger` 形式のインターフェースが存在するとき |
| `aimy-finding-report` | スキャン 1 回分が終わり、レポートや CI 向け SARIF が必要なとき |
| `aimy-rookie-mode` | 初心者、本番対象、または `mode=rookie` のとき |
| `aimy-veteran-mode` | 明確な認可があり、ステージング／ラボ環境で、より高いカバレッジと連鎖チェックを行うとき |

スキルは **手法のガイダンス**です。ツールを自動実行することはなく、`aimy_scope` をバイパスすることもできません。

## 上流からのアップグレード

| 観点 | 上流 `aimy-sikll` v2.0.0 | 本プラグイン v3.0.0 |
|---|---|---|
| 形態 | Python CLI、`python main.py <subcommand>` | DSH Cordis プラグイン、モデルが呼び出すツール |
| 認可 | 対象を入力すれば探査が始まる | 既定で拒否。まずスコープを登録 |
| ネットワーク出口 | 各モジュールが `requests` を自由に使用 | リクエストごとのスコープ検査を伴う、ガード付き単一プローブ |
| 出力 | ターミナルに JSON を出力 | 構造化された戻り値 + 3 つのレポート形式 |
| 依存関係 | `requests` など | 実行時のサードパーティ依存はゼロ |
| セッション | `.pkl` セッションファイル | ステートレス。資格情報の保存なし |
| 同時実行 | スレッドプール | 上限付き同時実行 + リクエスト予算 + キャンセル |
| 武器化 | あり（リバースシェル、データ吸い出し、ピボットなど） | **提供しません**。該当モジュールは移植していません |
| スキル | 101 個の Markdown ファイル | 8 つの実行可能なプレイブックに厳選 |

上流の全 34 ファイルについてのモジュール単位の扱い（移植／統合／部分的に吸収／移植せず、理由付き）と、CLI からツールへの対応表は [docs/MIGRATION.md](docs/MIGRATION.md)（中国語）を参照してください。

## 設定

設定は `cordis.patch.yml` の `config` から読み込まれ、既定値とマージされます。不正な値は既定値にフォールバックし、警告が出力されます。

```yaml
- insert:
    - id: daiyi-aimy-skill
      name: dsh-daiyi-aimy-skill
      config:
        mode: rookie
        persistScope: true
```

| キー | 型 | 既定値 | 説明 |
|---|---|---|---|
| `mode` | `rookie` \| `veteran` | `rookie` | 実行モード。予算とペイロードの積極性のみを変更し、認可境界は決して変えません |
| `persistScope` | boolean | `true` | スコープをディスクに永続化します。`false` の場合はメモリ内のみ |
| `scopeFile` | string | `<DSH_HOME>/daiyi-aimy-skill/scope.json` | スコープファイルのパス |
| `timeoutMs` | number | 8000（rookie） / 12000（veteran） | リクエストごとのタイムアウト。最大 60000 |
| `maxRequests` | number | 24 / 60 | ツール呼び出し 1 回あたりのリクエスト予算。最大 400 |
| `concurrency` | number | 4 / 8 | 同時実行の上限。最大 32 |
| `maxBodyBytes` | number | 262144 | レスポンスボディの上限。最大 4 MiB |
| `followRedirects` | boolean | `false` | 既定ではリダイレクトを追跡しません |
| `maxRedirects` | number | 3 | 追跡する場合の最大ホップ数 |
| `userAgent` | string | `dsh-daiyi-aimy-skill/3.0.0 (...)` | 既定の UA。対象側はテスターを識別できます |
| `allowPrivateNetworks` | boolean | `false` | スコープ内でループバック／プライベートな対象を許可 |
| `redactSecrets` | boolean | `true` | レポート内の資格情報らしき値をマスク |
| `maxFindings` | number | 800 | メモリ内の検出結果上限 |
| `maxRuns` | number | 60 | メモリ内の実行記録上限 |

## セキュリティとコンプライアンス

- **検出のみ**: リバースシェル、デシリアライズ攻撃チェーン、SSRF ピボット、OOB コールバック、WAF バイパス、データ抽出、資格情報への攻撃、MITM による資格情報の取得はありません。
- **既定で拒否（deny-by-default）**: スコープがなければすべてのネットワーク系ツールが拒否され、各スコープには書面による認可メモが必要です。
- **制限可能なスコープ**: `host`、`host:port`、スキーム、`*.` サブドメインワイルドカード、パス接頭辞、有効期限。ループバック／プライベートな対象は既定でブロックされます。
- **資格情報の保存なし**: プラグインはトークン、Cookie、セッションを永続化せず、スコープファイルにも資格情報は含まれません。
- **検出率の保証なし**: チェックはレスポンス差分に基づくヒューリスティックであり、見逃しや誤検知が起こりえます。認可を持つ人間が結論をレビューする必要があります。
- **合法的な利用**: **書面による認可**がある対象にのみ使用してください。無断の探査、データ抽出、永続化、サービス妨害は禁止されており、本プラグインの機能範囲外です。

認可モデルの全体像、マッチング規則、報告チャネル: [docs/SECURITY.md](docs/SECURITY.md)（中国語）。

**本プラグインの脆弱性を報告する場合**: GitHub Security Advisory の利用、または `1703205607@qq.com` へのメールを推奨します。修正前に詳細を公開しないでください。

## リポジトリ構成

```text
dsh-daiyi-aimy-skill/
├── lib/
│   ├── index.js            # plugin entry: name / inject / apply
│   ├── config.js           # config normalization and mode budgets
│   ├── scope.js            # authorization scope: parse, match, persist, audit
│   ├── http.js             # guarded HTTP probe (single network egress)
│   ├── store.js            # findings store, dedupe, run records
│   ├── report.js           # Markdown / JSON / SARIF renderers
│   ├── tools/              # 8 model-callable tools
│   ├── engine/             # detection modules + catalog
│   └── skills/             # skill loader
├── skills/                 # 8 aimy-* skills (SKILL.md)
├── docs/                   # TOOLS / MIGRATION / SECURITY / ARCHITECTURE / CONTRACT
├── scripts/                # validate-plugin.mjs contract checks
├── test/                   # contract, engine and skill tests
├── cordis.patch.yml
├── package.json
├── README.md               # Simplified Chinese (primary)
├── README.en.md            # English
├── README.zh-TW.md         # Traditional Chinese
├── README.ja.md            # Japanese
├── CHANGELOG.md
└── LICENSE
```

## 開発とテスト

Node `^22.19 || >=24`。**サードパーティ依存はゼロ**のため、`npm install` は不要です。

```bash
npm run check     # コントラクト検証 + リポジトリ全体の構文チェック
npm test          # node --test "test/**/*.test.js" (recursive)
npm run verify    # check + test (what CI runs)
```

単一ファイルをチェックする:

```bash
node --check lib/http.js
node --test test/engine/sqli.test.js
```

CI: [.github/workflows/ci.yml](.github/workflows/ci.yml) — `ubuntu-latest` + Node 24 で、`npm run verify` のみを実行し、追加のインストール手順はありません。

設計メモと検出モジュールの追加方法: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)（中国語）。

## ライセンス

[MIT](LICENSE) © 2026 戴亿 <1703205607@qq.com>

上流の `aimy-sikll` も MIT ライセンスです。本プラグインは独立した再開発であり、上流の公式リリースではありません。
