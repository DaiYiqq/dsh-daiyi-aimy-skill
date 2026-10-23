# dsh-daiyi-aimy-skill

<p align="center">
  <a href="README.md">简体中文</a> ·
  <a href="README.en.md">English</a> ·
  <b>繁體中文</b> ·
  <a href="README.ja.md">日本語</a>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="package.json"><img alt="Node" src="https://img.shields.io/badge/node-%5E22.19%20%7C%7C%20%3E%3D24-brightgreen.svg"></a>
  <a href="package.json"><img alt="DSH" src="https://img.shields.io/badge/DSH-%3E%3D0.2.0--rc.1-6f42c1.svg"></a>
  <img alt="dependencies" src="https://img.shields.io/badge/runtime%20deps-0-success.svg">
  <a href="https://github.com/zxz0119/aimy-sikll"><img alt="upstream" src="https://img.shields.io/badge/upstream-aimy--sikll%20v2.0.0-orange.svg"></a>
</p>

> **為 DeepSeek Harness 提供「授權範圍內」的偵察與 Web 弱點偵測能力：8 個原生工具 + 8 個技能，預設拒絕，只做偵測。**

`dsh-daiyi-aimy-skill` 是 [zxz0119/aimy-sikll](https://github.com/zxz0119/aimy-sikll)（Python CLI，v2.0.0）的 **DeepSeek Harness（DSH）Cordis 外掛**再開發版。它把上游的命令列腳本改造成宿主內常駐的原生工具，並加上了上游沒有的**授權範圍護欄**：沒有登記授權範圍時，任何網路工具都不會執行。

- 形態：ESM Cordis 外掛，執行時**零第三方相依套件**（只用 `node:` 內建模組）。
- 宿主：DSH `>=0.2.0-rc.1 <0.3.0`；Node `^22.19 || >=24`。
- 版本：`3.0.0`，MIT，作者 戴億。

## 特性

| 特性 | 說明 |
|---|---|
| **8 個模型可呼叫工具** | 範圍管理、偵察、連接埠、目錄、爬蟲、Web 偵測、JWT 稽核、報告 |
| **預設拒絕（deny-by-default）** | 任何網路目標都必須先以 `aimy_scope` 登記，未登記直接拒絕並提示下一步 |
| **授權依據與稽核** | 登記必須寫授權說明（≥ 8 字元），範圍可設過期時間，變更會寫入稽核日誌 |
| **12 個偵測模組 + 3 個偵察模組** | 偵測：sqli / xss / cmdi / ssti / ssrf / nosqli / lfi / cors / jwt / graphql / proto-pollution / headers；偵察：crawler / param-miner / tech-fingerprint。連接埠與目錄列舉在工具層實作 |
| **單一網路出口** | 所有請求都經 `lib/http.js` 護欄探針：逐請求 scope 驗證、預算、逾時、回應內容截斷、重新導向複檢 |
| **8 個中文技能** | 授權範圍、偵察、Web 判定、認證與 JWT、API 與 GraphQL、報告、菜鳥模式、老鳥模式 |
| **三種報告格式** | Markdown / JSON / SARIF，報告預設脫敏 |
| **零執行時相依套件** | 不用 `requests`、不用第三方 HTTP 函式庫；宿主提供 `dsh-tools` 與 `dsh-skill` |
| **只做偵測** | 不提供反彈 shell、反序列化利用鏈、SSRF 橫向、OOB 帶外、WAF 繞過等武器化能力 |
| **無 UI 面板** | 只提供工具、技能與報告檔案；沒有圖形介面 |

## 安裝

前置：DSH 桌面端（`>=0.2.0-rc.1 <0.3.0`）與 Node `^22.19 || >=24`。本外掛沒有建置步驟，也沒有執行時相依套件。

### 方式 A：用 DSH 外掛管理程式（建議）

打開 DSH 桌面端「**設定 → 外掛**」，用外掛管理程式安裝：

- **本機目錄**：選擇本儲存庫目錄（含 `package.json` 與 `cordis.patch.yml`）。
- **git 儲存庫**：填 `https://github.com/DaiYiqq/dsh-daiyi-aimy-skill`。

安裝後外掛管理程式的 reconcile 會讀取本套件的 `dsh.bundle.patch`，把 `cordis.patch.yml` 的 insert 項（`id: daiyi-aimy-skill`）寫入 profile。

### 方式 B：手動放進外掛目錄

1. 把本目錄放到 DSH 外掛目錄下（例如 `~/.dsh/plugins/dsh-daiyi-aimy-skill`）。
2. 在 profile 的 `package.json` 的 `dependencies` 中加入：

   ```json
   {
     "dsh-daiyi-aimy-skill": "file:~/dsh/plugins/dsh-daiyi-aimy-skill"
   }
   ```

   > `file:` 後面寫**本機絕對路徑**；上面的 `~/...` 只是示意。
3. 在 profile 目錄執行 `pnpm install`。
4. 重新啟動 / 重新載入 DSH。外掛管理程式 reconcile 時會因為本套件宣告了 `dsh.bundle.patch`，把套件名稱加入 `dsh.profile.bundles`。

安裝成功後，工作階段裡能看到 8 個 `aimy_*` 工具，技能目錄裡出現 8 個 `aimy-*` 技能。

## 快速開始（5 行）

```text
// 第 1 步：登記授權範圍——不登記，後面所有網路工具都會拒絕
aimy_scope(action="add", target="example.com", authorization="客戶授權函 #A-1024，範圍 example.com 全站", expiresInHours=72)
aimy_recon(target="https://example.com")
aimy_crawl(target="https://example.com/", maxPages=10)
aimy_web_scan(target="https://example.com/search?q=test", checks=["xss", "sqli"])
aimy_report(action="report", format="md", outputPath="reports/example-com.md")
```

一次完整呼叫的回傳範例（節錄）：

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
      "title": "反射型 XSS（HTML 情境）",
      "severity": "high",
      "confidence": "high",
      "url": "https://example.com/search?q=test",
      "param": "q",
      "payload": "aimy1337<script>alert(1)</script>",
      "evidence": "參數 q 在 HTML 情境中原樣回顯；payload「…」未編碼出現在回應中。回應 200，片段：<div>…</div>",
      "cwe": "CWE-79",
      "remediation": "依輸出情境做 HTML/屬性/JS 編碼，使用白名單過濾，並設定 CSP 作為縱深防禦。"
    }
  ],
  "requests": 9,
  "notes": ["runId=run-1a2b3c4d", "模式=rookie"]
}
```

> 上面的 finding 僅用於展示欄位形狀，不代表 `example.com` 真的存在該問題。實際回傳以你的目標與設定為準。

## 工具

| 工具 | 作用 | 需要授權範圍 |
|---|---|---|
| `aimy_scope` | 登記 / 檢視 / 移除 / 清空授權範圍，判定目標是否放行 | 否（閘門本身） |
| `aimy_recon` | DNS、HTTP 基線、安全回應標頭、技術堆疊指紋、robots.txt | 是 |
| `aimy_port_scan` | TCP 連接埠連通性探測（僅握手），高風險連接埠暴露告警 | 是 |
| `aimy_dir_fuzz` | 路徑/目錄列舉，軟 404 基線過濾，敏感路徑告警 | 是 |
| `aimy_crawl` | 同源爬取：頁面、連結、表單、參數、JS 介面路徑 | 是 |
| `aimy_web_scan` | 一次跑一組 Web 偵測（12 類 checks，見文件） | 是 |
| `aimy_jwt_audit` | 離線 JWT 稽核：演算法、弱金鑰、宣告、外部金鑰來源 | 否（純本機） |
| `aimy_report` | 彙總、列出發現、匯出 Markdown / JSON / SARIF | 否 |

完整參數表、回傳形狀、錯誤碼與限制見 [docs/TOOLS.md](docs/TOOLS.md)（中文文件）。

## 技能

| 技能 | 何時載入 |
|---|---|
| `aimy-authorized-scope` | 工作階段開始、切換/擴大目標，或工具回傳 `NO_SCOPE` / `NO_MATCH` / `EXPIRED` / `PRIVATE_BLOCKED` |
| `aimy-recon-workflow` | 範圍已登記，需要摸清網域、連接埠、目錄、頁面、參數與技術堆疊 |
| `aimy-web-vuln-triage` | 已有帶參數的 URL，需要判定 Web 弱點真偽與定級 |
| `aimy-auth-and-jwt` | 目標有登入狀態、Bearer token、JWT，或要驗證工作階段與物件層授權 |
| `aimy-api-and-graphql` | 存在 `/api`、`/graphql`、`/swagger` 等介面 |
| `aimy-finding-report` | 一輪偵測結束，需要出報告或給 CI 出 SARIF |
| `aimy-rookie-mode` | 新手、生產環境，或 `mode=rookie` 時 |
| `aimy-veteran-mode` | 授權明確、預發/靶場，需要更高覆蓋與鏈式驗證時 |

技能是**方法指導**，不會自動執行工具，也不能繞過 `aimy_scope`。

## 與上游的升級對照

| 維度 | 上游 `aimy-sikll` v2.0.0 | 本外掛 v3.0.0 |
|---|---|---|
| 形態 | Python CLI，`python main.py <子命令>` | DSH Cordis 外掛，模型直接呼叫工具 |
| 授權 | 輸入目標即探測 | deny-by-default，先登記範圍再探測 |
| 網路出口 | 各模組各自用 `requests` | 唯一護欄探針，逐請求 scope 驗證 |
| 輸出 | 終端機 JSON 文字 | 結構化回傳值 + 三種格式報告 |
| 相依 | `requests` 等 | 零執行時第三方相依 |
| 工作階段 | `.pkl` 工作階段檔案 | 無狀態，不保存憑證 |
| 並行 | 執行緒池 | 受控並行 + 請求預算 + 取消 |
| 武器化 | 有（反彈 shell、拖庫、橫向等） | **不提供**，對應模組不移植 |
| 技能 | 101 份 Markdown | 精選重寫為 8 個可執行 playbook |

34 個上游模組的逐項處置（移植 / 合併 / 只吸收部分 / 不移植及原因）與 CLI 命令對照見 [docs/MIGRATION.md](docs/MIGRATION.md)（中文文件）。

## 設定

設定來自 `cordis.patch.yml` 的 `config`，與預設值合併；非法值回退預設並記錄 warning。

```yaml
- insert:
    - id: daiyi-aimy-skill
      name: dsh-daiyi-aimy-skill
      config:
        mode: rookie
        persistScope: true
```

| 設定項 | 類型 | 預設 | 說明 |
|---|---|---|---|
| `mode` | `rookie` \| `veteran` | `rookie` | 執行模式；只影響預算與 payload 激進度，不放寬授權邊界 |
| `persistScope` | boolean | `true` | 是否把授權範圍寫入磁碟；`false` 時僅存在行程記憶體，重新啟動即失效 |
| `scopeFile` | string | `<DSH_HOME>/daiyi-aimy-skill/scope.json` | 授權範圍檔案路徑 |
| `timeoutMs` | number | 8000（rookie）/ 12000（veteran） | 單一請求逾時，上限 60000 |
| `maxRequests` | number | 24 / 60 | 單次工具呼叫請求預算，上限 400 |
| `concurrency` | number | 4 / 8 | 並行上限，上限 32 |
| `maxBodyBytes` | number | 262144 | 回應內容上限，最大 4 MiB |
| `followRedirects` | boolean | `false` | 預設不跟隨重新導向 |
| `maxRedirects` | number | 3 | 跟隨時的最大跳數 |
| `userAgent` | string | `dsh-daiyi-aimy-skill/3.0.0 (...)` | 預設 UA，目標可識別測試來源 |
| `allowPrivateNetworks` | boolean | `false` | 是否允許登記/存取回送與內網位址 |
| `redactSecrets` | boolean | `true` | 報告中對疑似憑證脫敏 |
| `maxFindings` | number | 800 | 記憶體中最多保留的 finding 數 |
| `maxRuns` | number | 60 | 記憶體中最多保留的執行記錄數 |

## 安全與合規

- **只做偵測**：不提供反彈 shell、反序列化利用鏈、SSRF 橫向、OOB 帶外回連、WAF 繞過、資料提取、憑證攻擊、MITM 憑證擷取。
- **預設拒絕**：沒有授權範圍時，所有網路工具直接拒絕；範圍必須寫明授權依據。
- **範圍可約束**：支援 `host`、`host:port`、scheme、`*.` 萬用字元子網域、路徑前綴與過期時間；回送/內網預設禁止。
- **不保存憑證**：外掛不持久化 token/cookie/登入狀態；範圍檔案不記錄憑證。
- **不承諾檢出率**：偵測基於回應差異啟發式，存在誤報漏報；結論必須由有授權的人類複核。
- **合法使用**：僅用於已取得**書面授權**的目標。未授權探測、資料提取、持久化存取、阻斷服務等均被禁止，也不在外掛能力範圍內。

完整授權模型、比對規則與弱點報告管道見 [docs/SECURITY.md](docs/SECURITY.md)（中文文件）。

**發現外掛自身的資安問題**：請優先透過 GitHub Security Advisory 或電子郵件 `1703205607@qq.com` 私下聯絡，修補前請勿公開細節。

## 目錄結構

```text
dsh-daiyi-aimy-skill/
├── lib/
│   ├── index.js            # 外掛入口：name / inject / apply
│   ├── config.js           # 設定正規化與模式預算
│   ├── scope.js            # 授權範圍：解析、比對、持久化、稽核
│   ├── http.js             # 護欄 HTTP 探針（唯一網路出口）
│   ├── store.js            # Finding 儲存、去重、執行記錄
│   ├── report.js           # Markdown / JSON / SARIF 渲染
│   ├── tools/              # 8 個模型可呼叫工具
│   ├── engine/             # 12 個偵測模組 + 3 個偵察模組 + 註冊表
│   └── skills/             # 技能載入器
├── skills/                 # 8 個 aimy-* 技能（SKILL.md）
├── docs/                   # TOOLS / MIGRATION / SECURITY / ARCHITECTURE / CONTRACT
├── scripts/                # validate-plugin.mjs 契約驗證
├── test/                   # 契約測試、引擎測試、技能測試
├── cordis.patch.yml
├── package.json
├── README.md               # 簡體中文（主語言）
├── README.en.md            # English
├── README.zh-TW.md         # 繁體中文
├── README.ja.md            # 日本語
├── CHANGELOG.md
└── LICENSE
```

## 開發與測試

要求 Node `^22.19 || >=24`。**零第三方相依套件**，因此不需要 `npm install`。

```bash
npm run check     # 契約驗證 + 全庫語法檢查
npm test          # node --test "test/**/*.test.js"（遞迴）
npm run verify    # check + test（CI 跑的就是這一條）
```

單獨驗證某個檔案：

```bash
node --check lib/http.js
node --test test/engine/sqli.test.js
```

CI：[.github/workflows/ci.yml](.github/workflows/ci.yml)，`ubuntu-latest` + Node 24，只跑 `npm run verify`，不做額外安裝。

更多設計說明見 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)（中文文件）；新增偵測模組的步驟也在那裡。

## 授權條款

[MIT](LICENSE) © 2026 戴億 <1703205607@qq.com>

上游專案 `aimy-sikll` 同為 MIT 授權條款；本外掛是獨立再開發，不是上游的官方發行版。
