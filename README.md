# SBOM 摄入与风险判定服务（本地版）

一个基于 Spring Boot 的本地软件成分清单（SBOM）摄入与风险判定服务。清单内容随请求提交，
漏洞与策略规则在本地维护，不依赖任何外部网络服务，使不同格式、不完整字段下的判定结论
**可预期、可复现**。

## 1. 功能概览

- **多格式摄入与归一化**：支持 CycloneDX JSON 与 SPDX 2.3 JSON，归一到统一 `Component`
  （生态 / 名称 / 版本）模型。
- **包坐标身份归一**：以 purl（Package URL）为可靠身份来源，支持 Maven
  （`组名:构件名`）与 npm（`@作用域/名称`）两类坐标；等价写法（大小写 scheme、
  `%40` 编码、qualifiers/subpath、随意的名字字段）归一到同一稳定身份；
  不同生态之间身份严格隔离，互不串号。
- **不静默跳过任何坏条目**：缺名称、缺版本、版本非法、文档内重复、不支持的坐标类型
  均给出**可区分的拒绝原因**；文档级畸形与条目级问题分开表达。
- **去重与幂等**：同一目标下组件以 `生态::名称@版本` 为键去重；同一份清单（含等价
  坐标写法）重复提交不产生重复记录；同一目标的并发提交经目标级锁串行化，保持幂等。
- **本地规则判定**：漏洞规则 + 策略规则，版本按语义化版本（SemVer 2.0）比较，
  正确处理范围与通配符；无法判定时结论为 **UNKNOWN**，绝不默认安全。
- **无法判定兜底**：生态无法识别（规则库未覆盖）或坐标解析不出可靠身份的组件，
  一律归为 **UNKNOWN**；只有确实能判定且未命中任何规则的组件才是 **CLEAN**。
- **可复现**：报告携带规则版本号；组件集合与规则版本不变时，判定结论逐字段一致；
  规则原子更新后，结论按新版本可复现地变化。
- **传输层可区分三态**：HTTP 状态码直接区分 整体失败（422）/ 部分成功（207）/
  成功（200）；幂等重复命中通过 `X-Idempotent-Replay` 响应头对外可见；
  响应体原有字段全部保留。

## 2. 支持的清单格式

| 格式 | 识别方式 | 组件数组 | 名称 | 版本 | 生态/身份来源 |
|---|---|---|---|---|---|
| CycloneDX JSON | `bomFormat == "CycloneDX"` | `components[]` | `name` | `version`（缺省时回退 purl 中的版本） | `purl` 坐标优先；无 purl 时取 `ecosystems[]` 首项，均无则 `unknown` |
| SPDX 2.3 JSON | 存在 `spdxVersion` 字段 | `packages[]` | `name` | `versionInfo`（缺省时回退 purl 中的版本） | `externalRefs` 中 `referenceType=purl` 的 `referenceLocator` 坐标优先；无则 `unknown` |

格式可在请求中显式指定（`format: "cyclonedx" | "spdx"`），为空时按字段特征自动识别。

### 2.1 组件身份归一规则（包坐标）

真实清单里组件主要靠包坐标标识，名字字段写得随意。本服务以 **purl 坐标为可靠身份来源**，
归一规则如下：

| 坐标类型 | 写法 | 归一后的组件身份（`Component.name`） |
|---|---|---|
| Maven | `pkg:maven/<groupId>/<artifactId>@<version>` | `groupId:artifactId`（与规则库登记写法一致） |
| npm（无作用域） | `pkg:npm/<name>@<version>` | `name`（小写） |
| npm（带作用域） | `pkg:npm/%40<scope>/<name>@<version>` 或 `pkg:npm/@<scope>/<name>@<version>` | `@scope/name`（小写） |

等价写法归一细节：

- scheme（`pkg:`）大小写不敏感，type 一律小写；
- qualifiers（`?type=jar...`）与 subpath（`#...`）不参与身份，直接剥离；
- 各段做百分号解码（`%40` → `@`），`+` 保持原样；
- npm 名称/作用域一律小写；npm 作用域段缺 `@` 前缀时自动补全；
- purl 解析成功时，**坐标身份优先于名字字段**（名字写得随意也不影响身份）；
- 条目版本字段缺失时，回退使用坐标中的版本。

**生态隔离**：身份键为 `生态::名称@版本`，规则匹配键为 `生态::名称`。
`pkg:maven/lodash/lodash@4.17.20`（身份 `maven::lodash:lodash`）与
`pkg:npm/lodash@4.17.20`（身份 `npm::lodash`）是两个不同组件，
npm 的漏洞规则不会命中 maven 同名构件，反之亦然。

**不支持的坐标类型**（pypi、golang 等）：条目以 `UNSUPPORTED_PURL_TYPE` 明确拒绝，
绝不当作普通名字混入；**畸形 purl**（缺 scheme、缺名称段、Maven 缺 groupId 等）：
坐标不可靠，回退到 `name` / `ecosystems` 字段（生态通常为 `unknown`，
判定层会归入 UNKNOWN，见第 4 节）。

### 2.2 拒绝原因（逐条、可区分，不静默跳过）

| 原因枚举 | 触发场景 |
|---|---|
| `MALFORMED_DOCUMENT` | 文档级：内容为空、JSON 非法、根不是对象、缺 `components`/`packages` 数组、格式无法识别（条目下标为 -1） |
| `MISSING_COMPONENT_NAME` | 条目缺 `name` 或为空白（且无可用 purl 身份） |
| `MISSING_COMPONENT_VERSION` | 条目缺版本字段且 purl 中也没有版本 |
| `MALFORMED_VERSION` | 版本不符合 SemVer 2.0（如 `v1.0.0`、`1.2`、`1.02.3`、`1.2.3-01`） |
| `DUPLICATE_COMPONENT` | 同一份提交文档内出现完全相同的组件 |
| `UNSUPPORTED_PURL_TYPE` | purl 坐标类型暂不支持（仅支持 maven / npm），明确拒绝、不当普通名字混入 |

> 文档级畸形 → 整份清单不入库（`FAILED`）；条目级问题 → 坏条目拒绝、好条目照常入库（`PARTIAL_SUCCESS`）。

## 3. 版本比较与范围语义

版本号遵循 **SemVer 2.0**：`major.minor.patch[-prerelease][+build]`，三段数字必填、
禁止前导零；预发布版小于对应正式版；数字型预发布标识按数值比较且小于字符串型标识；
构建元数据不参与比较。

漏洞/策略范围支持以下语法（单个表达式内约束为 AND，逗号或空格分隔；漏洞规则的
`affectedRanges` 数组各项之间为 OR）：

| 语法 | 含义 | 示例 |
|---|---|---|
| `*` / `x` | 匹配所有版本 | `*` |
| `=`、`>`、`>=`、`<`、`<=` | 比较（裸版本按精确匹配） | `>=1.2.3` |
| `^` | 兼容范围，锁定第一个非零位 | `^1.2.3` → `>=1.2.3 <2.0.0`；`^0.2.3` → `>=0.2.3 <0.3.0`；`^0.0.3` → `>=0.0.3 <0.0.4` |
| `~` | 补丁范围 | `~1.2.3` → `>=1.2.3 <1.3.0`；`~1` → `>=1.0.0 <2.0.0` |
| 通配段 | 锁定前缀 | `1.x` 匹配全部 1.\*；`1.2.*` 匹配全部 1.2.\* |
| 区间 | `[`/`]` 闭端、`(`/`)` 开端 | `[2.0.0,2.15.0)` 含 2.0.0、不含 2.15.0 |

非法区间（如 `[2.0.0,1.0.0]`、`>=not-a-version`、`1.*.2`）会被明确标记：
- 与判定中的组件相关时，该组件结论为 **UNKNOWN**，并在 `reasons` 中给出
  `UNKNOWN:illegal-vuln-range:<规则号>` 或 `UNKNOWN:illegal-policy-range:<规则号>`；
- 绝不会被当作“不命中”而默认安全。

## 4. 风险判定规则

对目标下每个已接受组件依次判定，等级取最严重者为目标总体等级：

| 等级 | 判定条件 |
|---|---|
| `DENIED`（最严重） | 命中本地策略规则（策略按 生态+名称 匹配；策略无 `range` 表示全版本） |
| `VULNERABLE` | 命中任一漏洞规则的受影响版本范围 |
| `UNKNOWN` | **无法判定**：生态无法识别（规则库未覆盖，含 `unknown`）、版本无法解析、或相关规则的版本区间非法。绝不默认安全；总体结论中 UNKNOWN 比 CLEAN 更需要关注 |
| `CLEAN` | 生态可判定（当前为 maven / npm）且确实无规则命中（依据明确：`CLEAN:no-rules-matched` 或 `CLEAN:all-ranges-excluded`） |

每条结论都带 `reasons` 判定依据，如：
`VULNERABLE:CVE-2021-44228:in-range[[2.0.0,2.12.3), [2.13.0,2.15.0)]`、
`DENIED:POLICY-BANNED-LEGACY:...`、`UNKNOWN:illegal-vuln-range:...`、
`UNKNOWN:unrecognized-ecosystem:unknown`。

> **UNKNOWN 兜底原则**：凡是生态认不出来、或坐标解析不出可靠身份的组件，
> 即使没有任何规则命中，也只会得到 `UNKNOWN`（依据
> `UNKNOWN:unrecognized-ecosystem:<生态>`），永远不会被当成“安全”。
> 目标总体等级取各组件最严重者，因此一个 UNKNOWN 组件会把总体结论抬到
> 至少 UNKNOWN。

### 本地规则文件

- `src/main/resources/rules/vulnerabilities.json`：`version` + `vulnerabilities[]`
  （`id` / `ecosystem` / `name` / `affectedRanges[]`）。
- `src/main/resources/rules/policies.json`：`version` + `policies[]`
  （`id` / `ecosystem` / `name` / `range`（可空=全版本）/ `message`）。

规则在启动时加载为不可变快照，匹配键为 `ecosystem::name`（均小写）。
`RuleRepository.replace(version, vulns, policies)` 原子切换快照；风险报告携带
`rulesVersion`，规则不变时同一输入的报告可复现。

## 5. HTTP 接口

### 5.1 提交清单 `POST /api/sbom/ingest`

请求体：

```json
{
  "targetId": "app-prod-1",
  "format": null,
  "content": "{\"bomFormat\":\"CycloneDX\",\"components\":[...]}"
}
```

- `targetId`：幂等域（同一应用/目标），必填。
- `format`：可选，`cyclonedx` / `spdx`；为空自动识别。
- `content`：清单原文 JSON 字符串。

**传输层状态语义**（客户端不看响应体即可区分三种结果）：

| HTTP 状态 | 含义 | 对应响应体 `status` |
|---|---|---|
| `200 OK` | 全部成功（含幂等重复命中） | `SUCCESS` |
| `207 Multi-Status` | 部分成功：有条目入库，同时存在被拒绝条目 | `PARTIAL_SUCCESS` |
| `422 Unprocessable Content` | 整体失败：文档畸形或条目全部非法，未写入任何组件 | `FAILED` |

此外：

- **幂等命中头**：重复提交同一份清单（或等价坐标写法）且本次没有产生任何新记录时，
  响应携带 `X-Idempotent-Replay: true` 头，客户端无需解析响应体即可识别幂等命中。
- **兼容范围**：响应体字段（`status` / `acceptedCount` / `rejectedCount` /
  `duplicateCount` / `components` / `rejected` / `summary`）全部保留，
  已依赖响应体的调用方不受影响；仅 HTTP 状态码由此前的恒 200 细化为上表三态。

响应示例（HTTP 207）：

```json
{
  "targetId": "app-prod-1",
  "status": "PARTIAL_SUCCESS",
  "acceptedCount": 1,
  "rejectedCount": 2,
  "duplicateCount": 0,
  "components": ["maven::ok@1.0.0"],
  "rejected": [
    {"index": 1, "reason": "MISSING_COMPONENT_VERSION", "detail": "component 'no-version' has no version"},
    {"index": 2, "reason": "MISSING_COMPONENT_NAME", "detail": "component at index 2 has no name"}
  ],
  "summary": "parsed=3, newlyAccepted=1, duplicates=0, rejected=2, storedForTarget=1"
}
```

- `FAILED`：无任何条目入库（文档畸形，或文档解析通过但条目全部非法/全部文档内重复）。
- `PARTIAL_SUCCESS`：有条目入库，同时存在被拒绝条目。
- `SUCCESS`：提交内容全部入库（可能全部为幂等重复命中，此时 `acceptedCount=0`、`duplicateCount>0`）。

### 5.2 查询风险报告 `GET /api/sbom/targets/{targetId}/report`

```json
{
  "targetId": "app-prod-1",
  "overallLevel": "VULNERABLE",
  "components": [
    {"component": "maven::org.apache.logging.log4j:log4j-core@2.14.0",
     "level": "VULNERABLE",
     "reasons": ["VULNERABLE:CVE-2021-44228:in-range[[2.0.0,2.12.3), [2.13.0,2.15.0)]"]}
  ],
  "rulesVersion": "vulns=2026-09-23/policies=2026-09-23",
  "evaluatedAt": "2026-09-23T06:00:00Z"
}
```

目标不存在（没有任何成功入库的组件）返回 `404 TARGET_NOT_FOUND`；请求体非法返回
`400 INVALID_REQUEST`。

## 6. 并发与幂等语义

- **目标级锁**：每个 `targetId` 一把锁，同一目标的并发提交被串行化，不同目标互不阻塞。
- **存储去重**：每个目标内部以 `TreeMap<组件键, 组件>` 存储，天然去重且遍历顺序稳定，
  因此风险报告的组件顺序确定，保证可复现。
- **重复提交**：同一份清单重复提交时，首次 `acceptedCount=N`，后续 `acceptedCount=0`、
  `duplicateCount=N`，存储记录始终只有一份，状态为 `SUCCESS`（幂等成功），
  且响应携带 `X-Idempotent-Replay: true` 头。
- **等价写法幂等**：同一组件的等价坐标写法（purl 坐标 vs 名字+生态、大小写/编码差异）
  归一到同一身份键，并发或先后提交都只产生一条记录。
- **大清单稳定**：清单条目数量增多不改变幂等与去重语义（500 条清单重复提交有测试覆盖）。
- **部分失败隔离**：单条目失败只记录到 `rejected[]`，不影响同份清单其他条目入库。
- **整体失败隔离**：文档级失败不创建任何组件记录，随后查询报告得到 404。
- **规则原子性**：规则快照为 `volatile` 引用整体替换，判定期间不会读到半更新状态。

## 7. 验证方法

### 运行全部测试（116 个）

```bash
mvn test
```

测试分层：

| 测试类 | 覆盖内容 |
|---|---|
| `version/SemVerTest` | SemVer 解析/预发布/前导零/比较（含输入摘要与依据日志） |
| `version/VersionRangeTest` | 比较符、`^`/`~`、通配符、开闭区间、OR 区间、非法区间 |
| `parser/PurlParserTest` | maven/npm 坐标解析、等价写法归一（scheme 大小写、`%40` 编码、qualifiers/subpath）、跨生态隔离、不支持类型、畸形坐标 |
| `parser/SbomParserTest` | 两种格式归一化、坐标身份优先、版本回退 purl、`UNSUPPORTED_PURL_TYPE`、畸形 purl 回退、字段缺失/非法版本分类、畸形文档、格式识别 |
| `service/SbomIngestServiceTest` | 三态分类、文档内去重、重复提交幂等、16 线程并发幂等、并发等价坐标写法、500 条大清单重复提交、并发不同组件 |
| `service/RiskEvaluationServiceTest` | DENIED/VULNERABLE/CLEAN/UNKNOWN、生态不可识别兜底 UNKNOWN、跨生态规则隔离、范围边界、规则原子更新、结论复现 |
| `web/SbomControllerIntegrationTest` | HTTP 全链路：两种格式、200/207/422 传输层三态、`X-Idempotent-Replay` 幂等头、等价写法去重、不支持坐标类型、400、404、HTTP 并发幂等 |

单元测试日志均打印**输入摘要与判定依据**，例如：

```
INFO ... SBOM ingest start | targetId=t1 | formatHint=auto | bytes=... | head={"bomFormat":...
INFO ... 输入摘要: purl=pkg:npm/%40angular/core@15.0.0 | 判定: Resolved[coordinate=...]
INFO ... Risk verdict | targetId=t1 | component=maven::...@2.14.0 | level=VULNERABLE
     | reasons=[VULNERABLE:CVE-2021-44228:in-range[...]]
```

### 手动验证

```bash
mvn spring-boot:run
```

```bash
# CycloneDX 摄入（log4j 2.14.0 命中 CVE-2021-44228）；-i 可看到 HTTP 200
curl -s -i -X POST localhost:8080/api/sbom/ingest -H 'Content-Type: application/json' -d '{
  "targetId":"demo",
  "content":"{\"bomFormat\":\"CycloneDX\",\"components\":[{\"name\":\"log4j-core\",\"version\":\"2.14.0\",\"purl\":\"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0\"}]}"
}'

# 再查报告（purl 坐标已归一为 maven::org.apache.logging.log4j:log4j-core@2.14.0）
curl -s localhost:8080/api/sbom/targets/demo/report | python3 -m json.tool

# 重复提交同一份清单：HTTP 200 且响应头 X-Idempotent-Replay: true
curl -s -i -X POST localhost:8080/api/sbom/ingest -H 'Content-Type: application/json' -d '{
  "targetId":"demo",
  "content":"{\"bomFormat\":\"CycloneDX\",\"components\":[{\"name\":\"log4j-core\",\"version\":\"2.14.0\",\"purl\":\"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0\"}]}"
}' | grep -i -E "HTTP/|x-idempotent-replay"

# 部分成功：HTTP 207；畸形文档：HTTP 422
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/api/sbom/ingest \
  -H 'Content-Type: application/json' -d '{"targetId":"demo2","content":"{broken"}'
```

## 8. 工程结构

```
src/main/java/com/github/lisama569/sbomriskservicejava/
├── model/        # 统一组件模型、拒绝原因、三态状态、风险等级与报告 DTO
├── parser/       # 格式识别 + CycloneDX / SPDX 解析器 + 条目归一化 + purl 坐标解析
├── version/      # SemVer 解析比较 + VersionRange（操作符/caret/tilde/通配符/区间）
├── rules/        # RuleRepository：本地规则加载、懒编译、原子快照
├── service/      # 摄入（锁/去重/三态）、判定（等级/UNKNOWN 兜底/复现）
└── web/          # REST 控制器（传输层三态 + 幂等头）与全局异常归类
src/main/resources/rules/   # vulnerabilities.json / policies.json
```
