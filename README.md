# SBOM 摄入与风险判定服务（本地版）

一个基于 Spring Boot 的本地软件成分清单（SBOM）摄入与风险判定服务。清单内容随请求提交，
漏洞与策略规则在本地维护，不依赖任何外部网络服务，使不同格式、不完整字段下的判定结论
**可预期、可复现**。

## 1. 功能概览

- **多格式摄入与归一化**：支持 CycloneDX JSON 与 SPDX 2.3 JSON，归一到统一 `Component`
  （生态 / 名称 / 版本）模型。
- **包坐标（purl）驱动的组件身份**：组件主要靠包坐标识别时，maven 坐标归一为
  `groupId:artifactId`、npm 坐标归一为 `name` / `@scope/name`（均小写），与规则库登记写法对齐；
  等价写法（purl / 冒号名 / 斜杠名 / 大小写差异）归一到同一身份，重复提交不产生重复记录；
  跨生态同名组件互不串号；不支持的坐标类型保留通用身份并归入“无法判定”，不当普通名字处理。
- **不静默跳过任何坏条目**：缺名称、缺版本、版本非法、坐标畸形、文档内重复均给出
  **可区分的拒绝原因**；文档级畸形与条目级问题分开表达。
- **去重与幂等**：同一目标下组件以 `生态::名称@版本` 为键去重；同一份清单重复提交
  不产生重复记录；同一目标的并发提交经目标级锁串行化，保持幂等；纯幂等重放通过响应头
  `X-Idempotent-Replay: true` 对外可见。
- **本地规则判定**：漏洞规则 + 策略规则，版本按语义化版本（SemVer 2.0）比较，
  正确处理范围与通配符；生态认不出来 / 坐标解析不出可靠身份 / 规则区间非法等情况
  一律归入 **UNKNOWN（无法判定）**，绝不默认安全；只有身份可靠且确认未命中任何规则的
  组件才是 CLEAN。
- **可复现**：报告携带规则版本号；组件集合与规则版本不变时，判定结论逐字段一致；
  规则原子更新后，结论按新版本可复现地变化。
- **传输层可区分的结果语义**：`200 OK`（全部成功）/ `207 Multi-Status`（部分成功）/
  `422 Unprocessable Content`（整体失败），客户端不看响应体即可判断；
  响应体细分字段保持不变，兼容已有调用方。

## 2. 支持的清单格式

| 格式 | 识别方式 | 组件数组 | 名称 | 版本 | 生态/身份来源 |
|---|---|---|---|---|---|
| CycloneDX JSON | `bomFormat == "CycloneDX"` | `components[]` | `name` | `version` | `purl` 优先（权威身份），其次 `ecosystems[]` 首项 + 名称，均无则 `unknown` |
| SPDX 2.3 JSON | 存在 `spdxVersion` 字段 | `packages[]` | `name` | `versionInfo` | `externalRefs` 中 `referenceType=purl` 的 `referenceLocator` 优先，无则仅名称（生态 `unknown`） |

格式可在请求中显式指定（`format: "cyclonedx" | "spdx"`），为空时按字段特征自动识别。

### 组件身份归一规则（包坐标优先）

条目携带 `purl` 时，组件身份（生态 + 规范名）由 purl 决定，`name` 字段写得再随意也不影响身份：

| purl 形态 | 归一身份 | 说明 |
|---|---|---|
| `pkg:maven/<groupId>/<artifactId>@<版本>` | 生态 `maven`，名 `groupId:artifactId`（小写） | 与规则库登记写法一致 |
| `pkg:npm/<name>@<版本>` | 生态 `npm`，名 `name`（小写） | |
| `pkg:npm/%40<scope>/<name>@<版本>` | 生态 `npm`，名 `@scope/name`（小写） | 作用域前缀保留，是 npm 身份的一部分 |
| `pkg:<其他类型>/...`（如 deb、pypi） | 生态=purl 类型，名为通用路径形态 | **不支持的坐标类型**：保留通用身份入库，判定时归入 UNKNOWN，绝不混为普通名字 |
| 结构无法解析的 purl | 条目拒绝，`MALFORMED_PACKAGE_URL` | 给不出可靠身份，明确拒绝而非猜测 |

无 `purl` 时退回名称 + `ecosystems[]` 推断，并按生态归一名称写法：

- `maven`：`group/artifact` 等价写法统一为 `group:artifact`，名称小写；
- `npm`：名称小写（`@scope/name` 原样保留作用域）；
- 其他/未知生态：保留原始写法，不做大小写假设。

归一后等价写法落到同一组件键（`生态::名称@版本`），因此同一组件用不同写法重复提交、
或整份清单重复提交，都只会命中幂等去重，不产生重复记录；不同生态之间键空间隔离，互不串号。

### 拒绝原因（逐条、可区分，不静默跳过）

| 原因枚举 | 触发场景 |
|---|---|
| `MALFORMED_DOCUMENT` | 文档级：内容为空、JSON 非法、根不是对象、缺 `components`/`packages` 数组、格式无法识别（条目下标为 -1） |
| `MISSING_COMPONENT_NAME` | 条目缺 `name` 或为空白（且无可用 purl 提供身份） |
| `MISSING_COMPONENT_VERSION` | 条目缺版本字段或为空白 |
| `MALFORMED_VERSION` | 版本不符合 SemVer 2.0（如 `v1.0.0`、`1.2`、`1.02.3`、`1.2.3-01`） |
| `MALFORMED_PACKAGE_URL` | 条目带 purl 但结构无法解析出可靠身份（如缺 `pkg:` 前缀、maven 缺组名） |
| `DUPLICATE_COMPONENT` | 同一份提交文档内出现归一后相同的组件 |

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
| `UNKNOWN` | **无法判定**：生态认不出来（无坐标无生态信息）、生态类型暂不支持（如 deb）、版本无法解析、相关规则的版本区间非法等。不默认安全 |
| `CLEAN`（最轻） | 身份可靠（受支持生态：maven / npm）且确认未命中任何规则（依据明确：`CLEAN:no-rules-matched` 或 `CLEAN:all-ranges-excluded`） |

**“无法判定”优先于“安全”**：严重度排序为 `CLEAN < UNKNOWN < VULNERABLE < DENIED`，
目标总体等级取最严重者，因此只要清单中存在无法判定的组件，目标总体结论就不会是 CLEAN。
生态认不出来或不受支持的组件不参与规则匹配（身份不可靠时匹配结果不可信），
直接给出 UNKNOWN 并说明原因。

每条结论都带 `reasons` 判定依据，如：
`VULNERABLE:CVE-2021-44228:in-range[[2.0.0,2.12.3), [2.13.0,2.15.0)]`、
`DENIED:POLICY-BANNED-LEGACY:...`、`UNKNOWN:illegal-vuln-range:...`、
`UNKNOWN:unidentified-component:no-ecosystem-or-coordinates`、
`UNKNOWN:unsupported-ecosystem:deb`。

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

**传输层状态语义**（客户端不看响应体即可判断结果类别）：

| HTTP 状态 | 含义 | 对应响应体 `status` |
|---|---|---|
| `200 OK` | 全部成功 | `SUCCESS` |
| `200 OK` + 响应头 `X-Idempotent-Replay: true` | 全部成功且本次为纯幂等重放（`acceptedCount=0`、`duplicateCount>0`、无拒绝） | `SUCCESS` |
| `207 Multi-Status` | 部分成功：有条目入库，同时存在被拒绝条目 | `PARTIAL_SUCCESS` |
| `422 Unprocessable Content` | 整体失败：无任何条目入库（文档畸形，或条目全部非法/全部文档内重复） | `FAILED` |
| `400 Bad Request` | 请求体本身非法（非 JSON、缺字段等） | —（`INVALID_REQUEST` 错误体） |

**兼容范围**：响应体字段（`status` / 计数 / `components` / `rejected` / `summary`）保持不变，
依赖响应体的既有调用方不受影响；仅传输层状态码由“恒 200”细化为上表，
仅依赖“200 即成功”的调用方需要按上表适配。

响应体示例（HTTP 207）：

```json
{
  "targetId": "app-prod-1",
  "status": "PARTIAL_SUCCESS",
  "acceptedCount": 1,
  "rejectedCount": 2,
  "duplicateCount": 0,
  "components": ["maven::ok@1.0.0"],
  "rejected": [
    {"index": 1, "reason": "MISSING_COMPONENT_VERSION", "detail": "component at index 1 has no version"},
    {"index": 2, "reason": "MISSING_COMPONENT_NAME", "detail": "component at index 2 has no name"}
  ],
  "summary": "parsed=3, newlyAccepted=1, duplicates=0, rejected=2, storedForTarget=1"
}
```

- `FAILED`：无任何条目入库（文档畸形，或文档解析通过但条目全部非法/全部文档内重复）。
- `PARTIAL_SUCCESS`：有条目入库，同时存在被拒绝条目。
- `SUCCESS`：提交内容全部入库（可能全部为幂等重复命中，此时 `acceptedCount=0`、`duplicateCount>0`，
  并携带 `X-Idempotent-Replay: true`）。

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
- **身份归一后去重**：等价写法（purl / 名称等价形态 / 大小写差异）归一到同一组件键，
  重复提交命中幂等；跨生态键空间隔离，同名组件互不串号。
- **重复提交**：同一份清单重复提交时，首次 `acceptedCount=N`，后续 `acceptedCount=0`、
  `duplicateCount=N`，存储记录始终只有一份，状态为 `SUCCESS`（HTTP 200 且携带
  `X-Idempotent-Replay: true`，外部可识别为幂等命中）。
- **规模稳定**：大清单（数百组件）与同一目标的并发重复提交下，全库 accepted 总和
  恰为组件数、其余全部为幂等命中，无重复记录、无漏判（有对应并发测试覆盖）。
- **部分失败隔离**：单条目失败只记录到 `rejected[]`，不影响同份清单其他条目入库。
- **整体失败隔离**：文档级失败不创建任何组件记录，随后查询报告得到 404。
- **规则原子性**：规则快照为 `volatile` 引用整体替换，判定期间不会读到半更新状态。

## 7. 验证方法

### 运行全部测试（112 个）

```bash
mvn test
```

测试分层：

| 测试类 | 覆盖内容 |
|---|---|
| `version/SemVerTest` | SemVer 解析/预发布/前导零/比较（含输入摘要与依据日志） |
| `version/VersionRangeTest` | 比较符、`^`/`~`、通配符、开闭区间、OR 区间、非法区间 |
| `parser/PackageUrlTest` | maven/npm 坐标归一、%40 作用域、不支持类型、畸形坐标分类 |
| `parser/SbomParserTest` | 两种格式归一化、字段缺失/非法版本分类、畸形文档、格式识别 |
| `service/SbomIngestServiceTest` | 三态分类、文档内去重、重复提交幂等、16 线程并发幂等、并发不同组件 |
| `service/ComponentIdentityIngestTest` | 等价坐标写法归一去重、跨生态隔离、畸形/不支持坐标处理、300 组件 × 8 线程并发幂等 |
| `service/RiskEvaluationServiceTest` | DENIED/VULNERABLE/CLEAN/UNKNOWN、无法判定兜底（无生态/不支持生态）、UNKNOWN 压过 CLEAN、规则原子更新、结论复现 |
| `web/SbomControllerIntegrationTest` | HTTP 全链路：200/207/422 状态语义、幂等重放头、400、404、HTTP 并发幂等 |

单元测试日志均打印**输入摘要与判定依据**，例如：

```
INFO ... SBOM ingest start | targetId=t1 | formatHint=auto | bytes=... | head={"bomFormat":...
INFO ... Risk verdict | targetId=t1 | component=maven::...@2.14.0 | level=VULNERABLE
     | reasons=[VULNERABLE:CVE-2021-44228:in-range[...]]
INFO ... purl 输入摘要: pkg:npm/%40Angular/Core@15.0.0 | 解析: status=OK, ecosystem=npm, name=@angular/core
```

### 手动验证

```bash
mvn spring-boot:run
```

```bash
# CycloneDX 摄入（log4j 2.14.0 命中 CVE-2021-44228）；-i 可看到 HTTP 状态与幂等重放头
curl -si -X POST localhost:8080/api/sbom/ingest -H 'Content-Type: application/json' -d '{
  "targetId":"demo",
  "content":"{\"bomFormat\":\"CycloneDX\",\"components\":[{\"name\":\"随意名字\",\"version\":\"2.14.0\",\"purl\":\"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0\"}]}"
}'

# 再查报告
curl -s localhost:8080/api/sbom/targets/demo/report | python3 -m json.tool
```

## 8. 工程结构

```
src/main/java/com/github/lisama569/sbomriskservicejava/
├── model/        # 统一组件模型、生态认知（Ecosystems）、拒绝原因、三态状态、风险等级与报告 DTO
├── parser/       # 格式识别 + CycloneDX / SPDX 解析器 + purl 坐标解析（PackageUrl）+ 条目归一化
├── version/      # SemVer 解析比较 + VersionRange（操作符/caret/tilde/通配符/区间）
├── rules/        # RuleRepository：本地规则加载、懒编译、原子快照
├── service/      # 摄入（锁/去重/三态）、判定（身份闸门/UNKNOWN 兜底/复现）
└── web/          # REST 控制器（传输层状态语义/幂等重放头）与全局异常归类
src/main/resources/rules/   # vulnerabilities.json / policies.json
```
