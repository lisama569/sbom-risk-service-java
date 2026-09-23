# SBOM Risk Service (本地软件成分清单摄入与风险判定服务)

一个纯本地、无外部依赖的 Spring Boot 服务：随 HTTP 请求**内联提交** SBOM 清单内容，
服务将不同格式的清单归一到统一的组件模型，按本地维护的漏洞/策略规则做确定性的
风险判定，并通过并发串行化保证同一目标重复提交的幂等性。

- Java 21 + Spring Boot 3.4（在 JDK 25 上同样可构建运行）
- 无数据库：组件、规则、幂等结果均保存在内存中
- 判定只依赖随包发布的 `src/main/resources/rules.json` 与运行期管理 API 写入的规则，
  不访问任何网络漏洞源，因此同一输入 + 同一规则集的结论**可预期、可复现**

---

## 1. 支持的清单格式

| 格式 | 识别标记 | 组件来源 | 文档 ID 来源 |
|---|---|---|---|
| CycloneDX JSON | `bomFormat == "CycloneDX"` | `components[]` | `serialNumber` |
| SPDX 2.x JSON | `spdxVersion` 以 `SPDX-` 开头 | `packages[]` | `documentNamespace`，缺失时退回 `SPDXID` |

统一组件模型 `Component`：

| 字段 | 含义 |
|---|---|
| `key` | 稳定标识。优先使用 purl（`pkg:type/[namespace/]name@version`，忽略 qualifiers/subpath）；无 purl 时为合成键 `pkg:<ecosystem>/<name>@<version>` |
| `name` / `version` | 组件名与原始版本字符串 |
| `purl` / `ecosystem` / `license` | purl、包生态（npm/maven/pypi…）、声明许可证 |
| `source` | 来源格式（CYCLONEDX_JSON / SPDX_JSON） |

说明：

- CycloneDX 顶层 `type`（library/framework…）是**组件分类**而非包生态，生态只从 purl 推断。
- Maven 生态在规则匹配时使用 `groupId:artifactId` 作为组件名（purl 的 namespace 即 groupId）。
- SPDX 的 `NOASSERTION` / `NONE` 按字段缺失处理。

### 条目级拒绝原因（不静默跳过，逐体现在响应的 `rejected[]` 中）

| reason | 触发条件 |
|---|---|
| `MISSING_NAME` | 条目缺少 name |
| `MISSING_VERSION` | 条目缺少 version |
| `INVALID_VERSION` | 版本既不是合法 semver，也不是纯点分数字版本（如 `banana`、`01.2.3`、`1.2-rc1`） |
| `MISSING_IDENTIFIER` | purl 存在但畸形；或既无合法 purl 又无生态可合成标识 |
| `INVALID_ENTRY` | 组件数组中的元素不是对象 |
| `DUPLICATE_ENTRY` | 同一份清单内出现相同组件 key |
| `ALREADY_EXISTS` | 跨提交命中已存在组件（在 `accepted[]` 中以 `duplicate=true` 体现，不算失败） |

### 文档级失败原因（整单不摄入，HTTP 400）

| reason | 触发条件 |
|---|---|
| `MALFORMED_PAYLOAD` | 请求体为空 / 非 JSON / JSON 根不是对象 |
| `UNSUPPORTED_FORMAT` | 无 CycloneDX/SPDX 识别标记 |
| `MISSING_COMPONENTS` | 已识别格式但缺少 `components`/`packages` 数组（或类型不是数组） |
| `MISSING_DOCUMENT` | `content` 为空 |

---

## 2. 版本比较语义

### 2.1 可接受的组件版本

- **严格 SemVer 2.0.0**：`MAJOR.MINOR.PATCH(-prerelease)?(+build)?`，允许可选前导 `v`；
  禁止数字段前导零；构建元数据不参与比较。
- **宽松点分数字版本**：如 `1.2`、`4.11.3.2024`。按 release 处理，比较时数字核心**右侧补零**，
  因此 `1.2` 与 `1.2.0` **相等**、且 `1.2 > 1.2.0-alpha`。
- 其余写法（含字母后缀、前导零等）在摄入时以 `INVALID_VERSION` 拒绝。
- 规则中的范围边界必须是**严格 semver**（非法范围在写入/启动加载时即被拒绝）。

### 2.2 比较规则

- SemVer 按 semver.org 2.0.0 优先级：核心数值比较；任意预发布 < 同核心正式版；
  预发布标识符逐段比较（数字段按数值且低于字符串段，`alpha.2 < alpha.10`）。
- 宽松版本与 semver 跨类型比较：纯数字核心可比较（补零）；若需要解释未知文本后缀
  才能定序，则结果为 **INCOMPARABLE**。
- INCOMPARABLE 在判定中映射为 **UNKNOWN**，绝不默认安全。

### 2.3 受影响版本范围语法

范围是若干**合取组的析取**：组间用 `||`（OR），组内原子用空格或逗号连接（AND）。

| 原子 | 含义 |
|---|---|
| `*` | 所有版本 |
| `1.2.3` | 精确等于该严格 semver（含预发布身份） |
| `1.*` / `1.2.*` | 数字核心前缀通配；预发布版本不被数字前缀通配覆盖 |
| `>=1.2.3` `>…` `<=…` `<…` `=…` `!=…` | 与严格 semver 边界比较 |
| `^1.2.3` | caret：锁定最左非零核心段（`>=1.2.3 <2.0.0`；`^0.2.3`→`>=0.2.3 <0.3.0`；`^0.0.3`→`>=0.0.3 <0.0.4`） |
| `~1.2.3` | tilde：`>=1.2.3 <1.3.0` |

匹配为**三值**：`true`（在范围内）、`false`（确定不在）、`null`（边界与版本不可比）。
析取组中任一组满足即为命中；没有任何组满足但存在不可比组时返回 `null`。

---

## 3. 风险判定规则

对每个组件按 id 升序评估全部生态/名称（及许可证）匹配的本地规则，结论优先级：

1. **VULNERABLE** —— 命中至少一条漏洞规则的受影响范围。
2. **POLICY_VIOLATION** —— 命中至少一条策略规则：
   - `BAN`：按生态+名称+范围封禁（范围 `*` 表示全版本）。
   - `LICENSE_DENY`：按许可证（跨生态）拒绝。
3. **UNKNOWN** —— 存在候选规则但其边界与该版本不可比，或组件版本无法解析
   （`unknownReason` 给出 `VERSION_INCOMPARABLE` / `INVALID_VERSION` 依据）。
4. **SAFE** —— 在当前规则集下没有任何规则命中。这是在固定规则集上的**显式结论**，
   不是"查不到所以安全"。

响应的 `findings[]` 按规则 id 升序列出每条命中：`ruleId / ruleType / severity /
matchedRange / basis`（basis 给出判定依据原文）。

### 可复现性

- 规则存储为 id 有序的并发 Map，匹配顺序确定；评估无随机、无外部调用、无缓存写入。
- 规则或清单更新后：同一组件 + 同一规则集，重复评估结果**完全一致**（测试中有等值断言）。
- 规则更新后，再次评估会得到反映新规则的结论，并同样保持确定性。

### 内置规则（`src/main/resources/rules.json`）

| 规则 | 目标 | 范围 |
|---|---|---|
| LOCAL-CVE-2024-0001 | npm lodash | `>=4.0.0 <4.17.21`（HIGH） |
| LOCAL-CVE-2024-0002 | npm minimist | `<0.2.1 || >1.0.0 <1.2.6`（CRITICAL） |
| LOCAL-CVE-2023-0010 | maven org.apache.logging.log4j:log4j-core | `>=2.0.0 <2.17.1`（CRITICAL） |
| LOCAL-CVE-2022-0099 | pypi requests | `~2.5.0`（MEDIUM） |
| LOCAL-POLICY-BAN-0001 | npm left-pad | `*`（BAN） |
| LOCAL-POLICY-LIC-0001 | 任意生态，GPL-3.0-only | `*`（LICENSE_DENY） |

非法规则（缺字段、范围语法非法、策略类型/目标缺失）在启动加载或管理 API 写入时
被拒绝，HTTP 400 + `reason=INVALID_RULE`，不会被静默保留。

---

## 4. 并发与幂等语义

### 目标键（documentId）解析顺序

1. 请求头 `Idempotency-Key`；
2. 请求体字段 `documentId`；
3. 清单内嵌 ID（CycloneDX `serialNumber` / SPDX `documentNamespace`）；
4. 都没有时，对原始内容计算 `sha256:<hex>` 作为键（内容相同 ⇒ 键相同）。

### 语义

- 每个 documentId 有独立锁：**不同文档完全并发**；同一 documentId 的并发/重复提交被串行化。
- 首个提交计算结果并缓存；同键的后续（含正在并发的）提交阻塞在同一把锁上，拿到**同一份
  缓存结果**，响应中 `idempotentReplay=true`，不会再次写入任何组件。
- 仅缓存成功结果；文档级异常不缓存，下一次提交会重新处理。
- 组件去重在存储层用 `putIfAbsent`/`putIfAbsent` 原子完成：重复提交**绝不产生重复组件记录**。
  跨文档提交到已存在组件时，`accepted[].duplicate=true`，仍计入 accepted 而非失败。

### 整体失败 vs 部分成功

| 场景 | HTTP | `status` |
|---|---|---|
| 文档级失败（畸形/不支持格式/缺组件数组） | 400 | 无响应体（错误信封 `reason`） |
| 全部条目被拒（无任何摄入） | 422 | `FAILED` |
| 部分条目接受、部分拒绝 | 207 | `PARTIAL` |
| 全部接受（含已存在去重） | 200 | `ACCEPTED` |

单个条目的失败不影响其余条目；每条拒绝都带 index、name、version、reason、detail。

---

## 5. HTTP API

### `POST /api/v1/sboms`
请求头可选 `Idempotency-Key`。请求体：

```json
{ "documentId": "optional-client-key", "format": null, "content": "{...SBOM JSON 字符串...}" }
```

### `GET /api/v1/components`
按 key 排序列出全部已摄入组件。

### `GET /api/v1/components/risk?key=<urlencoded component key>`
对单个组件做风险判定，返回 verdict/findings/unknownReason。key 是含 `/` 的 purl，故用查询参数。

### 规则管理
- `GET  /api/v1/rules/vulnerabilities` / `/policies`：列出规则（id 有序）。
- `POST /api/v1/rules/vulnerabilities` / `/policies`：新增/按 id 覆盖规则；
  非法范围或缺字段返回 400 `INVALID_RULE`。

漏洞规则体：`{id, ecosystem, name, range, severity}`（ecosystem 为 null 表示跨生态）。
策略规则体：`{id, type: BAN|LICENSE_DENY, ecosystem, name, range, license, severity}`。

---

## 6. 验证方法

### 构建与全部测试

```bash
mvn test
```

测试覆盖（当前 51 个用例，均会在日志打印**输入摘要**与**判定依据**）：

- `VersionCompareTest`：semver/宽松版本/预发布/前导 v/前导零拒绝；
- `RangeMatcherTest`：比较式、析取/合取、通配符、caret/tilde、非法范围拒绝；
- `RuleEvaluatorTest`：VULNERABLE/POLICY_VIOLATION/SAFE/UNKNOWN、优先级、可复现性；
- `SbomParserTest`：两种格式识别与解析、NOASSERTION、文档级失败原因区分；
- `NormalizerTest`：缺失字段/非法版本/畸形 purl/缺标识的可区分拒绝、稳定 key；
- `SbomIngestionServiceTest`：畸形清单、重复提交（文档内/跨文档）、部分成功、
  8 线程并发同键幂等、6 线程并发不同文档互不阻塞；
- `SbomApiIntegrationTest`：端到端 HTTP 状态码映射、重放标记、规则更新后的确定性结论。

查看判定依据日志：

```bash
mvn test -Dtest=RuleEvaluatorTest
# 日志示例：
# risk input: key=..., name=lodash, version=4.17.20, ...
# risk verdict: key=..., verdict=VULNERABLE, matchedRules=[LOCAL-CVE-2024-0001],
#   basis=[version '4.17.20' is within affected range '>=4.0.0 <4.17.21']
```

### 手工冒烟（启动后另开终端）

```bash
mvn spring-boot:run
```

```bash
# 1) 摄入一个含漏洞组件的 CycloneDX 清单
curl -s -X POST localhost:8080/api/v1/sboms -H 'Content-Type: application/json' -d '{
  "documentId":"demo-1",
  "content":"{\"bomFormat\":\"CycloneDX\",\"serialNumber\":\"urn:uuid:demo-1\",\"components\":[{\"name\":\"lodash\",\"version\":\"4.17.20\",\"purl\":\"pkg:npm/lodash@4.17.20\"}]}"
}'

# 2) 重复提交（结论一致，且 idempotentReplay=true）
curl -s -X POST localhost:8080/api/v1/sboms -H 'Content-Type: application/json' -d '{
  "documentId":"demo-1",
  "content":"{\"bomFormat\":\"CycloneDX\",\"serialNumber\":\"urn:uuid:demo-1\",\"components\":[{\"name\":\"lodash\",\"version\":\"4.17.20\",\"purl\":\"pkg:npm/lodash@4.17.20\"}]}"
}'

# 3) 风险判定
curl -s --get 'localhost:8080/api/v1/components/risk' --data-urlencode 'key=pkg:npm/lodash@4.17.20'

# 4) 部分成功：一条好条目 + 一条非法版本
curl -s -i -X POST localhost:8080/api/v1/sboms -H 'Content-Type: application/json' -d '{
  "documentId":"demo-2",
  "content":"{\"bomFormat\":\"CycloneDX\",\"components\":[{\"name\":\"minimist\",\"version\":\"1.2.5\",\"purl\":\"pkg:npm/minimist@1.2.5\"},{\"name\":\"broken\",\"version\":\"nope\",\"purl\":\"pkg:npm/broken@nope\"}]}"
}'   # HTTP 207，body.status=PARTIAL，rejected[0].reason=INVALID_VERSION

# 5) 非法范围规则被拒绝（400 INVALID_RULE）
curl -s -i -X POST localhost:8080/api/v1/rules/vulnerabilities -H 'Content-Type: application/json' -d '{
  "id":"BAD","ecosystem":"npm","name":"x","range":">=banana","severity":"LOW"
}'
```
