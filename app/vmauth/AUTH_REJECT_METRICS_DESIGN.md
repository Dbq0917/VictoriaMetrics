# 认证拒绝指标（vmauth_auth_rejected_requests_total）设计与验收

## 1. 背景与目标

`vmauth` 是统一的认证代理。当前认证类拒绝只体现在
`vmauth_http_request_errors_total{reason="invalid_auth_token"}` 这一个序列里，
无法区分"请求根本没带凭据"和"带了凭据但凭据错误"。业务层自行埋点又存在重复计数、
与网关口径对不上的问题。

本次在代理层统一新增一个独立计数器，满足：

- 无凭据拒绝单独计数，与凭据错误区分开。
- 计数可按后端（backend）与租户（tenant）维度拆分。
- 高并发下计数不成为瓶颈。
- 指标命名清晰，可被现有 Prometheus 兼容采集直接抓取。
- 不改变任何现有指标的名字与语义，不改变鉴权流程。
- 可灰度、可分钟级回退，可按环境区分，基数可控且有降级方案。

## 2. 口径定义（与监控平台对齐的唯一口径）

新增指标：

```text
vmauth_auth_rejected_requests_total{reason, backend, tenant[, env]}
```

类型：counter（单调递增，重启后从 0 开始，使用 `increase`/`rate` 消费）。

`reason` 取值：

| reason | 口径 | 触发位置 | HTTP 响应 |
| --- | --- | --- | --- |
| `missing_credentials` | 请求未携带任何认证凭据（无 `Authorization` 或配置的认证头），且 `unauthorized_user` 没有可服务该请求的路由（含 `deny_paths` 命中、无匹配路由） | `processEmptyAuthRequest`、`processRequest` 中未认证用户的 401 分支 | 401 |
| `invalid_credentials` | 请求携带了凭据，但静态 token、JWT、SSO 均未匹配到用户，且未配置可兜底的 `unauthorized_user` 路由 | `handleInvalidAuthToken` | 401 |

明确不计入本指标的情况：

- 请求被 `unauthorized_user` 正常代理（这不是"拒绝"）。
- SSO 浏览器登录页、302 跳转、403 Access Denied（属于交互式登录流，不是 API 凭据校验）。
- 并发限制 429、`missing_route`、`denied_paths`（已认证用户）、`client_canceled` 等既有 reason，
  继续只计入原有的 `vmauth_http_request_errors_total`，语义保持不变。

标签口径：

- `tenant`：从集群 URL `/{insert|select|delete}/{tenantID}/{suffix}` 解析；无法解析时为 `unknown`。
- `backend`：从命中的 `unauthorized_user` 的 `url_map` 推导，只取首个后端的 `scheme://host:port`，
  不包含路径、查询参数，也不使用 `-discoverBackendIPs` 发现的动态 IP；无法推导时为 `unknown`。
- `env`：由 `-authRejectMetrics.environment` 指定（如 `prod`/`staging`）；为空时不输出该标签。
- 标签关闭时取值固定为 `disabled`，而不是省略标签，保证标签集合稳定、看板查询不失效。

与现有指标的关系：

- 本指标是**纯增量**，不修改、不替换任何现有指标。
- 交叉校验等式（在未配置 `unauthorized_user` 兜底代理的环境）：
  `sum(increase(vmauth_auth_rejected_requests_total{reason="invalid_credentials"}[5m]))`
  应等于
  `increase(vmauth_http_request_errors_total{reason="invalid_auth_token"}[5m])`。
  `missing_credentials` 此前没有独立计数器，属于新增可见性。

## 3. 实现概要

代码位于 `app/vmauth/auth_reject_metrics.go`：

- `authRejectMetricsRegistry` 用 `sync.Map` 缓存「标签组合 -> counter」，
  热路径只有一次 map 读 + 一次原子自增，无锁、零分配。
- 新标签组合只在慢路径通过 `metrics.GetOrCreateCounter` 注册，注册后长期复用。
- 计数入口 `incAuthRejectCounter` 在开关关闭时立即返回，功能关闭即恢复原行为。
- 埋点只加在既有拒绝出口，不调整任何鉴权判断顺序、响应内容或 `slowdownUnauthorizedResponse` 逻辑。

开关（默认全部安全态，功能默认关闭）：

| Flag | 默认 | 作用 |
| --- | --- | --- |
| `-authRejectMetrics.enable` | `false` | 总开关 |
| `-authRejectMetrics.tenantLabel` | `true` | tenant 维度开关，关闭后值为 `disabled` |
| `-authRejectMetrics.backendLabel` | `true` | backend 维度开关，关闭后值为 `disabled` |
| `-authRejectMetrics.environment` | 空 | 环境标签，空则不输出 `env` |
| `-authRejectMetrics.maxLabelValueLength` | `128` | 标签值长度上限，超长截断 |

## 4. 基数预估与降级

序列数上界：

```text
系列数 <= reason 数(2) × backend 基数 × tenant 基数 × env 基数(0 或 1)
```

量级估算（按典型部署）：

| 场景 | backend 数 | tenant 数 | env | 预估系列数 |
| --- | --- | --- | --- | --- |
| 单后端、单租户 | 1 | 1 | 1 | 2 |
| 中等规模（10 后端、50 租户） | 10 | 50 | 1 | 1,000 |
| 大规模（30 后端、500 租户） | 30 | 500 | 1 | 30,000 |

约束条件：

- `reason` 只有 2 个固定值；`env` 每个环境只有 1 个值。
- `backend` 只取 `scheme://host:port`，动态 IP 不产生新序列。
- `tenant` 来自 URL 中的数字 `accountID[:projectID]`，天然有限；
  非集群格式路径统一收敛到 `unknown`，不会按任意路径膨胀。
- 标签值长度被 `-authRejectMetrics.maxLabelValueLength` 截断，杜绝超长值制造碎片序列。

降级方案（按顺序，每一步都不需要改代码、不需要重新发布）：

1. 关 tenant：`-authRejectMetrics.tenantLabel=false`，系列数降到 `2 × backend × env`。
2. 再关 backend：`-authRejectMetrics.backendLabel=false`，每个环境只剩 2 条序列（按 reason）。
3. 总开关回退：`-authRejectMetrics.enable=false`，指标完全消失，链路行为与上线前一致。

采集端若有单指标序列上限（如常见的 10k/50k），按上表预留 30% 余量选择开关档位；
降级期间计数不丢，只是维度变粗，容量分析仍可按 reason 总量进行。

## 5. 灰度、回退与环境隔离

灰度：

1. 先在 staging 用 `-authRejectMetrics.enable=true -authRejectMetrics.environment=staging` 验证。
2. 生产按实例灰度（先 1 台 -> 10% -> 全量），通过 `env` 标签或抓取 job 区分灰度实例。
3. 灰度期同时观察新指标与 `vmauth_http_request_errors_total`，用第 2 节的等式做口径对账。

回退（分钟级）：

- flag 变更随部署/配置下发，关闭 `-authRejectMetrics.enable` 后新请求立即不再产生该指标，
  无需改动鉴权配置；已暴露的序列在一个采集周期后自然停止更新。
- 因为是独立新指标，回退不影响任何现有看板与告警。

环境隔离：

- 用 `-authRejectMetrics.environment` 打上 `env` 标签，PromQL 用 `env="prod"` 过滤；
  不同环境也可通过独立 scrape job / remote write 租户物理隔离。
- 现有看板不引用新指标，因此新增维度对现有看板零影响；新看板/报表单独建设。

## 6. 性能验收数据

基准测试（AMD Ryzen 7 9700X，16 并行，`app/vmauth/auth_reject_metrics_timing_test.go`）：

```text
BenchmarkAuthRejectMetricsInc-16        89,059,152 次   13.49 ns/op   0 B/op   0 allocs/op
```

含义：热路径（标签组合已注册）每次计数约 13.5 纳秒、零内存分配，
相对一次代理请求的网络与后端开销可忽略，不会成为高并发瓶颈。

功能关闭时 `incAuthRejectCounter` 在入口处读一次布尔 flag 即返回，无额外对象创建。

## 7. 功能验收

自动化测试位于 `app/vmauth/auth_reject_metrics_test.go`，覆盖验收标准：

| 用例 | 断言 |
| --- | --- |
| `TestAuthRejectMetrics_CountsByCredentialOutcome` | 无凭据请求只使 `missing_credentials` +1；凭据错误只使 `invalid_credentials` +1；凭据正确两个计数器都不动；所有序列带 `env` 标签 |
| `TestAuthRejectMetrics_ConcurrentTotalMatchesRequests` | 32 协程 × 200 次 = 6,400 个并发无凭据请求，计数器总和严格等于 6,400 |
| `TestAuthRejectMetrics_CardinalityDegradation` | 关闭两个维度后，4 个不同租户/路径的请求收敛为 1 条序列、值为 4 |
| `TestAuthRejectMetrics_DisabledByDefault` | 总开关关闭时 `/metrics` 不出现该指标 |
| `TestAuthRejectMetrics_UnknownTenantAndBackend` | 无法解析的租户/后端统一记为 `unknown` |
| `TestAuthRejectMetrics_BackendLabelFromUnauthorizedRoute` | `deny_paths` 拒绝能归因到具体 backend |
| `TestBuildAuthRejectMetricName` | 指标命名与标签顺序符合约定 |

并发测试同时通过 `-race` 检测。

手工验收步骤（评审演示用）：

```bash
# 1. 无凭据
curl -s -o /dev/null -w '%{http_code}\n' http://vmauth:8427/select/0/prometheus/api/v1/query
# 期望 401，missing_credentials 序列 +1

# 2. 凭据错误
curl -s -o /dev/null -w '%{http_code}\n' -u user-a:wrong http://vmauth:8427/select/0/prometheus/api/v1/query
# 期望 401，invalid_credentials 序列 +1

# 3. 凭据正确
curl -s -o /dev/null -w '%{http_code}\n' -u user-a:correct http://vmauth:8427/select/0/prometheus/api/v1/query
# 期望 2xx，两个拒绝计数器均不变

# 4. 对账
curl -s http://vmauth:8427/metrics | grep vmauth_auth_rejected_requests_total
```

## 8. 报表与容量规划用法

建议 PromQL：

```promql
# 各租户无凭据拒绝速率（定位"谁在打"）
sum by (tenant) (rate(vmauth_auth_rejected_requests_total{reason="missing_credentials",env="prod"}[5m]))

# 各后端凭据错误速率
sum by (backend) (rate(vmauth_auth_rejected_requests_total{reason="invalid_credentials",env="prod"}[5m]))

# 拒绝总量对账（压测时与请求总数比对）
sum(increase(vmauth_auth_rejected_requests_total[1h]))

# 与旧指标交叉校验
increase(vmauth_http_request_errors_total{reason="invalid_auth_token"}[5m])
```

容量报表建议字段（按租户 × 后端，按小时/天聚合）：总拒绝、无凭据拒绝、凭据错误拒绝、
无凭据占比、环比。该报表是后续按租户做容量规划的输入。

## 9. 负责人与验收时间

| 事项 | 负责角色 | 时间点 |
| --- | --- | --- |
| 代码与单测 | vmauth 代码 Owner（代理层团队） | 提测前完成 |
| 监控平台口径对齐与抓取配置 | 可观测性/SRE 团队 | 灰度前完成 |
| 灰度发布与回退演练 | SRE 值班 + 代理层团队 | 发布窗口内 |
| 容量报表与看板 | 容量规划负责人 | 全量后 1 个迭代内 |
| 验收签字（含本文档数据复核） | 代理层负责人 + SRE 负责人 | 全量后 3 个工作日内 |

> 注：具体人名与日期由项目管理系统在立项时填入，本文档定义交付物与验收口径，不留无主事项。
