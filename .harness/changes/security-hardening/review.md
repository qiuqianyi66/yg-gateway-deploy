# security-hardening 代码评审

> 阶段 6 output。评审对象：`feature/security-hardening` 全量变更。
> 六维：正确性 / 性能 / 安全 / 一致性 / 可维护性 / 架构合规。

## 评审结论

**通过**。无 🔴 阻断，🟡 0 项。

## 一、正确性

| 项 | 结论 |
|---|---|
| F-001 MaxBytesReader | ✅ 超限返回 413 且 `*http.MaxBytesError` 精确识别；`err` 变量作用域正确（`var body []byte; var err error` 先声明后分支赋值） |
| F-002 matcher 解析 | ✅ 精确 IP + CIDR 混合、非法条目忽略、全非法回落 nil；`SplitHostPort` 处理 "IP:port" |
| F-002 extractClientIP | ✅ nil matcher → 不采信回落 RemoteAddr；命中 → 采信 XFF；未命中 → 回落。三态清晰 |
| F-003 限流 | ✅ 固定窗口 `allow` 原子计数（mu 锁）；窗口滑过整体重置；空 key 用 `\x00global` 隔离 |
| 限流挂载顺序 | ✅ withAuth 在外、rateLimited 在内——未鉴权者不消耗限流配额 |
| `/healthz` 不限流 | ✅ 有专门测试钉住（探活友好） |

## 二、性能

| 项 | 结论 |
|---|---|
| MaxBytesReader | ✅ 读取时截断，超大 body 不整体进内存（核心收益） |
| 限流 | ✅ 固定窗口 O(1)，map 计数；窗口滑过整体重建 map，无泄漏 |
| 无锁开销 | ✅ 限流器仅命中只读端点，chat 主路径零开销 |

## 三、安全

| 项 | 结论 |
|---|---|
| F-002 伪造 XFF | ✅ 直连部署默认不采信，消除上游风控/计费污染向量 |
| 牙齿验证 | ✅ 三条加固各注入 bug 均被测试精确抓到（含 F-002 注入「无条件信任 XFF」→ `extractClientIP(nil) = 169.254.169.254` 被抓） |
| 错误响应 | ✅ 413/429 均走 `writeOpenAIError`，不泄漏内部实现 |
| 配置 fail-fast | ✅ `limit>0` 但 window 空/非法 → 启动即报错，不静默关防护 |

## 四、一致性

| 项 | 结论 |
|---|---|
| IP 采集口径 | ✅ 日志侧 `captureClientInfo` 与 chat 侧 `extractClientIP` 同走受信任代理闸门，两条口径一致 |
| config 命名 | ✅ `server.max_body_bytes` / `security.trusted_proxy` / `security.read_only_rate_limit` 与既有命名风格一致 |
| 默认值 | ✅ 三个字段缺省均为旧行为（0/空/0），向后兼容 |

## 五、可维护性

| 项 | 结论 |
|---|---|
| 注释 | ✅ 每处改动写了"为什么"（含历史决策的重新质疑），与仓库讲 why 风格一致 |
| 死代码 | 🟢 `clientIPForLog` 生产路径已不再调用，但被测试引用（钉住旧回落语义），注释已标明「新增代码用 extractClientIP」 |
| 单一职责 | ✅ trusted_proxy.go / ratelimit.go 各管一域，边界清晰 |

## 六、架构合规

| 项 | 结论 |
|---|---|
| 依赖方向 | ✅ 未新增包间依赖；`extractClientIP` 复用 `upstream.ExtractClientIP`（单向 server→upstream） |
| 承重墙 | ✅ 未触及选号/冷却/熔断/凭证链路 |
| 红线 | ✅ R8（报文形态不动）、R14（Go 1.27.2）、R15（备份）均遵守 |
| 变更追踪 | ✅ `.harness/changes/security-hardening/` 已建 |

## 待办（不阻塞）

1. 🟢 `clientIPForLog` 是遗留死代码（仅测试引用）。可在后续清理时删除，或让它也接受
   matcher 统一语义——当前保留因为它钉住了「回落 RemoteAddr」的旧行为，删了要同步改测试。
2. 🟢 限流器是固定窗口（边界处允许瞬时 2× 突发）。对「防无脑刷取」够用；若未来要做
   精确配额（计费场景），再换令牌桶/滑窗。
