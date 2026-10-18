# 架构和状态机

```text
Suricata / trusted log-rule producer
              │ bounded JSONL, numeric fields only
              ▼
unprivileged observer ──→ shadow cases / audit / review CLI
              │                     │ optional model API
              │                     ▼
              │          classifier → supervisor → independent critic (high risk)
              │                     │ advisory result only
              ▼                     ▼
canonical proposal + evidence IDs ← human review
              │ explicit root invocation + exact proposal ID
              ▼
root executor: fixed root policy + trusted log reread + quotas + permission
              │ OR scoped signature grant (medium risk, deterministic only)
              ▼
nft -c → atomic nft transaction → set/structure verification
              │
              ▼
inet aegis_fw / input → dynamic → blocked4 / blocked6
              │
              └── kernel TTL + rollback + reconcile
```

只有执行器使用 `/usr/sbin/nft`，无 `shell=True`、命令拼接执行、sudo 调用、模型工具或任意 executable 参数。生成的 nft 文本仅包含严格验证的 IP、整数和常量；模型返回值从未插入规则。两端通过人工传递的有限 JSON 文档连接，不通过可被模型调用的提权 socket。

## 状态语义

| 状态 | 准入及行为 | 失败行为 |
|---|---|---|
| observe | 解析、归一化、事件窗口、签名白名单、双 flow；保存符合基础策略的候选 | 不合格分组计数，不写防火墙 |
| shadow | 默认模式；推演有限动作，不调用 nft | 保持只读 |
| propose | 显式 review；无 AI 模式只形成待人工审批提案；AI 模式需各层支持且置信度 ≥ 阈值 | hold/unavailable，无后续执行 |
| approve | root 精确 proposal hash 人工确认，或尚未到期的特定 signature 授权 | 拒绝；不接受模型自签批准 |
| enforce | 重新校验策略、证据、管理端口、冲突、配额；先持久化意图再写集合 | 尝试回滚；内核 TTL 兜底 |
| verify | 读取集合及表结构；确认目标元素存在且 owned table 未漂移 | 回滚；结构漂移时拒绝未知写入，等 TTL |
| rollback | 移除本项目特定 IP 元素，确认消失 | 明确失败，保留状态供恢复 |
| expired | 状态到期且内核元素消失 | 若仍存在则回滚 |

观察数据库与 root 执行状态不是共享信任域。root `approve` 审计记录同时记录人工/授权来源；root 不信任观察库的 `propose` 字样。`status` 会协调过期状态和未完成操作，因此有可能移除本项目残留元素；它不是纯只读命令。`doctor` 才是无需 root 的信息检查。

## 包过滤语义

独立 `inet` 表；INPUT base chain priority 10、policy accept。依次 return：loopback、established/related、管理 TCP/UDP 端口、保护名单，然后 jump 到 dynamic 链。仅按源 IP drop；无永久规则、无默认拒绝、无修改 NAT、无关闭现有连接。

nftables 一个 base chain 的 accept/return 不会跳过其他 base chains 的 drop。本项目既不保证 SSH 能通过原系统防火墙，也不添加“全局放行”绕过原系统策略。它仅确保本项目自己的 drop 不匹配已配置管理端口/来源；外部规则仍可以拒绝流量。

非标准 SSH 端口由 `sshd -T` 检查；socket activation、代理跳板、端口转发、VPN 等还需管理员补齐保护列表，`management_confirmed` 是此项授权的显式记录。未确认则 init/apply 都失败。支持仅地址集合的 input 封禁：一个源 IP 会影响其所有非管理端口的新连接，NAT/共享出口误报仍须人工评估。

## 冷启动与调度

“调度主管”首先是固定代码：普通事件过滤、分层次序、预算、缓存、反对否决；模型主管只评估事件，不分配系统权限。没有常驻模型循环，没有心跳 token。每次 review 仅必要层级调用；高风险才加独立供应商 reviewer。无 API 密钥仍完整支持观察、提案、人工审批、限时授权、执行、回滚。

云 API 按需调用不等于控制供应商 GPU 冷启动；Ollama 使用零 keep_alive，在完成后卸载本地模型。应用缓存只命中同角色/模型配置/策略/完整证据/提示版本的完全相同请求，五分钟后失效。失败后整个 council 五分钟冷却，无自动重试。

预算先在 SQLite 锁内预留最大输出费和保守输入估算，失败不返还预留。硬限制是每日调用次数和输出 token 参数；金额是基于用户维护价格的本地估计，并非账单级担保。应同时设置供应商侧预算。时间按 UTC 日计算。两个并发进程可能同时请求相同未命中的缓存，但都会占用原子预算预留。

## 受限自动模式

root 管理员逐条 signature 授权，期限 ≤3600 秒；动作 TTL、保护名单、目的本机地址、两条不同 flow、事件新鲜度和全局速率上限不能通过授权绕过。高风险 severity=1 绝不自动执行。定时器仅持有已授予规则，不会自动续期。重启不恢复集合，不自动重新初始化表；管理员重新检查后决定。

## 长期证据层预览

2026-10-15 增加了独立的本地历史证据和调查接口，见 [长期证据与多时间窗口架构](TEMPORAL_ARCHITECTURE.md)。上文的模型 Council 与 root 执行器权限不变；新的模型多实例计划不等于已运行的 Agent。
