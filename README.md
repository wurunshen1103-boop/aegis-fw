# Aegis FW — Linux AI 防火墙 Agent MVP

MIT 开源；Python 3.9+；运行时仅依赖 Python 标准库。目标平台 Debian 12 / Ubuntu 22.04、24.04。默认 **shadow、AI 关闭、零防火墙写入**。

本项目管理独立 `inet aegis_fw` 表内的 `dynamic` 链与 IPv4/IPv6 超时集合，不重写系统规则。仅保护授权 Linux 主机的 **INPUT 入站**，不管理路由器 FORWARD、容器转发或整网。它是可审查的 MVP，不是已认证的生产入侵防御系统。

## 立即运行：无需 root、API key 或 Linux

在项目目录中执行：

```sh
DEMO_DIR=$(mktemp -d /tmp/aegis-demo.XXXXXX)
python3 -m aegis_fw --db "$DEMO_DIR/observer.sqlite" simulate > "$DEMO_DIR/events.jsonl"
python3 -m aegis_fw --db "$DEMO_DIR/observer.sqlite" ingest "$DEMO_DIR/events.jsonl"
python3 -m aegis_fw --db "$DEMO_DIR/observer.sqlite" list
# 将上一步的 id 原样填入 CASE_ID；不要把字面量 CASE_ID 当作真实 id。
python3 -m aegis_fw --db "$DEMO_DIR/observer.sqlite" review CASE_ID
python3 -m aegis_fw --db "$DEMO_DIR/observer.sqlite" export CASE_ID
python3 -m aegis_fw --db "$DEMO_DIR/observer.sqlite" audit
python3 -m unittest discover -s tests -v
```

演示使用 `8.8.4.4` 作为合成事件源，**不发起网络访问，不得导入正式受信日志或用于真实封禁**。上述命令使用新建的独立临时目录，不覆盖已有文件。证据默认五分钟失效，演示过期后重新生成即可。`examples/policy.json` 的地址和规则 ID 都是占位示例，不能直接用于生产。

## 已实现

- Suricata EVE `alert` 与结构化 `log-rule` JSONL 输入；两个不同 flow、允许的 signature ID、目的本机地址、事件时效共同检查。
- `observe → shadow → propose → approve → enforce → verify → rollback/expired`；观察端与 root 执行端分别保存状态/审计。
- 默认不调用 AI；显式 `review` 才唤醒分类器、主管和高风险反对者。持久预算预留、每日调用上限、五分钟缓存、故障熔断；Ollama `keep_alive=0`。
- OpenAI、Anthropic、DeepSeek、Ollama 四种固定端点适配器；不提供模型工具、Shell、文件或 root 权限；禁用 HTTP 重定向与环境代理。
- 受保护网段、非公网源地址、本机地址、所有配置管理端口；保留已建立连接；核验 `sshd -T` 有效端口。
- root 执行器重新读取本机受保护日志，验证提案摘要及策略摘要。显式单项批准，或限时 signature 授权；高风险永不自主执行。
- 内核 TTL 5–3600 秒，默认 60 秒；重试不续期；活跃数量/每小时操作上限；写入前持久化意图、事后集合/结构检查、失败回滚、重启恢复。
- 独立表所有权指纹；遇到同名陌生表拒绝接管；安装的 UFW/firewalld、兼容 iptables 规则或读取失败均阻止接管。
- 可选 systemd 定时器，仅运行已逐项授权的 **无 AI 确定性路径**，默认不安装、不启用。

## 模型组合与权限

示例组合：`gpt-6-luna` 分类 → `deepseek-flash` 主管 → 高风险 `claude-sonnet-5-5` 独立反对者。这些名称与价格来自本次官方文档核对，参见 [模型与成本](docs/MODELS.md)。选择基于成本和供应商分离，尚未以真实攻击/误报数据评出最优模型。

AI 仅能输出 `support / abstain / oppose`、置信度及证据 ID。任何错误、反对、低置信度或预算不足都暂停 AI 提案流程；**不会自动切到另一个付费模型，不会因失败放宽权限**。管理员仍可通过明确人工审批走无 AI 路径。

自动授权明确授权的是管理员选定的确定性规则，不是“让 AI 获得 root”。自动路径不会宣称已经经过模型复核。模型意见属于不受信建议，不可作为 root 凭证；高风险始终需要人工审阅并批准。

## 文档与验证

- [安装、授权、运维、卸载](docs/INSTALL.md)
- [状态机、架构及权限边界](docs/ARCHITECTURE.md)
- [威胁模型和安全限制](docs/THREAT_MODEL.md)
- [官方文档、模型及价格](docs/MODELS.md)
- [测试结果与复现步骤](docs/TEST_RESULTS.md)

本次在 macOS 上运行单元/模拟集成测试。真实 Linux 内核测试已提供，但本次没有 Linux 运行环境，不能宣称 nftables 数据包路径已经实测。云 API 和 Ollama 也未使用真实凭据联调；适配器已进行模拟协议测试。
