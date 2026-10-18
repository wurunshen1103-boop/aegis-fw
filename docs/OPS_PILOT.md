# Linux 运维只读调查试用版

更新日期：2026-10-18。面向 Linux 运维／小型企业内网团队，首个场景是 SSH 登录异常的本地调查。输出分为程序统计的记录事实、运维人员声明的背景、模型待核对假设和缺失信息。这个版本不自动封禁，也不声称已经完成真实客户验证。

## 三个改进

1. **结论约束**：事实栏只接受程序对固定调查快照的统计。启用运维背景后，模型只返回预定义的候选假设/问题编号和证据引用；程序检查每个候选所需的记录类型，并用固定中文模板呈现为未核实假设。引用存在不等于推断成立；投票不能改变这一点。
2. **环境接入**：现有 Suricata EVE 输入继续使用；新增 `journalctl -o json` 的 sshd 登录记录转换。接收“失败”和“接受”记录，去除用户名、认证指纹和原始消息。目标主机名、IP、服务端口必须由操作者明确指定。
3. **试用执行**：提供一个小团队可采用的有限试用计划、访谈提纲、指标定义和空白反馈格式。真实客户反馈和付费意愿仍需实际取得。

## 代码接口

| 文件 | 用途 |
|---|---|
| `journal_bridge.py` | 有界、增量的 journald JSON 转换；稳定记录标识、来源偏移及摘要、路径绑定、重复导入 |
| `ops_context.py` | 资产/规则/维护窗口声明、固定快照事实、模型意见的程序审查标记 |
| `ops_report.py` | 将事实与假设隔离渲染，检查运行记录属于同一调查和背景配置 |
| `ops.py` | `journal`、`context`、`report` 三个普通用户命令 |
| `local_runner.py` | 增加 `--ops-context`；先独立反证，再审查负责人结论，默认共7个逻辑实例 |

新增内置编号1001001/1001002，仅解释规范化 `log-rule` 中的 SSH 失败/接受记录。它们不是攻击判定，也没有加入原防火墙授权规则。转换产生的 `flow_id` 是稳定的日志记录标识，不代表已经验证的独立网络会话。

## 在授权 Linux 主机上准备日志

由有日志读取权限的用户执行；程序不会提升权限，也不修改用户组或系统日志设置。以 Ubuntu 常见的 `ssh.service` 为例，其他系统需确认自己的 unit 名称。

```sh
LAB=$(mktemp -d /tmp/aegis-ops.XXXXXX)
umask 077
journalctl --unit=ssh.service --since='24 hours ago' --output=json --no-pager > "$LAB/ssh.jsonl"
```

先在本机确认导出是否包含 `_HOSTNAME`、`_COMM` 或 `SYSLOG_IDENTIFIER`、`__REALTIME_TIMESTAMP` 和字符串 `MESSAGE`。不需要上传原日志或 API 密钥。此版支持常见 OpenSSH `Failed/Accepted password/publickey/keyboard-interactive` 行；其他消息会计数为未支持，不应当作没有异常。

`ssh.jsonl` 是该批次的原始快照，保留不变。bridge 支持追加数据与文件轮转，但不能把任意改写后的文件视为连续可信的日志。后续独立批次建议使用新试用目录和独立调查，避免不明来源的数据混合。

## 转换、采集、冻结调查

先复制并修改项目示例 `policy.json`，保持 `mode=shadow`，填入授权 Linux 主机的真实地址。以下 `HOST_IP`、`HOSTNAME` 和 `INCIDENT_ID` 都须替换为实际值；SSH 非22端口需要一致调整。

```sh
python3 -m aegis_fw.ops --policy ./policy.json journal \
  --input "$LAB/ssh.jsonl" --bridge "$LAB/bridge" \
  --asset HOST_IP --hostname HOSTNAME --port 22

python3 -m aegis_fw --policy ./policy.json evidence --store "$LAB/history.sqlite" \
  collect "$LAB/bridge/events.jsonl" --sensor ssh-local

python3 -m aegis_fw --policy ./policy.json evidence --store "$LAB/history.sqlite" \
  open --asset HOST_IP --service tcp:22 --lookback-hours 24
```

原始日志只读打开。bridge 的原文 SHA-256、原始字节偏移和规范化事件 ID 存在独立 `provenance.jsonl`；用户名、消息正文及认证指纹不会复制到模型材料。`evidence show` 返回的 `observed.id` 可以与该来源表对应。文件在本机保留不等于已经加密或满足特定保密要求。

单批最多2万行、4 MiB；单行最多64 KiB；bridge 输出有容量上限。查看返回的 `wrong_host`、未支持消息、积压、轮转和收据计数，不能只看“命令执行成功”。崩溃可能在输出落盘后、游标保存前重复追加；下游同一 sensor 和规范化事件 ID 会去重。检测到不完整输出行时保留现场并拒绝继续。

## 添加运维背景

复制 `examples/ops-context.json`，至少填写资产 IP、服务和重要性；只加入已核对的规则释义和维护时间。

- 内置 SSH 记录释义不可覆盖。
- 自定义 Suricata 规则可填写含义和正常触发解释。
- `changes` 是人员声明，不是“维护期间一定无攻击”的证明。
- `telemetry` 的“未采集”与“故障”不同。即使人员声明其他系统有健康数据，此版未读取这些数据时仍标为未知。
- 配置文件须为当前用户或root所有、不可组/其他用户写入，不能使用符号链接。模型不能修改该文件。

## 先看无模型报告

```sh
python3 -m aegis_fw.ops --policy ./policy.json report \
  --store "$LAB/history.sqlite" --incident INCIDENT_ID \
  --ops-context ./ops-context.json --output "$LAB/report-no-ai.md"
```

事实包括：调查范围内记录数、唯一源IP数、迟到采集数量、SSH失败/接受记录数，以及心跳与业务健康证据缺失。告警数不是总流量，唯一IP数不是攻击者人数；“接受认证”也不证明账号使用获得授权。

## 可选本地模型调查

沿用 [本地运行器](MAC_LOCAL_RUNNER.md) 的本地服务配置，给命令增加 `--ops-context ./ops-context.json`。任务为原来的6个角色加上 `critic-audit`：第一轮反证保持独立，最后一轮对照程序事实审查负责人意见。

```sh
python3 -m aegis_fw.local_runner \
  --policy ./policy.json --store "$LAB/history.sqlite" --incident INCIDENT_ID \
  --ops-context ./ops-context.json --endpoint http://127.0.0.1:18123 \
  --key-file "$LAB/api-key" --run-dir "$LAB/run"

python3 -m aegis_fw.ops --policy ./policy.json report \
  --store "$LAB/history.sqlite" --incident INCIDENT_ID \
  --ops-context ./ops-context.json --run-state "$LAB/run/state.json" \
  --output "$LAB/report-with-ai.md"
```

报告合并时会核对数据库、调查ID和背景配置摘要。背景改变后应创建新的模型运行，不复用不同背景下的结果。此版运行契约为 `ops-evidence-v3`，不静默继续旧版运行目录。新的程序审查会标记未知规则、背景缺失和缺乏心跳/业务健康证据。候选目录中没有“传感器故障”“维护导致采集异常”等缺乏证据的原因，也不允许模型通过自由文字添加新事实。目录外情况应补证并由人处理；这种收窄提高输出可控性，不证明模型推理准确率提高。

## 已知边界

此版不连接 EDR、资产系统或业务监控，也不自动判断大规模协同攻击。journal 导出文件及来源标签不是经过认证的传感器身份。真正生产接入需要客户授权的日志与操作流程；本地格式样例通过不能代替真实客户验收。

工程检查与本地模型试跑结果见本轮交付记录；商业指标仍未测量。

## 参考

- [systemd journal 字段定义](https://github.com/systemd/systemd/blob/main/man/systemd.journal-fields.xml)
- [journalctl 输出格式](https://github.com/systemd/systemd/blob/main/man/journalctl.xml)
- [OpenSSH 认证日志实现](https://github.com/openssh/openssh-portable/blob/master/auth.c)
- [Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
