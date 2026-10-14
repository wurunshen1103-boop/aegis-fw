# 安装、逐项授权与卸载

适用 Debian 12、Ubuntu 22.04/24.04，Python ≥3.9、nftables、iproute2、OpenSSH server。先在有控制台的测试 VM 完成内核测试。仅用于你拥有或获得明确授权的 Linux 主机。

## 1. 安装是无接管操作

```sh
sudo apt-get update
sudo apt-get install python3 nftables iproute2 openssh-server
python3 -m unittest discover -s tests -v
sudo /usr/bin/python3 -I packaging/install.py
```

安装器离线复制本项目代码到 `/opt/aegis-fw`，使用 root 所有的固定入口，以 Python `-I` 隔离环境运行；创建固定配置和状态目录及两个 CLI。不运行 nft，不启用任何服务，不下载模型，不创建 sudoers 条目。已有任一目标路径时整体拒绝覆盖。安装中断留下的路径需检查后手工处理，不能直接强制覆盖。

普通用户也可 `python3 -m venv .venv && .venv/bin/pip install .` 安装 CLI 做影子分析；**不要给这个可写虚拟环境的 CLI 授予 sudo 权限**。正式 root 执行必须使用上面的 root-owned 离线安装。

## 2. 明确配置管理边界

编辑 `/etc/aegis-fw/policy.json`（root:root，0644，不可组写）。要求其所有父目录不可被非 root 写入、不可为符号链接。

- `local_addresses`：本机实际接收入站的 IPv4/IPv6 地址，执行时会用 `ip -j address show` 核验。示例 TEST-NET 地址必须替换。
- `protected_cidrs`：管理出口、跳板机、可信 VPN、DNS/关键依赖、监控来源及不能封禁的网络；保留回环与内网保护。所有非公网源地址额外硬保护，不能用配置解除。
- `management_ports`：必须包括 22 和全部自定义 SSH、VPN、应急管理 TCP/UDP 端口。`sshd -T` 的端口须全部包含。OpenSSH socket activation/端口映射不能单靠 sshd 配置发现，务必人工核对。
- `allowed_signatures`：只填写已经回放验证的本机 Suricata/log-rule 检测规则 ID。`9900001` 是演示 ID，不能作为生产规则照抄。
- `evidence_path`：本地 EVE JSONL；生产者、文件和父目录必须 root 所有且不可组/其他用户写。MVP 不接受普通用户写入的传感器日志；对于降权运行的 Suricata，应由受信日志管道生成 root-owned 副本，不要把不受信用户写入路径伪装为 root。
- `management_confirmed=true`：你已经确认上述保护范围。先保留 `mode=shadow` 回放；准备接管时明确改为 `enforce`。

`confidence_threshold` 默认 .95 是模型自报置信度门槛，不是误报概率承诺。两个不同 flow 也不等于两个独立安全传感器；无充分信任的规则不应自动授权。

## 3. 影子分析与可选 AI

```sh
aegis-fw --policy /etc/aegis-fw/policy.json --db ./observer.sqlite ingest ./eve-copy.jsonl
aegis-fw --policy /etc/aegis-fw/policy.json --db ./observer.sqlite list
aegis-fw --policy /etc/aegis-fw/policy.json --db ./observer.sqlite review CASE_ID --models ./models.json
```

`models.json` 从示例复制，默认 AI 关闭。启用时由普通用户设置必要 API key 环境变量，将 `enabled` 改 true。不要把密钥写进策略、日志、命令行参数或提交 Git。Ollama 角色用本机已安装的真实 tag 替换模板值；程序不会自动拉取模型。

只读取日志的副本做观察；复制文件不会使副本成为 root 执行器认可的来源。root 仍按固定 `evidence_path` 读取原始受信证据。自动处置只看最近 4 MiB/最多 20000 行，有异常超长行会拒绝；高吞吐日志需要独立轮转/聚合，MVP 不假装具有无限队列能力。

## 4. 接管专用表：必须显式授权

将配置改成 `enforce`，重新基于这个配置生成/审核提案（策略摘要改变会使旧提案失效）。

```sh
sudo /usr/local/bin/aegis-fw-admin policy-id
# 检查策略后，把输出的 POLICY_HASH 原样填入：
sudo /usr/local/bin/aegis-fw-admin init --confirm POLICY_HASH
```

会检查 Linux、nft 可读、UFW/firewalld 安装与规则、iptables/IPv6 兼容规则、管理端口及本机地址。检测到管理器就拒绝；**不要为了本项目直接卸载正在保护主机的 UFW/firewalld**。此时继续影子模式，或在另一个纯 nftables 测试主机演练。MVP 的兼容策略是“检测并拒绝写入”，不是保证与它们并行运行。

同名表已经存在但没有本项目状态时拒绝接管。既有其他 nftables 表保持原样。状态丢失、初始化断电或 root 管理员更改专用表时，不会猜测所有权或重写整套规则；检查 `nft -j list table inet aegis_fw` 并由管理员恢复。

## 5. 单事件人工批准

先审阅事件及模型意见，再导出：

```sh
aegis-fw --policy /etc/aegis-fw/policy.json --db ./observer.sqlite export CASE_ID > ./proposal.json
# 阅读 proposal.json：源 IP、全部证据、TTL、risk、policy_hash。
sudo /usr/local/bin/aegis-fw-admin apply --confirm CASE_ID < ./proposal.json
sudo /usr/local/bin/aegis-fw-admin status
sudo /usr/local/bin/aegis-fw-admin rollback --case CASE_ID
```

不要盲目复制一个未审阅的摘要当作批准。JSON 文档最多 64 KiB；根执行器严格重建提案，从受信日志重找全部证据并检查时效。在 root 端获批之前，观察库的任何状态都没有系统权限。

高风险和模型不可用事件仍可由管理员明确手动批准，所依据的是人的审查与固定安全策略。模型输出不是签名证明，因此不以客户端传来的“3 票通过”作为 root 授权。此取舍避免伪造模型结果获得系统权限。

## 6. 逐规则限时自主授权（无 AI 路径）

```sh
sudo /usr/local/bin/aegis-fw-admin grant --signature VERIFIED_SIGNATURE_ID --seconds 300
# 检查返回的 grant 内容后，填写其 confirmation：
sudo /usr/local/bin/aegis-fw-admin grant --signature VERIFIED_SIGNATURE_ID --seconds 300 --confirm GRANT_HASH
sudo /usr/local/bin/aegis-fw-admin auto
sudo /usr/local/bin/aegis-fw-admin revoke --signature VERIFIED_SIGNATURE_ID
```

每条规则分开批准，最多一小时；不允许自动续期。只有 medium 风险、证据完整、源不受保护且未超配额的事件才能自动应用。撤销授权不追溯删除正在生效的块；可立即 `rollback`，否则按 TTL 消失。

持续运行是额外显式操作。在确认 `/etc/systemd/system/aegis-fw-auto.*` 不存在后，复制项目 `packaging/` 的 service/timer 文件到该目录，root:root、0644，然后：

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-fw-auto.timer
sudo systemctl status aegis-fw-auto.timer
sudo journalctl -u aegis-fw-auto.service
```

每 15 秒检查一次，授权到期后不新增块。无需 API，服务进程不导入模型模块。没有授权时不应启用计时器。systemd 限制不能取代内核/管理员边界；有 root 的攻击者仍可改动系统。`systemctl stop` 后既有元素继续由内核 TTL 到期。

## 7. 回滚和卸载

1. 若启用过 timer，先 `sudo systemctl disable --now aegis-fw-auto.timer` 并停止 service。
2. 单事件可 `rollback --case CASE_ID`。整体移除仅删除本项目拥有且指纹匹配的表：

```sh
sudo /usr/local/bin/aegis-fw-admin uninstall --confirm DELETE-OWNED-TABLE
```

3. 若手工安装了 systemd unit，先核对确为本项目文件，只移除这两个 unit，再 `sudo systemctl daemon-reload`。
4. 删除软件（检查 manifest，遇到修改或未知文件则全盘拒绝，保留人工检查）：

```sh
sudo /usr/bin/python3 -I /opt/aegis-fw/uninstall.py --confirm-remove-software
```

配置 `/etc/aegis-fw`、root 审计/状态 `/var/lib/aegis-fw`、原始安全日志、观察数据库不会删除。保留以便审计；需要清理时单独审阅这些目录。不会卸载系统 nftables、修改系统服务或删除其他规则。

主机重启后 nft 临时表通常消失而本地状态保留。MVP 此时故意拒绝自动重建。先核对 live ruleset，然后归档旧 `state.json` 以保留审计，再明确 init；不要自动持久化当前动态集合到 `/etc/nftables.conf`。
