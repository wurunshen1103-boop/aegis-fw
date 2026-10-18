# 测试结果

本报告记录初版测试，不覆盖2026-10-15新增的长期证据架构预览。用户要求暂不继续测试，因此本次没有运行新增功能或测试。

执行日期：2026-10-14（Asia/Shanghai）。本机 macOS、Python 3.9.6。

```text
python3 -m unittest discover -s tests -v
Ran 65 tests in 1.769s
OK (skipped=1)
```

**64 项通过，1 项跳过，0 失败。** 完整输出见 [test-output.txt](test-output.txt)。

| 层级 | 实际运行范围 | 结果 |
|---|---|---|
| 核心策略 | IPv4/IPv6、保护 CIDR、管理端口、签名白名单、时效、双 flow、摘要/策略篡改、状态转换、模型输出校验 | 通过 |
| 执行器模拟集成 | 人工批准、逐规则自动授权/到期、高风险人工要求、可信证据重读、漂移拒绝、配额、TTL不续期、故障回滚、崩溃恢复、旧事件回滚隔离 | 通过；使用内存 nft 替身 |
| CLI 子进程端到端 | simulate → ingest → shadow → review（无 AI）→ propose → export → audit；重复导入 | 通过；无 firewall 调用 |
| HTTP 协议集成 | 真实 localhost HTTP server 接收四种适配器请求、返回模拟厂商 JSON；重定向拒绝 | 通过；非真实供应商认证 |
| 模型调度 | 分层、独立供应商、预算预留、每日调用上限、缓存、错误熔断、拒绝 root AI、反对否决 | 通过 |
| Linux 内核数据包 | IPv4/IPv6 drop、TTL、SSH 端口、已建立连接、回滚、原表保持 | **跳过：本机无 Linux/容器运行时** |
| root 安装/卸载、systemd | 提供脚本与文档；未在当前主机安装 | **未实际运行** |
| 真实 OpenAI/Anthropic/DeepSeek/Ollama | 官方文档已读，适配器协议已测 | **未进行真实服务联调或计费核验** |

本地测试不证明 Linux nft 语法、内核路径或目标发行版上的服务权限配置已经工作。不能把跳过项写成通过。所有 Python 文件另外做了语法解析；正式部署须先跑下面的 Linux 隔离测试。

## 复现无权限测试

在项目目录：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

测试临时目录与 HTTP server 在结束时清理；不访问付费端点，不写本机防火墙。

## Linux 内核集成测试

在一次性 Debian/Ubuntu VM（安装 nftables、iproute2、util-linux 后）运行：

```sh
sudo env AEGIS_KERNEL_TESTS=1 python3 -m unittest discover -s tests -p test_kernel.py -v
```

父测试不运行 nft；先 `unshare --net`，子程序比较网络命名空间标识，未与父环境隔离就拒绝。创建第二个匿名 namespace 和 veth 作为客户端，所有合成公网地址只存在于隔离网络中，没有外网路由。

目标断言：自有集合 IPv4/IPv6 真正丢弃新 TCP；管理端口2222仍通；已建立连接可继续；五秒 TTL 后恢复；精确回滚恢复；卸载后既有 `existing` 表指纹不变且它原有的拒绝规则仍有效。测试成功应包含 `KERNEL_PASS`。未开启 opt-in 或非 Linux 时明确 skip。

GitHub Actions 文件包含 Python 3.9/3.12 单元测试与 Ubuntu 24.04 隔离内核测试。当前没有创建/推送远端仓库，所以没有声称 CI 已运行。
