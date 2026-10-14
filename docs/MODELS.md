# 官方资料、模型组合与成本

核对日期：**2026-10-14（Asia/Shanghai）**。以下为本次实际打开的官方页面支持的名称/标价，不复用前一对话的假定值。标价不是账号可用性或调用成功证明；服务商可调整模型、区域费率与权限。配置独立于代码，不自动追逐“最新”。

## 建议的初始组合

| 职位 | 示例 API ID | 标准输入 / 输出，美元/百万 token | 选择理由 |
|---|---|---:|---|
| 低成本分类器 | `gpt-6-luna` | 0.10 / 0.50 | 成本低，仅作结构化初筛，设置 `reasoning_effort=none` |
| 按需主管 | `deepseek-flash` | 0.30 / 1.20（峰时、未缓存） | 第二厂商复核；非思考模式，节省小任务延迟 |
| 高风险反对者 | `claude-sonnet-5-5` | 2.00 / 10.00 | 第三厂商；只对高风险调用，寻求误报/证据不足 |
| 更强主管备选 | `gpt-6.1-sol` | 2.00 / 10.00 | 仅经本地回放确有收益再升级，不默认常驻 |
| 兼容备选 | `gpt-5.4-mini` | 0.75 / 4.50 | 文档仍提供价格及接口；无需锁死组合 |
| 本机替代 | Ollama 已安装 tag | 无云端逐 token 费 | 有本机硬件/耗电/延迟成本；不虚构模型 tag |

OpenAI 官方 [Luna 型号/价格/端点](https://developers.openai.com/api/docs/models/gpt-6-luna)、[Sol 型号](https://developers.openai.com/api/docs/models/gpt-6.1-sol)、[mini 型号](https://developers.openai.com/api/docs/models/gpt-5.4-mini)、[价格页](https://developers.openai.com/api/docs/pricing)；Anthropic 官方 [Sonnet 5.5 型号与价格](https://platform.claude.com/docs/en/models/sonnet-5-5/overview)。Sonnet 文档说明默认 adaptive thinking，因此代码不强行套用旧版禁用思考参数；输出限制包括模型思考开销，截断/非 JSON 则安全暂停。

DeepSeek 官方 [Models & Pricing](https://api-docs.deepseek.com/quick_start/pricing/) 将 `deepseek-flash` 标为当前 Flash 请求名，并公布峰/谷价格。示例预算按较高峰时输入/输出费率计，不假定获得供应商缓存折扣。旧 `deepseek-v4-flash` 名称虽兼容，文档说明其对应模型已退休，故不用于示例。

选择上述组合是可测试的设计建议，不是对安全分类能力的实测排名。新部署先保持 AI 关闭，用真实本机误报/攻击样本评估，再启用模型建议。高风险最终始终由人批准。

## 量级估算

仅作可复算示例：100 个需要模型的事件，各层每次 2000 输入、300 输出 token；全部调用分类器和主管，其中 10 个高风险加 reviewer。按上表标准未缓存费率：

```text
分类器：100 × (2000 × 0.10 + 300 × 0.50) / 1,000,000 = $0.035
主管：  100 × (2000 × 0.30 + 300 × 1.20) / 1,000,000 = $0.096
复核：   10 × (2000 × 2.00 + 300 × 10.00) / 1,000,000 = $0.070
合计：$0.201
```

这不是程序实际账单：证据长度、思考 token、失败调用、地区费率会改变成本。默认 `daily_calls=100` 意味着最多100次模型 HTTP请求，**不是100个完整三模型事件**；上述估算需要210次调用，若做该规模评测要由用户显式调整调用上限。默认 `daily_usd=0.50`；程序按请求字节+4096额外输入 token 估算并预留最大输出费用，超时也不退款。金额估算不能替代供应商账单限额。

## 冷启动与协议

- 云 API 无常驻对话轮询，未执行 review 就不请求；不宣称能控制云 GPU 冷启动。
- Ollama `/api/chat` 的 `keep_alive=0` 用于请求后卸载；`stream=false`、JSON format。模型需自行预先安装，模板不自动下载。[官方 Chat API](https://docs.ollama.com/api/chat)、[FAQ](https://docs.ollama.com/faq)。
- 结构化输出为强校验 JSON，不依赖厂商一致支持的 JSON schema 参数。错误/文本/工具调用无法进入执行器。
- API 依据：[OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)、[Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create)、[DeepSeek First API Call](https://api-docs.deepseek.com/quick_start/pricing-details-cny/)。

## 防火墙与事件文档依据

- [nftables element timeouts](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts)：元素 TTL 由内核计时；进程不必常驻维护到期。
- [nftables configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)：base chain 的 priority/policy 与跨链 verdict 语义；本项目固定 INPUT priority 10。
- [nftables sets](https://wiki.nftables.org/wiki-nftables/index.php/Sets)：IPv4/IPv6 类型集合与 timeout。
- [Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)：alert、地址、flow_id、signature/severity 等结构。latest 链接本次显示开发版本，MVP 只使用长期存在的基础字段，不依赖开发版特性。
- [Debian UFW 手册](https://manpages.debian.org/bookworm/ufw/ufw.8.en.html)、[firewalld 配置](https://firewalld.org/documentation/man-pages/firewalld.conf.html)：作为现有规则管理器识别依据；本项目不写其内部表，也不承诺并行接管。
