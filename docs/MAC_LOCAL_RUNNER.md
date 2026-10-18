# Mac 本地多实例调查试跑

2026-10-15 在 Apple M2 MacBook Air、16 GB 内存上，使用官方 Qwen3-4B-Q4_K_M 和 llama.cpp b11429 完成一次真实本地推理试跑。它验证的是调查流程的执行、上下文预算和恢复机制，不是安全检测准确率，也没有接管 Mac 或 Linux 防火墙。

## 已跑通的流程

1. 将横跨7天的6条合成 EVE 告警写入独立证据库。
2. 冻结调查快照，为6个逻辑实例生成各自材料包。
3. 通过服务端聊天模板和 tokenizer 计算真实输入 token，再把同一批 token ID 交给生成接口。
4. 顺序运行两个流量角色、时间线、业务审查、反证和负责人。使用同一个加载的模型，每次是独立请求；没有同时加载6份模型。
5. 验证结构化输出和证据引用，保存6个检查点。
6. 再次恢复同一运行目录，全部复用已完成结果，生成调用总数保持6。

角色输入为2590、2590、2594、2595、2598、3407 token，总输入16374、总输出982 token。8192 token 上下文设置下，512 token 预留输出、256 token 安全余量，输入预算7424。

另外用3072 token 的较小预算检查材料裁剪：输入从2590减少到2178 token，保留3条记录，并列出省略的 E2/E3/E4；2178未超过2304输入预算。该检查没有请求额外生成。

## 新模块

`aegis_fw/local_runner.py` 提供受限的 llama.cpp 本地运行器：

- 只接受明确的 `http://127.0.0.1:PORT`；禁用环境代理和 HTTP 重定向。
- 仅调用健康、属性、模型信息、聊天模板、tokenizer、completion 这几个固定接口。
- 不注册工具，没有任意 SQL、Shell、网页读取或防火墙调用。
- 接收独立权限的本地 API key 文件，key 不写入提示词、状态文件或日志。
- 每次最多8个逻辑实例，顺序执行；负责人依赖前序角色完成。
- 单次运行最多12次生成尝试，每角色最多2次尝试；失败需要显式 `--resume`，没有无限自动重试。
- 冻结任务计划，并保存每角色 token 计数、截断信息、引用映射、结果和检查点。
- 文件锁防止同一运行目录被重复启动；状态文件以私有临时文件和原子替换写入。
- 角色输出只保存为调查假设/问题，不会作为已证实攻击或执行授权。

## 调用方式

先启动自己控制的 llama.cpp 本地服务，配置8192上下文、一个服务槽、API key 文件，并关闭 UI、内置工具和 MCP；本次 Mac 试跑还对推理进程和客户端应用了独立的 macOS 文件/网络限制。单独运行这个 Python 模块不会自动建立操作系统沙箱，不能把代码里的限制当成 OS 隔离。

在项目目录中，使用已经创建的证据库和调查 ID：

```sh
python3 -m aegis_fw.local_runner \
  --policy examples/policy.json \
  --config examples/evidence.json \
  --store /path/to/private-lab/history.sqlite \
  --incident INCIDENT_ID \
  --endpoint http://127.0.0.1:18123 \
  --key-file /path/to/private-lab/api-key \
  --run-dir /path/to/private-lab/run \
  --context-tokens 8192 \
  --output-tokens 512
```

首次 `run` 目录必须不存在；恢复时使用相同参数追加 `--resume`。证据库和调查快照的建立方法见 [长期证据架构](TEMPORAL_ARCHITECTURE.md)。key 文件要求0600，历史库命令及运行器都拒绝 root。

服务端必须支持 `/apply-template`、`/tokenize` 和 `/completion`。这不是通用 OpenAI 兼容适配器，也不能直接把 Ollama 地址替换进来。发送 token ID 能使预算核算与实际使用的输入一致，超出预算且无法保留最小材料时拒绝生成。

## 结果边界

6/6角色完成意味着流程和引用校验通过，不代表结论正确。同一种4B模型在这次试跑中仍有过度解释缺失遥测、输出混入英文等现象；一些角色意见重复。原始证据、业务上下文、人工审查和确定性权限限制仍然必要。

此试跑没有验证多模型并行吞吐、长时间稳定性、真实攻击检出率、误报率、Linux nftables 执行或企业/涉密部署合规。试跑服务已在完成后停止。模型和推理程序保留于任务独立缓存，便于复用，未安装全局服务。

## 来源与固定版本

- [Qwen 官方模型与许可证](https://huggingface.co/Qwen/Qwen3-4B-GGUF)：Apache-2.0，使用 Q4_K_M 量化文件；不是“最强安全模型”选型结论。
- 模型修订：`bc640142c66e1fdd12af0bd68f40445458f3869b`。
- 模型 SHA-256：`7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`。
- [llama.cpp b11429 官方发布](https://github.com/ggml-org/llama.cpp/releases/tag/b11429)。
- macOS arm64 发布包 SHA-256：`740288ec6887be94280a5dfa25b5e23a78285cab104519e6c7e218904ee82459`。
- [服务端接口说明](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)。

运行器是本地新增文件；此前架构和初版测试报告保留原记录，此次真实试跑结果以本说明及单独试跑报告为准。未自动发布到远端仓库。
