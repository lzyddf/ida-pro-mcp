# 使用代理

<a id="open-file"></a>

## 让大模型打开和关闭二进制文件（`open_file`）

代理会按需启动无界面的 `idat -A`，因此大模型能够端到端管理 IDA 生命周期：

- `open_file(path)` 启动 `idat -A`，等待自动分析完成，并返回会话信息和 IDA 日志路径。如果同一个二进制文件已有活动会话，则直接复用。代理只通过 `IDA_PRO_HOME` 定位 `idat`，不提供逐次指定可执行文件或超时的工具参数。
- `close_file(session=None)` 先请求无界面 IDA 正常退出，必要时再强制终止。只有一个会话时可以省略 `session`；存在多个会话时必须指定目标会话。
- `reanalyse_file(path)` 会永久删除现有 IDA 数据库文件，然后重新分析。由于它可能破坏人工分析结果，只有代理以 `--unsafe` 启动时才会暴露该工具。

<a id="multiple-sessions"></a>

## 多 IDA 会话

代理可以同时驱动多个无界面 IDA。每次 `open_file` 都会在 `~/.ida-pro-mcp-headless/sessions/<id>.json` 中发布一个会话文件，记录 `session_id`、主机、端口、进程 ID、IDB 路径和原始输入文件。代理在每次请求时读取这些文件，因此无需额外配置多会话模式。

相关路由规则：

- `list_ida_sessions()` 返回所有活动 IDA，包括 `session_id`、`port`、`idb_path`、`input_file`、`pid` 和 `created_at`。
- 其他工具都会获得可选的 `session` 参数。仅有一个会话时可以省略；有多个会话时，应传入 `list_ida_sessions()` 返回的 `session_id`。若目标不明确，代理会返回清晰的“会话有歧义”错误。

`session_id` 根据**输入文件路径**生成，因此重复打开同一个二进制文件会稳定地复用同一个 ID。进程已经消失的过期会话文件会被自动过滤和清理。

## 从命令行关闭会话

`close_file` 是 MCP 工具，只有大模型主动调用才会执行；分析结束后模型经常不调用它，导致无界面 IDA 继续占用内存、许可证和 IDB 锁。可以直接在 shell 中查看和关闭：

```sh
# 列出所有活动会话（JSON，字段与 list_ida_sessions() 一致）
ida-pro-mcp-headless session list

# 关闭全部活动会话
ida-pro-mcp-headless session close --all

# 按会话 id 关闭（id 来自上面的 list）
ida-pro-mcp-headless session close <session_id>

# 按二进制路径关闭，无需记 hash id；可重复指定多个
ida-pro-mcp-headless session close --path /samples/crackme.exe
ida-pro-mcp-headless session close --path a.exe --path b.exe

# 缩短优雅退出的等待时间（默认 30 秒，超时后强制终止）
ida-pro-mcp-headless session close --all --timeout 5

# 跳过优雅退出，直接强制终止（等价于 --timeout 0）
ida-pro-mcp-headless session close --all --force
```

`--path` 使用与 `open_file` **完全相同**的路径归一化（展开 `~`、转为绝对路径），所以相对路径和 `~/...` 都能正确匹配到对应会话。`--force` 用于 IDA 卡死、优雅通道无人应答的场景，避免白等一个超时周期；代价是跳过 bootstrap 的正常收尾，可能留下不完整的 IDB。

该命令复用代理本身的关闭协议（kill-switch 哨兵文件 + 会话文件轮询），因此**不要求代理正在运行**，也不与代理的状态冲突：代理下次解析会话时会发现该会话已消失并自动失效缓存。每个会话独立关闭，一个失败不会中断其余会话；只要有一个失败，命令就以退出码 2 结束，成功时把每个会话的结果以 JSON 输出到标准输出。`--all` 在没有活动会话时是无害的空操作（输出 `[]`，退出码 0）。

## 指定 `idat` 位置

代理只通过 `IDA_PRO_HOME` 环境变量定位 `idat`，不搜索 `PATH`，也不接受逐次调用覆盖。安装、校验规则和配置生成说明见[安装文档](installation.md#ida-home)。

<a id="available-tools"></a>

## 可用工具

默认工具集包含只读分析，以及容易撤销的注释和重命名。`--unsafe` 额外开放调试器控制、字节补丁、破坏性重新分析、结构修改和原型/类型设置。

以下工具针对大模型上下文开销做了优化：

- `decompile_function_text(function)`：按十六进制地址或名称反编译函数，并返回单个伪代码字符串。不需要逐行地址映射时，应优先于 `decompile_function`；后者经过 JSON 编码后的体积约大五倍。
- `disassemble_function_text(function)`：以 `<地址>  <指令>[  ; <注释>]` 形式返回单个反汇编字符串，用户标签单独成行。不需要逐行结构化数据时，应优先于 `disassemble_function`。
- `get_function(function)`：使用函数名或函数内部任意地址查询函数，返回的地址始终是规范化的函数起始地址。
- `get_global_variable_value(target)`：按名称或地址读取带类型的全局变量。
- `read_value(address, kind)`：读取 byte、word、dword、qword 或 NUL 结尾字符串。`read_bytes(address, size, output_format="hex_compact")` 用于原始字节范围，并支持 `hex_spaced`、`hex_compact` 和 `base64`。
- `convert_number(text, size=None)`：在代理侧执行数字和字节转换，即使尚未打开 IDA 会话也能使用。
- 列表工具默认使用 `offset=0, count=100`；只有翻页时才需要显式传入分页参数。
- `list_segments()`：低开销查看节/段、权限、IDA 段类别和位数，适合在深入具体地址前快速了解二进制布局。

完整工具实现位于 `src/ida_pro_mcp/plugin/tools/`。MCP 客户端也会在运行时通过 `tools/list` 自动枚举当前实际开放的工具。
