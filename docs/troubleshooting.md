# 故障排查

## 验证连接

在 MCP 客户端中让大模型调用 `check_connection`。连接正常时会返回类似 `Successfully connected to IDA Pro (open file: <module>)` 的信息。

如果还没有活动会话，应先调用 `open_file(path=...)`。也可以调用 `list_ida_sessions()` 查看代理当前发现的会话。

## 常见故障

| 现象 | 常见原因 | 处理方法 |
| --- | --- | --- |
| `ida-pro-mcp-headless config --ida-home ...` 以退出码 2 结束，提示目录不存在 | `--ida-home` 不是有效目录 | 传入包含 `idat` / `idat.exe` 的 IDA 安装目录，而不是可执行文件本身 |
| `config` 提示在目录内找不到 `idat` | 目录存在，但不是 IDA 安装根目录，或当前平台的文件不可执行 | 检查错误中的 `searched` 路径和文件权限；Windows 目录中应有 `idat.exe` |
| `ida-pro-mcp-headless config` 输出关于占位符的 `[NOTE]` | 既没有传入 `--ida-home`，也没有设置 `IDA_PRO_HOME` | 使用 `--ida-home <绝对路径>` 重新生成，或替换 JSON 中的 `REPLACE_WITH_PATH_TO_IDA_INSTALL_DIR` |
| `No IDA session is running. Call open_file(path=...)…` | 代理尚未启动无界面 IDA | 让大模型先调用 `open_file(path=...)`，或用 `list_ida_sessions()` 检查活动会话 |
| `IdatNotFoundError: IDA_PRO_HOME is not set` | 代理进程没有收到 `IDA_PRO_HOME` | stdio 模式下重新生成客户端配置；HTTP 模式下在启动代理的 shell 或服务配置中设置变量，然后重启 |
| `IdatNotFoundError: ... is not a directory` | `IDA_PRO_HOME` 指向文件或不存在的路径 | 将其改为包含 `idat` / `idat.exe` 的目录 |
| `IdatNotFoundError: Could not locate ... inside IDA install directory ...` | 目录存在，但其中没有可执行的 `idat` | 检查安装根目录、平台对应的文件名和 POSIX 执行权限 |
| Cursor 报告 `Tool name … exceeds 60 characters` | 配置仍使用旧版的超长服务器键 `github.com/...` | 删除旧条目，重新合并 `ida-pro-mcp-headless config` 生成的短键 `ida-pro-mcp-headless` |
| URL 配置能够连接，但 `open_file` 报 `IdatNotFoundError` | HTTP 代理或服务进程没有有效的 `IDA_PRO_HOME` | 在代理主机设置变量；Windows 服务可重新执行 `ida-pro-mcp-headless service install --ida-home <绝对路径>` |
| 代理启动时报 `OSError: [WinError 10048]` | 后台服务和手工启动的代理争用同一个端口 | 使用 `ida-pro-mcp-headless service status` 检查，保留其中一种运行方式或更换端口 |
| `open_file` 提示 IDA 提前退出或超时 | 许可证、IDAPython、处理器模块、解码器、数据库锁或样本权限存在问题 | 先查看错误中附带的日志尾部，再检查下述完整日志 |

## 无界面 IDA 日志

代理通过 `open_file` 启动 IDA 时，会在 `~/.ida-pro-mcp-headless/logs/` 下创建：

- `<session_id>.ida.log`：IDA 自身的分析日志。
- `<session_id>.stdio.log`：子进程的标准输出和标准错误。

`open_file` 失败或超时时应优先查看这两个文件。缺少插件、IDB 被锁定、许可证异常和 IDAPython 启动错误通常都会先出现在日志中。

## 其他排查位置

- `~/.ida-pro-mcp-headless/sessions/`：每个活动无界面 IDA 对应一个 JSON 会话文件。如果代理报告没有会话，请检查其中的 `pid` 是否仍对应运行中的 `idat` 进程。
- `%LOCALAPPDATA%\ida-pro-mcp-headless\service\proxy.stdout.log` 和 `proxy.stderr.log`（Windows）：无窗口后台服务的累计输出和异常堆栈；计划任务级故障仍可在任务计划程序历史中查看。
- MCP 客户端自身的服务器日志：用于确认客户端是否读取了最新 JSON、是否启动了正确的 Python 绝对路径，以及 stdio 进程是否继承了生成配置中的环境变量。

## 开发者验证

普通测试套件使用 IDA SDK stub，不证明真实 IDA 安装一定可启动。发布、升级 IDA 或切换 IDAPython 后，应按[开发文档中的真实 IDA 冒烟测试](development.md#real-ida-smoke-test)验证完整链路。
