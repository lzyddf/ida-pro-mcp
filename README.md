# IDA Pro MCP

一个 [MCP 服务器](https://modelcontextprotocol.io/introduction)，让大模型驱动 IDA Pro 完成逆向分析。

## 环境要求

- **Python 3.11+**（无需与 IDAPython 版本一致；IDA 侧只依赖标准库）
- **IDA Pro 9.0+**（不支持 IDA Free）
- **支持 MCP 的客户端**：Cursor、Claude Desktop、Cline、Roo Code、Windsurf、LM Studio 等

代理按需启动无界面 IDA（`idat -A`），无需安装 IDA 插件，也无需打开图形界面。

## 安装

### 1. 安装 uv

```powershell
# Windows (PowerShell)，装完需重开终端
irm https://astral.sh/uv/install.ps1 | iex
```

```sh
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. 安装代理

```sh
git clone https://github.com/lzyddf/ida-pro-mcp.git
cd ida-pro-mcp
uv tool install .
```

升级时使用 `uv tool install --reinstall --no-cache .`。

### 3. 生成配置

```sh
ida-pro-mcp-headless config --ida-home "/path/to/IDA"
```

- `--ida-home` 指向包含 `idat` / `idat.exe` 的 **IDA 安装目录**（不是可执行文件本身）；目录或 `idat` 校验失败时命令以退出码 2 结束且不输出 JSON。
- 需要调试、补丁、破坏性操作、类型编辑等高危工具时加 `--unsafe`。
- 也可以先设置 `IDA_PRO_HOME` 环境变量，再运行 `config`。

## 使用

1. 把 `config` 输出的 `mcpServers` JSON 合并进客户端配置（各客户端位置见 [docs/installation.md](docs/installation.md)），重启客户端。
2. 让大模型依次调用 `open_file("<二进制文件路径>")` 和 `check_connection`。
3. 之后即可直接让模型执行反编译、反汇编、重命名、注释、交叉引用等分析操作。

## 文档

| 主题 | 文档 |
| --- | --- |
| 完整安装指南（各平台、IDA-Python 引导、客户端配置位置） | [docs/installation.md](docs/installation.md) |
| 使用：多会话、可用工具 | [docs/usage.md](docs/usage.md) |
| 从另一台主机通过网络驱动 IDA | [docs/remote-access.md](docs/remote-access.md) |
| 作为后台服务运行（Windows 计划任务） | [docs/service.md](docs/service.md) |
| 验证连接、常见故障与日志 | [docs/troubleshooting.md](docs/troubleshooting.md) |
| 提示词工程建议 | [docs/prompting.md](docs/prompting.md) |
| 仓库结构、新增工具、测试 | [docs/development.md](docs/development.md) |

## 主要特性

- **端到端驱动**：`open_file(path)` 按需启动无界面 `idat -A`，等待分析完成并返回会话 ID；`close_file()` 关闭会话。
- **多会话**：同时打开任意数量的二进制文件，自动发现会话，通过 `session` 参数路由。
- **省 token**：`decompile_function_text` / `disassemble_function_text` 返回单个字符串，体积约为逐行结构化结果的 1/5；`read_bytes` 支持紧凑十六进制 / Base64。
- **远程访问**：`serve --transport streamable-http` 让 MCP 客户端运行在另一台主机（无内置认证，仅限可信网络）。
- **服务化**：`service install` 注册 Windows 计划任务，登录自启、崩溃自动重启。

## 许可证

[MIT](LICENSE)
