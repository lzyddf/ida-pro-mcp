# 安装

README 之外的完整安装信息：组件协作方式、各平台安装方法、指定 IDA 目录、客户端配置位置。

## 组件如何协作

```text
┌────────────────────┐  启动   ┌──────────────┐  启动    ┌──────────────────────┐
│ MCP 客户端（Cursor、│────────▶│ ida-pro-mcp-headless  │─────────▶│ idat -A（无界面）     │
│ Claude 等）         │  stdio  │ 代理服务器    │ idat -A  │ + ida_pro_mcp        │
└────────────────────┘         └──────────────┘  + IPC   │   bootstrap          │
                                       ▲                 └──────────────────────┘
                                       │ 基于本机 HTTP 的 JSON-RPC
                                       │ （每个会话使用临时端口；会话文件位于
                                       │   ~/.ida-pro-mcp-headless/sessions/）
                                       │
                                MCP 工具调用在此转发。
```

代理（`ida-pro-mcp-headless` 命令）运行在普通 Python 环境中。大模型调用 `open_file(path)` 时，代理启动无界面 `idat -A`；IDA 内的引导脚本等分析完成后在临时端口起 JSON-RPC 服务，并把会话信息写入 `~/.ida-pro-mcp-headless/sessions/`，代理据此转发后续工具调用。`close_file(session)` 先请求正常退出，超时再强制终止。全程无需安装 IDA 图形界面插件。

## 1. 安装代理

### 安装 uv（推荐，若还没有）

```sh
# Windows (PowerShell)，装完后重开终端
irm https://astral.sh/uv/install.ps1 | iex

# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 用 uv 安装

```sh
git clone https://github.com/lzyddf/ida-pro-mcp.git
cd ida-pro-mcp
uv tool install .
```

升级（强制从源码重建，避免复用过期 wheel）：

```sh
uv tool install --reinstall --no-cache .
```

### 备选：pipx / 虚拟环境 / pip

```sh
pipx install ./ida-pro-mcp

# 或虚拟环境：
python3.11 -m venv .venv
source .venv/bin/activate        # Windows：.venv\Scripts\activate
pip install .

# 或直接 pip（仅适用于允许写入的 Python 环境）：
pip install .
```

<a id="ida-home"></a>

## 2. 指定 IDA 目录并生成配置

代理只通过 `IDA_PRO_HOME` 环境变量定位 `idat`（Windows 为 `idat.exe`），不搜索 `PATH`，也不接受逐次调用覆盖。

```sh
ida-pro-mcp-headless config --ida-home "/path/to/IDA"
# 开放调试、补丁、破坏性操作、类型修改时加 --unsafe
```

- `--ida-home` 指向包含 `idat` / `idat.exe` 的 **IDA 安装目录**。目录不存在或缺少可执行文件时，命令以退出码 2 结束且不输出 JSON。
- 也可先设置 `IDA_PRO_HOME` 再运行 `config`；两者都没有时，JSON 中写入 `REPLACE_WITH_PATH_TO_IDA_INSTALL_DIR` 占位符并输出 `[NOTE]` 提示。
- stdio 配置会把 `IDA_PRO_HOME` 烘焙进 `env`；HTTP 传输（`streamable-http` / `sse`）生成的配置只有 `url`，`IDA_PRO_HOME` 只需在代理主机上设置。

代理自身的 Python 与 IDA 内部的 IDAPython 是两个独立进程，**两者版本无需一致**：IDA 侧代码只依赖标准库，因此代理可以用任意 Python 3.11+ 环境（包括 uv 默认选择的版本），不必运行 `idapyswitch`。

## 3. 配置 MCP 客户端

`config` 的标准输出只包含 JSON（诊断写入 stderr），可放心使用 `ida-pro-mcp-headless config | clip`。把输出的 `mcpServers` 项合并到客户端配置，常见位置：

| 客户端 | 配置路径 |
| --- | --- |
| Cursor | `~/.cursor/mcp.json` |
| Claude Desktop | macOS：`~/Library/Application Support/Claude/claude_desktop_config.json`；Windows：`%APPDATA%\Claude\claude_desktop_config.json` |
| Cline / Roo Code | VS Code 扩展的 `globalStorage` 目录 |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| LM Studio | `~/.lmstudio/mcp.json` |

保存后重启客户端。若客户端中已存在本项目的旧条目（旧版使用 `github.com/...` 形式的超长键名），先删除再合并，重复键会静默遮蔽新配置。

Windows 上通过 uv tool 安装后的典型 stdio 配置：

```json
{
  "mcpServers": {
    "ida-pro-mcp-headless": {
      "command": "C:\\Users\\you\\AppData\\Roaming\\uv\\tools\\ida-pro-mcp-headless\\Scripts\\python.exe",
      "args": [
        "C:\\Users\\you\\AppData\\Roaming\\uv\\tools\\ida-pro-mcp-headless\\Lib\\site-packages\\ida_pro_mcp\\__main__.py",
        "serve"
      ],
      "timeout": 1800,
      "disabled": false,
      "env": {
        "PYTHONHOME": "C:\\Users\\you\\AppData\\Roaming\\uv\\python\\cpython-3.11-windows-x86_64-none",
        "IDA_PRO_HOME": "C:\\Program Files\\IDA Professional 9.0"
      }
    }
  }
}
```

手工编辑时注意：

- `command` 是能够 `import ida_pro_mcp` 的**代理 Python 解释器绝对路径**，不是 `ida-pro-mcp-headless` 包装脚本，这样客户端不依赖 `PATH`。
- uv 环境可能需要转发 `PYTHONHOME`；不要删除生成配置中的 Python 环境变量。

## 4. 冒烟验证

在客户端中让大模型执行：*在 IDA 中打开 `~/samples/crackme.exe`，并说明入口点的作用。* 正常流程为 `open_file` → `check_connection` → 反编译/反汇编；首次打开需等待自动分析，之后复用会话。开发者可另用[真实 IDA 冒烟测试](development.md#real-ida-smoke-test)验证完整链路。

## 后续阅读

- [通过网络运行代理](remote-access.md)：从另一台主机驱动 IDA。
- [作为后台服务运行](service.md)：登录时自动启动并在崩溃后重启。
- [故障排查](troubleshooting.md)：常见错误和日志位置。
