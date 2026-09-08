# 将代理作为后台服务运行

`ida-pro-mcp-headless service` 封装操作系统的服务机制，避免手工编写计划任务 XML、plist 或 unit 文件。

```powershell
# 安装并启动服务（当前仅实现 Windows）
ida-pro-mcp-headless service install `
    --host 127.0.0.1 --port 13337 `
    --ida-home "C:\Program Files\IDA Professional 9.0"

# 查看状态
ida-pro-mcp-headless service status

# 删除服务
ida-pro-mcp-headless service uninstall
```

各平台的设计如下：

| 平台 | 后端 | 触发方式 | 自动重启 | 权限 |
| --- | --- | --- | --- | --- |
| Windows | 当前用户的计划任务（`schtasks` / `InteractiveToken`） | 用户登录 | 无窗口 Python 监督器在代理退出 5 秒后重新启动 | 当前用户、无需管理员权限，以便读取用户级 IDA 许可证 |
| macOS | 计划使用 LaunchAgent（`~/Library/LaunchAgents/com.lzyddf.ida-pro-mcp-headless.plist`） | 用户登录 | 计划由 launchd `KeepAlive` 恢复 | 当前用户、无需 `sudo` |
| Linux | 计划使用 `systemd --user` unit | 用户会话或启用 linger 后的 `default.target` | 计划使用 `Restart=on-failure` | 当前用户、无需 root |

目前只有 Windows 后端已经实现。macOS 和 Linux 调用 `service install` 时会得到明确的 `ServiceUnsupportedError`；在对应实现完成前，可通过 `screen`、`tmux` 或自己的 systemd/launchd 配置运行[远程访问命令](remote-access.md)。

## Windows 生成文件

`service install` 使用同一 Python 环境中的 `pythonw.exe` 启动代理，因此不会打开或保留 CMD 窗口。它会在 `%LOCALAPPDATA%\ida-pro-mcp-headless\service\` 下写入：

- `service.json`：经过验证的服务参数，包括 `IDA_PRO_HOME`、传输、监听地址、端口和 `unsafe` 状态。
- `task.xml`：已注册的计划任务定义。可以使用 `Get-ScheduledTask -TaskName ida-pro-mcp-headless` 查看。
- `proxy.stdout.log` / `proxy.stderr.log`：代理输出和异常堆栈，以追加方式保留多次启动记录。

计划任务直接执行：

```text
pythonw.exe -m ida_pro_mcp.installer.service._windows.runner --config <service.json>
```

`runner` 负责读取配置、设置 `IDA_PRO_HOME`、重定向日志，并通过 `CREATE_NO_WINDOW` 启动代理子进程。代理无论以何种状态退出，监督器都会等待 5 秒后使用全新进程启动；整个过程不再使用批处理或控制台窗口。

监督器使用 Windows Job Object 管理代理进程：停止或更新计划任务时，代理监听器会随监督器一起退出；IDA 子进程允许脱离该 Job，因此已经打开的无界面 IDA 会话不会因为重启代理而被强制关闭。

## 运维建议

- 不要同时运行后台服务和手工启动的同端口代理，否则其中一个会因端口占用报 `WinError 10048`。先用 `ida-pro-mcp-headless service status` 检查。
- `uv tool install --reinstall` 后应重新运行 `service install`。计划任务记录了 `pythonw.exe` 的绝对路径，重装到新位置后旧路径会失效。
- 修改传输、端口、IDA 路径或 `--unsafe` 时可以直接重新执行 `service install`。安装器会先停止旧任务、确认旧端口已经释放，再注册并启动新配置。
- 服务进程不会可靠继承交互式 shell 环境，因此推荐显式传入 `--ida-home`，把路径写入 `service.json`。具体路径会在注册任务前立即验证。
- 安装器启动任务后会等待监听端口就绪；端口冲突或启动失败不会错误地报告为成功。使用 `service status` 可查看配置 URL 和 `healthy` 状态。
- `streamable-http` 是默认传输；只有兼容旧客户端时才需要显式选择 `sse`。
