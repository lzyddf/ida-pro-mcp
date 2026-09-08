# 通过网络驱动 IDA

`ida-pro-mcp-headless config` 默认生成 stdio 配置，由 MCP 客户端在本机启动代理，因此客户端与 IDA 必须位于同一台主机。如果希望在笔记本上对话、由另一台高性能工作站运行 IDA，可以只把第一层传输改为 TCP。代理与每个 IDA 之间仍使用本机临时端口，多会话机制不变。

## 在 IDA 主机启动代理

```sh
ida-pro-mcp-headless serve --transport streamable-http --host 0.0.0.0 --port 13337

# 更推荐只绑定需要的网卡地址
ida-pro-mcp-headless serve --transport streamable-http --host 192.168.1.50 --port 13337
```

启动代理的 shell 或后台服务必须设置有效的 `IDA_PRO_HOME`。HTTP 客户端配置中的 `--ida-home` 不参与远程代理启动。

## 生成远程客户端配置

以下命令可在任意一台主机运行，因为它只负责渲染 URL：

```sh
ida-pro-mcp-headless config --transport streamable-http --host 192.168.1.50 --port 13337
```

输出为 URL 形式，而不是 `command` / `args` / `env`：

```json
{
  "mcpServers": {
    "ida-pro-mcp-headless": {
      "url": "http://192.168.1.50:13337/mcp",
      "timeout": 1800,
      "disabled": false
    }
  }
}
```

将配置粘贴到远程 MCP 客户端并重启。旧式 SSE 传输也受支持，使用 `--transport sse`，端点为 `/sse`。

## 安全注意事项

- **HTTP 监听器没有内置身份认证。** 任何能够访问 `host:port` 的设备都可以驱动 IDA；若代理以 `--unsafe` 启动，还能执行补丁、调试等修改操作。只应在可信网络中使用，或放在 SSH 端口转发、Tailscale、WireGuard 等安全隧道之后。
- 默认 `127.0.0.1` 仅监听本机。`0.0.0.0` 会监听所有网卡，而且它本身不是远程客户端可连接的目标地址；生成配置后必须替换为客户端实际可访问的 IP 或主机名。
- `13337` 只是第一层 HTTP 传输的默认端口，可以更换。代理与 IDA 之间仍为每个 IDA 分配独立的本机临时端口。
- 不要在不可信网络上启用 `--unsafe`，也不要把监听端口直接暴露到公网。

## 保持代理运行

采用 URL 配置后，通常需要代理在登录时自动启动并在异常退出后恢复。Windows 可以使用[后台服务](service.md)；macOS 和 Linux 当前需要使用用户自己的进程管理器。
