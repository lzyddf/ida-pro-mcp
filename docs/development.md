# 开发

项目按运行边界拆分为代理侧与 IDA 侧模块。新增工具通常只需在 `src/ida_pro_mcp/plugin/tools/` 下增加或修改对应领域模块，并使用 `@jsonrpc` 注册。组合入口会显式加载工具，而普通协议模块不会因为被导入就加载 IDA SDK。

## 本地开发环境

使用可编辑安装，让源码修改立即生效：

```sh
uv sync --dev
# 或在已激活的虚拟环境中：pip install -e .
```

运行默认测试和静态检查：

```sh
uv run ruff check src tests
uv run pytest tests
```

默认测试全部运行在 IDA 之外。`tests/conftest.py` 会加载轻量 IDA SDK stub，因此工具注册、参数解析、格式化、会话路由、HTTP/JSON-RPC 和启动器失败路径都能在普通 CI 中验证。平台专属测试会在不适用的操作系统上跳过，并由 CI 的 Windows、macOS、Linux 矩阵互补覆盖。

默认套件**不等价于真实 IDA 兼容性验证**。真实 IDA 的 Python 绑定、许可证、处理器模块和无界面启动只能通过下述显式集成测试验证。

## 仓库结构

- `src/ida_pro_mcp/`：运行在普通 Python 中的**代理侧**代码，包括 FastMCP 服务（`server.py`）、CLI（`cli.py`）、数字转换、会话注册表、无界面 IDA 启动器（`spawner/`）和服务安装器（`installer/`）。
- `src/ida_pro_mcp/plugin/`：运行在 IDAPython 内部的 **IDA 侧**代码。所有调用 `idaapi` / `ida_*` 的实现都位于这里；公共工具从 `plugin/tools/*.py` 显式加载。
- `tests/`：默认单元测试、协议集成测试、启动器测试，以及需要显式环境变量才能运行的真实 IDA 测试。
- `docs/`：安装、使用、远程访问、服务化、排错和提示词文档。

关键模块：

- `plugin/headless_bootstrap.py`：在无界面 IDA 中运行，等待自动分析、启动 JSON-RPC 服务、写入会话文件并处理正常关闭。
- `plugin/http_server.py`：只监听本机的单线程 JSON-RPC HTTP 服务。单线程是有意设计，因为它运行在 IDA 主线程上，使 `@idaread` / `@idawrite` 能正确配合 `execute_sync`。
- `plugin/registry.py` 与 `_tool_bridge.py`：具名参数 JSON-RPC 注册表，以及把工具暴露为带可选 `session` 参数的 FastMCP 工具的桥接层。
- `plugin/ida_sync.py`：把数据库访问调度到 IDA 主线程。
- `plugin/frames.py`：供栈帧与反汇编工具共享的栈帧辅助函数。
- `plugin/_pid_check.py`：跨平台检查 PID 是否存活，用于清理过期会话文件。
- `spawner/locator.py`：集中实现 IDA 安装目录和 `idat` 可执行文件校验；配置生成与运行时启动共享同一逻辑。
- `installer/proxy_python.py`：为生成的 MCP 配置寻找能够导入本包的代理 Python。
- `installer/service/`：操作系统服务后端；当前只有 `_windows/` 已完整实现。

## 新增工具

1. 在 `src/ida_pro_mcp/plugin/tools/` 中选择或创建按领域划分的模块，例如 `comments.py` 或 `stack.py`。
2. 使用 `..registry` 中的 `@jsonrpc` 装饰函数。调试器控制、补丁、破坏性或结构性修改、原型和类型修改还必须添加 `@unsafe`；容易撤销的注释和重命名可以保留在默认集合。
3. 添加完整类型注解，它们会自动转换成 MCP 工具 schema。可以直接使用 `plugin/models.py` 中的 `TypedDict`；参数说明与数值边界用 `plugin/doc.py` 的 `Doc`，不要用 `pydantic.Field`（见下节）。
4. 任何接触 IDA 数据库的 API 调用都必须使用 `@idaread` 或 `@idawrite`，确保执行发生在 IDA 主线程。纯代理侧能力应放在 `plugin/` 之外，`number_conversion.py` 是参考实现。
5. 在 `tests/` 下增加对应测试。大多数逻辑应通过 `plugin/_ida_stub.py` 在普通 CI 中覆盖；只有 SDK 真实行为才进入显式 IDA 集成测试。

## IDA 侧依赖约束

`src/ida_pro_mcp/plugin/` 会被**两个不同的解释器**导入：代理自己的 Python，以及 IDA 内置的 IDAPython。两者版本通常不同，因此这条导入链里**不能出现任何编译扩展**——`pydantic_core` 就曾因为代理是 3.11、IDA 是 3.12 而导致 IDA 启动即崩溃（`ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'`）。

具体规则：

- IDA 侧只允许标准库，以及纯 Python 的 `typing_extensions`。新增第三方依赖前必须先确认它没有编译扩展。
- 参数说明和数值边界用 `plugin/doc.py` 的 `Doc`，参数转换用 `plugin/coerce.py`，二者都是纯标准库。
- 代理侧需要 pydantic 时，由 `_schema.py` 把 `Doc` 翻译成 `pydantic.Field`（FastMCP 只认后者），这条翻译路径保证 `tools/list` 里的描述和 `minimum`/`exclusiveMinimum` 不丢失。
- `tests/test_ida_side_stdlib_only.py` 会在屏蔽 `pydantic` 的子进程中导入整条 IDA 侧链路，任何新引入的编译依赖都会让该测试失败。

<a id="real-ida-smoke-test"></a>

## 真实 IDA 冒烟测试

`tests/integration/test_live_ida.py` 是显式启用的端到端测试，覆盖以下链路：

```text
Spawner → idat -A → headless_bootstrap → 本机 JSON-RPC → get_metadata → 关闭会话
```

准备一个**可丢弃的二进制文件副本**。IDA 可能在样本旁创建或更新 `.i64` / `.idb` 等数据库文件，不要直接使用唯一的生产样本。然后设置两个环境变量：

- `IDA_PRO_HOME`：包含 `idat` / `idat.exe` 的真实 IDA 安装目录。
- `IDA_PRO_MCP_INTEGRATION_BINARY`：可丢弃测试二进制的绝对路径。

macOS / Linux：

```sh
export IDA_PRO_HOME="/opt/idapro"
export IDA_PRO_MCP_INTEGRATION_BINARY="$HOME/samples/smoke-copy"
uv run pytest tests/integration/test_live_ida.py -m integration
```

Windows PowerShell：

```powershell
$env:IDA_PRO_HOME = 'C:\Program Files\IDA Professional 9.0'
$env:IDA_PRO_MCP_INTEGRATION_BINARY = 'C:\samples\smoke-copy.exe'
uv run pytest tests/integration/test_live_ida.py -m integration
```

未设置 `IDA_PRO_MCP_INTEGRATION_BINARY` 时，该测试明确跳过，不会尝试寻找许可证或启动 IDA。如果变量已设置但路径、IDA 安装或 RPC 链路无效，测试会失败并保留正常的启动日志供排查。测试只会关闭自己新建的会话，不会关闭已经存在且被复用的会话。

## 测试策略

- `tests/test_*.py`：默认快速测试，覆盖代理、安装器、会话、启动器、协议层和使用 SDK stub 的 IDA 辅助逻辑。
- `tests/integration/test_live_ida.py`：需要许可证、真实 IDAPython 和显式样本路径的端到端冒烟测试。
- `.github/workflows/ci.yml`：在三个操作系统和 Python 3.11、3.12、3.13 上运行默认测试；由于 CI 没有专有 IDA 安装，真实 IDA 测试保持跳过。

修改工具签名、错误类型、传输协议或会话格式后，至少重跑上面的静态检查和默认测试；涉及启动器、IDAPython 或 IDA SDK 行为的变更，发布前还应运行真实 IDA 冒烟测试。
