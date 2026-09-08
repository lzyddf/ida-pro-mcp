"""``ida-pro-mcp-headless`` console-script entry point and CLI dispatch.

The CLI is organised as a small set of *subcommands* rather than a flat
list of mode flags::

    ida-pro-mcp-headless                 # implicit default: serve with default args
    ida-pro-mcp-headless serve [...]
    ida-pro-mcp-headless config [...]
    ida-pro-mcp-headless session list
    ida-pro-mcp-headless session close [...]
    ida-pro-mcp-headless service install [...]
    ida-pro-mcp-headless service uninstall
    ida-pro-mcp-headless service status

Each subcommand owns *only* the flags that affect it (e.g. ``--transport``
only appears under ``serve`` / ``config`` / ``service install``). This
keeps ``--help`` output focused and prevents nonsense combinations from
parsing successfully.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import sys

from .installer import print_mcp_config
from .installer.service import (
    ServiceUnsupportedError,
    install_service,
    service_status,
    uninstall_service,
)
from .plugin.constants import DEFAULT_HOST, DEFAULT_REMOTE_PORT
from .runtime_args import HTTP_TRANSPORTS, VALID_TRANSPORTS
from .server import build_mcp_server
from .session_control import close_sessions, live_session_ids, live_sessions, resolve_targets
from .session_registry import SessionRegistry
from .spawner import IdatNotFoundError, Spawner

# Subcommand label for the implicit ``serve`` action used when no subcommand
# is given. Kept as a constant so the dispatch table and the default-argv
# fallback agree without a magic string drifting between the two.
_DEFAULT_SUBCOMMAND = "serve"


def _port_type(raw: str) -> int:
    """``argparse``-friendly TCP port validator.

    Returns the parsed integer or raises :class:`argparse.ArgumentTypeError`
    so argparse formats the error consistently with its other "invalid value"
    messages. Bind-time errors (already-in-use, permission-denied) still
    surface from the kernel; this only filters out values that obviously
    can't be ports.
    """
    try:
        port = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"port must be an integer, got {raw!r}") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port must be in 1-65535, got {port}")
    return port


def _timeout_type(raw: str) -> float:
    """``argparse``-friendly validator for the graceful-shutdown timeout.

    Zero is accepted and meaningful: it skips the wait entirely and escalates
    to a hard kill, which is what ``--force`` maps to.
    """
    try:
        seconds = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"timeout must be a number, got {raw!r}") from exc
    if seconds < 0:
        raise argparse.ArgumentTypeError(f"timeout must not be negative, got {seconds}")
    return seconds


def _add_transport_flags(
    p: argparse.ArgumentParser,
    *,
    include_unsafe: bool,
    choices: tuple[str, ...] = VALID_TRANSPORTS,
    default: str = "stdio",
) -> None:
    """Attach the shared ``--transport`` / ``--host`` / ``--port`` options.

    Pulled out so ``serve`` / ``config`` / ``service install`` stay in lock-
    step on naming, defaults, and help wording. ``--unsafe`` rides along
    because every command that takes transport flags also takes ``--unsafe``
    and the help text reads better when they're co-located.
    """
    supports_stdio = "stdio" in choices
    transport_help = (
        f"Transport for the MCP host (default: {default}). 'stdio' runs the "
        "proxy as a subprocess of the MCP client; 'streamable-http' / 'sse' "
        "expose it on a TCP socket."
        if supports_stdio
        else (
            f"HTTP transport for the service listener (default: {default}). "
            "Use 'streamable-http' for modern MCP clients or 'sse' for legacy clients."
        )
    )
    p.add_argument(
        "--transport",
        choices=choices,
        default=default,
        help=transport_help,
    )
    p.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=(
            f"Bind address for HTTP transports (default {DEFAULT_HOST!r}, loopback "
            "only). Pass a specific LAN IP (e.g. 192.168.1.50) for remote access. "
            "Avoid '0.0.0.0' unless you trust every interface on this machine. "
            + ("Ignored when --transport is 'stdio'." if supports_stdio else "")
        ),
    )
    p.add_argument(
        "--port",
        type=_port_type,
        default=DEFAULT_REMOTE_PORT,
        help=(
            f"TCP port for HTTP transports (default {DEFAULT_REMOTE_PORT}). "
            + ("Ignored when --transport is 'stdio'. " if supports_stdio else "")
            + "Has no effect on the "
            "proxy<->IDA layer, which always binds ephemeral ports per IDA."
        ),
    )
    if include_unsafe:
        p.add_argument(
            "--unsafe",
            action="store_true",
            help=(
                "Enable high-risk tools (debugging, patching, destructive and "
                "type-changing operations). Comments and renames remain available "
                "by default. DANGEROUS over remote transports."
            ),
        )


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the top-level parser with one subparser per action."""
    parser = argparse.ArgumentParser(
        prog="ida-pro-mcp-headless",
        description="IDA Pro MCP proxy server.",
    )
    sub = parser.add_subparsers(dest="cmd", metavar="<command>")

    # --- serve (default) ---------------------------------------------------
    p_serve = sub.add_parser(
        _DEFAULT_SUBCOMMAND,
        help="Run the MCP proxy server (default action when no command is given).",
        description=(
            "Run the MCP proxy server. With no arguments the proxy listens on "
            "stdio so an MCP host (Cursor / Claude Desktop / ...) can spawn it as "
            "a subprocess. With --transport streamable-http / sse the proxy binds "
            "a TCP socket for remote clients."
        ),
    )
    _add_transport_flags(p_serve, include_unsafe=True)

    # --- config ------------------------------------------------------------
    p_config = sub.add_parser(
        "config",
        help="Print an MCP client JSON snippet for the current installation.",
        description=(
            "Print a stand-alone ``mcpServers`` entry (stdout JSON) for the user "
            "to paste into their MCP client config. Diagnostics go to stderr so "
            "``ida-pro-mcp-headless config | clip`` captures only the JSON."
        ),
    )
    _add_transport_flags(p_config, include_unsafe=True)
    p_config.add_argument(
        "--ida-home",
        default=None,
        help=(
            "IDA install directory to validate and bake into a stdio config. The "
            "directory must contain an executable idat / idat.exe. This is a "
            "convenient alternative to setting IDA_PRO_HOME before running config."
        ),
    )

    # --- session (group) ---------------------------------------------------
    p_session = sub.add_parser(
        "session",
        help="Stop headless IDA sessions the MCP client left running.",
        description=(
            "Stop headless IDA sessions. The close_file MCP tool only runs when "
            "the language model calls it, so an agent that finishes an analysis "
            "can leave idat processes behind; this command lets you reclaim them "
            "from a shell without involving the model."
        ),
    )
    sub_session = p_session.add_subparsers(dest="session_cmd", metavar="<action>")

    sub_session.add_parser(
        "list",
        help="Print every live session as JSON.",
        description=(
            "Print every live session as a JSON array, with the same fields the "
            "list_ida_sessions MCP tool returns. Use it to find the session id "
            "that `session close` expects."
        ),
    )

    p_session_close = sub_session.add_parser(
        "close",
        help="Stop one or more headless IDA sessions.",
        description=(
            "Stop the given sessions, or every live session with --all. Each "
            "session is closed independently, so one failure does not prevent "
            "the others from being closed. Prints one JSON object per session "
            "to stdout and exits 2 if any session could not be closed."
        ),
    )
    p_session_close.add_argument(
        "session_ids",
        nargs="*",
        metavar="session_id",
        help=(
            "Session ids to close, as reported by `session list` or "
            "list_ida_sessions()."
        ),
    )
    p_session_close.add_argument(
        "--path",
        action="append",
        default=[],
        dest="paths",
        metavar="BINARY",
        help=(
            "Close the session for this binary instead of naming its id. May be "
            "repeated. The path is resolved exactly as open_file resolves it, so "
            "a relative path or ~/... works."
        ),
    )
    p_session_close.add_argument(
        "--all",
        action="store_true",
        dest="close_all",
        help="Close every live session instead of naming ids or paths.",
    )
    close_timing = p_session_close.add_mutually_exclusive_group()
    close_timing.add_argument(
        "--timeout",
        type=_timeout_type,
        default=None,
        help=(
            "Seconds to wait for a graceful exit before escalating to a hard "
            "kill (default: the spawner's own timeout). Use 0 to skip the wait."
        ),
    )
    close_timing.add_argument(
        "--force",
        action="store_true",
        help=(
            "Skip the graceful shutdown request and hard-kill immediately; "
            "equivalent to --timeout 0. Use when IDA is wedged and would "
            "otherwise make you wait out the timeout."
        ),
    )

    # --- service (group) ---------------------------------------------------
    p_service = sub.add_parser(
        "service",
        help="Manage a per-user OS service that auto-starts the proxy.",
        description=(
            "Manage a per-user OS service that auto-starts the proxy at login "
            "and restarts it on crash. Implemented on Windows via Scheduled "
            "Tasks; macOS (launchd) and Linux (systemd --user) are placeholders."
        ),
    )
    sub_service = p_service.add_subparsers(dest="service_cmd", metavar="<action>")

    p_svc_install = sub_service.add_parser(
        "install",
        help="Render and register the service.",
    )
    _add_transport_flags(
        p_svc_install,
        include_unsafe=True,
        choices=HTTP_TRANSPORTS,
        default="streamable-http",
    )
    p_svc_install.add_argument(
        "--ida-home",
        default=None,
        help=(
            "Absolute path to your IDA install directory (the folder containing "
            "idat / idat.exe), baked into the service environment as "
            "IDA_PRO_HOME. If omitted, IDA_PRO_HOME from the current shell is "
            "used; if that is also unset, the service still installs but "
            "open_file will fail until you re-run `service install --ida-home "
            "<dir>`."
        ),
    )

    sub_service.add_parser("uninstall", help="Stop and unregister the service.")
    sub_service.add_parser("status", help="Print the service's current state as JSON.")

    return parser


# --- subcommand handlers ---------------------------------------------------


def _cmd_serve(args: argparse.Namespace) -> None:
    """Run the FastMCP proxy with the requested transport."""
    registry = SessionRegistry()
    spawner = Spawner()
    # FastMCP derives its transport-security policy in ``__init__`` from the
    # bind host. Pass HTTP settings while constructing the server rather than
    # mutating ``mcp.settings`` afterwards; late mutation makes a 0.0.0.0
    # socket retain localhost-only Host-header validation and return HTTP 421.
    host = args.host if args.transport != "stdio" else DEFAULT_HOST
    port = args.port if args.transport != "stdio" else DEFAULT_REMOTE_PORT
    mcp = build_mcp_server(
        registry,
        include_unsafe=args.unsafe,
        spawner=spawner,
        host=host,
        port=port,
    )

    with contextlib.suppress(KeyboardInterrupt):
        mcp.run(transport=args.transport)


def _cmd_config(args: argparse.Namespace) -> None:
    try:
        print_mcp_config(
            unsafe=args.unsafe,
            transport=args.transport,
            host=args.host,
            port=args.port,
            ida_home=args.ida_home,
        )
    except IdatNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _cmd_session(args: argparse.Namespace) -> None:
    """Route ``session <action>`` to the session-control helpers."""
    action = args.session_cmd
    if action is None:
        raise SystemExit(
            "missing session action; use 'ida-pro-mcp-headless session list' or "
            "'... session close <session_id>|--path <binary>|--all'"
        )
    if action == "list":
        _cmd_session_list()
    elif action == "close":
        _cmd_session_close(args)
    else:  # pragma: no cover -- argparse choices guard this
        raise SystemExit(f"unknown session action: {action!r}")


def _cmd_session_list() -> None:
    """Print every live session as JSON (same shape as list_ida_sessions)."""
    print(json.dumps([info.to_dict() for info in live_sessions()], indent=2, default=str))


def _cmd_session_close(args: argparse.Namespace) -> None:
    """Close the requested sessions and report each outcome as JSON."""
    if args.close_all and (args.session_ids or args.paths):
        print(
            "error: --all cannot be combined with session ids or --path",
            file=sys.stderr,
        )
        raise SystemExit(2)

    if args.close_all:
        # ``--all`` with nothing running is a successful no-op, not an error:
        # it is the idempotent "clean up whatever is left" spelling.
        targets = live_session_ids()
    else:
        targets = resolve_targets(session_ids=args.session_ids, paths=args.paths)
        if not targets:
            print(
                "error: specify at least one session id, --path <binary>, or --all",
                file=sys.stderr,
            )
            raise SystemExit(2)

    # ``--force`` is the readable spelling of "don't wait for a graceful exit".
    timeout = 0.0 if args.force else args.timeout
    outcomes = close_sessions(targets, timeout=timeout)
    print(json.dumps([outcome.to_dict() for outcome in outcomes], indent=2))

    failed = [outcome for outcome in outcomes if not outcome.closed]
    if failed:
        for outcome in failed:
            print(f"error: session {outcome.session_id}: {outcome.error}", file=sys.stderr)
        raise SystemExit(2)


def _cmd_service(args: argparse.Namespace) -> None:
    """Route ``service <action>`` to the cross-platform installer."""
    action = args.service_cmd
    if action is None:
        raise SystemExit(
            "missing service action; use 'ida-pro-mcp-headless service install' / "
            "'service uninstall' / 'service status'"
        )

    try:
        if action == "install":
            install_service(
                transport=args.transport,
                host=args.host,
                port=args.port,
                unsafe=args.unsafe,
                ida_home=args.ida_home,
            )
        elif action == "uninstall":
            uninstall_service()
        elif action == "status":
            print(json.dumps(service_status(), indent=2, default=str))
        else:  # pragma: no cover -- argparse choices guard this
            raise SystemExit(f"unknown service action: {action!r}")
    except (ServiceUnsupportedError, IdatNotFoundError, RuntimeError) as exc:
        # Friendlier than a raw stack trace; the message itself spells out
        # which platform isn't wired up yet and what the user can do today.
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


# Dispatch table: keyed by the top-level subcommand. ``service`` has its own
# inner dispatch in :func:`_cmd_service` so the table stays one level deep.
_DISPATCH = {
    "serve": _cmd_serve,
    "config": _cmd_config,
    "session": _cmd_session,
    "service": _cmd_service,
}


def main(argv: list[str] | None = None) -> None:
    """Console-script entry point.

    *argv* defaults to ``sys.argv[1:]`` so the function is unit-testable;
    callers that already split ``sys.argv`` (tests, embedders) pass the
    list explicitly. When no subcommand is given we implicitly dispatch to
    ``serve`` so existing setups that expect ``ida-pro-mcp-headless`` to immediately
    start the proxy keep working.
    """
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = [_DEFAULT_SUBCOMMAND]

    args = _build_arg_parser().parse_args(argv)
    handler = _DISPATCH[args.cmd]
    handler(args)


if __name__ == "__main__":
    main()
