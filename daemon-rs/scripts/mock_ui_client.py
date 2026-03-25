#!/usr/bin/env python3
"""Lightweight mock OpenSnitch UI gRPC server for daemon-rs live compatibility checks.

This script intentionally implements only behavior flow orchestration (no GUI):
- Ping: echo reply id
- Subscribe: acknowledge daemon client config
- Notifications: receive daemon stream replies and emit minimal keepalive notifications
- AskRule/PostAlert: deterministic allow/ack behavior
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
from concurrent import futures
from pathlib import Path

import grpc


def _add_proto_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    proto_dir = repo_root / "ui" / "opensnitch" / "proto"
    sys.path.insert(0, str(proto_dir))


_add_proto_path()

import ui_pb2  # type: ignore  # noqa: E402
import ui_pb2_grpc  # type: ignore  # noqa: E402


class MockUiService(ui_pb2_grpc.UIServicer):
    def Ping(self, request, context):
        print(f"MOCK_UI Ping id={request.id}", flush=True)
        return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        print(
            "MOCK_UI AskRule"
            f" proto={request.protocol} dst={request.dst_ip}:{request.dst_port}",
            flush=True,
        )
        return ui_pb2.Rule(name="mock-ui-allow", enabled=True, action="allow", duration="once")

    def Subscribe(self, request, context):
        print(
            "MOCK_UI Subscribe"
            f" id={request.id} name={request.name} version={request.version}",
            flush=True,
        )
        return ui_pb2.ClientConfig(
            id=request.id,
            name="mock-ui-client",
            version=request.version or "0.5.0",
            logLevel=request.logLevel,
            config=request.config,
        )

    def Notifications(self, request_iterator, context):
        print("MOCK_UI Notifications stream open", flush=True)
        for msg in request_iterator:
            print(
                "MOCK_UI NotificationReply"
                f" id={msg.id} code={int(msg.code)} data={msg.data}",
                flush=True,
            )
            yield ui_pb2.Notification(
                id=msg.id,
                clientName="mock-ui-client",
                serverName="mock-ui-server",
                type=ui_pb2.NONE,
                data="mock-ui-keepalive",
            )

    def PostAlert(self, request, context):
        print(
            "MOCK_UI PostAlert"
            f" id={request.id} type={int(request.type)} what={int(request.what)}",
            flush=True,
        )
        return ui_pb2.MsgResponse(id=request.id)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a mock non-UI OpenSnitch gRPC endpoint")
    parser.add_argument(
        "--socket",
        default="/tmp/osui.sock",
        help="Unix socket path (without unix:// prefix). Default: /tmp/osui.sock",
    )
    parser.add_argument(
        "--runtime-seconds",
        type=int,
        default=30,
        help="How long to keep the mock server alive before exiting. Default: 30",
    )
    parser.add_argument(
        "--ready-file",
        default="",
        help="Optional path to write once server is ready.",
    )

    args = parser.parse_args()
    sock_path = Path(args.socket)
    endpoint = f"unix://{sock_path}"

    stop_event = threading.Event()

    def _handle_signal(signum, _frame):
        print(f"MOCK_UI signal={signum} shutting down", flush=True)
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if sock_path.exists():
        sock_path.unlink()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    ui_pb2_grpc.add_UIServicer_to_server(MockUiService(), server)
    bound = server.add_insecure_port(endpoint)
    if bound == 0:
        print(f"MOCK_UI failed to bind endpoint={endpoint}", flush=True)
        return 1

    server.start()
    print(f"MOCK_UI READY endpoint={endpoint}", flush=True)

    if args.ready_file:
        Path(args.ready_file).write_text(f"ready endpoint={endpoint}\n", encoding="utf-8")

    deadline = time.monotonic() + max(1, args.runtime_seconds)
    while not stop_event.is_set() and time.monotonic() < deadline:
        time.sleep(0.2)

    server.stop(grace=1)
    print("MOCK_UI STOP", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
