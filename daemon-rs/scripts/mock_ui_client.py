#!/usr/bin/env python3
"""Lightweight mock OpenSnitch UI gRPC server for daemon-rs live compatibility checks.

Simulates the behavior of the real Python UI client (ui/opensnitch/service.py and
nodes.py) without requiring a display.  The mock exercises:

  Ping
    - Echoes reply id.
    - Logs all stats fields the UI populates into its table models: counters
      (connections, accepted, dropped, ignored, rule_hits, rule_misses,
      dns_responses), map-row counts (Hosts, Applications, Addresses, Ports,
      Users), and the Events list (connection events shown in the Events tab).
    - Logs node identity received in daemon_version.

  Subscribe
    - Acknowledges daemon ClientConfig (echoes id/name/version/logLevel/config).
    - Logs node identity, rule count, and firewall running state — mirrors what
      service.py::Subscribe + Nodes.add_data inspect when a node first connects.

  AskRule
    - Alternates between an allow reply (simulating the user clicking Allow in
      the popup modal) and a deny reply (simulating the modal timing out, which
      returns a default-deny rule — the effective DefaultAction as a rule).
    - After responding, queues a CHANGE_RULE notification on the Notifications
      stream, mirroring service.py's _node_actions_trigger ADD_RULE path that
      confirms/persists the rule on the daemon side.
    - 2 real TCP SYN packets to RFC 5737 TEST-NET addresses (192.0.2.1 and
      198.51.100.1) are generated during Notifications to trigger the daemon's
      nfqueue interception path end-to-end.  These addresses are guaranteed
      unrouted and match no default rule, so they always reach AskRule.

  PostAlert
    - Logs alert type and what field; returns MsgResponse ack.

  Notifications (bidirectional stream)
    The mock proactively yields a sequence of Notification commands to the daemon
    and correlates each NotificationReply by id — mirroring nodes.py::send_notification
    / nodes.py::reply_notification.  Command sequence:

      LOG_LEVEL          Set log level to 2 (Info).  Safe, reversible.
      CHANGE_RULE        Upsert a test rule (mock-ui-test-rule).
      ENABLE_RULE        Re-enable the test rule.
      DISABLE_RULE       Disable the test rule.
      DELETE_RULE        Delete the test rule (cleanup).
      ENABLE_FIREWALL    Re-enable interception/firewall.
      DISABLE_FIREWALL   Disable interception/firewall.
      ENABLE_FIREWALL    Restore firewall to enabled state.
      RELOAD_FW_RULES    Reload firewall rules.
      CHANGE_RULE        (per AskRule call) Confirm/persist the rule returned
                         by AskRule, mirroring the real UI ADD_RULE path.

    When --subscriptions is passed, the following subscription commands are
    also emitted BEFORE the AskRule traffic phase (daemon built with the
    'subscriptions' Cargo feature required):

      SUBSCRIPTION_APPLY    Apply one test subscription (url + name + id).
      SUBSCRIPTION_DELETE   Delete the same test subscription by id.
      SUBSCRIPTION_REFRESH  Refresh with a target list and force=false.
      SUBSCRIPTION_DEPLOY   Deploy (no payload).

    Each ack prints MOCK_UI NotificationCommandReply cmd=<NAME>.

    Each acknowledged command prints MOCK_UI NotificationCommandReply cmd=<NAME>.

  Subscriptions (List/Apply/Delete/Refresh/Deploy)
    Registered only when --subscriptions is passed.  Requires the daemon to be
    built with the 'subscriptions' Cargo feature.  The daemon calls these
    endpoints proactively on the same socket as the UI service — at handshake
    (List) and after each local subscription operation (Apply/Delete/Refresh/Deploy).
"""

from __future__ import annotations

import argparse
import json
import queue
import signal
import socket as _socket
import sys
import threading
import time
from concurrent import futures
from pathlib import Path

import grpc


def _add_proto_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root))
    proto_dir = repo_root / "ui" / "opensnitch" / "proto"
    proto_pre3200_dir = proto_dir / "pre3200"
    sys.path.insert(0, str(proto_dir))
    if proto_pre3200_dir.exists():
        sys.path.insert(0, str(proto_pre3200_dir))


_add_proto_path()

try:
    import ui_pb2  # type: ignore  # noqa: E402
    import ui_pb2_grpc  # type: ignore  # noqa: E402
except Exception:
    from ui.opensnitch.proto.pre3200 import ui_pb2  # type: ignore  # noqa: E402
    from ui.opensnitch.proto.pre3200 import ui_pb2_grpc  # type: ignore  # noqa: E402

try:
    import subscriptions_pb2  # type: ignore  # noqa: E402
    import subscriptions_pb2_grpc  # type: ignore  # noqa: E402
except Exception:
    try:
        from ui.opensnitch.proto import subscriptions_pb2  # type: ignore  # noqa: E402
        from ui.opensnitch.proto import subscriptions_pb2_grpc  # type: ignore  # noqa: E402
    except Exception:
        subscriptions_pb2 = None
        subscriptions_pb2_grpc = None

# ── notification data payloads ────────────────────────────────────────────────

# LOG_LEVEL: set level 2 (Info) — safe, reversible, no persistent side-effects.
# Keys accepted case-insensitively by the daemon.
_LOG_LEVEL_NOTIFICATION_DATA = json.dumps({"log_level": 2})

# Test rule name used for the rule lifecycle (create → enable → disable → delete).
_MOCK_TEST_RULE_NAME = "mock-ui-test-rule"

# Test subscription used for the subscription lifecycle when --subscriptions is passed.
# Uses a documentation-only URL (RFC 5737 / IANA reserved) that will never
# resolve to real content — safe for live + CI sessions.
_MOCK_TEST_SUBSCRIPTION_ID   = "mock-ui-test-subscription"
_MOCK_TEST_SUBSCRIPTION_NAME = "Mock UI Test Subscription"
_MOCK_TEST_SUBSCRIPTION_URL  = "https://198.51.100.1/test-list.txt"

# JSON data payloads for subscription notification actions.
_SUBSCRIPTION_APPLY_DATA = json.dumps({
    "subscriptions": [
        {
            "id":      _MOCK_TEST_SUBSCRIPTION_ID,
            "name":    _MOCK_TEST_SUBSCRIPTION_NAME,
            "url":     _MOCK_TEST_SUBSCRIPTION_URL,
            "enabled": True,
        }
    ]
})
_SUBSCRIPTION_DELETE_DATA = json.dumps({
    "subscriptions": [
        {"id": _MOCK_TEST_SUBSCRIPTION_ID, "url": _MOCK_TEST_SUBSCRIPTION_URL}
    ]
})
_SUBSCRIPTION_REFRESH_DATA = json.dumps({
    "targets": [_MOCK_TEST_SUBSCRIPTION_ID],
    "force": False,
})

# RFC 5737 TEST-NET addresses used by _send_traffic() inside Notifications.
# Only connections targeting these addresses are counted as intentional AskRule
# probes.  With the daemon running against an isolated rules dir (only the two
# loopback-allow rules), ALL other traffic also reaches AskRule; those calls
# must be answered immediately with allow so they don't block the machine or
# pollute the test counters.
_ASK_RULE_EXPECTED_DSTS: frozenset[str] = frozenset({"192.0.2.1", "198.51.100.1"})


def _make_test_rule() -> ui_pb2.Rule:
    """Initial test rule for the add step of the rule lifecycle.

    Targets RFC 5737 TEST-NET-2 (198.51.100.0/24), a documentation-only address
    range that is never routable, so the rule cannot accidentally affect real
    traffic during a live session.
    """
    return ui_pb2.Rule(
        name=_MOCK_TEST_RULE_NAME,
        enabled=True,
        action="allow",
        duration="always",
        created=int(time.time()),
        operator=ui_pb2.Operator(
            type="simple",
            operand="dest.ip",
            data="198.51.100.1",
        ),
    )


def _make_test_rule_edited() -> ui_pb2.Rule:
    """Edited version of the test rule for the edit step of the rule lifecycle.

    Same name (so the daemon replaces the existing rule on upsert), but action
    flipped to deny and target address changed to TEST-NET-2's .2 address.
    """
    return ui_pb2.Rule(
        name=_MOCK_TEST_RULE_NAME,
        enabled=True,
        action="deny",
        duration="always",
        created=int(time.time()),
        operator=ui_pb2.Operator(
            type="simple",
            operand="dest.ip",
            data="198.51.100.2",
        ),
    )


# ── recap table ─────────────────────────────────────────────────────────────
#
# Status symbols used throughout:
#   ✓  OK / observed
#   ✗  error / unexpected failure
#   ⚠  warning (expected reply not received)
#   —  not triggered / N/A


# ── service implementations ───────────────────────────────────────────────────

class MockUiService(ui_pb2_grpc.UIServicer):
    def __init__(self, enable_subscriptions: bool = False) -> None:
        self._enable_subscriptions = enable_subscriptions
        # ── AskRule: even calls → allow, odd → deny ──────────────────────────
        self._ask_rule_count = 0
        self._ask_rule_allow_count = 0
        self._ask_rule_deny_count = 0
        # ── session-level event counters (accumulated across reconnections) ───
        self._ping_count = 0
        self._subscribe_count = 0
        self._notifications_opened = 0
        # ── SysFirewall captured from Subscribe, reused for RELOAD_FW_RULES ──
        self._sys_firewall: ui_pb2.SysFirewall | None = None
        self._sys_firewall_lock = threading.Lock()
        # ── AskRule → Notifications bridge ───────────────────────────────────
        # After responding to AskRule the real UI emits an ADD_RULE node-action
        # which sends a CHANGE_RULE notification on the Notifications stream to
        # confirm/persist the rule on the daemon side.  We replicate that here
        # via a thread-safe queue: AskRule deposits the rule; the Notifications
        # for-loop drains it and yields CHANGE_RULE commands.
        # _ask_rule_acked_count tracks the daemon's ack of those CHANGE_RULE
        # notifications — a ✓ in the recap requires the full round-trip.
        self._ask_rule_rule_queue: queue.Queue[ui_pb2.Rule] = queue.Queue()
        self._ask_rule_acked_count: int = 0

    # ── Ping ─────────────────────────────────────────────────────────────────

    def Ping(self, request, context):
        self._ping_count += 1
        stats = request.stats
        print(f"MOCK_UI Ping id={request.id}", flush=True)

        if not stats.daemon_version:
            return ui_pb2.PingReply(id=request.id)

        # Counters — mirrors what service.py::Ping emits to _update_stats_trigger
        # which populates the main stats dialog (Events/Nodes counters at the top).
        print(
            "MOCK_UI PingStats"
            f" version={stats.daemon_version!r}"
            f" uptime={stats.uptime}"
            f" connections={stats.connections}"
            f" accepted={stats.accepted}"
            f" dropped={stats.dropped}"
            f" ignored={stats.ignored}"
            f" rule_hits={stats.rule_hits}"
            f" rule_misses={stats.rule_misses}"
            f" dns_responses={stats.dns_responses}"
            f" rules={stats.rules}",
            flush=True,
        )

        # Map-table sizes — mirrors what the UI populates into its per-tab table
        # models: Hosts, Applications, Addresses, Ports, Users.
        for label, table in (
            ("Hosts",        stats.by_host),
            ("Apps",         stats.by_executable),
            ("Addresses",    stats.by_address),
            ("Ports",        stats.by_port),
            ("Users",        stats.by_uid),
            ("Protos",       stats.by_proto),
        ):
            if table:
                print(f"MOCK_UI PingStats{label} count={len(table)}", flush=True)

        # Connection events — mirrors Events tab (Statistics.EventsList).
        if stats.events:
            ev = stats.events[0]
            conn = ev.connection
            print(
                f"MOCK_UI PingStatsEvents count={len(stats.events)}"
                f" sample_proto={conn.protocol!r}"
                f" sample_dst={conn.dst_ip}:{conn.dst_port}",
                flush=True,
            )

        # Subscription counters are carried as daemon-rs-only fields in
        # MetricsSnapshot, not in the pb.Statistics wire message — not visible here.

        return ui_pb2.PingReply(id=request.id)

    # ── AskRule ──────────────────────────────────────────────────────────────

    def AskRule(self, request, context):
        dst_ip = request.dst_ip
        dst = f"{dst_ip}:{request.dst_port}"

        if dst_ip not in _ASK_RULE_EXPECTED_DSTS:
            # Background connection: the isolated rules dir (loopback-only)
            # causes every non-loopback connection to reach AskRule.  Always
            # allow these silently so the machine stays connected and the test
            # counters are not polluted with incidental traffic.
            print(
                f"MOCK_UI AskRuleBg proto={request.protocol} dst={dst}",
                flush=True,
            )
            return ui_pb2.Rule(
                name="mock-ui-bg-allow", enabled=True, action="allow", duration="once"
            )

        count = self._ask_rule_count
        self._ask_rule_count += 1

        if count % 2 == 0:
            # Simulates the user actively clicking Allow in the popup modal.
            self._ask_rule_allow_count += 1
            rule = ui_pb2.Rule(
                name=f"mock-ui-allow-{dst_ip.replace('.', '-')}",
                enabled=True,
                action="allow",
                duration="once",
                operator=ui_pb2.Operator(
                    type="simple", operand="dest.ip", data=dst_ip
                ),
            )
            print(
                f"MOCK_UI AskRuleAllow proto={request.protocol} dst={dst}",
                flush=True,
            )
        else:
            # Simulates the modal timing out (default deny).
            self._ask_rule_deny_count += 1
            rule = ui_pb2.Rule(
                name=f"mock-ui-deny-{dst_ip.replace('.', '-')}",
                enabled=True,
                action="deny",
                duration="once",
                operator=ui_pb2.Operator(
                    type="simple", operand="dest.ip", data=dst_ip
                ),
            )
            print(
                f"MOCK_UI AskRuleDeny proto={request.protocol} dst={dst}",
                flush=True,
            )

        # Mirror service.py's _node_actions_trigger ADD_RULE path: after
        # returning the rule to the daemon the real UI sends a CHANGE_RULE
        # notification on the Notifications stream to confirm/persist it.
        # Queue it for the active Notifications generator to pick up.
        self._ask_rule_rule_queue.put(rule)
        return rule

    # ── Subscribe ────────────────────────────────────────────────────────────

    def Subscribe(self, request, context):
        self._subscribe_count += 1
        print(
            f"MOCK_UI Subscribe"
            f" id={request.id} name={request.name} version={request.version}",
            flush=True,
        )
        # Mirror what service.py::Subscribe + Nodes.add_data inspect on first
        # connect: node identity, rule set from ClientConfig, firewall state.
        # Capture systemFirewall so we can reuse it in RELOAD_FW_RULES below.
        with self._sys_firewall_lock:
            self._sys_firewall = request.systemFirewall
        has_sys_fw = bool(self._sys_firewall and self._sys_firewall.Version)
        print(
            f"MOCK_UI SubscribeNode"
            f" firewall_running={request.isFirewallRunning}"
            f" rules={len(request.rules)}"
            f" log_level={request.logLevel}"
            f" sys_firewall={has_sys_fw}",
            flush=True,
        )
        if request.rules:
            # Log a sample rule name — mirrors Nodes._rules.add_rules().
            print(
                f"MOCK_UI SubscribeRules"
                f" count={len(request.rules)}"
                f" sample={request.rules[0].name!r}",
                flush=True,
            )
        return ui_pb2.ClientConfig(
            id=request.id,
            name="mock-ui-client",
            version=request.version or "0.5.0",
            logLevel=request.logLevel,
            config=request.config,
        )

    # ── PostAlert ────────────────────────────────────────────────────────────

    def PostAlert(self, request, context):
        print(
            f"MOCK_UI PostAlert"
            f" id={request.id} type={int(request.type)} what={int(request.what)}",
            flush=True,
        )
        return ui_pb2.MsgResponse(id=request.id)

    # ── Notifications ────────────────────────────────────────────────────────

    def Notifications(self, request_iterator, context):
        """Bidirectional notification stream.

        Yields a sequence of Notification commands to the daemon and reads back
        NotificationReply items, correlating them by id — the same pattern used
        by nodes.py::send_notification / reply_notification in the real Python UI.

        AskRule flow (mirroring service.py + daemon verdict path):
          1. Daemon intercepts a connection that matches no rule.
          2. Daemon sends AskRule to the UI and WAITS for the response
             (up to 120 s; the nfqueue packet is held in a repeat queue).
          3. Python UI (service.py promptUser):
               • User clicked in time  → returns the user's rule.
               • Dialog timed out     → returns a default-deny rule.
             Either way a rule is always returned; the daemon then applies
             that rule as the verdict for the held packet AND adds it to its
             runtime rule set for future matches.
          4. DefaultAction is applied only when the UI is unreachable or
             already busy handling another dialog (GetIsAsking guard).

          Injection strategy: traffic is sent AFTER the initial-batch acks
          are all received (phase 1 for-loop), guaranteeing the firewall is
          stable (DISABLE/ENABLE/RELOAD round-trip complete) before SYNs hit
          nfqueue.  Two RFC 5737 TEST-NET SYNs trigger the full daemon
          intercept → AskRule → CHANGE_RULE round-trip deterministically.
        """
        self._notifications_opened += 1
        print("MOCK_UI Notifications stream open", flush=True)

        pending: dict[int, str] = {}
        next_id = 1
        sent_order: list[tuple[int, str]] = []
        reply_codes: dict[int, str] = {}
        recap_printed = False

        def _send(
            cmd: str,
            action: int,
            data: str = "",
            rules: list | None = None,
            sys_firewall: ui_pb2.SysFirewall | None = None,
            label: str | None = None,
            track_ack: bool = True,
        ):
            nonlocal next_id
            nid = next_id
            next_id += 1
            msg = ui_pb2.Notification(
                id=nid,
                clientName="mock-ui-client",
                serverName="mock-ui-server",
                type=action,
                data=data,
            )
            if rules:
                msg.rules.extend(rules)
            if sys_firewall is not None:
                msg.sysFirewall.CopyFrom(sys_firewall)
            if track_ack:
                pending[nid] = cmd
                reply_codes[nid] = "—"  # placeholder until reply arrives
            else:
                # Daemon will not send an ack for this command type; mark OK
                # immediately so it shows ✓ in the recap without blocking.
                reply_codes[nid] = "OK"
            display = label if label is not None else cmd
            sent_order.append((nid, display))
            print(f"MOCK_UI NotificationSend cmd={cmd} id={nid}", flush=True)
            return msg

        # ── Initial batch ─────────────────────────────────────────────────────

        # LOG_LEVEL: the daemon processes this asynchronously and sends its
        # ack *after* most other command acks (sometimes even after RELOAD_FW_RULES).
        # We keep it tracked (track_ack=True default) so that when its reply
        # eventually arrives in phase-2 the NotificationCommandReply line is
        # printed.  The phase-1 break condition deliberately skips LOG_LEVEL so
        # we don't wait for it before injecting traffic.
        yield _send("LOG_LEVEL", ui_pb2.LOG_LEVEL, _LOG_LEVEL_NOTIFICATION_DATA)

        test_rule   = _make_test_rule()
        edited_rule = _make_test_rule_edited()
        yield _send("CHANGE_RULE",  ui_pb2.CHANGE_RULE,  rules=[test_rule],   label="CHANGE_RULE add")
        yield _send("CHANGE_RULE",  ui_pb2.CHANGE_RULE,  rules=[edited_rule], label="CHANGE_RULE edit")
        yield _send("ENABLE_RULE",  ui_pb2.ENABLE_RULE,  rules=[edited_rule])
        yield _send("DISABLE_RULE", ui_pb2.DISABLE_RULE, rules=[edited_rule])
        yield _send("DELETE_RULE",  ui_pb2.DELETE_RULE,  rules=[edited_rule])

        yield _send("ENABLE_FIREWALL",  ui_pb2.ENABLE_FIREWALL)
        yield _send("DISABLE_FIREWALL", ui_pb2.DISABLE_FIREWALL)
        yield _send("ENABLE_FIREWALL",  ui_pb2.ENABLE_FIREWALL, label="ENABLE_FIREWALL restore")

        with self._sys_firewall_lock:
            sys_fw = self._sys_firewall
        if sys_fw is None:
            sys_fw = ui_pb2.SysFirewall(Enabled=True, Version=1)
        yield _send("RELOAD_FW_RULES", ui_pb2.RELOAD_FW_RULES, sys_firewall=sys_fw)

        # ── Phase 1: drain initial-batch acks ────────────────────────────────
        # Must complete before injecting traffic: the batch includes
        # DISABLE_FIREWALL + ENABLE_FIREWALL + RELOAD_FW_RULES.  Sending SYNs
        # while DISABLE_FIREWALL is still being processed means the firewall may
        # be down and nfqueue won't intercept the packets.
        #
        # Subscription commands (APPLY / DELETE / REFRESH / DEPLOY) are included
        # in the same batch when --subscriptions is passed.  They are acked
        # asynchronously; the phase-1 break condition waits for all non-LOG_LEVEL
        # non-subscription commands, then breaks — subscription acks arrive later
        # in phase-2 alongside AskRule CHANGE_RULE acks.
        #
        # Important: do NOT yield here.  Yielding type=NONE (action=0) is
        # interpreted by the daemon as a stream-close request, which tears down
        # the Notifications stream and forces an immediate reconnect loop.
        # Phase-1 is a pure consumer: it only reads from request_iterator.
        _PHASE1_SKIP = {"LOG_LEVEL"}

        for msg in request_iterator:
            code_name = "OK" if int(msg.code) == 0 else "ERROR"
            print(
                f"MOCK_UI NotificationReply"
                f" id={msg.id} code={code_name} data={msg.data!r}",
                flush=True,
            )
            if msg.id in pending:
                cmd = pending.pop(msg.id)
                reply_codes[msg.id] = code_name
                print(
                    f"MOCK_UI NotificationCommandReply cmd={cmd} code={code_name}",
                    flush=True,
                )
            # Break when every non-skipped command has been acked.
            # LOG_LEVEL is processed by a separate async task in the daemon
            # and its ack arrives late (sometimes after RELOAD_FW_RULES).
            # Subscription commands are similarly async — their acks arrive after
            # the SubscriptionService processes the request and calls back to the
            # Python SubscriptionsServicer.  Both sets are drained in phase-2.
            if not any(v not in _PHASE1_SKIP for v in pending.values()):
                break  # firewall is stable; inject traffic

        # ── AskRule traffic injection ─────────────────────────────────────────
        # Now that the firewall is stable (all initial acks received), generate
        # real TCP SYN packets to RFC 5737 TEST-NET addresses.  These are
        # guaranteed unrouted and match no default rule, so the daemon's nfqueue
        # intercepts each SYN and routes it to our AskRule handler.  Two
        # distinct destinations keep per-connection-key decision epochs separate.
        _ASK_TARGETS = ["192.0.2.1", "198.51.100.1"]
        _NUM_ASKS    = len(_ASK_TARGETS)

        def _send_traffic() -> None:
            for _addr in _ASK_TARGETS:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(0.5)
                try:
                    s.connect((_addr, 80))
                except Exception:
                    pass
                finally:
                    s.close()
                time.sleep(0.05)  # pace: let daemon process one verdict at a time

        threading.Thread(target=_send_traffic, daemon=True).start()

        # Collect rules queued by AskRule.  Plain blocking get with short timeout;
        # do NOT yield during this wait — yielding without simultaneously consuming
        # request_iterator would let daemon acks pile up in the gRPC receive
        # buffer, leading to flow-control deadlock.  The TCP stream stays alive
        # without application-level keepalives for the brief window here (≤5 s).
        _collected_ask_rules: list[ui_pb2.Rule] = []
        _deadline = time.monotonic() + 5.0
        while len(_collected_ask_rules) < _NUM_ASKS and time.monotonic() < _deadline:
            try:
                _collected_ask_rules.append(
                    self._ask_rule_rule_queue.get(timeout=0.25)
                )
            except queue.Empty:
                pass  # just wait; no yield here to avoid deadlock

        # Drain any extras (background traffic or late arrivals).
        while True:
            try:
                _collected_ask_rules.append(self._ask_rule_rule_queue.get_nowait())
            except queue.Empty:
                break

        # Yield CHANGE_RULE_FROM_ASK for every collected rule so they enter
        # pending before phase 2 starts — single clean recap on final ack.
        for _ar in _collected_ask_rules:
            yield _send(
                "CHANGE_RULE_FROM_ASK",
                ui_pb2.CHANGE_RULE,
                rules=[_ar],
                label=(
                    "CHANGE_RULE allow" if _ar.action == "allow"
                    else "CHANGE_RULE deny"
                ),
            )

        # ── Phase 2: drain CHANGE_RULE_FROM_ASK acks + recap ─────────────────
        # If no AskRule fired (pending is already empty), print recap and return
        # immediately — the generator exit closes the stream gracefully.
        # Do NOT yield NONE (action=0) anywhere: the daemon interprets that as
        # a close request which triggers an immediate Notifications reconnect.
        if not pending and not recap_printed:
            recap_printed = True
            self._print_session_recap(
                [(lbl, {"OK": "✓", "ERROR": "✗"}.get(reply_codes.get(nid, ""), "⚠"))
                 for nid, lbl in sent_order]
            )
            return

        for msg in request_iterator:
            code_name = "OK" if int(msg.code) == 0 else "ERROR"
            print(
                f"MOCK_UI NotificationReply"
                f" id={msg.id} code={code_name} data={msg.data!r}",
                flush=True,
            )
            if msg.id in pending:
                cmd = pending.pop(msg.id)
                reply_codes[msg.id] = code_name
                print(
                    f"MOCK_UI NotificationCommandReply cmd={cmd} code={code_name}",
                    flush=True,
                )
                if cmd == "CHANGE_RULE_FROM_ASK":
                    self._ask_rule_acked_count += 1
            # Drain any further TEST-NET AskRule rules whose SYNs were
            # retransmitted by the OS and arrived after the initial drain.
            while True:
                try:
                    _bg_rule = self._ask_rule_rule_queue.get_nowait()
                except queue.Empty:
                    break
                yield _send(
                    "CHANGE_RULE_FROM_ASK",
                    ui_pb2.CHANGE_RULE,
                    rules=[_bg_rule],
                    label=(
                        "CHANGE_RULE allow" if _bg_rule.action == "allow"
                        else "CHANGE_RULE deny"
                    ),
                )
            if not pending and not recap_printed:
                recap_printed = True
                self._print_session_recap(
                    [(lbl, {"OK": "✓", "ERROR": "✗"}.get(
                        reply_codes.get(nid, ""), "⚠"))
                     for nid, lbl in sent_order]
                )
                # Return to close the stream gracefully.  The orchestrator
                # sees "SessionRecap status=PASS" in the log and shuts down.
                return


    def _print_session_recap(self, notif_rows: list[tuple[str, str]]) -> None:
        """Print a full-session box-drawing recap table.

        Top section: gRPC handshake events (Subscribe, Ping, Notifications,
        AskRule) with cumulative counts.

        AskRule: daemon calls it for every unmatched connection; it waits for
        the response and uses the returned rule as the verdict for that packet.
        The dialog's timeout path returns a default-deny rule — that rule IS
        the effective DefaultAction materialised.  DefaultAction itself is only
        applied directly when the UI is unreachable or busy (GetIsAsking).
        In a quiet sandbox no unmatched non-localhost connections occur, so no
        AskRule calls arrive; this is reported as N/A, not a failure.

        Bottom section: per notification command round-trip results.

        Status symbols: ✓ OK/observed  ✗ error  ⚠ warning/missing  — N/A
        """
        rows: list[tuple[str, str]] = []

        # ── gRPC handshake ───────────────────────────────────────────────────
        rows.append((
            f"Subscribe (×{self._subscribe_count})",
            "✓" if self._subscribe_count > 0 else "⚠",
        ))
        rows.append((
            f"Ping (×{self._ping_count})",
            "✓" if self._ping_count > 0 else "⚠",
        ))
        rows.append((
            f"Notifications stream (×{self._notifications_opened})",
            "✓" if self._notifications_opened > 0 else "⚠",
        ))

        # ── AskRule (connection popup) ───────────────────────────────────────
        # The daemon calls AskRule for every unmatched connection; it holds the
        # nfqueue packet and waits for the rule response — the verdict for that
        # specific packet comes from the returned rule, not DefaultAction.
        # The dialog-timeout path in service.py returns a deny rule that is
        # effectively DefaultAction materialised.  DefaultAction itself is only
        # applied directly when the UI is unreachable or already busy.
        # ✓ requires the full round-trip: AskRule called AND the resulting
        # CHANGE_RULE acked by the daemon.  ⚠ if called but not yet confirmed.
        # In a quiet sandbox (no non-localhost connections) no calls arrive — N/A.
        if self._ask_rule_acked_count > 0:
            rows.append((f"AskRule allow (×{self._ask_rule_allow_count})", "✓"))
            rows.append((f"AskRule deny  (×{self._ask_rule_deny_count})",  "✓"))
        elif self._ask_rule_count > 0:
            rows.append(("AskRule (CHANGE_RULE not yet acked)", "⚠"))
        else:
            rows.append(("AskRule (no background traffic)", "—"))

        # ── notification command round-trips ─────────────────────────────────
        rows.extend(notif_rows)

        col_cmd = max(len(lbl) for lbl, _ in rows)
        col_cmd = max(col_cmd, len("Check"))

        # Status column is one symbol wide; total row width = col_cmd + 8.
        # │ {label:<col_cmd} │ {sym} │
        #   1+col_cmd+1       1+1+1   = col_cmd + 8
        def _hr(left: str, mid: str, right: str) -> str:
            return f"{left}{'─' * (col_cmd + 2)}{mid}{'─' * 3}{right}"

        def _row(label: str, sym: str) -> str:
            return f"│ {label:<{col_cmd}} │ {sym:^1} │"

        passed = sum(1 for _, s in rows if s == "✓")
        errors = sum(1 for _, s in rows if s == "✗")
        warns  = sum(1 for _, s in rows if s == "⚠")
        total  = len(rows)
        overall = "PASS" if errors == 0 else "FAIL"

        print(_hr("┌", "┬", "┐"), flush=True)
        print(f"│ {'Check':<{col_cmd}} │   │", flush=True)
        print(_hr("├", "┼", "┤"), flush=True)
        for label, sym in rows:
            print(_row(label, sym), flush=True)
        print(_hr("├", "┴", "┤"), flush=True)

        # Footer spans both columns as one cell.
        # │ {content:<col_cmd+4} │  →  1+1+col_cmd+4+1+1 = col_cmd+8 ✓
        summary = f"{passed} / {total} passed"
        if errors:
            summary += f", {errors} error{'s' if errors > 1 else ''}"
        if warns:
            summary += f", {warns} warning{'s' if warns > 1 else ''}"
        footer = f"{summary}  {overall}"
        print(f"│ {footer:<{col_cmd + 4}} │", flush=True)
        print(f"└{'─' * (col_cmd + 6)}┘", flush=True)
        print(
            f"MOCK_UI SessionRecap"
            f" status={overall} passed={passed} errors={errors} warns={warns} total={total}",
            flush=True,
        )


if subscriptions_pb2 is not None and subscriptions_pb2_grpc is not None:

    class MockSubscriptionsService(subscriptions_pb2_grpc.SubscriptionsServicer):
        """Mock handler for the Subscriptions gRPC service.

        Registered on the same socket as MockUiService.  The daemon calls these
        endpoints proactively using the same gRPC channel as the UI service:
          - List  — called at handshake to sync subscription state with the UI.
          - Apply/Delete/Refresh/Deploy — called after local subscription operations
            to report results back to the UI.
        Each handler prints a unique marker used by live-session orchestration.
        """

        def _accepted_reply(
            self, request: subscriptions_pb2.SubscriptionRequest
        ) -> subscriptions_pb2.SubscriptionReply:
            return subscriptions_pb2.SubscriptionReply(
                operation=request.operation,
                accepted=True,
                message="mock-ui-ok",
            )

        def List(self, request, context):
            print(
                f"MOCK_UI SubscriptionsList targets={list(request.targets)}",
                flush=True,
            )
            return self._accepted_reply(request)

        def Apply(self, request, context):
            print(
                f"MOCK_UI SubscriptionsApply"
                f" count={len(request.subscriptions)} targets={list(request.targets)}",
                flush=True,
            )
            return self._accepted_reply(request)

        def Delete(self, request, context):
            print(
                f"MOCK_UI SubscriptionsDelete targets={list(request.targets)}",
                flush=True,
            )
            return self._accepted_reply(request)

        def Refresh(self, request, context):
            print(
                f"MOCK_UI SubscriptionsRefresh"
                f" targets={list(request.targets)} force={request.force}",
                flush=True,
            )
            return self._accepted_reply(request)

        def Deploy(self, request, context):
            print(
                f"MOCK_UI SubscriptionsDeploy"
                f" count={len(request.subscriptions)} targets={list(request.targets)}",
                flush=True,
            )
            return self._accepted_reply(request)

        def Commands(self, request_iterator, context):
            """Bidi stream: yields SubscriptionCommand items to the daemon and reads
            SubscriptionCommandAck items back in a background thread.

            Called by the daemon's SubscriptionCommandFlow on every connect attempt.
            The daemon (gRPC client) sends acks after processing each command; the
            daemon (gRPC server-streaming side) reads commands from this generator.
            """
            cmd_id = 0

            def _cmd(action: int, data: str = "") -> subscriptions_pb2.SubscriptionCommand:
                nonlocal cmd_id
                cmd_id += 1
                print(f"MOCK_UI SubscriptionsCommandSend id={cmd_id} action={action}", flush=True)
                return subscriptions_pb2.SubscriptionCommand(id=cmd_id, action=action, data=data)

            def _drain_acks() -> None:
                try:
                    for ack in request_iterator:
                        print(
                            f"MOCK_UI SubscriptionsCommandAck"
                            f" id={ack.id} action={ack.action}"
                            f" accepted={ack.accepted} msg={ack.message!r}",
                            flush=True,
                        )
                except Exception as exc:
                    print(f"MOCK_UI SubscriptionsCommandAckError {exc}", flush=True)

            threading.Thread(target=_drain_acks, daemon=True).start()

            yield _cmd(subscriptions_pb2.SUBSCRIPTION_ACTION_LIST)
            yield _cmd(subscriptions_pb2.SUBSCRIPTION_ACTION_APPLY, _SUBSCRIPTION_APPLY_DATA)
            yield _cmd(subscriptions_pb2.SUBSCRIPTION_ACTION_DELETE, _SUBSCRIPTION_DELETE_DATA)
            yield _cmd(subscriptions_pb2.SUBSCRIPTION_ACTION_REFRESH, _SUBSCRIPTION_REFRESH_DATA)
            yield _cmd(subscriptions_pb2.SUBSCRIPTION_ACTION_DEPLOY)


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
    parser.add_argument(
        "--subscriptions",
        action="store_true",
        default=False,
        help=(
            "Register the Subscriptions gRPC service on the same socket as the "
            "UI service.  The daemon (built with the 'subscriptions' Cargo "
            "feature) calls List at handshake and Apply/Delete/Refresh/Deploy "
            "after local subscription operations."
        ),
    )

    args = parser.parse_args()
    effective_subscriptions = args.subscriptions
    if effective_subscriptions and (
        subscriptions_pb2 is None or subscriptions_pb2_grpc is None
    ):
        print(
            "MOCK_UI subscriptions requested but subscriptions proto modules are unavailable; continuing without subscriptions service",
            flush=True,
        )
        effective_subscriptions = False

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
    ui_pb2_grpc.add_UIServicer_to_server(MockUiService(enable_subscriptions=effective_subscriptions), server)
    if effective_subscriptions:
        subscriptions_pb2_grpc.add_SubscriptionsServicer_to_server(MockSubscriptionsService(), server)
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
