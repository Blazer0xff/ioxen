import base64
import plistlib
import pprint
from datetime import datetime, timezone

from rich.markup import escape
from rich.text import Text


HISTORY_OUTCOME_CELL = {
    "forwarded":          Text("→",  style="bold #26a368"),
    "modified_forwarded": Text("✎→", style="bold #26a368"),
    "dropped":            Text("✗",  style="bold red"),
}


def ipc_direction(ipc) -> str:
    return str((ipc or {}).get("direction") or "")


def ipc_peer_label(ipc) -> str:
    """Peer process of an iOS IPC event: its path, else its PID."""
    peer = (ipc or {}).get("peer") or {}
    if peer.get("path"):
        return str(peer["path"])
    pid = peer.get("pid")
    if isinstance(pid, int) and pid > 0:
        return str(pid)
    return ""


# Keep in sync with buildFilterContext() in agent/ios/format.js: the agent
# evaluates intercept filters itself before holding a thread.
def entry_to_filter_context(entry: dict) -> dict:
    info = entry.get("intent", {}) or {}
    ipc = entry.get("ipc") or {}
    return {
        "class": str(entry.get("class") or ""),
        "method": str(entry.get("method") or ""),
        "action": str(info.get("action") or ""),
        "component": str(info.get("component") or ""),
        "data": str(info.get("data") or ""),
        "direction": ipc_direction(ipc),
        "peer": ipc_peer_label(ipc),
    }


def payload_to_filter_context(payload: dict) -> dict:
    info = payload.get("infoIntent", {}) or {}
    ipc = payload.get("ipc") or {}
    return {
        "class": str(payload.get("className", "")),
        "method": str(payload.get("methodName", "")),
        "action": str(info.get("action") or ""),
        "component": str(info.get("component") or ""),
        "data": str(info.get("data") or ""),
        "direction": ipc_direction(ipc),
        "peer": ipc_peer_label(ipc),
    }


def payload_to_history_entry(payload: dict, now: datetime | None = None) -> dict:
    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    entry = {
        "id": None,
        "timestamp": timestamp,
        "class": payload.get("className"),
        "method": payload.get("methodName"),
        "intent": payload.get("infoIntent") or {},
        "stackTrace": payload.get("stackTrace") or [],
        "attackSurface": payload.get("attackSurface") or {},
        "platform": payload.get("platform") or "ios",
        "ipc": payload.get("ipc") or {},
    }
    decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
    if isinstance(decision.get("mods"), list):
        entry["supportedMods"] = list(decision["mods"])
    return entry


def is_ios_entry(entry: dict) -> bool:
    return (entry or {}).get("platform") == "ios"


def history_sort_key(entry: dict, column: str | None):
    info = entry.get("intent", {}) or {}
    if column == "id":
        return entry.get("id", 0)
    if column == "time":
        return entry.get("timestamp", "")
    if column == "method":
        return (entry.get("method") or "").lower()
    if column == "class":
        return (entry.get("class") or "").lower()
    if column == "component":
        return (info.get("component") or "").lower()
    if column == "action":
        return (info.get("action") or "").lower()
    if column == "extras":
        return bool(info.get("extras"))
    if column == "outcome":
        return entry.get("outcome") or ""
    return ""


def history_search_matches(entry: dict, query: str) -> bool:
    normalized_query = query.lower()
    info = entry.get("intent", {}) or {}
    fields = [
        str(entry.get("class") or ""),
        str(entry.get("method") or ""),
        str(info.get("action") or ""),
        str(info.get("component") or ""),
        str(info.get("data") or ""),
    ]
    for key, value in (info.get("extras") or {}).items():
        fields.append(str(key))
        fields.append(str(value.get("value", "")))
    ipc = entry.get("ipc") or {}
    if ipc:
        fields.append(ipc_direction(ipc))
        fields.append(ipc_peer_label(ipc))
        fields.append(str(ipc.get("kind") or ""))
    return any(normalized_query in field.lower() for field in fields)


def filter_sort_history_entries(
    entries: list[dict],
    filter_manager,
    search_text: str = "",
    sort_column: str | None = None,
    sort_reverse: bool = False,
) -> list[dict]:
    filtered = []
    for entry in list(entries):
        if not filter_manager.is_visible(entry_to_filter_context(entry)):
            continue
        filtered.append(entry)

    if search_text:
        filtered = [entry for entry in filtered if history_search_matches(entry, search_text)]
    if sort_column:
        filtered.sort(key=lambda entry: history_sort_key(entry, sort_column), reverse=sort_reverse)
    return filtered


def history_row_values(entry: dict, visible_columns: set[str], columns: list[tuple[str, str]]) -> list:
    info = entry.get("intent", {}) or {}
    extras = info.get("extras", {}) or {}
    timestamp = entry.get("timestamp", "")
    time_str = timestamp[:19].replace("T", " ") if len(timestamp) >= 19 else timestamp
    outcome = entry.get("outcome")
    all_values = {
        "id":        str(entry["id"]),
        "outcome":   HISTORY_OUTCOME_CELL.get(outcome, Text("")),
        "time":      time_str,
        "method":    str(entry.get("method") or ""),
        "class":     str(entry.get("class") or ""),
        "component": str(info.get("component") or ""),
        "action":    str(info.get("action") or ""),
        "extras":    Text("✓", style="#26a368") if extras else "",
    }
    return [all_values[key] for key, _label in columns if key in visible_columns]


def _markup(value) -> str:
    return "" if value is None else escape(str(value))


def render_intercept_block(payload: dict, intercept_counter: int, show_stack: bool, stack_depth: int) -> str:
    entry = payload_to_history_entry(payload)
    entry["id"] = intercept_counter
    header = [
        "[bold #F2C94C]" + "━" * 50 + "[/bold #F2C94C]",
        f"[bold #F2C94C]  INTERCEPTED[/bold #F2C94C] [#F2C94C]#{intercept_counter}[/#F2C94C]",
    ]
    return "\n".join(header) + render_ios_detail(entry, show_stack, stack_depth)


def render_intent_detail(entry: dict, show_stack: bool = False, stack_depth: int = 15) -> str:
    return render_ios_detail(entry, show_stack, stack_depth)


def _render_extras_changes(orig_extras: dict, mod_extras: dict, title: str) -> list[str]:
    removed_keys = [key for key in orig_extras if key not in mod_extras]
    added_keys = [key for key in mod_extras if key not in orig_extras]
    changed_keys = [
        key for key in orig_extras
        if key in mod_extras and
        str(orig_extras[key].get("value", "")) != str(mod_extras[key].get("value", ""))
    ]
    if not (removed_keys or added_keys or changed_keys):
        return []
    out = ["", f"  [bold dim]{title}[/bold dim]"]
    for key in changed_keys:
        old_value = orig_extras[key]
        new_value = mod_extras[key]
        out.append(
            f"  [#F2C94C][~][/#F2C94C] [bold]{_markup(key)}[/bold]  "
            f"[dim]({_markup(old_value.get('type'))})[/dim]  "
            f"[dim]{_markup(old_value.get('value'))}[/dim] → {_markup(new_value.get('value'))}"
        )
    for key in removed_keys:
        value = orig_extras[key]
        out.append(
            f"  [#FFB1B1][-][/#FFB1B1] [bold]{_markup(key)}[/bold]  "
            f"[dim]({_markup(value.get('type'))})[/dim]  [dim]{_markup(value.get('value'))}[/dim]"
        )
    for key in added_keys:
        value = mod_extras[key]
        out.append(
            f"  [#26a368][+][/#26a368] [bold]{_markup(key)}[/bold]  "
            f"[dim]({_markup(value.get('type'))})[/dim]  {_markup(value.get('value'))}"
        )
    return out


# --- iOS -------------------------------------------------------------------

_IOS_DIRECTION_LABELS = {
    "outgoing": "[#26a368][Outgoing][/#26a368]",
    "incoming": "[#C94A8A][Incoming][/#C94A8A]",
    "reply": "[#F2C94C][Reply][/#F2C94C]",
}

# Exposure labels mark where another process (or a URL / notification sent by
# anyone) can reach code in the target.
_IOS_EXPOSURE_LABELS = {
    "listener": "[#C94A8A][Listener][/#C94A8A]",
    "service": "[#C94A8A][Exposed service][/#C94A8A]",
    "exported_method": "[#C94A8A][Exported method][/#C94A8A]",
    "exported_interface": "[#C94A8A][Exported interface][/#C94A8A]",
    "declared_scheme": "[#C94A8A][URL scheme][/#C94A8A]",
    "url_scheme": "[#F2C94C][Undeclared scheme][/#F2C94C]",
    "universal_link": "[#C94A8A][Universal link][/#C94A8A]",
    "darwin_listener": "[#C94A8A][Darwin listener][/#C94A8A]",
    "darwin_notification": "[#F2C94C][Darwin broadcast][/#F2C94C]",
    "scheme_query": "[dim][Scheme query][/dim]",
    "js_bridge": "[#C94A8A][JS bridge][/#C94A8A]",
    "webview_scheme": "[#C94A8A][Web view scheme][/#C94A8A]",
}

_IOS_KIND_TITLES = {
    "xpc": "XPC MESSAGE",
    "nsxpc_call": "NSXPC CALL",
    "nsxpc_reply": "NSXPC REPLY",
    "nsxpc_accept": "NSXPC LISTENER",
    "nsxpc_interface": "NSXPC INTERFACE",
    "nsxpc_connection": "NSXPC CONNECTION",
    "url": "URL",
    "darwin_notification": "DARWIN NOTIFICATION",
    "objc": "OBJC CALL",
    "webview": "WEB VIEW",
    "network": "NETWORK REQUEST",
}

_IOS_SERVICE_KINDS = {
    "mach": "Mach service",
    "service": "XPC service",
    "endpoint": "endpoint",
    "peer": "peer connection",
    "anonymous": "anonymous",
    "named": "named",
}

_IOS_ARGUMENT_KINDS = {"nsxpc_call", "nsxpc_reply", "objc"}


def render_ios_surface_labels(attack_surface: dict) -> list[str]:
    labels = []
    direction = _IOS_DIRECTION_LABELS.get(attack_surface.get("direction"))
    if direction:
        labels.append(direction)
    exposure = _IOS_EXPOSURE_LABELS.get(attack_surface.get("exposure"))
    if exposure:
        labels.append(exposure)
    if attack_surface.get("serviceKind") == "mach":
        labels.append("[dim][Mach service][/dim]")
    if attack_surface.get("privileged"):
        labels.append("[#F2C94C][Privileged][/#F2C94C]")
    return labels


def ios_peer_text(peer: dict) -> str:
    parts = []
    pid = (peer or {}).get("pid")
    if isinstance(pid, int) and pid > 0:
        parts.append(f"pid {pid}")
    if (peer or {}).get("path"):
        parts.append(str(peer["path"]))
    euid = (peer or {}).get("euid")
    if isinstance(euid, int) and euid >= 0 and parts:
        parts.append(f"euid {euid}")
    return "  ".join(parts)


def decode_bplist00(encoded: str, max_lines: int = 40) -> list[str]:
    """Pretty-print a base64 bplist00 blob (e.g. an NSKeyedArchiver archive)."""
    try:
        value = plistlib.loads(base64.b64decode(encoded))
    except Exception as e:
        return [f"(undecodable bplist00: {e})"]
    lines = pprint.pformat(value, width=100, compact=True).splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... (+{len(lines) - max_lines} lines)"]
    return lines


def render_ios_detail(entry: dict, show_stack: bool = False, stack_depth: int = 15) -> str:
    info = entry.get("intent", {}) or {}
    ipc = entry.get("ipc") or {}
    attack_surface = entry.get("attackSurface") or {}
    kind = ipc.get("kind") or "xpc"

    outcome_str = {
        "forwarded":          "[#26a368]→ forwarded[/#26a368]",
        "modified_forwarded": "[#26a368]✎→ forwarded (modified)[/#26a368]",
        "dropped":            "[#FFB1B1]✗ dropped[/#FFB1B1]",
    }.get(entry.get("outcome") or "", "[dim]pending[/dim]")
    timestamp = entry.get("timestamp", "")
    time_str = timestamp[:19].replace("T", " ") if len(timestamp) >= 19 else timestamp
    sep = "[dim]─[/dim]" * 50

    out = [
        "",
        f"[bold #F2C94C]#{entry.get('id')}[/bold #F2C94C]  [dim]{time_str}[/dim]  {outcome_str}",
        sep,
        f"  [bold]Method[/bold]     {_markup(entry.get('method'))}",
    ]
    labels = render_ios_surface_labels(attack_surface)
    label_text = ("  " + " ".join(labels)) if labels else ""
    out.append(f"  [bold]Class[/bold]      [dim]{_markup(entry.get('class'))}[/dim]{label_text}")

    out.append("")
    out.append(f"  [bold dim]{_IOS_KIND_TITLES.get(kind, kind.upper())}[/bold dim]")
    connection = ipc.get("connection") or {}
    service_label = "Service"
    if kind == "darwin_notification":
        service_label = "Name"
    elif kind == "network" or (kind == "webview" and info.get("data")):
        service_label = "Host"
    elif kind == "webview":
        service_label = "Bridge"
    elif kind == "url" and attack_surface.get("direction") == "incoming":
        service_label = "Source"
    if info.get("component"):
        out.append(f"  [bold]{service_label:<10}[/bold] {_markup(info.get('component'))}")
    kind_text = _IOS_SERVICE_KINDS.get(connection.get("kind") or ipc.get("serviceKind") or "")
    if kind_text:
        flags = [kind_text]
        if connection.get("listener"):
            flags.append("listener")
        if connection.get("privileged"):
            flags.append("privileged")
        out.append(f"  [bold]Connection[/bold] {_markup(' · '.join(flags))}")
    if info.get("action"):
        source = ipc.get("selectorSource")
        hint = "  [dim](guessed from bplist16)[/dim]" if source == "heuristic" else ""
        label = "Selector" if kind in ("xpc", "nsxpc_call", "nsxpc_reply", "objc") and ":" in str(info.get("action")) else "Action"
        out.append(f"  [bold]{label:<10}[/bold] {_markup(info.get('action'))}{hint}")
    if ipc.get("protocol"):
        out.append(f"  [bold]Protocol[/bold]   {_markup(ipc.get('protocol'))}")
    if info.get("data"):
        out.append(f"  [bold]URL[/bold]        {_markup(info.get('data'))}")
    peer_text = ios_peer_text(ipc.get("peer") or {})
    if peer_text:
        out.append(f"  [bold]Peer[/bold]       {_markup(peer_text)}")
    new_peer = ios_peer_text(ipc.get("newPeer") or {})
    if new_peer:
        out.append(f"  [bold]New peer[/bold]   {_markup(new_peer)}")
    event_bits = []
    if ipc.get("messageType") and kind == "xpc":
        event_bits.append(str(ipc["messageType"]))
    if ipc.get("nsxpc"):
        event_bits.append(f"NSXPC ({ipc['nsxpc'].get('encoding')})")
    if ipc.get("expectsReply"):
        event_bits.append("expects reply")
    if ipc.get("correlation"):
        event_bits.append(f"request {ipc['correlation']}")
    if ipc.get("nsxpcCall"):
        event_bits.append(f"decoded as NSXPC call {ipc['nsxpcCall']}")
    if event_bits:
        out.append(f"  [bold]Event[/bold]      {_markup(' · '.join(event_bits))}")

    extras = info.get("extras") or {}
    if extras:
        out.append("")
        title = "ARGUMENTS" if kind in _IOS_ARGUMENT_KINDS else ("MESSAGE" if kind == "xpc" else "DETAILS")
        out.append(f"  [bold dim]{title}[/bold dim]")
        for key, value in extras.items():
            out.append(
                f"  [bold]{_markup(key)}[/bold]  "
                f"[dim]({_markup(value.get('type'))})[/dim]  {_markup(value.get('value'))}"
            )

    blobs = ipc.get("blobs") or []
    if blobs:
        out.append("")
        out.append("  [bold dim]EMBEDDED DATA[/bold dim]")
        for blob in blobs:
            fmt = blob.get("format") or "data"
            out.append(f"  [bold]{_markup(blob.get('path'))}[/bold]  [dim]{_markup(blob.get('length'))} bytes {_markup(fmt)}[/dim]")
            if blob.get("base64") and fmt == "bplist00":
                for line in decode_bplist00(blob["base64"]):
                    out.append(f"    [dim]{_markup(line)}[/dim]")
            elif blob.get("strings"):
                out.append(f"    [dim]strings:[/dim] {_markup(', '.join(blob['strings'][:24]))}")

    original = entry.get("original_intent")
    if original:
        out.append("")
        out.append("  [bold dim]CHANGES[/bold dim]")
        out.append(sep)
        changes = []
        orig_data = original.get("data") or ""
        mod_data = info.get("data") or ""
        if orig_data != mod_data:
            changes.append(
                f"  [bold]URL[/bold]        "
                f"[dim]{_markup(orig_data or '(none)')}[/dim] → {_markup(mod_data or '(none)')}"
            )
        title = "ARGUMENTS" if kind in _IOS_ARGUMENT_KINDS else "MESSAGE"
        changes.extend(_render_extras_changes(original.get("extras") or {}, extras, title))
        out.extend(changes or ["  [dim](forwarded without changes)[/dim]"])

    description = ipc.get("description")
    if description and (not extras or "…" in extras):
        out.append("")
        out.append("  [bold dim]RAW[/bold dim]")
        for line in str(description).splitlines()[:40]:
            out.append(f"  [dim]{_markup(line)}[/dim]")

    trace = entry.get("stackTrace", [])
    if show_stack:
        out.append("")
        if trace:
            out.append("  [bold dim]STACK TRACE[/bold dim]")
            for line in trace[:stack_depth]:
                out.append(f"  [dim]{_markup(line)}[/dim]")
            if len(trace) > stack_depth:
                out.append(f"  [dim]... (+{len(trace)-stack_depth} more)[/dim]")
        else:
            out.append("  [dim]No stack trace captured.[/dim]")

    out.append("")
    return "\n".join(out)
