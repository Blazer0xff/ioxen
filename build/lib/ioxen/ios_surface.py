"""iOS attack-surface mapping.

Combines the static surface reported by the iOS agent (Info.plist URL types,
document types, app extensions and the entitlements embedded in the code
signature) with the IPC observed at runtime (History entries): XPC services
contacted, listeners and exported NSXPC interfaces, URLs received and Darwin
notifications.
"""

import plistlib
from collections import Counter

from rich.markup import escape

# Entitlements that widen or describe how other code can reach the app.
NOTABLE_ENTITLEMENTS = {
    "com.apple.developer.associated-domains": "universal links / shared web credentials",
    "com.apple.security.application-groups": "shared containers with other apps/extensions",
    "keychain-access-groups": "shared keychain items",
    "com.apple.security.exception.mach-lookup.global-name": "sandbox exception: reachable Mach services",
    "com.apple.security.temporary-exception.mach-lookup.global-name": "sandbox exception: reachable Mach services",
    "com.apple.developer.icloud-container-identifiers": "iCloud containers",
    "com.apple.developer.ubiquity-kvstore-identifier": "iCloud key-value store",
    "aps-environment": "push notifications",
    "get-task-allow": "debuggable (development signing)",
    "platform-application": "platform binary",
    "com.apple.private.security.no-sandbox": "runs without sandbox",
    "com.apple.developer.nfc.readersession.formats": "NFC tag reading",
}

_XPC_KINDS = {"xpc"}


def parse_entitlements(xml) -> tuple[dict, str | None]:
    """Parse the XML entitlements plist. Returns (entitlements, error)."""
    if not xml:
        return {}, None
    try:
        value = plistlib.loads(str(xml).encode("utf-8"))
    except Exception as e:
        return {}, f"invalid entitlements plist: {e}"
    if not isinstance(value, dict):
        return {}, "entitlements plist is not a dictionary"
    return value, None


def _ios_entries(entries):
    return [entry for entry in entries or [] if (entry or {}).get("platform") == "ios"]


def summarize_observed(entries) -> dict:
    outgoing = {}
    listeners = {}
    incoming_peers = Counter()
    interfaces = {}
    exported_calls = Counter()
    urls_in = {}
    urls_out = {}
    scheme_queries = Counter()
    darwin_posted = Counter()
    darwin_listening = Counter()
    js_bridges = {}
    bridge_messages = Counter()
    web_loads = Counter()
    web_navigation = Counter()
    web_scripts = Counter()
    web_schemes = {}
    web_browsers = Counter()
    network_hosts = Counter()

    for entry in _ios_entries(entries):
        ipc = entry.get("ipc") or {}
        info = entry.get("intent") or {}
        kind = ipc.get("kind")
        direction = ipc.get("direction")
        component = info.get("component") or "(unnamed)"
        action = info.get("action")
        peer = ipc.get("peer") or {}
        peer_label = peer.get("path") or (f"pid {peer['pid']}" if peer.get("pid") else None)

        if kind == "nsxpc_call" and direction == "outgoing":
            # Decoded NSXPC call; its raw libxpc message is counted separately.
            item = outgoing.setdefault(component, {"messages": 0, "kinds": set(), "selectors": set(), "peer": None})
            item["kinds"].add("NSXPC")
            if action:
                item["selectors"].add(action)
        elif kind in _XPC_KINDS and direction == "outgoing":
            item = outgoing.setdefault(component, {"messages": 0, "kinds": set(), "selectors": set(), "peer": None})
            item["messages"] += 1
            conn_kind = (ipc.get("connection") or {}).get("kind")
            if conn_kind:
                item["kinds"].add(conn_kind)
            if action:
                item["selectors"].add(action)
            if peer_label:
                item["peer"] = peer_label
        elif kind in _XPC_KINDS and direction == "incoming":
            new_peer = ipc.get("newPeer") or {}
            conn = ipc.get("connection") or {}
            if ipc.get("messageType") == "connection":
                name = conn.get("name") or component
                item = listeners.setdefault(name, {"api": "libxpc", "peers": Counter()})
                item["peers"][new_peer.get("path") or f"pid {new_peer.get('pid')}"] += 1
            elif peer_label and (conn.get("kind") == "peer" or conn.get("listenerName")):
                incoming_peers[(conn.get("listenerName") or component, peer_label)] += 1
        elif kind == "nsxpc_accept":
            item = listeners.setdefault(component, {"api": "NSXPC", "peers": Counter()})
            item["peers"][peer_label or "unknown"] += 1
        elif kind == "nsxpc_interface":
            key = component
            item = interfaces.setdefault(key, {"exported": None, "remote": None})
            for side in ("exported", "remote"):
                if ipc.get(side):
                    item[side] = ipc[side]
        elif kind == "nsxpc_call" and direction != "outgoing":
            exported_calls[(component, ipc.get("selector") or action or "?")] += 1
        elif kind == "url":
            url = info.get("data")
            if not url:
                continue
            if action == "canOpenURL":
                scheme_queries[url.split(":", 1)[0]] += 1
            elif direction == "incoming":
                urls_in.setdefault(url, {"via": entry.get("method"), "source": info.get("component")})
            else:
                urls_out.setdefault(url, {"via": entry.get("method")})
        elif kind == "darwin_notification":
            if direction == "outgoing":
                darwin_posted[component] += 1
            else:
                darwin_listening[component] += 1
        elif kind == "webview":
            extras = info.get("extras") or {}
            if action == "register JS bridge" or action == "expose native object":
                js_bridges[component] = (extras.get("handler") or extras.get("object") or {}).get("value") or ""
            elif action == "script message":
                bridge_messages[component] += 1
            elif action in ("load request", "load HTML", "load file", "load data"):
                web_loads[info.get("data") or f"({action})"] += 1
            elif action == "navigation":
                web_navigation[info.get("component") or info.get("data") or "?"] += 1
            elif action == "evaluate JavaScript":
                web_scripts[info.get("component") or "(no page)"] += 1
            elif action in ("register URL scheme handler", "URL scheme request"):
                web_schemes.setdefault(component.split(":")[0], (extras.get("handler") or {}).get("value") or "")
            elif action in ("in-app browser", "web authentication"):
                web_browsers[f"{action}: {info.get('data')}"] += 1
        elif kind == "network":
            network_hosts[component] += 1

    return {
        "outgoing_services": {
            name: {
                "messages": item["messages"],
                "kinds": sorted(item["kinds"]),
                "selectors": sorted(item["selectors"]),
                "peer": item["peer"],
            }
            for name, item in sorted(outgoing.items())
        },
        "listeners": {
            name: {"api": item["api"], "peers": dict(item["peers"])}
            for name, item in sorted(listeners.items())
        },
        "incoming_peers": [
            {"service": service, "peer": peer, "messages": count}
            for (service, peer), count in sorted(incoming_peers.items())
        ],
        "nsxpc_interfaces": interfaces,
        "exported_calls": [
            {"service": service, "selector": selector, "calls": count}
            for (service, selector), count in sorted(exported_calls.items())
        ],
        "urls_incoming": [{"url": url, **meta} for url, meta in urls_in.items()],
        "urls_outgoing": [{"url": url, **meta} for url, meta in urls_out.items()],
        "scheme_queries": dict(sorted(scheme_queries.items())),
        "darwin_posted": dict(sorted(darwin_posted.items())),
        "darwin_listening": dict(sorted(darwin_listening.items())),
        "web": {
            "js_bridges": dict(sorted(js_bridges.items())),
            "bridge_messages": dict(sorted(bridge_messages.items())),
            "loads": dict(web_loads.most_common()),
            "navigation_hosts": dict(web_navigation.most_common()),
            "evaluated_js": dict(web_scripts.most_common()),
            "url_schemes": dict(sorted(web_schemes.items())),
            "browsers": dict(web_browsers.most_common()),
        },
        "network_hosts": dict(network_hosts.most_common()),
    }


def build_surface(static: dict | None, entries) -> dict:
    static = dict(static or {})
    entitlements, error = parse_entitlements(static.pop("entitlements", None))
    surface = {"static": static, "entitlements": entitlements, "observed": summarize_observed(entries)}
    if error:
        surface["entitlementsError"] = error
    return surface


# --- Rendering ---------------------------------------------------------------

def _m(value) -> str:
    return escape("" if value is None else str(value))


def _section(out: list[str], title: str) -> None:
    out.append("")
    out.append(f"[bold #F2C94C]{title}[/bold #F2C94C]")


def _empty(out: list[str], text: str = "none") -> None:
    out.append(f"  [dim]{_m(text)}[/dim]")


def render_surface_report(surface: dict) -> str:
    static = surface.get("static") or {}
    observed = surface.get("observed") or {}
    entitlements = surface.get("entitlements") or {}
    bundle = static.get("bundle") or {}
    process = static.get("process") or {}
    out = []

    out.append("[bold #26a368]iOS ATTACK SURFACE[/bold #26a368]")
    if bundle:
        out.append(
            f"  [bold]{_m(bundle.get('name') or bundle.get('identifier'))}[/bold]  "
            f"{_m(bundle.get('identifier'))}  [dim]{_m(bundle.get('version'))} ({_m(bundle.get('build'))})[/dim]"
        )
        if bundle.get("path"):
            out.append(f"  [dim]{_m(bundle.get('path'))}[/dim]")
        executable = bundle.get("executable") or process.get("name")
        if executable:
            # The module name ioxen shows in the Class column for the app's own code.
            out.append(f"  [bold]Executable[/bold]  {_m(executable)}  [dim](use as class={_m(executable)})[/dim]")
    elif process:
        out.append(f"  [bold]{_m(process.get('name'))}[/bold]  [dim]{_m(process.get('path'))}[/dim]")
    if not static:
        out.append("  [dim]No static data yet: connect to an iOS target and run /surface.[/dim]")

    _section(out, "URL SCHEMES")
    url_types = static.get("urlTypes") or []
    if url_types:
        for url_type in url_types:
            schemes = ", ".join(f"{s}://" for s in url_type.get("schemes") or [])
            out.append(f"  [#C94A8A]{_m(schemes)}[/#C94A8A]  [dim]{_m(url_type.get('name') or '')}[/dim]")
    else:
        _empty(out, "no CFBundleURLTypes declared")
    domains = entitlements.get("com.apple.developer.associated-domains") or []
    if domains:
        out.append("  [bold]Associated domains[/bold]")
        for domain in domains:
            out.append(f"    [#C94A8A]{_m(domain)}[/#C94A8A]")
    if static.get("userActivityTypes"):
        out.append(f"  [bold]User activity types[/bold]  {_m(', '.join(static['userActivityTypes']))}")
    received = observed.get("urls_incoming") or []
    if received:
        out.append("  [bold]Received at runtime[/bold]")
        for item in received:
            source = f"  [dim]from {_m(item['source'])}[/dim]" if item.get("source") else ""
            out.append(f"    {_m(item['url'])}  [dim]{_m(item.get('via'))}[/dim]{source}")

    _section(out, "DOCUMENTS & SHARING")
    doc_types = static.get("documentTypes") or []
    for doc in doc_types:
        out.append(f"  {_m(doc.get('name') or '?')}  [dim]{_m(', '.join(doc.get('types') or []))}[/dim]")
    flags = [
        label for key, label in (
            ("fileSharing", "UIFileSharingEnabled"),
            ("openInPlace", "LSSupportsOpeningDocumentsInPlace"),
            ("supportsDocumentBrowser", "UISupportsDocumentBrowser"),
        ) if static.get(key)
    ]
    if flags:
        out.append(f"  [#F2C94C]{_m(', '.join(flags))}[/#F2C94C]")
    groups = entitlements.get("com.apple.security.application-groups") or []
    if groups:
        out.append(f"  [bold]App groups[/bold]  {_m(', '.join(groups))}")
    if not (doc_types or flags or groups):
        _empty(out)

    _section(out, "APP EXTENSIONS")
    extensions = static.get("extensions") or []
    if extensions:
        for ext in extensions:
            out.append(
                f"  {_m(ext.get('bundleId') or ext.get('name'))}  "
                f"[#C94A8A]{_m(ext.get('point'))}[/#C94A8A]  [dim]{_m(ext.get('principalClass') or '')}[/dim]"
            )
    else:
        _empty(out)

    _section(out, "XPC LISTENERS (exposed)")
    listeners = observed.get("listeners") or {}
    if listeners:
        for name, item in listeners.items():
            peers = ", ".join(f"{peer} ×{count}" for peer, count in item["peers"].items())
            out.append(f"  [#C94A8A]{_m(name)}[/#C94A8A]  [dim]{_m(item['api'])}[/dim]  {_m(peers)}")
    else:
        _empty(out, "none observed")
    for item in observed.get("incoming_peers") or []:
        out.append(f"  {_m(item['service'])} ← {_m(item['peer'])}  [dim]{item['messages']} message(s)[/dim]")

    _section(out, "NSXPC INTERFACES")
    interfaces = observed.get("nsxpc_interfaces") or {}
    if interfaces:
        for name, item in interfaces.items():
            out.append(f"  [bold]{_m(name)}[/bold]")
            for side, color in (("exported", "#C94A8A"), ("remote", "#26a368")):
                proto = item.get(side)
                if not proto:
                    continue
                out.append(f"    [{color}]{side}[/{color}] {_m(proto.get('name'))}")
                for method in proto.get("methods") or []:
                    out.append(f"      [dim]-[/dim] {_m(method)}")
    else:
        _empty(out, "none observed")
    for call in observed.get("exported_calls") or []:
        out.append(f"  call {_m(call['service'])} {_m(call['selector'])}  [dim]×{call['calls']}[/dim]")

    _section(out, "XPC SERVICES CONTACTED")
    services = observed.get("outgoing_services") or {}
    if services:
        for name, item in services.items():
            kinds = f" [dim]({_m(', '.join(item['kinds']))})[/dim]" if item["kinds"] else ""
            out.append(f"  {_m(name)}{kinds}  [dim]{item['messages']} message(s)[/dim]")
            for selector in item["selectors"][:12]:
                out.append(f"    [dim]-[/dim] {_m(selector)}")
    else:
        _empty(out, "none observed")
    mach_exceptions = (
        list(entitlements.get("com.apple.security.exception.mach-lookup.global-name") or []) +
        list(entitlements.get("com.apple.security.temporary-exception.mach-lookup.global-name") or [])
    )
    if mach_exceptions:
        out.append("  [bold]Sandbox mach-lookup exceptions[/bold]")
        for name in mach_exceptions:
            out.append(f"    [#F2C94C]{_m(name)}[/#F2C94C]")

    _section(out, "WEB VIEWS")
    web = observed.get("web") or {}
    for name, handler in (web.get("js_bridges") or {}).items():
        count = (web.get("bridge_messages") or {}).get(name, 0)
        out.append(f"  [#C94A8A]JS bridge[/#C94A8A] {_m(name)}  [dim]{_m(handler)}  {count} message(s)[/dim]")
    for name, count in (web.get("bridge_messages") or {}).items():
        if name not in (web.get("js_bridges") or {}):
            out.append(f"  [#C94A8A]JS bridge[/#C94A8A] {_m(name)}  [dim]{count} message(s), registered before capture[/dim]")
    for scheme, handler in (web.get("url_schemes") or {}).items():
        out.append(f"  [#C94A8A]scheme handler[/#C94A8A] {_m(scheme)}://  [dim]{_m(handler)}[/dim]")
    for url, count in list((web.get("loads") or {}).items())[:20]:
        out.append(f"  loads {_m(url)}  [dim]×{count}[/dim]")
    for host, count in list((web.get("navigation_hosts") or {}).items())[:20]:
        out.append(f"  navigates to {_m(host)}  [dim]×{count}[/dim]")
    for page, count in (web.get("evaluated_js") or {}).items():
        out.append(f"  evaluates JavaScript in {_m(page)}  [dim]×{count}[/dim]")
    for item, count in (web.get("browsers") or {}).items():
        out.append(f"  {_m(item)}  [dim]×{count}[/dim]")
    if not any(web.get(key) for key in web):
        _empty(out, "none observed")

    _section(out, "NETWORK REQUESTS")
    hosts = observed.get("network_hosts") or {}
    for host, count in hosts.items():
        out.append(f"  {_m(host)}  [dim]×{count}[/dim]")
    if not hosts:
        _empty(out, "none observed (enable the network hook)")

    _section(out, "DARWIN NOTIFICATIONS")
    listening = observed.get("darwin_listening") or {}
    posted = observed.get("darwin_posted") or {}
    for name in listening:
        out.append(f"  [#C94A8A]listens[/#C94A8A] {_m(name)}")
    for name, count in posted.items():
        out.append(f"  [dim]posts[/dim]   {_m(name)}  [dim]×{count}[/dim]")
    if not listening and not posted:
        _empty(out, "none observed")

    _section(out, "OUTGOING URLS")
    queried = static.get("queriedSchemes") or []
    if queried:
        out.append(f"  [bold]LSApplicationQueriesSchemes[/bold]  {_m(', '.join(queried))}")
    for scheme, count in (observed.get("scheme_queries") or {}).items():
        out.append(f"  canOpenURL {_m(scheme)}://  [dim]×{count}[/dim]")
    for item in observed.get("urls_outgoing") or []:
        out.append(f"  {_m(item['url'])}  [dim]{_m(item.get('via'))}[/dim]")
    if not queried and not observed.get("scheme_queries") and not observed.get("urls_outgoing"):
        _empty(out, "none observed")

    _section(out, "ENTITLEMENTS")
    if surface.get("entitlementsError"):
        out.append(f"  [red]{_m(surface['entitlementsError'])}[/red]")
    if entitlements:
        for key in sorted(entitlements):
            note = NOTABLE_ENTITLEMENTS.get(key)
            if note is None and key.startswith("com.apple.private."):
                note = "private entitlement"
            value = entitlements[key]
            text = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
            if len(text) > 160:
                text = text[:160] + "…"
            note_text = f"  [#F2C94C]{_m(note)}[/#F2C94C]" if note else ""
            out.append(f"  [bold]{_m(key)}[/bold]  {_m(text)}{note_text}")
    elif not surface.get("entitlementsError"):
        _empty(out, "not available")

    out.append("")
    return "\n".join(out)
