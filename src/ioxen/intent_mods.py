import copy


IntentMod = tuple[str, str, str, str]
IntentModParseResult = tuple[IntentMod | None, str | None]


# Values are XPC/Objective-C values. Common short names are accepted as
# aliases (int/long -> int64, float -> double, boolean -> bool).
IOS_VALUE_TYPES = ("string", "int64", "uint64", "bool", "double", "data")
_IOS_TYPE_ALIASES = {"int": "int64", "long": "int64", "boolean": "bool", "float": "double"}
IOS_EXTRA_TYPES = frozenset(IOS_VALUE_TYPES) | frozenset(_IOS_TYPE_ALIASES)

MOD_COMMAND_NAMES = {
    "data": "data",
    "extra_add": "+x",
    "extra_rem": "-x",
}


def normalize_ios_type(extra_type: str) -> str:
    extra_type = (extra_type or "string").lower()
    return _IOS_TYPE_ALIASES.get(extra_type, extra_type)


def ios_editable_type(type_name: str) -> str | None:
    """Simple value type for an iOS extra that can be edited in place."""
    type_name = type_name or ""
    if type_name in ("string", "int64", "uint64", "bool", "double"):
        return type_name
    if "String" in type_name or "URL" in type_name:
        return "string"
    return None


def validate_mod_for_entry(entry: dict | None, mod: IntentMod) -> str | None:
    """Return an error message when a staged modification cannot apply."""
    mod_type, _key, _value, extra_type = mod
    command = MOD_COMMAND_NAMES.get(mod_type, mod_type)
    supported = (entry or {}).get("supportedMods")
    if supported is not None and mod_type not in supported:
        allowed = ", ".join(MOD_COMMAND_NAMES.get(m, m) for m in supported) or "none (forward or drop only)"
        return f"[red]'{command}' is not supported for this event. Supported: {allowed}[/red]"
    if mod_type == "extra_add" and (extra_type or "string").lower() not in IOS_EXTRA_TYPES:
        return f"[red]Unsupported value type '{extra_type}'[/red]"
    return None


def value_type_display(type_name: str) -> str:
    """Return a display name for a value type."""
    return type_name or "-"


def parse_intent_mod_command(parts: list[str]) -> IntentModParseResult:
    if not parts:
        return None, None

    command = parts[0].lower()
    if command == "data":
        if len(parts) < 2:
            return None, "[red]Usage: data <url>[/red]"
        return ("data", "", parts[1], ""), None
    if command == "+x":
        return _extra_add_mod(parts)
    if command == "-x":
        if len(parts) < 2:
            return None, "[red]Usage: -x <key>[/red]"
        return ("extra_rem", parts[1], "", ""), None
    return None, None


def apply_mods_to_entry(entry: dict, mods: list[IntentMod]) -> None:
    """Apply staged modifications to a stored History entry."""
    if not mods:
        return

    entry["original_intent"] = copy.deepcopy(entry.get("intent") or {})

    info = entry["intent"] = dict(entry.get("intent") or {})
    info["extras"] = dict(info.get("extras") or {})

    for mod_type, key, value, extra_type in mods:
        if mod_type == "data":
            info["data"] = value or None
        elif mod_type == "extra_rem":
            info["extras"].pop(key, None)
        elif mod_type == "extra_add":
            # The agent writes the staged type, so record that one.
            info["extras"][key] = {"type": normalize_ios_type(extra_type), "value": value}


def _extra_add_mod(parts: list[str]) -> IntentModParseResult:
    if len(parts) < 3:
        return None, "[red]Usage: +x (type) <key> <value>[/red]"

    possible_type = parts[1].lower()
    if possible_type in IOS_EXTRA_TYPES and len(parts) >= 4:
        return ("extra_add", parts[2], " ".join(parts[3:]), possible_type), None
    return ("extra_add", parts[1], " ".join(parts[2:]), "string"), None
