import json
from dataclasses import dataclass
from pathlib import Path

from ioxen.logging_ui import log_debug, log_error, log_warning


PACKAGE_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PACKAGE_ROOT.parents[1]
RUNTIME_ROOT = PACKAGE_ROOT / "runtime"

SOURCE_HOOKS_FILE = SOURCE_ROOT / "config" / "ios_hooks.json"
SOURCE_BUNDLE_SCRIPT_FILE = SOURCE_ROOT / "agent" / "ios_script_bundle.js"

PACKAGED_HOOKS_FILE = RUNTIME_ROOT / "config" / "ios_hooks.json"
PACKAGED_BUNDLE_SCRIPT_FILE = RUNTIME_ROOT / "agent" / "ios_script_bundle.js"

HOOKS_FILE = SOURCE_HOOKS_FILE
BUNDLE_SCRIPT_FILE = SOURCE_BUNDLE_SCRIPT_FILE
HOOKS_LABEL = "config/ios_hooks.json"
BUNDLE_SCRIPT_LABEL = "agent/ios_script_bundle.js"
PASSTHROUGH_AGENT = (
    "rpc.exports = { proxy: function(h){}, forward: function(){ return false; }, "
    "drop: function(){ return false; }, stageMod: function(){ return false; }, "
    "interceptoff: function(){ return null; }, intercepton: function(){}, "
    "setFilters: function(){ return true; }, getProcessInfo: function(){ return {}; }, "
    "getAttackSurface: function(){ return {}; } };"
)


@dataclass(frozen=True)
class HooksLoadResult:
    hooks: list
    messages: list[str]


@dataclass(frozen=True)
class ScriptLoadResult:
    code: str
    messages: list[str]


def load_json_hooks(filepath: str | Path) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def _resolve_runtime_path(configured_path: str | Path, source_default: Path, packaged_default: Path) -> Path:
    path = Path(configured_path)
    if path.exists() or path != source_default:
        return path
    return packaged_default


def load_hook_config(custom_hooks: str | None = None) -> HooksLoadResult:
    hooks = []
    messages = []

    default_path = _resolve_runtime_path(HOOKS_FILE, SOURCE_HOOKS_FILE, PACKAGED_HOOKS_FILE)
    try:
        hooks = load_json_hooks(default_path)
    except FileNotFoundError:
        messages.append(log_error(f"Hooks file not found: {HOOKS_LABEL}", "loader"))
    except json.JSONDecodeError as e:
        messages.append(log_error(f"Invalid JSON in {HOOKS_LABEL}: {e}", "loader"))

    if custom_hooks:
        try:
            hooks.extend(load_json_hooks(custom_hooks))
        except FileNotFoundError:
            messages.append(log_error(f"Custom hooks file not found: {custom_hooks}", "loader"))
        except json.JSONDecodeError as e:
            messages.append(log_error(f"Invalid JSON in {custom_hooks}: {e}", "loader"))

    return HooksLoadResult(hooks, messages)


def load_agent_script(extra_script: str | None = None) -> ScriptLoadResult:
    return _append_extra_script(_load_bundle_script(), extra_script)


def _load_bundle_script() -> ScriptLoadResult:
    # The agent imports helper modules and frida-objc-bridge, so only the
    # frida-compile bundle is runnable; there is no raw-source fallback.
    bundle_file = _resolve_runtime_path(
        BUNDLE_SCRIPT_FILE,
        SOURCE_BUNDLE_SCRIPT_FILE,
        PACKAGED_BUNDLE_SCRIPT_FILE,
    )
    try:
        with open(bundle_file, "r", encoding="utf-8") as f:
            return ScriptLoadResult(f.read(), [])
    except FileNotFoundError:
        return ScriptLoadResult(
            PASSTHROUGH_AGENT,
            [log_warning(f"{BUNDLE_SCRIPT_LABEL} not found; running in passthrough mode (run npm run build)", "loader")],
        )


def _append_extra_script(result: ScriptLoadResult, extra_script: str | None) -> ScriptLoadResult:
    if not extra_script:
        return result
    code = result.code
    messages = list(result.messages)
    try:
        with open(extra_script, "r", encoding="utf-8") as f:
            code += "\n\n" + f.read()
        messages.append(log_debug(f"Extra script loaded: {extra_script}", "loader"))
    except FileNotFoundError:
        messages.append(log_warning(f"Extra script not found: {extra_script}", "loader"))
    return ScriptLoadResult(code, messages)
