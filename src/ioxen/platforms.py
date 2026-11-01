"""Target platform detection.

ioxen ships a single Frida agent that hooks libxpc/NSXPC, URL schemes and
Darwin notifications, so it only works on Apple targets. Detection is used
to label the session and to warn when the target is not an Apple process.
"""

from dataclasses import dataclass

IOS = "ios"
IOS_LABEL = "iOS"

# Frida reports Apple platforms through query_system_parameters()["os"]["id"].
# All of them use libxpc, so they share the iOS agent; UIKit-specific hooks
# simply find nothing on the others.
APPLE_OS_IDS = frozenset({"ios", "ipados", "tvos", "watchos", "visionos", "xros", "macos"})


@dataclass(frozen=True)
class PlatformInfo:
    platform: str | None
    label: str
    os_id: str = ""


def platform_from_system_parameters(params) -> PlatformInfo:
    if not isinstance(params, dict):
        return PlatformInfo(None, "")
    os_info = params.get("os") if isinstance(params.get("os"), dict) else {}
    os_id = str(os_info.get("id") or "").lower()
    name = str(os_info.get("name") or "").strip()
    version = str(os_info.get("version") or "").strip()
    label = " ".join(part for part in (name, version) if part)

    if os_id in APPLE_OS_IDS or str(params.get("platform") or "").lower() == "darwin":
        platform = IOS
    else:
        platform = None
    if not label and platform:
        label = IOS_LABEL
    return PlatformInfo(platform, label, os_id)


def detect_device_platform(device) -> PlatformInfo:
    query = getattr(device, "query_system_parameters", None)
    if query is None:
        return PlatformInfo(None, "")
    try:
        return platform_from_system_parameters(query())
    except Exception:
        return PlatformInfo(None, "")


# Injected right after attaching: the target process itself is the most
# reliable answer to "is this an Apple process" (device queries can fail or
# be unavailable on older frida-server builds).
PLATFORM_PROBE_SCRIPT = "rpc.exports = { platform: function () { return Process.platform; } };"


def unsupported_target_reason(device_info: PlatformInfo, process_platform: str | None) -> str | None:
    """Describe why the target is not an Apple process, or None if it is (or is unknown).

    The probed target process wins over the device query.
    """
    value = str(process_platform or "").lower()
    if value:
        return None if value == "darwin" else f"the target process runs on {value}"
    if device_info.platform is None and device_info.os_id:
        return f"the device runs {device_info.label or device_info.os_id}"
    return None
