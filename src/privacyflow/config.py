from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

OPTIONAL_SCALAR_LABELS = {
    "dns": "DNS",
    "mtu": "MTU",
    "table": "Table",
    "saveconfig": "SaveConfig",
    "listenport": "ListenPort",
    "fwmark": "FwMark",
    "persistentkeepalive": "PersistentKeepalive",
}


@dataclass(frozen=True)
class PrivacyflowConfig:
    interval_seconds: int
    require_kill_switch: bool
    profiles: tuple[Path, ...]


class ConfigError(ValueError):
    """Raised when a Privacyflow or WireGuard configuration is invalid."""


def _validate_key(value: str, label: str, filename: str) -> None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError(f"{filename} contains an invalid {label} (expected base64 WireGuard key)") from exc
    if len(decoded) != 32:
        raise ConfigError(f"{filename} contains an invalid {label} (expected a 32-byte WireGuard key)")


def _validate_addresses(value: str, label: str, filename: str, *, network: bool) -> None:
    entries = [item.strip() for item in value.split(",")]
    if not entries or any(not item for item in entries):
        raise ConfigError(f"{filename} contains an empty entry in {label}")
    for item in entries:
        try:
            ipaddress.ip_network(item, strict=False) if network else ipaddress.ip_interface(item)
        except ValueError as exc:
            raise ConfigError(f"{filename} contains an invalid {label} entry: {item}") from exc


def _validate_endpoint(value: str, filename: str) -> None:
    if not value or any(ch.isspace() for ch in value):
        raise ConfigError(f"{filename} contains an invalid Peer.Endpoint")
    try:
        parsed = urlsplit(f"//{value}")
        hostname = parsed.hostname
    except ValueError as exc:
        raise ConfigError(f"{filename} contains an invalid Peer.Endpoint") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"{filename} Peer.Endpoint must be a hostname or IP followed by a port") from exc
    if not hostname or port is None or not 1 <= port <= 65535:
        raise ConfigError(f"{filename} Peer.Endpoint must be a hostname or IP followed by a port")
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ConfigError(f"{filename} contains an invalid Peer.Endpoint")
    if ":" in hostname:
        try:
            ipaddress.IPv6Address(hostname)
        except ValueError as exc:
            raise ConfigError(f"{filename} contains an invalid IPv6 Peer.Endpoint") from exc
    else:
        try:
            ipaddress.IPv4Address(hostname)
        except ValueError:
            labels = hostname.rstrip(".").split(".")
            label_pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
            numeric_dotted = all(label.isdecimal() for label in labels)
            if numeric_dotted or not labels or any(not label_pattern.fullmatch(label) for label in labels):
                raise ConfigError(f"{filename} contains an invalid Peer.Endpoint hostname")


def load_config(path: str | Path) -> PrivacyflowConfig:
    config_path = Path(path).resolve()
    try:
        import tomllib
        if config_path.stat().st_size > 1024 * 1024:
            raise ConfigError("TOML config exceeds the 1 MiB safety limit")
        raw = tomllib.loads(config_path.read_text(encoding="utf-8-sig"))
    except ConfigError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise ConfigError(f"Cannot read TOML config: {exc.__class__.__name__}") from exc

    rotation = raw.get("rotation", {})
    if not isinstance(rotation, dict):
        raise ConfigError("rotation must be a TOML table")
    interval = rotation.get("interval_seconds", 1800)
    kill_switch = rotation.get("require_kill_switch", True)
    profiles_raw = raw.get("profiles", [])

    if isinstance(interval, bool) or not isinstance(interval, int) or not 60 <= interval <= 86400:
        raise ConfigError("rotation.interval_seconds must be an integer from 60 to 86400")
    if not isinstance(kill_switch, bool):
        raise ConfigError("rotation.require_kill_switch must be true or false")
    if not kill_switch:
        raise ConfigError("This starter requires the kill switch policy to remain enabled")
    if not isinstance(profiles_raw, list) or not profiles_raw:
        raise ConfigError("profiles must contain at least one WireGuard config path")
    if any(not isinstance(item, str) or not item.strip() for item in profiles_raw):
        raise ConfigError("Every profiles entry must be a non-empty string path")

    profile_paths = tuple((config_path.parent / item).resolve() for item in profiles_raw)
    if len(set(profile_paths)) != len(profile_paths):
        raise ConfigError("profiles must not contain duplicate paths")
    for profile in profile_paths:
        if not profile.is_file():
            raise ConfigError(f"WireGuard profile file not found: {profile}")
        validate_wireguard_profile(profile)
    return PrivacyflowConfig(interval, kill_switch, profile_paths)


def validate_wireguard_profile(path: str | Path) -> None:
    profile_path = Path(path)
    try:
        if profile_path.stat().st_size > 1024 * 1024:
            raise ConfigError(f"{profile_path.name} exceeds the 1 MiB safety limit")
        content = profile_path.read_text(encoding="utf-8-sig")
    except ConfigError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"Invalid WireGuard profile file: {profile_path.name}") from exc

    sections: list[tuple[str, dict[str, str]]] = []
    current_name: str | None = None
    current_values: dict[str, str] | None = None
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if name not in {"Interface", "Peer"}:
                raise ConfigError(f"{profile_path.name} contains unsupported section [{name}] on line {line_number}")
            if name == "Interface" and any(section_name == "Interface" for section_name, _ in sections):
                raise ConfigError(f"{profile_path.name} contains more than one [Interface] section")
            current_name = name
            current_values = {}
            sections.append((name, current_values))
            continue
        if current_values is None or "=" not in line:
            raise ConfigError(f"{profile_path.name} has invalid syntax on line {line_number}")
        key, value = (part.strip() for part in line.split("=", 1))
        normalized_key = key.lower()
        if not normalized_key or normalized_key in current_values:
            raise ConfigError(f"{profile_path.name} has an empty or duplicate key on line {line_number}")
        supported = (
            {"privatekey", "address", "dns", "mtu", "table", "saveconfig", "listenport", "fwmark"}
            if current_name == "Interface"
            else {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}
        )
        command_hooks = {"preup", "postup", "predown", "postdown"}
        if normalized_key in command_hooks:
            raise ConfigError(f"{profile_path.name} uses {key}, an executable wg-quick hook not supported by Privacyflow")
        if normalized_key not in supported:
            raise ConfigError(f"{profile_path.name} contains unsupported {current_name}.{key} on line {line_number}")
        if normalized_key in OPTIONAL_SCALAR_LABELS and not value:
            raise ConfigError(f"{profile_path.name} contains an empty {current_name}.{OPTIONAL_SCALAR_LABELS[normalized_key]}")
        current_values[normalized_key] = value

    interfaces = [values for name, values in sections if name == "Interface"]
    peers = [values for name, values in sections if name == "Peer"]
    if len(interfaces) != 1 or not peers:
        raise ConfigError(f"{profile_path.name} must include one [Interface] section and at least one [Peer] section")
    interface = interfaces[0]

    for key in ("privatekey", "address"):
        if not interface.get(key, "").strip():
            raise ConfigError(f"{profile_path.name} is missing Interface.{key.title()}")
    _validate_key(interface["privatekey"].strip(), "Interface.PrivateKey", profile_path.name)
    _validate_addresses(interface["address"].strip(), "Interface.Address", profile_path.name, network=False)

    mtu = interface.get("mtu", "").strip()
    if mtu and (not mtu.isdecimal() or not 576 <= int(mtu) <= 65535):
        raise ConfigError(f"{profile_path.name} contains an invalid Interface.MTU (expected 576..65535)")

    table = interface.get("table", "").strip().lower()
    if table and table not in {"auto", "off"} and (not table.isdecimal() or int(table) < 1):
        raise ConfigError(f"{profile_path.name} contains an invalid Interface.Table")

    save_config = interface.get("saveconfig", "").strip().lower()
    if save_config and save_config not in {"true", "false"}:
        raise ConfigError(f"{profile_path.name} Interface.SaveConfig must be true or false")

    listen_port = interface.get("listenport", "").strip()
    if listen_port and (not listen_port.isdecimal() or not 1 <= int(listen_port) <= 65535):
        raise ConfigError(f"{profile_path.name} contains an invalid Interface.ListenPort")

    fwmark = interface.get("fwmark", "").strip().lower()
    if fwmark:
        try:
            mark_value = int(fwmark, 16 if fwmark.startswith("0x") else 10)
        except ValueError as exc:
            raise ConfigError(f"{profile_path.name} contains an invalid Interface.FwMark") from exc
        if not 0 <= mark_value <= 0xFFFFFFFF:
            raise ConfigError(f"{profile_path.name} contains an invalid Interface.FwMark")

    dns = interface.get("dns", "").strip()
    if dns:
        domain_pattern = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
        for item in dns.split(","):
            candidate = item.strip()
            if not candidate:
                raise ConfigError(f"{profile_path.name} contains an empty Interface.DNS entry")
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                numeric_dotted = all(part.isdecimal() for part in candidate.split("."))
                if numeric_dotted or not domain_pattern.fullmatch(candidate):
                    raise ConfigError(f"{profile_path.name} contains an invalid Interface.DNS entry: {candidate}")

    for peer_number, peer in enumerate(peers, start=1):
        for key in ("publickey", "endpoint", "allowedips"):
            if not peer.get(key, "").strip():
                raise ConfigError(f"{profile_path.name} Peer #{peer_number} is missing {key.title()}")
        _validate_key(peer["publickey"].strip(), "Peer.PublicKey", profile_path.name)
        if "presharedkey" in peer:
            if not peer["presharedkey"].strip():
                raise ConfigError(f"{profile_path.name} Peer #{peer_number} has an empty PresharedKey")
            _validate_key(peer["presharedkey"].strip(), "Peer.PresharedKey", profile_path.name)
        _validate_endpoint(peer["endpoint"].strip(), profile_path.name)
        _validate_addresses(peer["allowedips"].strip(), "Peer.AllowedIPs", profile_path.name, network=True)
        keepalive = peer.get("persistentkeepalive", "").strip()
        if keepalive:
            if not keepalive.isdecimal() or not 0 <= int(keepalive) <= 65535:
                raise ConfigError(f"{profile_path.name} Peer #{peer_number} has invalid PersistentKeepalive")


def rotation_plan(config: PrivacyflowConfig) -> list[dict[str, str | int]]:
    return [
        {
            "step": index + 1,
            "profile": profile.stem,
            "interval_seconds": config.interval_seconds,
            "action": "would-switch-after-health-check",
        }
        for index, profile in enumerate(config.profiles)
    ]
