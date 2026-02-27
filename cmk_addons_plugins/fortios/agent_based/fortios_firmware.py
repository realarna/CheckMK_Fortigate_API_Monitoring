#!/usr/bin/env python3
"""FortiOS firmware monitoring (updates, branch changes, maturity).

This check extends the original FortiOS special agent with firmware information
from the FortiGate REST API endpoint: /api/v2/monitor/system/firmware.

The logic is adapted from the standalone 'fortigate_firmware' extension and
integrated under the FortiOS special agent output section 'fortios_firmware'.
"""

from __future__ import annotations

import itertools
import json
from typing import Any, Dict, Optional

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


def _parse_json_section(string_table):
    if not string_table:
        return None
    try:
        flatlist = list(itertools.chain.from_iterable(string_table))
        json_str = " ".join(flatlist)
        return json.loads(json_str)
    except (json.JSONDecodeError, ValueError, TypeError):
        return {"status": "error", "error": "parse", "message": "JSON parse failed"}


agent_section_fortios_firmware = AgentSection(
    name="fortios_firmware",
    parse_function=_parse_json_section,
)


def discover_fortios_firmware(section):
    if section:
        yield Service()


def check_fortios_firmware(section):
    if not section:
        yield Result(state=State.UNKNOWN, summary="No firmware data received")
        return

    # Structured error payload from special agent
    if section.get("status") == "error" or "error" in section:
        err_type = str(section.get("error", "")).lower()
        msg = section.get("message") or section.get("error") or "Cannot retrieve firmware information"
        detail = section.get("detail")

        unknown_hints = [
            "no route to host",
            "failed to connect",
            "failed to establish",
            "dns",
            "resolution",
            "refused",
            "timed out",
            "timeout",
        ]
        is_unknown = (
            err_type in ("connection", "timeout")
            or any(h in str(msg).lower() for h in unknown_hints)
            or (detail and any(h in str(detail).lower() for h in unknown_hints))
        )
        state = State.UNKNOWN if is_unknown else State.WARN

        yield Result(state=state, summary=f"Cannot check updates: {msg}", details=(detail or None))
        return

    if section.get("status", "success") != "success":
        yield Result(state=State.WARN, summary="Cannot retrieve firmware information")
        return

    # Compatibility: data is expected in section['results'] with 'current' and 'available'
    results_raw = section.get("results")
    results = dict(results_raw) if isinstance(results_raw, dict) else {}

    current_fw = results.get("current") if isinstance(results.get("current"), dict) else {}
    available_raw = results.get("available") if isinstance(results.get("available"), list) else []

    current_version = current_fw.get("version") or "Unknown"
    current_build_value = current_fw.get("build")
    current_build_str = str(current_build_value) if current_build_value not in (None, "") else "Unknown"

    cfg = section.get("config") if isinstance(section.get("config"), dict) else {}
    critical_on_branch_change = bool(cfg.get("critical_on_branch_change", True))
    ok_if_unmatured_branch = bool(cfg.get("ok_if_unmatured_branch", False))

    def _to_int(value: Any) -> int:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return 0

    def _version_tuple(fw: Dict[str, Any]) -> tuple[int, int, int, int]:
        return (
            _to_int(fw.get("major")),
            _to_int(fw.get("minor")),
            _to_int(fw.get("patch")),
            _to_int(fw.get("build")),
        )

    def _platform_id(data: Dict[str, Any]) -> Optional[str]:
        for key in ("platform-id", "platform_id", "platformId"):
            value = data.get(key)
            if value:
                return str(value)
        return None

    def _is_mature_fw(fw: Dict[str, Any]) -> bool:
        maturity = fw.get("maturity")
        if maturity is None:
            return False
        return str(maturity).strip().upper().startswith("M")

    current_major_int = _to_int(current_fw.get("major"))
    current_minor_int = _to_int(current_fw.get("minor"))
    current_tuple = _version_tuple(current_fw)

    current_platform_id = _platform_id(current_fw)

    available_fw = []
    skipped_incompatible = 0
    for fw in available_raw:
        if not isinstance(fw, dict):
            continue
        if fw.get("can_upgrade") is False:
            skipped_incompatible += 1
            continue
        if current_platform_id:
            fw_platform = _platform_id(fw)
            if fw_platform and fw_platform != current_platform_id:
                skipped_incompatible += 1
                continue
        available_fw.append(fw)

    if not available_fw:
        details = f"Current: {current_version} build {current_build_str}"
        if skipped_incompatible:
            details += f" (skipped {skipped_incompatible} incompatible images)"
        yield Result(state=State.OK, summary=f"System is up to date: {current_version}", details=details)
        yield Metric("updates_available", 0)
        return

    available_fw.sort(key=_version_tuple)

    newer_updates = []
    recommended_fw = None
    highest_fw = None
    mature_updates = 0
    has_same_branch_updates = False
    next_branch_updates = []

    for fw in available_fw:
        fw_tuple = _version_tuple(fw)
        if fw_tuple <= current_tuple:
            continue

        newer_updates.append(fw)

        if _is_mature_fw(fw):
            mature_updates += 1

        fw_major = _to_int(fw.get("major"))
        fw_minor = _to_int(fw.get("minor"))

        if fw_major == current_major_int and fw_minor == current_minor_int:
            has_same_branch_updates = True
            if recommended_fw is None or fw_tuple < _version_tuple(recommended_fw):
                recommended_fw = fw
        else:
            next_branch_updates.append(fw)

        if highest_fw is None or fw_tuple > _version_tuple(highest_fw):
            highest_fw = fw

    if not newer_updates:
        yield Result(
            state=State.OK,
            summary=f"System is up to date: {current_version}",
            details=f"Current: {current_version} build {current_build_str}",
        )
        yield Metric("updates_available", 0)
        return

    updates_count = len(newer_updates)

    # Determine state
    if has_same_branch_updates:
        state = State.WARN
        state_reason = "Updates available"
    else:
        # only branch updates
        if ok_if_unmatured_branch and mature_updates == 0:
            state = State.OK
            state_reason = "Only immature branch updates available"
        else:
            state = State.CRIT if critical_on_branch_change else State.WARN
            state_reason = "Updates available (branch change)"

    # Summary + details
    summary = f"{state_reason}: {updates_count} update(s) available"

    # pick a recommended target
    target = recommended_fw or highest_fw or newer_updates[-1]
    target_version = target.get("version") or "Unknown"
    target_build = target.get("build")
    target_build_str = str(target_build) if target_build not in (None, "") else "Unknown"

    details_lines = [
        f"Current: {current_version} build {current_build_str}",
        f"Recommended: {target_version} build {target_build_str}",
    ]

    if not has_same_branch_updates and next_branch_updates:
        # show first branch candidate
        first = min(next_branch_updates, key=_version_tuple)
        details_lines.append(
            "Branch candidate: "
            f"{first.get('version','Unknown')} build {str(first.get('build','Unknown'))}"
        )

    if skipped_incompatible:
        details_lines.append(f"Skipped {skipped_incompatible} incompatible image(s)")

    yield Result(state=state, summary=summary, details="\n".join(details_lines))

    yield Metric("updates_available", updates_count)
    yield Metric("mature_updates", mature_updates)


check_plugin_fortios_firmware = CheckPlugin(
    name="fortios_firmware",
    service_name="FortiOS Firmware",
    sections=["fortios_firmware"],
    discovery_function=discover_fortios_firmware,
    check_function=check_fortios_firmware,
)
