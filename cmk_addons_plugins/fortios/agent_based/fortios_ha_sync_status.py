#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# This is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  check_mk is  distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# tails. You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston, MA 02110-1301 USA.

# WAGNER AG
# Developer: opensource@wagner.ch

"""
Check_MK agent based checks to be used with agent_fortios Datasource

Checks FortiGate HA configuration synchronization by evaluating the
/api/v2/monitor/system/ha-checksums REST API payload.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, CheckResult, DiscoveryResult, Result, Service, State


_STATUS_KEYS = (
    "sync",
    "sync_status",
    "sync-status",
    "synchronized",
    "synchronised",
    "checksum_status",
    "checksum-status",
    "conf_status",
    "configuration_status",
    "configuration-sync",
    "configuration_sync",
    "ha_sync_status",
    "ha-sync-status",
)

_OK_STATUS_VALUES = {
    "1",
    "true",
    "yes",
    "ok",
    "up",
    "sync",
    "synced",
    "in-sync",
    "in sync",
    "synchronized",
    "synchronised",
    "success",
    "successful",
    "matched",
    "matching",
    "identical",
}

_CRIT_STATUS_VALUES = {
    "0",
    "false",
    "no",
    "down",
    "error",
    "failed",
    "failure",
    "mismatch",
    "mismatched",
    "different",
    "out-of-sync",
    "out of sync",
    "not synchronized",
    "not synchronised",
    "unsynchronized",
    "unsynchronised",
}


@dataclass(frozen=True)
class HASyncMember:
    serial: str
    hostname: str
    role: str
    status_fields: Mapping[str, Any]
    checksums: Mapping[str, Any]
    raw: Mapping[str, Any]

    @property
    def label(self) -> str:
        serial = self.serial or "unknown serial"
        if self.hostname:
            return f"{self.hostname} ({serial})"
        return serial


@dataclass(frozen=True)
class HASyncSection:
    members: list[HASyncMember]
    raw: Mapping[str, Any]

    @property
    def is_cluster(self) -> bool:
        return len(self.members) > 1


def _normalise_key(key: str) -> str:
    return key.lower().replace("_", "-")


def _looks_like_member(value: Mapping[str, Any]) -> bool:
    if any(key in value for key in ("serial", "serial_no", "serial-number", "serial_number", "checksum", "checksums")):
        return True
    return any("checksum" in key.lower() for key in value)


def _extract_member_list(results: Any) -> list[Mapping[str, Any]]:
    if isinstance(results, list):
        return [item for item in results if isinstance(item, dict)]

    if isinstance(results, dict):
        # Some FortiOS versions wrap the members below a dedicated key.
        for key in ("members", "peers", "cluster", "nodes", "checksums"):
            value = results.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                keyed_members = []
                for member_key, member_value in value.items():
                    if isinstance(member_value, dict) and _looks_like_member(member_value):
                        member = dict(member_value)
                        member.setdefault("serial", member_key)
                        keyed_members.append(member)
                if keyed_members:
                    return keyed_members

        keyed_members = []
        for member_key, member_value in results.items():
            if isinstance(member_value, dict) and _looks_like_member(member_value):
                member = dict(member_value)
                member.setdefault("serial", member_key)
                keyed_members.append(member)
        if keyed_members:
            return keyed_members

        # A single dict with serial/checksum fields can still represent a single member.
        if _looks_like_member(results):
            return [results]

    return []


def _extract_status_fields(member: Mapping[str, Any]) -> dict[str, Any]:
    status_fields: dict[str, Any] = {}
    for key, value in member.items():
        key_l = key.lower()
        key_norm = _normalise_key(key)
        if key_l in _STATUS_KEYS or key_norm in _STATUS_KEYS or "sync" in key_l and not isinstance(value, (dict, list)):
            status_fields[key] = value
    return status_fields


def _extract_checksums(member: Mapping[str, Any]) -> dict[str, Any]:
    for key in ("checksum", "checksums", "checksum_all", "ha_checksum"):
        value = member.get(key)
        if isinstance(value, dict):
            return dict(value)

    # Fallback for payloads that expose checksum values directly at member level.
    checksums = {}
    for key, value in member.items():
        key_l = key.lower()
        if "checksum" in key_l and not isinstance(value, list):
            checksums[key] = value
    return checksums


def _flatten_checksums(value: Any, prefix: str = "") -> dict[str, str]:
    if isinstance(value, dict):
        flattened: dict[str, str] = {}
        for key in sorted(value):
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(_flatten_checksums(value[key], next_prefix))
        return flattened

    if isinstance(value, list):
        flattened = {}
        for idx, item in enumerate(value):
            next_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            flattened.update(_flatten_checksums(item, next_prefix))
        return flattened

    if value is None:
        return {}

    return {prefix or "checksum": str(value)}


def _serial_from_member(member: Mapping[str, Any]) -> str:
    for key in ("serial", "serial_no", "serial-number", "serial_number", "sn"):
        value = member.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _hostname_from_member(member: Mapping[str, Any]) -> str:
    for key in ("hostname", "host", "name"):
        value = member.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _role_from_member(member: Mapping[str, Any]) -> str:
    for key in ("role", "state", "ha_role"):
        value = member.get(key)
        if value not in (None, ""):
            return str(value)

    for key in ("is_manage_master", "is_root_master", "root_master", "master", "primary"):
        value = member.get(key)
        if value is True or value == 1 or str(value).lower() in {"1", "true", "yes", "master", "primary"}:
            return "master"

    return "secondary"


def parse_fortios_ha_sync_status(string_table) -> HASyncSection | None:
    try:
        json_data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return None

    results = json_data.get("results") if isinstance(json_data, dict) else None
    if results in ({}, [], None):
        return None

    members: list[HASyncMember] = []
    for member in _extract_member_list(results):
        checksums = _extract_checksums(member)
        members.append(
            HASyncMember(
                serial=_serial_from_member(member),
                hostname=_hostname_from_member(member),
                role=_role_from_member(member),
                status_fields=_extract_status_fields(member),
                checksums=checksums,
                raw=member,
            )
        )

    if not members:
        return None

    return HASyncSection(members=members, raw=json_data)


agent_section_fortios_ha_sync_status = AgentSection(
    name="fortios_ha_sync_status",
    parse_function=parse_fortios_ha_sync_status,
)


def discovery_fortios_ha_sync_status(section: HASyncSection) -> DiscoveryResult:
    # Only discover a service when an HA cluster is actually visible.
    # Standalone FortiGates may still answer the endpoint on some FortiOS releases.
    if section and section.is_cluster:
        yield Service(item="status")


def _state_from_status_value(value: Any) -> State | None:
    if isinstance(value, bool):
        return State.OK if value else State.CRIT

    if value is None:
        return None

    text = str(value).strip().lower()
    if text in _OK_STATUS_VALUES:
        return State.OK
    if text in _CRIT_STATUS_VALUES:
        return State.CRIT
    return None


def _state_from_status_field(field: str, value: Any) -> State | None:
    field_text = field.lower().replace("-", "_")
    negative_sync_field = "out" in field_text and "sync" in field_text or field_text.startswith("not_")

    if negative_sync_field:
        if isinstance(value, bool):
            return State.CRIT if value else State.OK
        text = str(value).strip().lower()
        if text in {"1", "true", "yes"}:
            return State.CRIT
        if text in {"0", "false", "no"}:
            return State.OK

    return _state_from_status_value(value)


def _evaluate_explicit_status_fields(section: HASyncSection) -> tuple[State | None, list[str]]:
    messages: list[str] = []
    worst_state: State | None = None

    for member in section.members:
        for field, value in member.status_fields.items():
            state = _state_from_status_field(field, value)
            if state is None:
                continue
            messages.append(f"{member.label}: {field}={value}")
            if worst_state is None or state.value > worst_state.value:
                worst_state = state

    return worst_state, messages


def _evaluate_checksums(section: HASyncSection) -> tuple[State | None, list[str], list[str]]:
    flattened_by_member = {member.label: _flatten_checksums(member.checksums) for member in section.members}
    flattened_by_member = {member: values for member, values in flattened_by_member.items() if values}

    if len(flattened_by_member) < 2:
        return None, [], []

    checksum_keys = sorted(set().union(*(values.keys() for values in flattened_by_member.values())))
    mismatches: list[str] = []
    matches: list[str] = []

    for checksum_key in checksum_keys:
        values = {member: checksums.get(checksum_key, "<missing>") for member, checksums in flattened_by_member.items()}
        unique_values = set(values.values())
        if len(unique_values) == 1:
            matches.append(checksum_key)
            continue

        short_values = ", ".join(f"{member}={value}" for member, value in values.items())
        mismatches.append(f"{checksum_key}: {short_values}")

    if mismatches:
        return State.CRIT, mismatches, matches

    if matches:
        return State.OK, mismatches, matches

    return None, [], []


def check_fortios_ha_sync_status(item: str, section: HASyncSection) -> CheckResult:
    if not section or not section.members:
        yield Result(state=State.UNKNOWN, summary="No HA sync data available")
        return

    if not section.is_cluster:
        yield Result(state=State.OK, summary="No HA cluster detected")
        return

    status_state, status_messages = _evaluate_explicit_status_fields(section)
    checksum_state, checksum_mismatches, checksum_matches = _evaluate_checksums(section)

    member_summary = ", ".join(f"{member.label} [{member.role}]" for member in section.members)
    details_lines = [f"Cluster members: {member_summary}"]

    if status_messages:
        details_lines.append("Explicit sync/status fields:")
        details_lines.extend(f"- {message}" for message in status_messages)

    if checksum_matches:
        details_lines.append("Matching checksum fields:")
        details_lines.extend(f"- {checksum_key}" for checksum_key in checksum_matches)

    if checksum_mismatches:
        details_lines.append("Mismatching checksum fields:")
        details_lines.extend(f"- {message}" for message in checksum_mismatches)

    # Prefer a critical explicit sync state. Otherwise use checksum comparison.
    if status_state == State.CRIT:
        yield Result(
            state=State.CRIT,
            summary=f"HA sync is not OK - {member_summary}",
            details="\n".join(details_lines),
        )
        return

    if checksum_state == State.CRIT:
        yield Result(
            state=State.CRIT,
            summary=f"HA configuration checksums differ - {member_summary}",
            details="\n".join(details_lines),
        )
        return

    if status_state == State.OK or checksum_state == State.OK:
        yield Result(
            state=State.OK,
            summary=f"HA sync OK - {len(section.members)} member(s): {member_summary}",
            details="\n".join(details_lines),
        )
        return

    yield Result(
        state=State.UNKNOWN,
        summary=f"HA cluster detected, but sync status/checksum data could not be interpreted - {member_summary}",
        details="\n".join(details_lines),
    )


check_plugin_fortios_ha_sync_status = CheckPlugin(
    name="fortios_ha_sync_status",
    service_name="HA sync %s",
    discovery_function=discovery_fortios_ha_sync_status,
    check_function=check_fortios_ha_sync_status,
)
