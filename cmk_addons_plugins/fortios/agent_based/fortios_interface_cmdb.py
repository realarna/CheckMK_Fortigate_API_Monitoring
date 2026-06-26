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
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.

# WAGNER AG
# Developer: opensource@wagner.ch

"""
Check_MK agent based checks to be used with agent_fortios Datasource

"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

from cmk.agent_based.v2 import AgentSection, InventoryPlugin, InventoryResult, TableRow


class InterfaceCMDB(BaseModel):
    """FortiOS configured interface data from /api/v2/cmdb/system/interface.

    The FortiOS CMDB response can differ between FortiOS versions and interface
    types. Keep known fields as normal attributes and preserve every additional
    key from the API response for inventory via ``extra='allow'``.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    alias: str = ""
    allowaccess: str = ""
    description: str = ""
    device_identification: str = Field(default="", alias="device-identification")
    interface: str = ""
    ip: str = ""
    ipv6: Mapping[str, Any] | None = None
    macaddr: str = ""
    mode: str = ""
    name: str = ""
    q_origin_key: str = ""
    role: str = ""
    secondary_IP: str = Field(default="", alias="secondary-IP")
    secondaryip: list[Mapping[str, Any]] = Field(default_factory=list)
    status: str = ""
    type: str = ""
    vdom: str = ""
    vlanid: int | str | None = None


def _column_name(key: str) -> str:
    """Convert FortiOS keys to safe inventory column names."""
    return (
        key.strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
        .replace(".", "_")
        .replace("/", "_")
    )


def _to_inventory_value(value: Any) -> str | int | float | bool:
    """Return a Checkmk inventory-safe value.

    Keep primitive values as-is where possible and serialize complex FortiOS
    structures as deterministic JSON strings so no API data is lost.
    """
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _netmask_to_prefix(netmask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except ValueError:
        return None


def fortios_ip_to_cidr(value: Any) -> str:
    """Convert FortiOS IPv4 notation to CIDR notation.

    FortiOS commonly returns configured IPv4 addresses as
    ``"192.168.1.1 255.255.255.0"``. Some versions or interface types can
    return an empty value, ``0.0.0.0 0.0.0.0`` or already normalized values.
    """
    if not value:
        return ""

    value_str = str(value).strip()
    if not value_str:
        return ""

    parts = value_str.split()
    if len(parts) == 2:
        ip_address, netmask = parts
        if ip_address == "0.0.0.0" and netmask == "0.0.0.0":
            return ""
        prefix = _netmask_to_prefix(netmask)
        if prefix is not None:
            return f"{ip_address}/{prefix}"

    return value_str


def secondary_ips_to_cidr(value: Any) -> str:
    """Return configured secondary IPv4 addresses as comma-separated CIDR list."""
    if not value:
        return ""
    if not isinstance(value, list):
        return _to_inventory_value(value)

    addresses: list[str] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            continue
        address = fortios_ip_to_cidr(entry.get("ip"))
        if address:
            addresses.append(address)
    return ", ".join(addresses)


def parse_fortios_interfaces_cmdb(string_table):
    try:
        json_data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return None

    if (interface_data := json_data.get("results")) is None:
        return None

    if isinstance(interface_data, Mapping):
        iterable = interface_data.values()
    else:
        iterable = interface_data

    return {
        interface.get("name", interface.get("q_origin_key")): InterfaceCMDB(**interface)
        for interface in iterable
        if isinstance(interface, Mapping) and (interface.get("name") or interface.get("q_origin_key"))
    }


agent_section_fortios_interfaces_cmdb = AgentSection(
    name="fortios_interfaces_cmdb",
    parse_function=parse_fortios_interfaces_cmdb,
)


def inventory_fortios_interfaces_cmdb(section: Mapping[str, InterfaceCMDB]) -> InventoryResult:
    """Inventory all configured FortiOS interface data.

    The inventory contains normalized commonly used columns plus a sanitized
    column for every key returned by the FortiGate CMDB endpoint. Complex values
    are serialized as JSON strings.
    """
    if section is None:
        return

    path = ["networking", "fortios", "interfaces"]
    for _interface_key, interface in sorted(section.items()):
        raw_data = interface.model_dump(mode="json", by_alias=False)

        inventory_columns = {
            "alias": interface.alias,
            "description": interface.description,
            "type": interface.type,
            "role": interface.role,
            "status": interface.status,
            "mode": interface.mode,
            "ip_address": fortios_ip_to_cidr(interface.ip),
            "secondary_ip_addresses": secondary_ips_to_cidr(interface.secondaryip),
            "vlan_id": "" if interface.vlanid is None else str(interface.vlanid),
            "parent_interface": interface.interface,
            "vdom": interface.vdom,
            "allow_access": interface.allowaccess,
            "mac_address": interface.macaddr,
        }

        # Add every FortiOS CMDB field so that inventory keeps all data returned
        # by the firewall. Known normalized columns above remain available with
        # stable names, while raw columns use a raw_ prefix.
        for raw_key, raw_value in sorted(raw_data.items()):
            inventory_columns[f"raw_{_column_name(raw_key)}"] = _to_inventory_value(raw_value)

        yield TableRow(
            path=path,
            key_columns={"name": interface.name or interface.q_origin_key or _interface_key},
            inventory_columns=inventory_columns,
        )


inventory_plugin_fortios_interfaces_cmdb = InventoryPlugin(
    name="fortios_interfaces_cmdb",
    inventory_function=inventory_fortios_interfaces_cmdb,
)
