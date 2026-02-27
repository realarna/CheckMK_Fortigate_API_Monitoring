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

import json
from typing import Any, Dict, Mapping, Optional

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
    check_levels,
)
from pydantic import BaseModel, field_validator

DEFAULT_OFFSET_LEVELS: Dict = {"stratum": ("fixed", (8, 12)), "offset_levels": ("fixed", (0.2, 0.5))}


class FortiNTP(BaseModel, frozen=True):
    server: str
    reachable: bool
    stratum: Optional[int] = None
    ip: Optional[str] = None
    offset: Optional[float] = 0
    selected: Optional[bool] = None

    # convert ms to s
    @field_validator("offset", mode="after")
    @classmethod
    def convert_offset(cls, v):
        return v / 1000

    @property
    def summary(self):
        return f"Server: {self.server}, IP: {self.ip}, Selected: {self.selected}"


def parse_fortios_ntp(string_table) -> Mapping[str, FortiNTP] | None:
    try:
        json_data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return None

    if (forti_ntp_servers := json_data.get("results")) in ({}, []):
        return None

    return {item["server"]: FortiNTP(**item) for item in forti_ntp_servers}


agent_section_fortios_ntp = AgentSection(
    name="fortios_ntp",
    parse_function=parse_fortios_ntp,
)


def discovery_fortios_ntp(section: Mapping[str, FortiNTP]) -> DiscoveryResult:
    for item in section:
        ntp = section.get(item)
        if ntp.selected:
            yield Service()
            break
    for item in section:
        ntp = section.get(item)
        if ntp.reachable and ntp.offset:
            yield Service()


def check_fortios_ntp(params: Mapping[str, Any], section: Mapping[str, FortiNTP]) -> CheckResult:
    ntp = next(iter(section.values()), None)
    if ntp:
        yield Result(state=State.OK, summary=ntp.summary)
    else:
        yield Result(state=State.WARN, summary="No NTP Server is enabled or available")

    warn, crit = params.get("offset_levels")[1]
    yield from check_levels(
        value=ntp.offset,
        levels_upper=("fixed", (warn, crit)),
        levels_lower=("fixed", (-warn, -crit)),
        metric_name="time_offset",
        render_func=lambda f: "%.1f ms" % (f * 1000),
        label="Time offset",
    )

    warn, crit = params.get("stratum")[1]
    if ntp.stratum is not None:
        yield from check_levels(
            value=ntp.stratum,
            levels_upper=("fixed", (warn, crit)),
            render_func=lambda d: str(int(d)),
            label="Stratum",
        )


check_plugin_fortios_ntp = CheckPlugin(
    name="fortios_ntp",
    service_name="NTP Time",
    discovery_function=discovery_fortios_ntp,
    check_ruleset_name="fortios_ntp",
    check_function=check_fortios_ntp,
    check_default_parameters=DEFAULT_OFFSET_LEVELS,
)
