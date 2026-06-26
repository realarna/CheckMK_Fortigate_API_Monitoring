#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation in version 2. check_mk is distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along
# with GNU Make; see the file COPYING. If not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# WAGNER AG
# Developer: opensource@wagner.ch

"""
Check_MK agent based checks to be used with agent_fortios Datasource

"""

from __future__ import annotations

import json
from typing import Optional

from pydantic import BaseModel

from cmk.agent_based.v2 import CheckPlugin, AgentSection, Metric, Result, Service, State, CheckResult, DiscoveryResult


class Thresholds(BaseModel):
    upper_non_critical: Optional[float] = None
    upper_critical: Optional[float] = None
    upper_non_recoverable: Optional[float] = None
    lower_non_critical: Optional[float] = None
    lower_critical: Optional[float] = None
    lower_non_recoverable: Optional[float] = None


class Sensor(BaseModel):
    id: str
    name: str
    type: str
    value: float
    alarm: bool
    thresholds: Thresholds


def get_sensors_with_alarm(sensors: list[Sensor]) -> str:
    # Filter and format sensors where alarm is True
    formatted_sensors = [f"Name: {sensor.name}, Type: {sensor.type}, Value: {sensor.value}" for sensor in sensors if sensor.alarm]

    return " ".join(formatted_sensors)


def parse_fortios_sensors(string_table) -> list[Sensor] | None:
    try:
        json_data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return None

    if (sensor_data := json_data.get("results")) in ({}, []):
        return None

    return [Sensor(**item) for item in sensor_data]


agent_section_fortios_sensors = AgentSection(
    name="fortios_sensors",
    parse_function=parse_fortios_sensors,
)


def discovery_fortios_sensors(section: list[Sensor]) -> DiscoveryResult:
    yield Service()


def check_fortios_sensors(section: list[Sensor]) -> CheckResult:
    if not section:
        yield Result(
            state=State.UNKNOWN,
            summary="Sensors are missing",
        )
        return

    alarm_count = sum(1 for item in section if item.alarm)
    alarm_summary = get_sensors_with_alarm(section)

    if alarm_count > 0:
        yield Result(
            state=State.CRIT,
            summary=f"Alarms: {alarm_summary}",
        )
    else:
        yield Result(
            state=State.OK,
            summary="No hardware alarms",
        )

    yield Metric("alarm_count", alarm_count)


check_plugin_fortios_sensors = CheckPlugin(
    name="fortios_sensors",
    service_name="Sensors",
    discovery_function=discovery_fortios_sensors,
    check_function=check_fortios_sensors,
)
