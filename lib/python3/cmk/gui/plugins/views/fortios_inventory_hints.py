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

from cmk.gui.i18n import _
from cmk.gui.views.inventory.registry import inventory_displayhints

inventory_displayhints.update(
    {
        ".networking.fortios.": {
            "title": _("Fortigate Managed Devices"),
            "view": "fortiosinventory",
        },
        "networking.fortios.wifi.": {
            "title": _("WiFi"),
        },
        ".networking.fortios.wifi.devices:": {
            "title": _("Devices"),
            "keyorder": ["mac_address", "association_time", "ip_address", "hostname", "ap_name"],
        },
        ".networking.fortios.wifi.devices:*.association_time": {
            "title": _("Association Time"),
        },
        ".networking.fortios.wifi.devices:*.mac_address": {
            "title": _("MAC Address"),
        },
        ".networking.fortios.wifi.devices:*.ip_address": {
            "title": _("IP Address"),
        },
        ".networking.fortios.wifi.devices:*.hostname": {
            "title": _("Hostname"),
        },
        ".networking.fortios.wifi.devices:*.ap_name": {
            "title": _("Accesspoint Name"),
        },
        ".networking.fortios.wifi.accesspoints:": {
            "title": _("Accesspoints"),
            "keyorder": ["name", "ip_address", "model", "serial_number", "version", "build", "end_of_support"],
        },
        ".networking.fortios.wifi.accesspoints:*.name": {"title": _("Name")},
        ".networking.fortios.wifi.accesspoints:*.ip_address": {"title": _("IP address")},
        ".networking.fortios.wifi.accesspoints:*.model": {"title": _("Model")},
        ".networking.fortios.wifi.accesspoints:*.serial_number": {"title": _("Serial number")},
        ".networking.fortios.wifi.accesspoints:*.version": {"title": _("Version")},
        ".networking.fortios.wifi.accesspoints:*.build": {"title": _("Build")},
        ".networking.fortios.wifi.accesspoints:*.end_of_support": {"title": _("End of support")},
        ".networking.fortios.wifi.accesspoints.lldp:": {
            "title": _("LLDP"),
            "keyorder": ["switch_name", "switch_port", "switch_description", "local_port", "local_port_description"],
        },
        ".networking.fortios.wifi.accesspoints.lldp:*.local_port": {
            "title": _("Local Port"),
        },
        ".networking.fortios.wifi.accesspoints.lldp:*.local_port_description": {
            "title": _("Local Port description"),
        },
        ".networking.fortios.wifi.accesspoints.lldp:*.switch_name": {
            "title": _("Switch Name"),
        },
        ".networking.fortios.wifi.accesspoints.lldp:*.switch_port": {
            "title": _("Switch Port"),
        },
        ".networking.fortios.wifi.accesspoints.lldp:*.switch_description": {
            "title": _("Switch Description"),
        },
        ".networking.fortios.switches:": {
            "title": _("Switches"),
            "keyorder": ["name", "model", "serial_number", "version", "build", "end_of_support"],
        },
        ".networking.fortios.switches:*.name": {
            "title": _("Name"),
        },
        ".networking.fortios.switches:*.model": {
            "title": _("Model"),
        },
        ".networking.fortios.switches:*.serial_number": {
            "title": _("Serial number"),
        },
        ".networking.fortios.switches:*.version": {
            "title": _("Version"),
        },
        ".networking.fortios.switches:*.build": {
            "title": _("Build"),
        },
        ".networking.fortios.switches:*.end_of_support": {
            "title": _("End of support"),
        },
    }
)
