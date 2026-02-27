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
Check_MK WATO rule spec for FortiOS special agent

"""

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import DictElement, Dictionary, List, String, validators
from cmk.rulesets.v1.rule_specs import CheckParameters, Topic, HostAndItemCondition


def _form_check_fortios_ipsec() -> Dictionary:
    return Dictionary(
        title=Title("FortiOS IPSec VPN tunnels"),
        elements={
            "item_names_excluded": DictElement(
                parameter_form=List[str](
                    title=Title("Names of IPSec VPN tunnels to ignore in monitoring"),
                    help_text=Help("IPSec VPN phase2 tunnel names listed here will be excluded from monitoring"),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=1),),
                    ),
                    editable_order=False,
                ),
            ),
            "item_dst_excluded": DictElement(
                parameter_form=List[str](
                    title=Title("Destination subnets to ignore in monitoring"),
                    help_text=Help("IPSec VPN destinations listed here will be excluded from monitoring. Example: '10.10.10.0-10.10.10.255' or '10.10.10.0/255.255.255.0'"),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=1),),
                    ),
                    editable_order=False,
                ),
            ),
        },
    )


rule_spec_fortios_ipsec = CheckParameters(
    title=Title("FortiOS IPSec VPN tunnels"),
    topic=Topic.NETWORKING,
    name="fortios_ipsec",
    parameter_form=_form_check_fortios_ipsec,
    condition=HostAndItemCondition(item_title=Title("IPSec VPN Tunnel Name or Destination Subnet")),
)
