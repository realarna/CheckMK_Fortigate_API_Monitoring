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
Check_MK WATO rule spec for FortiOS special agent

"""

from cmk.rulesets.v1 import Title
from cmk.rulesets.v1.form_specs import DictElement, Dictionary, InputHint, Integer, LevelDirection, SimpleLevels
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def _form_check_fortios_dhcp_scope() -> Dictionary:
    return Dictionary(
        title=Title("Thresholds for DHCP scope usage"),
        elements={
            "dhcp_scope_levels": DictElement(
                parameter_form=SimpleLevels[int](
                    title=Title("Scope levels"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Integer(),
                    prefill_fixed_levels=InputHint(value=(80, 90)),
                )
            ),
        },
    )


rule_spec_fortios_dhcp_scope = CheckParameters(
    title=Title("FortiOS DHCP scope usage levels"),
    topic=Topic.NETWORKING,
    name="fortios_dhcp_scope",
    parameter_form=_form_check_fortios_dhcp_scope,
    condition=HostAndItemCondition(item_title=Title("DHCP scope name")),
)
