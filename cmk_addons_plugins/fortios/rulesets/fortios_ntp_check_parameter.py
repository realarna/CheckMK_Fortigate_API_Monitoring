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

from cmk.rulesets.v1 import Title, Help
from cmk.rulesets.v1.form_specs import DictElement, Dictionary, InputHint, Integer, Float, SimpleLevels, LevelDirection
from cmk.rulesets.v1.rule_specs import CheckParameters, Topic, HostAndItemCondition


def _form_check_fortios_ntp() -> Dictionary:
    return Dictionary(
        title=Title("Thresholds for NTP time"),
        elements={
            "stratum": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Critical at stratum"),
                    prefill_fixed_levels=InputHint(value=(8, 12)),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Integer(),
                    help_text=Help("The stratum ('distance' to the reference clock) at which the check gets critical."),
                ),
            ),
            "offset_levels": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Thresholds for quality of time"),
                    prefill_fixed_levels=InputHint(value=(0.2, 0.5)),
                    level_direction=LevelDirection.UPPER.LOWER,
                    form_spec_template=Float(),
                    help_text=Help("The offset in seconds at which a warning or critical state is triggered."),
                ),
            ),
        },
    )


rule_spec_fortios_ntp = CheckParameters(
    title=Title("FortiOS NTP offset levels"),
    topic=Topic.NETWORKING,
    name="fortios_ntp",
    parameter_form=_form_check_fortios_ntp,
    condition=HostAndItemCondition(item_title=Title("NTP Server Name")),
)
