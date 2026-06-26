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
from cmk.rulesets.v1.form_specs import DictElement, Dictionary, Integer, validators, SimpleLevels, LevelDirection, InputHint
from cmk.rulesets.v1.rule_specs import CheckParameters, Topic, HostAndItemCondition


def _form_check_fortios_license() -> Dictionary:
    return Dictionary(
        title=Title("Days left for Fortigate licenses"),
        elements={
            "day_levels": DictElement(
                parameter_form=SimpleLevels[int](
                    title=Title("Days left until license expires"),
                    level_direction=LevelDirection.UPPER,
                    custom_validate=(validators.LengthInRange(min_value=1),),
                    form_spec_template=Integer(),
                    prefill_fixed_levels=InputHint(value=(45, 30)),
                    help_text=Help("The specified values indicate the number of days prior to license expiration at which the check status is set to WARN or CRIT."),
                ),
            ),
        },
    )


rule_spec_fortios_license = CheckParameters(
    title=Title("FortiOS license check levels"),
    topic=Topic.NETWORKING,
    name="fortios_license",
    parameter_form=_form_check_fortios_license,
    condition=HostAndItemCondition(item_title=Title("License name")),
)
