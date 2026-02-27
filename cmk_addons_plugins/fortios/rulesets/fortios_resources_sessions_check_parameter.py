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
from cmk.rulesets.v1.form_specs import DictElement, Dictionary, InputHint, Integer, LevelDirection, SimpleLevels
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def _form_check_fortios_session_levels() -> Dictionary:
    return Dictionary(
        title=Title("Thresholds for session count"),
        elements={
            "session_levels": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Session count levels"),
                    prefill_fixed_levels=InputHint(value=(20000, 30000)),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Integer(),
                    help_text=Help("Number of sessions at which the status becomes WARN or CRIT."),
                )
            ),
        },
    )


rule_spec_fortios_session_levels = CheckParameters(
    title=Title("FortiOS session count levels"),
    topic=Topic.NETWORKING,
    name="fortios_resources_sessions",
    parameter_form=_form_check_fortios_session_levels,
    condition=HostAndItemCondition(item_title=Title("Session count levels")),
)
