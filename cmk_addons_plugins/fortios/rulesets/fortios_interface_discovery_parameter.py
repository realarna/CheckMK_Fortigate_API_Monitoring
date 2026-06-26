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
from cmk.rulesets.v1.form_specs import DictElement, Dictionary, List, SingleChoice, SingleChoiceElement, String, DefaultValue, validators
from cmk.rulesets.v1.rule_specs import DiscoveryParameters, Topic


def _form_check_fortios_interface_included() -> Dictionary:
    return Dictionary(
        title=Title("FortiOS interface discovery"),
        elements={
            "item_included_by_type": DictElement(
                parameter_form=Dictionary(
                    title=Title("Configuration for included interfaces"),
                    help_text=Help("Set interface discovery parameters for interfaces that should always be monitored."),
                    elements={
                        "type": DictElement(
                            required=True,
                            parameter_form=SingleChoice(
                                title=Title("Include only network interfaces by"),
                                help_text=Help("This option makes CheckMK discover interfaces either by description, name or alias."),
                                elements=[
                                    SingleChoiceElement("name", title=Title("Use name for inclusion")),
                                    SingleChoiceElement("descr", title=Title("Use description for inclusion")),
                                    SingleChoiceElement("alias", title=Title("Use alias for inclusion")),
                                ],
                                prefill=DefaultValue("name"),
                            ),
                        ),
                        "strings": DictElement(
                            required=True,
                            parameter_form=List[str](
                                title=Title("List of interfaces to include"),
                                help_text=Help("Interfaces to be included by monitoring. Can be full or partial strings."),
                                element_template=String(
                                    custom_validate=(validators.LengthInRange(min_value=1),),
                                ),
                                editable_order=False,
                            ),
                        ),
                    },
                ),
            ),
            "item_excluded_by_type": DictElement(
                parameter_form=Dictionary(
                    title=Title("Configuration for excluded interfaces"),
                    help_text=Help("Set interface discovery parameters for interfaces that should not be monitored."),
                    elements={
                        "type": DictElement(
                            required=True,
                            parameter_form=SingleChoice(
                                title=Title("Exclude only network interfaces by"),
                                help_text=Help("This option makes CheckMK to ignore interfaces either by description, name or alias."),
                                elements=[
                                    SingleChoiceElement("name", title=Title("Use name for inclusion")),
                                    SingleChoiceElement("descr", title=Title("Use description for inclusion")),
                                    SingleChoiceElement("alias", title=Title("Use alias for inclusion")),
                                ],
                                prefill=DefaultValue("name"),
                            ),
                        ),
                        "strings": DictElement(
                            required=True,
                            parameter_form=List[str](
                                title=Title("List of interfaces to exclude"),
                                help_text=Help("Interfaces to be excluded by monitoring. Can be full or partial strings."),
                                element_template=String(
                                    custom_validate=(validators.LengthInRange(min_value=1),),
                                ),
                                editable_order=False,
                            ),
                        ),
                    },
                ),
            ),
        },
    )


rule_spec_fortios_interface_discovery = DiscoveryParameters(
    title=Title("FortiOS interface discovery"),
    topic=Topic.NETWORKING,
    name="fortios_interface_discovery",
    parameter_form=_form_check_fortios_interface_included,
)
