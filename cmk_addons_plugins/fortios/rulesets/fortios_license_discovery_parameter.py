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
from cmk.rulesets.v1.form_specs import DictElement, Dictionary, MultipleChoice, MultipleChoiceElement
from cmk.rulesets.v1.rule_specs import DiscoveryParameters, Topic


def _form_check_fortios_license() -> Dictionary:
    return Dictionary(
        title=Title("FortiOS licensed feature discovery"),
        help_text=Help("Select the licensed features to be monitored."),
        elements={
            "features": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Licensed features"),
                    elements=[
                        MultipleChoiceElement(
                            name="antivirus",
                            title=Title("Antivirus"),
                        ),
                        MultipleChoiceElement(
                            name="forticare",
                            title=Title("Forticare"),
                        ),
                        MultipleChoiceElement(
                            name="fortiguard",
                            title=Title("Fortiguard"),
                        ),
                        MultipleChoiceElement(
                            name="appctrl",
                            title=Title("Application Control"),
                        ),
                        MultipleChoiceElement(
                            name="web_filtering",
                            title=Title("Web Filtering"),
                        ),
                        MultipleChoiceElement(
                            name="vdom",
                            title=Title("VDOM"),
                        ),
                    ],
                ),
            ),
        },
    )


rule_spec_fortios_license_discovery = DiscoveryParameters(
    title=Title("FortiOS license discovery"),
    topic=Topic.NETWORKING,
    name="fortios_license_discovery",
    parameter_form=_form_check_fortios_license,
)
