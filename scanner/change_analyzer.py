SECURITY_CONTROLS = {

    "public_access": {
        "control": "PUBLIC_ACCESS_CONTROL",
        "category": "Internet Exposure",
        "impact_when_changed_to": True,
        "severity": "HIGH",
        "description": (
            "Public access increases the external exposure "
            "of the resource."
        )
    },

    "encryption": {
        "control": "ENCRYPTION_CONTROL",
        "category": "Data Protection",
        "impact_when_changed_to": False,
        "severity": "HIGH",
        "description": (
            "Disabling encryption reduces protection "
            "for stored data."
        )
    },

    "logging": {
        "control": "LOGGING_CONTROL",
        "category": "Monitoring",
        "impact_when_changed_to": False,
        "severity": "MEDIUM",
        "description": (
            "Disabling logging reduces security visibility "
            "and auditability."
        )
    },

        "resource_criticality": {
        "control": "RESOURCE_CRITICALITY_CONTROL",
        "category": "Resource Criticality",
        "severity": "HIGH",
        "description": (
            "Changing resource criticality changes the "
            "security importance assigned to the resource."
        )
    },

    "data_sensitivity": {
        "control": "DATA_SENSITIVITY_CONTROL",
        "category": "Data Protection",
        "severity": "HIGH",
        "description": (
            "Changing data sensitivity changes the level "
            "of protection required for the resource."
        )
    },

    "exploitability": {
        "control": "EXPLOITABILITY_CONTROL",
        "category": "Threat Exposure",
        "severity": "HIGH",
        "description": (
            "Changing exploitability changes the estimated "
            "likelihood that the resource can be exploited."
        )
    }
}


def analyze_property_changes(current, proposed):

    changes = []

    all_keys = set(current.keys()) | set(proposed.keys())

    for key in sorted(all_keys):

        current_value = current.get(key)
        proposed_value = proposed.get(key)

        if current_value == proposed_value:
            continue

        change = {
            "property": key,
            "current_value": current_value,
            "proposed_value": proposed_value
        }

        if key in SECURITY_CONTROLS:

            control = SECURITY_CONTROLS[key]

            change["security_impact"] = {
                "control": control["control"],
                "category": control["category"],
                "severity": control["severity"],
                "description": control["description"]
            }

        else:

            change["security_impact"] = {
                "control": "NONE",
                "category": "No Known Security Impact",
                "severity": "NONE",
                "description": (
                    "No security-sensitive control is associated "
                    "with this property."
                )
            }

        changes.append(change)

    return changes



def analyze_dependency_impact(
    resource_name,
    dependencies
):

    affected_resources = dependencies.get(
        resource_name,
        []
    )

    return {
        "resource": resource_name,
        "affected_resources": affected_resources,
        "affected_count": len(affected_resources)
    }