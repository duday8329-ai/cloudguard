from change_analyzer import (
    analyze_property_changes,
    analyze_dependency_impact
)


current_state = {
    "resource_type": "S3",
    "resource_name": "cloudguard-demo-bucket",
    "public_access": False,
    "encryption": True,
    "logging": True
}


proposed_state = {
    "resource_type": "S3",
    "resource_name": "cloudguard-demo-bucket",
    "public_access": True,
    "encryption": False,
    "logging": True
}


# Example dependency graph
dependencies = {
    "cloudguard-demo-bucket": [
        "cloudguard-web-app",
        "cloudguard-lambda",
        "cloudguard-app-role"
    ]
}


# Property + security control analysis
changes = analyze_property_changes(
    current_state,
    proposed_state
)


print("\nCloudGuard Change Analyzer")
print("=" * 55)

print(f"\nChanges detected: {len(changes)}")

for change in changes:

    print(f"\nProperty: {change['property']}")
    print(f"Current:  {change['current_value']}")
    print(f"Proposed: {change['proposed_value']}")

    impact = change["security_impact"]

    print(f"Security Control: {impact['control']}")
    print(f"Category: {impact['category']}")
    print(f"Severity: {impact['severity']}")
    print(f"Description: {impact['description']}")


# Dependency analysis
dependency_impact = analyze_dependency_impact(
    current_state["resource_name"],
    dependencies
)


print("\n" + "=" * 55)
print("DEPENDENCY IMPACT")
print("=" * 55)

print(f"\nResource: {dependency_impact['resource']}")

print(
    f"Affected Resources: "
    f"{dependency_impact['affected_count']}"
)

for resource in dependency_impact["affected_resources"]:
    print(f" - {resource}")