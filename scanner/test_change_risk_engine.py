from change_analyzer import analyze_dependency_impact
from change_risk_engine import calculate_change_risk


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


dependencies = {
    "cloudguard-demo-bucket": [
        "cloudguard-web-app",
        "cloudguard-lambda",
        "cloudguard-app-role"
    ]
}


dependency_impact = analyze_dependency_impact(
    current_state["resource_name"],
    dependencies
)


result = calculate_change_risk(
    current_state,
    proposed_state,
    dependency_impact
)


print("\nCloudGuard Unified Change Risk Analysis")
print("=" * 55)

print(f"\nBefore Risk : {result['before_risk']}/100")
print(f"Before Level: {result['before_level']}")

print(f"\nAfter Risk  : {result['after_risk']}/100")
print(f"After Level : {result['after_level']}")

print(f"\nRisk Delta  : {result['risk_delta']:+d}")

print(f"\nImpact      : {result['impact']}")

print(
    f"\nAffected Resources: "
    f"{result['dependency_count']}"
)