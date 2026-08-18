from risk_engine import calculate_risk


result = calculate_risk(
    severity="HIGH",
    internet_exposure="HIGH",
    resource_criticality="HIGH",
    data_sensitivity="HIGH",
    exploitability="HIGH"
)


print("\nCloudGuard Risk Assessment")
print("=" * 40)

print(f"Risk Score: {result['risk_score']}/100")
print(f"Risk Level: {result['risk_level']}")

print("\nRisk Factors:")

for factor, score in result["factors"].items():
    print(f"{factor}: {score}")