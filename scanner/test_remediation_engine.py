from s3_scanner import scan_s3_configuration
from remediation_engine import remediate_s3_configuration


test_config = {
    "resource_type": "S3",
    "resource_name": "cloudguard-demo-bucket",
    "public_access": False,
    "encryption": True,
    "logging": False
}


print("\nCloudGuard Remediation Test")
print("=" * 40)

print("\nBEFORE REMEDIATION")
print(test_config)


findings = scan_s3_configuration(test_config)

print("\nFINDINGS")

for finding in findings:
    print(
        f"{finding['rule_id']} - "
        f"{finding['issue']} - "
        f"{finding['severity']}"
    )


result = remediate_s3_configuration(
    test_config,
    findings
)


print("\nREMEDIATION")

for action in result["actions"]:
    print(f"Action: {action['action']}")
    print(f"Status: {action['status']}")
    print(f"Message: {action['message']}")


print("\nAFTER REMEDIATION")
print(result["updated_configuration"])