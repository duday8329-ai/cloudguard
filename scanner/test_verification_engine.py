from s3_scanner import scan_s3_configuration
from remediation_engine import remediate_s3_configuration
from verification_engine import verify_remediation


test_config = {
    "resource_type": "S3",
    "resource_name": "cloudguard-demo-bucket",
    "public_access": False,
    "encryption": True,
    "logging": False
}


print("\nCloudGuard Remediation Verification")
print("=" * 45)

print("\n1. INITIAL CONFIGURATION")
print(test_config)


# Initial scan
initial_findings = scan_s3_configuration(test_config)

print("\n2. INITIAL FINDINGS")

for finding in initial_findings:
    print(
        f"{finding['rule_id']} - "
        f"{finding['issue']} - "
        f"{finding['severity']}"
    )


# Remediation
remediation_result = remediate_s3_configuration(
    test_config,
    initial_findings
)

updated_config = remediation_result["updated_configuration"]

print("\n3. REMEDIATION")

for action in remediation_result["actions"]:
    print(f"{action['action']} - {action['status']}")


print("\n4. UPDATED CONFIGURATION")
print(updated_config)


# Re-scan
verification_findings = scan_s3_configuration(updated_config)

print("\n5. RE-SCAN")

if len(verification_findings) == 0:
    print("No security findings detected.")
else:
    for finding in verification_findings:
        print(
            f"{finding['rule_id']} - "
            f"{finding['issue']} - "
            f"{finding['severity']}"
        )


# Verification
verification_result = verify_remediation(
    verification_findings
)

print("\n6. VERIFICATION")
print(f"Status: {verification_result['status']}")
print(f"Message: {verification_result['message']}")