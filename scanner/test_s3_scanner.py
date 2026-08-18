from s3_scanner import scan_s3_configuration


test_config = {
    "resource_type": "S3",
    "resource_name": "cloudguard-demo-bucket",
    "public_access": True,
    "encryption": False,
    "logging": False
}


findings = scan_s3_configuration(test_config)

print("\nCloudGuard S3 Security Scan")
print("=" * 40)

for finding in findings:
    print(f"\nRule ID: {finding['rule_id']}")
    print(f"Issue: {finding['issue']}")
    print(f"Severity: {finding['severity']}")
    print(f"Description: {finding['description']}")
    print(f"Recommendation: {finding['recommendation']}")