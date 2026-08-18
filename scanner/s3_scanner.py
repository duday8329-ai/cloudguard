def scan_s3_configuration(config):
    findings = []

    # Rule 1: Public access
    if config.get("public_access") is True:
        findings.append({
            "rule_id": "S3-001",
            "resource": config.get("resource_name", "Unknown"),
            "issue": "Public S3 bucket",
            "severity": "HIGH",
            "description": "The S3 bucket is publicly accessible.",
            "recommendation": "Disable public access."
        })

    # Rule 2: Encryption
    if config.get("encryption") is False:
        findings.append({
            "rule_id": "S3-002",
            "resource": config.get("resource_name", "Unknown"),
            "issue": "Encryption disabled",
            "severity": "MEDIUM",
            "description": "The S3 bucket does not have encryption enabled.",
            "recommendation": "Enable server-side encryption."
        })

    # Rule 3: Logging
    if config.get("logging") is False:
        findings.append({
            "rule_id": "S3-003",
            "resource": config.get("resource_name", "Unknown"),
            "issue": "Logging disabled",
            "severity": "LOW",
            "description": "Logging is disabled for the S3 bucket.",
            "recommendation": "Enable access logging."
        })

    return findings