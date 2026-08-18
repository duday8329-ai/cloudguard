def remediate_s3_configuration(config, findings):
    updated_config = config.copy()
    remediation_actions = []

    for finding in findings:

        # Safe remediation: enable logging
        if finding["rule_id"] == "S3-003":
            if updated_config.get("logging") is False:

                updated_config["logging"] = True

                remediation_actions.append({
                    "rule_id": "S3-003",
                    "action": "ENABLE_LOGGING",
                    "status": "APPLIED",
                    "message": "S3 logging was enabled."
                })

    return {
        "updated_configuration": updated_config,
        "actions": remediation_actions
    }