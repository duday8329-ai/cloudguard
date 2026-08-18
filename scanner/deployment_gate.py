# ============================================================
# CLOUDGUARD DEPLOYMENT GATE
# ============================================================


def evaluate_deployment(decision):
    """
    Decide whether a deployment can proceed based on
    the CloudGuard change decision.
    """

    action = decision.get("action")


    # --------------------------------------------------------
    # ALLOW
    # --------------------------------------------------------

    if action == "ALLOW":

        return {
            "deployment_status": "ALLOWED",
            "deployment_action": "PROCEED",
            "message": (
                "Security policy passed. "
                "Deployment is permitted."
            )
        }


    # --------------------------------------------------------
    # HUMAN APPROVAL
    # --------------------------------------------------------

    if action == "HUMAN_APPROVAL":

        return {
            "deployment_status": "PENDING_APPROVAL",
            "deployment_action": "WAIT",
            "message": (
                "Security review is required "
                "before deployment."
            )
        }


    # --------------------------------------------------------
    # BLOCK
    # --------------------------------------------------------

    if action == "BLOCK":

        return {
            "deployment_status": "BLOCKED",
            "deployment_action": "STOP",
            "message": (
                "Security policy failed. "
                "Deployment has been blocked."
            )
        }


    # --------------------------------------------------------
    # Unknown action
    # --------------------------------------------------------

    return {
        "deployment_status": "BLOCKED",
        "deployment_action": "STOP",
        "message": (
            "Unknown security decision. "
            "Deployment is blocked for safety."
        )
    }