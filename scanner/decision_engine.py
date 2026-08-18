# ============================================================
# CLOUDGUARD DECISION ENGINE
# ============================================================


# ============================================================
# SINGLE-STATE DECISION
# ============================================================

def make_decision(
    risk_score,
    risk_level
):
    """
    Decide what to do with a single cloud security state.
    """

    risk_level = str(
        risk_level
    ).upper()


    # --------------------------------------------------------
    # LOW RISK
    # --------------------------------------------------------

    if risk_level == "LOW":

        action = "AUTO_REMEDIATE"

        message = (
            "Low-risk issue. "
            "Automatic remediation is permitted."
        )


    # --------------------------------------------------------
    # MEDIUM RISK
    # --------------------------------------------------------

    elif risk_level == "MEDIUM":

        action = "HUMAN_APPROVAL"

        message = (
            "Medium-risk issue. "
            "Human approval is required."
        )


    # --------------------------------------------------------
    # HIGH RISK
    # --------------------------------------------------------

    elif risk_level == "HIGH":

        action = "BLOCK"

        message = (
            "High-risk configuration. "
            "Deployment is blocked."
        )


    # --------------------------------------------------------
    # CRITICAL RISK
    # --------------------------------------------------------

    elif risk_level == "CRITICAL":

        action = "BLOCK"

        message = (
            "Critical-risk configuration. "
            "Deployment is blocked for safety."
        )


    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    else:

        action = "BLOCK"

        message = (
            "Unknown risk level. "
            "Deployment is blocked for safety."
        )


    return {

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "action":
            action,

        "message":
            message
    }


# ============================================================
# CHANGE DECISION
# ============================================================

def make_change_decision(
    before_risk,
    after_risk,
    risk_delta,
    impact
):
    """
    Decide whether a proposed infrastructure change
    should be allowed.

    CloudGuard evaluates three things:

        1. Final risk level
        2. Risk delta
        3. Direction of security change

    Safety principle:

        CRITICAL final risk = BLOCK

    A lower risk score is treated as a security improvement.
    """


    # --------------------------------------------------------
    # NORMALIZE VALUES
    # --------------------------------------------------------

    before_risk = int(
        before_risk
    )

    after_risk = int(
        after_risk
    )

    risk_delta = int(
        risk_delta
    )

    impact = str(
        impact
    )


    # ========================================================
    # RULE 1
    # SECURITY IMPROVEMENT
    # ========================================================

    if risk_delta < 0:

        return {

            "action": "ALLOW",

            "reason": (
                "The proposed change reduces "
                "security risk."
            ),

            "before_risk":
                before_risk,

            "after_risk":
                after_risk,

            "risk_delta":
                risk_delta,

            "impact":
                "SECURITY_IMPROVEMENT"
        }


    # ========================================================
    # RULE 2
    # CRITICAL FINAL RISK
    # ========================================================

    if after_risk >= 76:

        return {

            "action": "BLOCK",

            "reason": (
                "The proposed configuration "
                "results in critical security risk."
            ),

            "before_risk":
                before_risk,

            "after_risk":
                after_risk,

            "risk_delta":
                risk_delta,

            "impact":
                "CRITICAL_IMPACT"
        }


    # ========================================================
    # RULE 3
    # CRITICAL RISK INCREASE
    # ========================================================

    if risk_delta > 60:

        return {

            "action": "BLOCK",

            "reason": (
                "The proposed change introduces "
                "a critical increase in security risk."
            ),

            "before_risk":
                before_risk,

            "after_risk":
                after_risk,

            "risk_delta":
                risk_delta,

            "impact":
                impact
        }


    # ========================================================
    # RULE 4
    # HIGH RISK INCREASE
    # ========================================================

    if risk_delta > 35:

        return {

            "action": "BLOCK",

            "reason": (
                "The proposed change introduces "
                "a high increase in security risk."
            ),

            "before_risk":
                before_risk,

            "after_risk":
                after_risk,

            "risk_delta":
                risk_delta,

            "impact":
                impact
        }


    # ========================================================
    # RULE 5
    # MODERATE RISK INCREASE
    # ========================================================

    if risk_delta > 15:

        return {

            "action": "HUMAN_APPROVAL",

            "reason": (
                "The proposed change requires "
                "security review."
            ),

            "before_risk":
                before_risk,

            "after_risk":
                after_risk,

            "risk_delta":
                risk_delta,

            "impact":
                impact
        }


    # ========================================================
    # RULE 6
    # NO SECURITY CHANGE
    # ========================================================

    if risk_delta == 0:

        return {

            "action": "ALLOW",

            "reason": (
                "The proposed change has no "
                "measured security impact."
            ),

            "before_risk":
                before_risk,

            "after_risk":
                after_risk,

            "risk_delta":
                0,

            "impact":
                "NO_SECURITY_CHANGE"
        }


    # ========================================================
    # RULE 7
    # SMALL INCREASE
    # ========================================================

    return {

        "action": "ALLOW",

        "reason": (
            "The proposed change has "
            "a low security impact."
        ),

        "before_risk":
            before_risk,

        "after_risk":
            after_risk,

        "risk_delta":
            risk_delta,

        "impact":
            impact
    }