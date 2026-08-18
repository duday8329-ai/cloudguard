# ============================================================
# CLOUDGUARD CHANGE RISK ENGINE
# ============================================================

from risk_engine import calculate_risk


# ============================================================
# SECURITY SEVERITY
# ============================================================

def determine_severity(state):

    if state.get("public_access") is True:
        return "HIGH"

    if state.get("encryption") is False:
        return "MEDIUM"

    if state.get("logging") is False:
        return "LOW"

    return "LOW"


# ============================================================
# INTERNET EXPOSURE
# ============================================================

def determine_internet_exposure(state):

    if state.get("public_access") is True:
        return "HIGH"

    return "LOW"


# ============================================================
# RESOURCE CRITICALITY
# ============================================================

def determine_resource_criticality(state):

    value = state.get(
        "resource_criticality",
        "HIGH"
    )

    return str(value).upper()


# ============================================================
# DATA SENSITIVITY
# ============================================================

def determine_data_sensitivity(state):

    value = state.get(
        "data_sensitivity",
        "HIGH"
    )

    return str(value).upper()


# ============================================================
# EXPLOITABILITY
# ============================================================

def determine_exploitability(state):

    value = state.get(
        "exploitability",
        "HIGH"
    )

    return str(value).upper()


# ============================================================
# CALCULATE SINGLE STATE RISK
# ============================================================

def calculate_state_risk(
    state,
    dependency_count=0
):

    severity = determine_severity(
        state
    )

    internet_exposure = (
        determine_internet_exposure(
            state
        )
    )

    resource_criticality = (
        determine_resource_criticality(
            state
        )
    )

    data_sensitivity = (
        determine_data_sensitivity(
            state
        )
    )

    exploitability = (
        determine_exploitability(
            state
        )
    )

    logging_enabled = state.get(
        "logging",
        True
    )

    risk = calculate_risk(

        severity=severity,

        internet_exposure=internet_exposure,

        resource_criticality=resource_criticality,

        data_sensitivity=data_sensitivity,

        exploitability=exploitability,

        logging_enabled=logging_enabled

    )

    return risk


# ============================================================
# CHANGE RISK ANALYSIS
# ============================================================

def calculate_change_risk(
    current_state,
    proposed_state,
    dependency_impact
):

    # --------------------------------------------------------
    # DEPENDENCIES
    # --------------------------------------------------------

    dependency_count = dependency_impact.get(
        "affected_count",
        0
    )


    # --------------------------------------------------------
    # BEFORE RISK
    # --------------------------------------------------------

    before_risk = calculate_state_risk(

        state=current_state,

        dependency_count=dependency_count

    )


    # --------------------------------------------------------
    # AFTER RISK
    # --------------------------------------------------------

    after_risk = calculate_state_risk(

        state=proposed_state,

        dependency_count=dependency_count

    )


    # --------------------------------------------------------
    # SCORES
    # --------------------------------------------------------

    before_score = before_risk[
        "risk_score"
    ]

    after_score = after_risk[
        "risk_score"
    ]


    # --------------------------------------------------------
    # RISK DELTA
    # --------------------------------------------------------

    risk_delta = (
        after_score
        - before_score
    )


    # --------------------------------------------------------
    # SECURITY IMPACT
    #
    # Final risk level takes priority over delta.
    # This prevents:
    #
    # 60 → 80
    # from being called only "MODERATE_IMPACT".
    #
    # 80 is CRITICAL in the CloudGuard risk model.
    # --------------------------------------------------------

    if risk_delta < 0:

        impact = "SECURITY_IMPROVEMENT"


    elif risk_delta == 0:

        # A configuration can technically change without
        # changing the measured risk.

        if after_risk["risk_level"] == "CRITICAL":

            impact = "CRITICAL_IMPACT"

        else:

            impact = "NO_SECURITY_CHANGE"


    elif after_risk["risk_level"] == "CRITICAL":

        impact = "CRITICAL_IMPACT"


    elif risk_delta <= 15:

        impact = "LOW_IMPACT"


    elif risk_delta <= 35:

        impact = "MODERATE_IMPACT"


    elif risk_delta <= 60:

        impact = "HIGH_IMPACT"


    else:

        impact = "CRITICAL_IMPACT"


    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    return {

        "before_risk":
            before_score,

        "before_level":
            before_risk[
                "risk_level"
            ],

        "after_risk":
            after_score,

        "after_level":
            after_risk[
                "risk_level"
            ],

        "risk_delta":
            risk_delta,

        "impact":
            impact,

        "dependency_count":
            dependency_count,

        "before_factors":
            before_risk[
                "factors"
            ],

        "after_factors":
            after_risk[
                "factors"
            ]

    }