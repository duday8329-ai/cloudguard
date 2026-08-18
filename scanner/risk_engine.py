SEVERITY_SCORES = {
    "LOW": 15,
    "MEDIUM": 25,
    "HIGH": 35,
    "CRITICAL": 40
}


INTERNET_SCORES = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 20,
    "CRITICAL": 25
}


CRITICALITY_SCORES = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 15,
    "CRITICAL": 20
}


SENSITIVITY_SCORES = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 15,
    "CRITICAL": 15
}


EXPLOITABILITY_SCORES = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 15,
    "CRITICAL": 15
}


def calculate_risk(
    severity,
    internet_exposure,
    resource_criticality,
    data_sensitivity,
    exploitability,
    logging_enabled=True
):

    severity_score = SEVERITY_SCORES.get(
        severity.upper(),
        0
    )

    internet_score = INTERNET_SCORES.get(
        internet_exposure.upper(),
        0
    )

    criticality_score = CRITICALITY_SCORES.get(
        resource_criticality.upper(),
        0
    )

    sensitivity_score = SENSITIVITY_SCORES.get(
        data_sensitivity.upper(),
        0
    )

    exploitability_score = EXPLOITABILITY_SCORES.get(
        exploitability.upper(),
        0
    )

    logging_control_penalty = (
        0 if logging_enabled else 10
    )

    total_score = (
        severity_score
        + internet_score
        + criticality_score
        + sensitivity_score
        + exploitability_score
        + logging_control_penalty
    )

    total_score = min(
        total_score,
        100
    )

    if total_score <= 30:
        risk_level = "LOW"

    elif total_score <= 55:
        risk_level = "MEDIUM"

    elif total_score <= 75:
        risk_level = "HIGH"

    else:
        risk_level = "CRITICAL"

    return {
        "risk_score": total_score,
        "risk_level": risk_level,
        "factors": {
            "severity": severity_score,
            "internet_exposure": internet_score,
            "resource_criticality": criticality_score,
            "data_sensitivity": sensitivity_score,
            "exploitability": exploitability_score,
            "logging_control_penalty": logging_control_penalty
        }
    }