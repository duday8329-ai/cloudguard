from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCANNER_PATH = PROJECT_ROOT / "scanner"

if str(SCANNER_PATH) not in sys.path:
    sys.path.append(str(SCANNER_PATH))


# ============================================================
# CLOUDGUARD MODULES
# ============================================================

from s3_scanner import scan_s3_configuration

from risk_engine import calculate_risk

from decision_engine import (
    make_decision,
    make_change_decision
)

from remediation_engine import (
    remediate_s3_configuration
)

from verification_engine import (
    verify_remediation
)

from change_analyzer import (
    analyze_property_changes,
    analyze_dependency_impact
)

from change_risk_engine import (
    calculate_change_risk
)

from deployment_gate import (
    evaluate_deployment
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="CloudGuard API",
    description="Change-Aware Cloud Security Gate",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATA MODELS
# ============================================================

class S3Configuration(BaseModel):

    resource_type: str

    resource_name: str

    public_access: bool

    encryption: bool

    logging: bool

    # Risk context
    resource_criticality: str = "HIGH"

    data_sensitivity: str = "HIGH"

    exploitability: str = "HIGH"


class ChangeAnalysisRequest(BaseModel):

    current_state: S3Configuration

    proposed_state: S3Configuration

    dependencies: dict[str, list[str]] = {}


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {
        "project": "CloudGuard",

        "status": "running",

        "message": (
            "CloudGuard Security Gate is online"
        )
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# S3 SECURITY SCANNER
# ============================================================

@app.post("/scan/s3")
def scan_s3(config: S3Configuration):

    configuration = config.model_dump()


    # --------------------------------------------------------
    # Step 1: Security scan
    # --------------------------------------------------------

    findings = scan_s3_configuration(
        configuration
    )


    # --------------------------------------------------------
    # Step 2: Determine highest severity
    # --------------------------------------------------------

    if any(
        finding["severity"] == "CRITICAL"
        for finding in findings
    ):

        severity = "CRITICAL"

    elif any(
        finding["severity"] == "HIGH"
        for finding in findings
    ):

        severity = "HIGH"

    elif any(
        finding["severity"] == "MEDIUM"
        for finding in findings
    ):

        severity = "MEDIUM"

    elif any(
        finding["severity"] == "LOW"
        for finding in findings
    ):

        severity = "LOW"

    else:

        severity = "LOW"


    # --------------------------------------------------------
    # Step 3: Internet exposure
    # --------------------------------------------------------

    internet_exposure = (

        "HIGH"

        if config.public_access

        else "LOW"
    )


    # --------------------------------------------------------
    # Step 4: Calculate risk
    # --------------------------------------------------------

    risk = calculate_risk(

        severity=severity,

        internet_exposure=(
            internet_exposure
        ),

        resource_criticality=(
            config.resource_criticality
        ),

        data_sensitivity=(
            config.data_sensitivity
        ),

        exploitability=(
            config.exploitability
        ),

        logging_enabled=(
            config.logging
        )
    )


    # --------------------------------------------------------
    # Step 5: Security decision
    # --------------------------------------------------------

    decision = make_decision(

        risk_score=(
            risk["risk_score"]
        ),

        risk_level=(
            risk["risk_level"]
        )
    )


    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {

        "project": "CloudGuard",

        "resource": (
            config.resource_name
        ),

        "scanner": (
            "S3 Security Scanner"
        ),

        "findings_count": (
            len(findings)
        ),

        "findings": findings,

        "risk_assessment": risk,

        "decision": decision
    }


# ============================================================
# S3 REMEDIATION
# ============================================================

@app.post("/remediate/s3")
def remediate_s3(
    config: S3Configuration
):

    configuration = config.model_dump()


    # --------------------------------------------------------
    # Step 1: Initial scan
    # --------------------------------------------------------

    initial_findings = (
        scan_s3_configuration(
            configuration
        )
    )


    # --------------------------------------------------------
    # Step 2: Apply safe remediation
    # --------------------------------------------------------

    remediation_result = (
        remediate_s3_configuration(

            configuration,

            initial_findings
        )
    )


    updated_configuration = (
        remediation_result[
            "updated_configuration"
        ]
    )


    # --------------------------------------------------------
    # Step 3: Re-scan
    # --------------------------------------------------------

    remaining_findings = (
        scan_s3_configuration(

            updated_configuration
        )
    )


    # --------------------------------------------------------
    # Step 4: Verify remediation
    # --------------------------------------------------------

    verification = (
        verify_remediation(

            remaining_findings
        )
    )


    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {

        "project": "CloudGuard",

        "resource": (
            config.resource_name
        ),

        "initial_findings_count": (
            len(initial_findings)
        ),

        "initial_findings": (
            initial_findings
        ),

        "remediation": (
            remediation_result
        ),

        "remaining_findings_count": (
            len(remaining_findings)
        ),

        "remaining_findings": (
            remaining_findings
        ),

        "verification": (
            verification
        )
    }


# ============================================================
# CHANGE-AWARE SECURITY ANALYSIS
# ============================================================

@app.post("/analyze-change")
def analyze_change(
    request: ChangeAnalysisRequest
):

    # --------------------------------------------------------
    # Convert models to dictionaries
    # --------------------------------------------------------

    current_state = (
        request.current_state.model_dump()
    )

    proposed_state = (
        request.proposed_state.model_dump()
    )


    # --------------------------------------------------------
    # Step 1: Property Change Analysis
    # --------------------------------------------------------

    property_changes = (
        analyze_property_changes(

            current_state,

            proposed_state
        )
    )


    # --------------------------------------------------------
    # Step 2: Dependency Impact Analysis
    # --------------------------------------------------------

    dependency_impact = (
        analyze_dependency_impact(

            current_state[
                "resource_name"
            ],

            request.dependencies
        )
    )


    # --------------------------------------------------------
    # Step 3: Before/After Risk Analysis
    # --------------------------------------------------------

    risk_analysis = (
        calculate_change_risk(

            current_state,

            proposed_state,

            dependency_impact
        )
    )


    # --------------------------------------------------------
    # Step 4: Change-Aware Decision
    # --------------------------------------------------------

    decision = (
        make_change_decision(

            before_risk=(
                risk_analysis[
                    "before_risk"
                ]
            ),

            after_risk=(
                risk_analysis[
                    "after_risk"
                ]
            ),

            risk_delta=(
                risk_analysis[
                    "risk_delta"
                ]
            ),

            impact=(
                risk_analysis[
                    "impact"
                ]
            )
        )
    )


    # --------------------------------------------------------
    # Step 5: Deployment Gate
    # --------------------------------------------------------

    deployment = (
        evaluate_deployment(
            decision
        )
    )


    # --------------------------------------------------------
    # Final CloudGuard Response
    # --------------------------------------------------------

    return {

        "project": "CloudGuard",

        "resource": (
            current_state[
                "resource_name"
            ]
        ),

        "change_analysis": {

            "changes_detected": (
                len(property_changes)
            ),

            "property_changes": (
                property_changes
            )
        },

        "dependency_impact": (
            dependency_impact
        ),

        "risk_analysis": (
            risk_analysis
        ),

        "decision": (
            decision
        ),

        "deployment": (
            deployment
        )
    }