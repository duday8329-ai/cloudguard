const API_URL = "http://127.0.0.1:8000";


// ============================================================
// GET BOOLEAN VALUE
// ============================================================

function getBoolean(id) {

    return document.getElementById(id).value === "true";

}


// ============================================================
// BUILD CURRENT STATE
// ============================================================

function getCurrentState() {

    return {

        resource_type: "S3",

        resource_name:
            document.getElementById(
                "resourceName"
            ).value,

        public_access:
            getBoolean(
                "currentPublicAccess"
            ),

        encryption:
            getBoolean(
                "currentEncryption"
            ),

        logging:
            getBoolean(
                "currentLogging"
            ),

        resource_criticality:
            document.getElementById(
                "currentCriticality"
            ).value,

        data_sensitivity:
            document.getElementById(
                "currentSensitivity"
            ).value,

        exploitability:
            document.getElementById(
                "currentExploitability"
            ).value
    };

}


// ============================================================
// BUILD PROPOSED STATE
// ============================================================

function getProposedState() {

    return {

        resource_type: "S3",

        resource_name:
            document.getElementById(
                "resourceName"
            ).value,

        public_access:
            getBoolean(
                "proposedPublicAccess"
            ),

        encryption:
            getBoolean(
                "proposedEncryption"
            ),

        logging:
            getBoolean(
                "proposedLogging"
            ),

        resource_criticality:
            document.getElementById(
                "proposedCriticality"
            ).value,

        data_sensitivity:
            document.getElementById(
                "proposedSensitivity"
            ).value,

        exploitability:
            document.getElementById(
                "proposedExploitability"
            ).value
    };

}


// ============================================================
// ANALYZE CHANGE
// ============================================================

async function analyzeChange() {

    const button =
        document.getElementById(
            "analyzeButton"
        );

    const results =
        document.getElementById(
            "results"
        );

    const errorBox =
        document.getElementById(
            "errorMessage"
        );


    errorBox.classList.add(
        "hidden"
    );


    button.disabled = true;


    button.querySelector(
        "span"
    ).textContent =
        "ANALYZING...";


    try {

        const currentState =
            getCurrentState();


        const proposedState =
            getProposedState();


        const resourceName =
            currentState.resource_name;


        const requestBody = {

            current_state:
                currentState,

            proposed_state:
                proposedState,

            dependencies: {

                [resourceName]: [

                    "cloudguard-web-app",

                    "cloudguard-lambda",

                    "cloudguard-app-role"

                ]

            }

        };


        const response =
            await fetch(

                `${API_URL}/analyze-change`,

                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify(
                            requestBody
                        )

                }

            );


        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `API Error ${response.status}: ${errorText}`
            );

        }


        const data =
            await response.json();


        displayResults(data);


        results.classList.remove(
            "hidden"
        );


        results.scrollIntoView({

            behavior: "smooth",

            block: "start"

        });


    }

    catch (error) {

        console.error(error);


        errorBox.textContent =
            "CloudGuard API connection failed: "
            + error.message;


        errorBox.classList.remove(
            "hidden"
        );

    }

    finally {

        button.disabled = false;


        button.querySelector(
            "span"
        ).textContent =
            "ANALYZE CHANGE";

    }

}


// ============================================================
// DISPLAY RESULTS
// ============================================================

function displayResults(data) {


    const risk =
        data.risk_analysis;


    const decision =
        data.decision;


    const deployment =
        data.deployment;


    // --------------------------------------------------------
    // RISK
    // --------------------------------------------------------

    document.getElementById(
        "beforeRisk"
    ).textContent =
        `${risk.before_risk}/100`;


    document.getElementById(
        "beforeLevel"
    ).textContent =
        risk.before_level;


    document.getElementById(
        "afterRisk"
    ).textContent =
        `${risk.after_risk}/100`;


    document.getElementById(
        "afterLevel"
    ).textContent =
        risk.after_level;


    const delta =
        risk.risk_delta;


    document.getElementById(
        "riskDelta"
    ).textContent =

        delta > 0

            ? `+${delta}`

            : `${delta}`;


    document.getElementById(
        "impact"
    ).textContent =
        risk.impact;



    // --------------------------------------------------------
    // CHANGES
    // --------------------------------------------------------

    const changesList =
        document.getElementById(
            "changesList"
        );


    changesList.innerHTML = "";


    const changes =
        data.change_analysis
            .property_changes || [];


    if (changes.length === 0) {

        changesList.innerHTML = `

            <div class="change-item">

                No configuration changes detected.

            </div>

        `;

    }

    else {

        changes.forEach(
            change => {

                const item =
                    document.createElement(
                        "div"
                    );


                item.className =
                    "change-item";


                item.innerHTML = `

                    <div class="change-property">

                        ${escapeHtml(
                            change.property
                        )}

                    </div>


                    <div class="change-values">

                        ${escapeHtml(
                            String(
                                change.current_value
                            )
                        )}

                        →

                        ${escapeHtml(
                            String(
                                change.proposed_value
                            )
                        )}

                    </div>


                    <span class="impact-label">

                        ${escapeHtml(
                            change.security_impact.control
                        )}

                    </span>

                `;


                changesList.appendChild(
                    item
                );

            }
        );

    }



    // --------------------------------------------------------
    // DEPENDENCIES
    // --------------------------------------------------------

    const dependencyData =
        data.dependency_impact;


    document.getElementById(
        "dependencyCount"
    ).textContent =
        dependencyData.affected_count;


    const dependencyList =
        document.getElementById(
            "dependencyList"
        );


    dependencyList.innerHTML = "";


    if (
        dependencyData.affected_resources
            .length === 0
    ) {

        dependencyList.innerHTML = `

            <div class="dependency-item">

                No dependent resources affected.

            </div>

        `;

    }

    else {

        dependencyData
            .affected_resources
            .forEach(
                resource => {

                    const item =
                        document.createElement(
                            "div"
                        );


                    item.className =
                        "dependency-item";


                    item.textContent =
                        resource;


                    dependencyList.appendChild(
                        item
                    );

                }
            );

    }



    // --------------------------------------------------------
    // DECISION
    // --------------------------------------------------------

    document.getElementById(
        "decisionAction"
    ).textContent =
        decision.action;


    document.getElementById(
        "decisionReason"
    ).textContent =
        decision.reason;



    // --------------------------------------------------------
    // DEPLOYMENT
    // --------------------------------------------------------

    document.getElementById(
        "deploymentText"
    ).textContent =
        deployment.deployment_status;



    // --------------------------------------------------------
    // RISK FACTORS
    // --------------------------------------------------------

    displayRiskFactors(
        risk.after_factors
    );

}


// ============================================================
// DISPLAY RISK FACTORS
// ============================================================

function displayRiskFactors(
    factors
) {

    const container =
        document.getElementById(
            "riskFactors"
        );


    container.innerHTML = "";


    Object.entries(
        factors
    ).forEach(
        ([name, value]) => {

            const item =
                document.createElement(
                    "div"
                );


            item.className =
                "factor";


            item.innerHTML = `

                <span>

                    ${formatFactorName(
                        name
                    )}

                </span>


                <strong>

                    ${value}

                </strong>

            `;


            container.appendChild(
                item
            );

        }
    );

}


// ============================================================
// DEMO SCENARIOS
// ============================================================

function loadScenario(
    scenario
) {


    // --------------------------------------------------------
    // SECURITY IMPROVEMENT
    // --------------------------------------------------------

    if (
        scenario === "safe"
    ) {

        setCurrent(

            false,

            false,

            false,

            "HIGH",

            "HIGH",

            "HIGH"

        );


        setProposed(

            false,

            true,

            true,

            "HIGH",

            "HIGH",

            "HIGH"

        );

    }



    // --------------------------------------------------------
    // MODERATE RISK
    // --------------------------------------------------------

    else if (
        scenario === "moderate"
    ) {

        setCurrent(

            false,

            true,

            true,

            "HIGH",

            "HIGH",

            "HIGH"

        );


        setProposed(

            false,

            true,

            true,

            "CRITICAL",

            "HIGH",

            "HIGH"

        );

    }



    // --------------------------------------------------------
    // CRITICAL CHANGE
    // --------------------------------------------------------

    else if (
        scenario === "critical"
    ) {

        setCurrent(

            false,

            true,

            true,

            "HIGH",

            "HIGH",

            "HIGH"

        );


        setProposed(

            true,

            false,

            true,

            "HIGH",

            "HIGH",

            "HIGH"

        );

    }


    // --------------------------------------------------------
    // Scroll to configuration
    // --------------------------------------------------------

    document
        .querySelector(
            ".configuration-grid"
        )
        .scrollIntoView({

            behavior: "smooth",

            block: "start"

        });

}


// ============================================================
// SET CURRENT
// ============================================================

function setCurrent(

    publicAccess,

    encryption,

    logging,

    criticality,

    sensitivity,

    exploitability

) {

    document.getElementById(
        "currentPublicAccess"
    ).value =
        String(publicAccess);


    document.getElementById(
        "currentEncryption"
    ).value =
        String(encryption);


    document.getElementById(
        "currentLogging"
    ).value =
        String(logging);


    document.getElementById(
        "currentCriticality"
    ).value =
        criticality;


    document.getElementById(
        "currentSensitivity"
    ).value =
        sensitivity;


    document.getElementById(
        "currentExploitability"
    ).value =
        exploitability;

}


// ============================================================
// SET PROPOSED
// ============================================================

function setProposed(

    publicAccess,

    encryption,

    logging,

    criticality,

    sensitivity,

    exploitability

) {

    document.getElementById(
        "proposedPublicAccess"
    ).value =
        String(publicAccess);


    document.getElementById(
        "proposedEncryption"
    ).value =
        String(encryption);


    document.getElementById(
        "proposedLogging"
    ).value =
        String(logging);


    document.getElementById(
        "proposedCriticality"
    ).value =
        criticality;


    document.getElementById(
        "proposedSensitivity"
    ).value =
        sensitivity;


    document.getElementById(
        "proposedExploitability"
    ).value =
        exploitability;

}


// ============================================================
// FORMAT FACTOR NAME
// ============================================================

function formatFactorName(
    name
) {

    return name

        .replaceAll(
            "_",
            " "
        )

        .replace(
            /\b\w/g,
            letter =>
                letter.toUpperCase()
        );

}


// ============================================================
// HTML ESCAPING
// ============================================================

function escapeHtml(
    value
) {

    return value

        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );

}