from deployment_gate import evaluate_deployment


test_decisions = [

    {
        "action": "ALLOW"
    },

    {
        "action": "HUMAN_APPROVAL"
    },

    {
        "action": "BLOCK"
    }
]


print("\nCloudGuard Deployment Gate")
print("=" * 50)


for decision in test_decisions:

    result = evaluate_deployment(
        decision
    )

    print("\n------------------------------")

    print(
        f"Decision: "
        f"{decision['action']}"
    )

    print(
        f"Deployment Status: "
        f"{result['deployment_status']}"
    )

    print(
        f"Deployment Action: "
        f"{result['deployment_action']}"
    )

    print(
        f"Message: "
        f"{result['message']}"
    )