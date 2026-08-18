from decision_engine import make_decision


test_cases = [
    (20, "LOW"),
    (45, "MEDIUM"),
    (70, "HIGH"),
    (90, "CRITICAL")
]


print("\nCloudGuard Decision Engine")
print("=" * 40)

for score, level in test_cases:

    result = make_decision(score, level)

    print(f"\nRisk Score: {score}")
    print(f"Risk Level: {level}")
    print(f"Action: {result['action']}")
    print(f"Message: {result['message']}")