from decision_engine import make_change_decision


test_cases = [
    {
        "before": 45,
        "after": 100,
        "delta": 55,
        "impact": "HIGH_IMPACT"
    },
    {
        "before": 60,
        "after": 80,
        "delta": 20,
        "impact": "CRITICAL_IMPACT"
    },
    {
        "before": 70,
        "after": 65,
        "delta": -5,
        "impact": "SECURITY_IMPROVEMENT"
    },
    {
        "before": 30,
        "after": 30,
        "delta": 0,
        "impact": "NO_SECURITY_CHANGE"
    }
]


print("\nCloudGuard Change Decision Engine")
print("=" * 55)


for case in test_cases:

    result = make_change_decision(
        before_risk=case["before"],
        after_risk=case["after"],
        risk_delta=case["delta"],
        impact=case["impact"]
    )

    print("\n---------------------------------------")
    print(f"Before Risk : {case['before']}")
    print(f"After Risk  : {case['after']}")
    print(f"Risk Delta  : {case['delta']:+d}")
    print(f"Impact      : {case['impact']}")
    print(f"Decision    : {result['action']}")
    print(f"Reason      : {result['reason']}")