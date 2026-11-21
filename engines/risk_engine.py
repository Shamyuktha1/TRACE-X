
def calculate_risk_score(alerts):
    """
    Calculate an incident-based investigation priority score.
    Each alert category contributes only once.
    Maximum score: 100.
    """

    weights = {
        "BRUTE_FORCE_ATTEMPT": 20,
        "SUCCESS_AFTER_FAILURES": 20,
        "UNFAMILIAR_IP": 10,
        "SENSITIVE_FILE_ACCESS": 10,
        "SENSITIVE_FILE_MODIFICATION": 20
    }

    detected_categories = set()
    explanations = []

    for alert in alerts:
        alert_type = alert["alert_type"]

        if alert_type == "SENSITIVE_FILE_ACTIVITY":
            if "FILE_MODIFIED" in alert["description"]:
                category = "SENSITIVE_FILE_MODIFICATION"
            else:
                category = "SENSITIVE_FILE_ACCESS"
        else:
            category = alert_type

        if category in weights and category not in detected_categories:
            detected_categories.add(category)

            explanations.append({
                "reason": category.replace("_", " ").title(),
                "points": weights[category]
            })

    score = min(sum(item["points"] for item in explanations), 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": score,
        "risk_level": level,
        "explanations": explanations
    }
