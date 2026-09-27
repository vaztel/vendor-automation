import requests
import json
from datetime import datetime

# Mock SecurityScorecard API (free tier has limits; we'll mock for demo)
def get_security_score(vendor_domain):
    # In reality, you'd call SecurityScorecard's API:
    # api_url = f"https://api.securityscorecard.io/v1/companies/{vendor_domain}"
    # headers = {"Authorization": "Bearer YOUR_API_KEY"}
    # response = requests.get(api_url, headers=headers)
    # return response.json().get("score", 0)
    # Mock response for demo:
    mock_scores = {
        "google.com": 95,
        "unknown-vendor.com": 40,
        "github.com": 90,
        "risky-vendor.com": 30
    }
    return mock_scores.get(vendor_domain, 50)  # Default to 50 if not found

# Mock Shodan API (for open ports, vulnerabilities)
def get_shodan_risk(vendor_domain):
    # In reality: use Shodan API to check for open ports/vulnerabilities.
    # Mock response:
    mock_risks = {
        "google.com": {"open_ports": 0, "vulnerabilities": 0},
        "unknown-vendor.com": {"open_ports": 5, "vulnerabilities": 2},
        "github.com": {"open_ports": 1, "vulnerabilities": 0},
        "risky-vendor.com": {"open_ports": 10, "vulnerabilities": 5}
    }
    return mock_risks.get(vendor_domain, {"open_ports": 0, "vulnerabilities": 0})

# Risk tier calculation
def calculate_risk_tier(score, data_classification):
    # Adjust score based on data classification
    classification_weights = {
        "public": 0,
        "internal": -5,
        "confidential": -15,
        "restricted": -25
    }
    adjusted_score = score + classification_weights.get(data_classification, 0)
    adjusted_score = max(0, min(100, adjusted_score))  # Clamp between 0-100

    if adjusted_score >= 80:
        return "Low"
    elif adjusted_score >= 50:
        return "Medium"
    else:
        return "High"

# Generate triage summary
def generate_triage_summary(vendor_name, vendor_domain, category, data_classification):
    security_score = get_security_score(vendor_domain)
    shodan_data = get_shodan_risk(vendor_domain)
    risk_tier = calculate_risk_tier(security_score, data_classification)

    summary = {
        "vendor_name": vendor_name,
        "vendor_domain": vendor_domain,
        "category": category,
        "data_classification": data_classification,
        "security_score": security_score,
        "shodan_risk": shodan_data,
        "risk_tier": risk_tier,
        "timestamp": datetime.now().isoformat(),
        "recommendation": (
            "Proceed to full review (automated checks passed)."
            if risk_tier == "Low" else
            "Manual review required (elevated risk detected)."
        )
    }
    return summary

# Example usage
if __name__ == "__main__":
    # Mock user input (in reality, this would come from a form/API)
    vendor_name = "Example SaaS"
    vendor_domain = "unknown-vendor.com"  # Try "google.com" or "risky-vendor.com"
    category = "SaaS"
    data_classification = "confidential"

    triage_summary = generate_triage_summary(
        vendor_name, vendor_domain, category, data_classification
    )

    # Output as JSON
    #print(json.dumps(triage_summary, indent=2))

    # Output as Markdown
    markdown_summary = f"""
# Vendor Security Triage Summary

**Vendor:** {triage_summary['vendor_name']}
**Domain:** {triage_summary['vendor_domain']}
**Category:** {triage_summary['category']}
**Data Classification:** {triage_summary['data_classification']}

---
## Risk Assessment
- **Security Score:** {triage_summary['security_score']}/100
- **Shodan Risk:**
  - Open Ports: {triage_summary['shodan_risk']['open_ports']}
  - Vulnerabilities: {triage_summary['shodan_risk']['vulnerabilities']}
- **Risk Tier:** **{triage_summary['risk_tier']}**
- **Recommendation:** {triage_summary['recommendation']}

---
**Generated at:** {triage_summary['timestamp']}
"""
    print(markdown_summary)
