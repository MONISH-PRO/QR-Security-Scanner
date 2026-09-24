from urllib.parse import urlparse


def analyze_url(url):

    risk_score = 0
    reasons = []

    # HTTPS check
    if url.startswith("https://"):
        reasons.append("✓ Uses HTTPS")
    else:
        risk_score += 20
        reasons.append("⚠ Uses HTTP instead of HTTPS")

    # Suspicious keywords
    keywords = [
        "login",
        "signin",
        "verify",
        "account",
        "password",
        "bank",
        "confirm",
        "security"
    ]

    found = []

    for word in keywords:
        if word in url.lower():
            found.append(word)

    if found:
        risk_score += 20
        reasons.append(
            "⚠ Phishing-related keywords: "
            + ", ".join(found)
        )

    # IP address
    domain = urlparse(url).netloc

    parts = domain.split(".")

    if len(parts) == 4 and all(part.isdigit() for part in parts):
        risk_score += 30
        reasons.append("⚠ URL uses an IP address")

    # @ symbol
    if "@" in url:
        risk_score += 25
        reasons.append("⚠ URL contains @ symbol")

    # Long URL
    if len(url) > 100:
        risk_score += 10
        reasons.append("⚠ URL is unusually long")

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        status = "DANGEROUS"
    elif risk_score >= 30:
        status = "SUSPICIOUS"
    else:
        status = "NO INDICATORS DETECTED"

    return risk_score, reasons, status