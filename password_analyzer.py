import math
import re
import string

COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "12345678",
    "qwerty", "qwerty123", "admin", "admin123", "letmein",
    "welcome", "iloveyou", "abc123", "111111", "000000",
    "123123", "passw0rd", "password1", "changeme", "monkey"
}
KEYBOARD_PATTERNS = ("qwerty", "asdf", "zxcv", "12345", "98765", "qazwsx")

def calculate_entropy(password: str) -> float:
    """Rough theoretical estimate based on character pool; not a crack-time guarantee."""
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in string.punctuation for c in password): pool += len(string.punctuation)
    if any(c.isspace() for c in password): pool += 1
    return len(password) * math.log2(pool) if pool else 0.0

def analyze_password(password: str) -> dict:
    if not password:
        return {
            "score": 0, "strength": "Not entered", "entropy": 0.0,
            "checks": [], "suggestions": ["Enter a password to analyze it."],
            "issues": ["No password entered."]
        }

    lower = password.lower()
    checks = [
        ("At least 8 characters", len(password) >= 8),
        ("At least 12 characters (recommended)", len(password) >= 12),
        ("Contains lowercase letters", any(c.islower() for c in password)),
        ("Contains uppercase letters", any(c.isupper() for c in password)),
        ("Contains numbers", any(c.isdigit() for c in password)),
        ("Contains special characters", any(not c.isalnum() and not c.isspace() for c in password)),
        ("Not in the built-in common-password list", lower not in COMMON_PASSWORDS),
        ("No character repeated 4 or more times consecutively", not re.search(r"(.)\1{3,}", password)),
        ("No obvious keyboard/sequential pattern", not any(p in lower for p in KEYBOARD_PATTERNS)),
    ]

    score = sum(ok for _, ok in checks)
    issues = [label for label, ok in checks if not ok]
    suggestions = []
    if len(password) < 12:
        suggestions.append("Use 12–16 or more characters. Length is especially valuable.")
    if not any(c.isupper() for c in password):
        suggestions.append("Add uppercase letters.")
    if not any(c.islower() for c in password):
        suggestions.append("Add lowercase letters.")
    if not any(c.isdigit() for c in password):
        suggestions.append("Add numbers.")
    if not any(not c.isalnum() and not c.isspace() for c in password):
        suggestions.append("Add symbols, if the service allows them.")
    if lower in COMMON_PASSWORDS:
        suggestions.append("Avoid common passwords and predictable substitutions.")
    if re.search(r"(.)\1{3,}", password):
        suggestions.append("Avoid long runs of repeated characters.")
    if any(p in lower for p in KEYBOARD_PATTERNS):
        suggestions.append("Avoid keyboard walks and sequential patterns.")
    if not suggestions:
        suggestions.append("Good result. Use a different random password for every account.")

    if lower in COMMON_PASSWORDS or len(password) < 8:
        strength = "Very Weak"
    elif score <= 4:
        strength = "Weak"
    elif score <= 6:
        strength = "Moderate"
    elif score <= 8:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return {
        "score": score,
        "strength": strength,
        "entropy": round(calculate_entropy(password), 2),
        "checks": checks,
        "suggestions": suggestions,
        "issues": issues
    }
