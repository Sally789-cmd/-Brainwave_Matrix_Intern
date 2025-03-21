import re
from urllib.parse import urlparse

def is_valid_url(url):
    """Check if the given string is a valid URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_suspicious(url):
    """Analyze the URL for common phishing patterns."""
    phishing_keywords = [
        "login", "verify", "secure", "account", "update", "banking", "password", 
        "authenticate", "confirm", "paypal", "ebay", "reset", "support", "service", 
        "transaction", "wallet", "identity", "alert"
    ]

    # Check for too many dots
    if url.count('.') > 3:
        return "⚠️ Suspicious: Too many dots in the URL (potential subdomain attack)."

    # Check for too many hyphens (often used in deceptive domains)
    if url.count('-') > 3:
        return "⚠️ Suspicious: Too many hyphens (possible deceptive domain)."

    # Check for IP address in URL
    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", url):
        return "⚠️ Suspicious: Contains an IP address instead of a domain (common phishing tactic)."

    # Check for phishing keywords in the domain
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return "⚠️ Suspicious: Contains phishing-related keywords."

    # Check for uncommon or strange TLDs
    common_tlds = {".com", ".net", ".org", ".gov", ".edu", ".io", ".tech"}
    parsed_url = urlparse(url)
    domain_tld = "." + parsed_url.netloc.split('.')[-1]
    
    if domain_tld not in common_tlds:
        return f"⚠️ Suspicious: Uncommon TLD detected ({domain_tld})."

    return "✅ URL looks safe (Basic Check)."

# Main execution
url = input("Enter a URL to check: ").strip()

# Add "http://" prefix if missing (prevents parsing issues)
if not url.startswith(("http://", "https://")):
    url = "http://" + url

# Validate URL format before checking
if is_valid_url(url):
    print(is_suspicious(url))
else:
    print("❌ Invalid URL format. Please enter a valid URL.")

