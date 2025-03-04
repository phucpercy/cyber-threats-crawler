import requests
from bs4 import BeautifulSoup
import re
import logging

# Set up basic logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Define keywords for different cyber threat data components
cyber_threat_categories = {
    "Attack Vectors": ["phishing", "malware", "ransomware", "denial-of-service", "dos", "supply chain", "zero-day",
                       "sql injection"],
    "TTPs": ["tactics", "techniques", "procedures", "mitre", "spear phishing", "credential dumping"],
    "IoCs": ["ioc", "indicators", "ip address", "domain", "file hash", "md5", "sha-256", "registry"],
    "Attack Timelines": ["reconnaissance", "initial compromise", "lateral movement", "data exfiltration",
                         "persistence"],
    "Incident Reports": ["incident report", "case study", "breach", "forensic", "analysis"],
    "Threat Intelligence Feeds": ["threat intelligence", "feed", "alienvault", "recorded future", "threat feed"]
}

# Regular expression to find CVE identifiers
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")


def analyze_content(content):
    """
    Analyze the page content for cyber threat data indicators.
    Returns a dictionary with categories and found keywords/CVEs.
    """
    content_lower = content.lower()
    analysis_results = {}

    # Check each category for keywords
    for category, keywords in cyber_threat_categories.items():
        found_keywords = [keyword for keyword in keywords if keyword in content_lower]
        if found_keywords:
            analysis_results[category] = list(set(found_keywords))  # ensure unique keywords

    # Look for CVE identifiers using regex
    cve_matches = cve_pattern.findall(content)
    if cve_matches:
        analysis_results["CVEs"] = list(set(cve_matches))

    return analysis_results


def crawl_and_analyze(url):
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; Python crawler)'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        return None

    soup = BeautifulSoup(response.text, 'html.parser')

    # Try to extract main content within <article> or fallback to entire text if not found.
    article = soup.find("article")
    content = article.get_text(separator=" ", strip=True) if article else soup.get_text(separator=" ", strip=True)

    # Analyze the content for cyber threat data components
    analysis_results = analyze_content(content)

    logger.info(f"URL: {url}")
    if analysis_results:
        logger.info("Cyber Threat Data Identified:")
        for category, items in analysis_results.items():
            for item in items:
                logger.info(f"  - {category}: {item}")
    else:
        logger.info("No specific cyber threat data found.")

    return analysis_results


def lambda_handler(event, context):
    # List of cybersecurity websites to crawl
    websites = [
        "https://krebsonsecurity.com/",
        "https://www.schneier.com/",
        "https://www.darkreading.com/",
        "https://thehackernews.com/",
        "https://threatpost.com/",
        "https://isc.sans.edu/"
    ]

    results = {}
    for site in websites:
        logger.info(f"Fetching and analyzing: {site}")
        result = crawl_and_analyze(site)
        results[site] = result

    # Optionally, you can process results further (e.g., store in S3, send notifications)
    logger.info("Crawling complete.")

    return {
        "statusCode": 200,
        "body": results
    }




