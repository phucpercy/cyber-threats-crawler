import hashlib
import json
import logging
import re
import sys
from datetime import datetime

import boto3
from botocore.exceptions import ClientError
from botocore.vendored import requests
from bs4 import BeautifulSoup

# Set up basic logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

# Initialize DynamoDB resource and specify your table name
dynamodb = boto3.resource('dynamodb')
TABLE_NAME = 'CyberThreatData'
table = dynamodb.Table(TABLE_NAME)

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
  headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    'Accept-Encoding': 'none',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive'
  }
  try:
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
  except requests.RequestException as e:
    logger.error(f"Error fetching {url}: {e}")
    return None, None

  soup = BeautifulSoup(response.text, 'html.parser')
  # Try to extract main content within <article> or fallback to entire text if not found.
  article = soup.find("article")
  content = article.get_text(separator=" ", strip=True) if article else soup.get_text(separator=" ", strip=True)

  analysis_results = analyze_content(content)
  return analysis_results, content


def generate_threat_id(source, analysis_results):
  """
  Generate a unique ThreatID based on the source and canonicalized threat data.
  """
  # Convert analysis_results to a canonical JSON string
  canonical_data = json.dumps(analysis_results, sort_keys=True)
  # Concatenate the source and canonical threat data then hash it
  data_to_hash = source + canonical_data
  threat_id = hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()
  return threat_id


def save_to_dynamodb(source, analysis_results, raw_content):
  """
  Save the analyzed threat data to DynamoDB using a conditional write to avoid duplicates.
  """
  timestamp = datetime.utcnow().isoformat() + "Z"  # e.g., "2025-03-04T12:00:00Z"
  threat_id = generate_threat_id(source, analysis_results)

  item = {
    "ThreatID": threat_id,
    "Source": source,
    "CrawlTimestamp": timestamp,
    "ThreatCategories": analysis_results,
    "RawContent": raw_content
  }

  try:
    # Use a condition expression to ensure no duplicate ThreatID exists.
    table.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(ThreatID)"
    )
    logger.info(f"Record saved for {source} with ThreatID: {threat_id}")
  except ClientError as e:
    if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
      logger.info(f"Duplicate record for ThreatID: {threat_id}. Skipping insert.")
    else:
      logger.error(f"Error saving record to DynamoDB: {e}")


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
    analysis_results, raw_content = crawl_and_analyze(site)
    if analysis_results is not None:
      save_to_dynamodb(site, analysis_results, raw_content)
      results[site] = analysis_results
    else:
      results[site] = "Error fetching or analyzing data."

  logger.info("Crawling and saving complete.")
  return {
    "statusCode": 200,
    "body": results
  }
