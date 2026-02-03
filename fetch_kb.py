import requests
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

def fetch_data():
    # Retrieve secrets from GitHub Environment Variables
    username = os.getenv("QUALYS_USERNAME")
    password = os.getenv("QUALYS_PASSWORD")
    base_url = os.getenv("QUALYS_URL") 
    
    # Calculate the date for 'published_after' (e.g., last 7 days)
    # Format required: YYYY-MM-DDTHH:MM:SSZ
    target_date = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # API Endpoint using published_after instead of severity
    api_endpoint = f"{base_url}/api/2.0/fo/knowledge_base/vuln/"
    params = {
        'action': 'list',
        'details': 'Basic',
        'published_after': target_date
    }
    
    headers = {
        'X-Requested-With': 'Python Requests'
    }

    try:
        response = requests.get(api_endpoint, auth=(username, password), params=params, headers=headers)
        response.raise_for_status()
        
        # Parse XML Response
        root = ET.fromstring(response.content)
        vuln_list = root.findall('.//VULN')
        
        parsed_vulns = []
        for vuln in vuln_list:
            parsed_vulns.append({
                "qid": vuln.findtext('QID'),
                "title": vuln.findtext('TITLE'),
                "severity": vuln.findtext('SEVERITY'),
                "category": vuln.findtext('CATEGORY'),
                "published": vuln.findtext('PUBLISHED_DATETIME')
            })
            
        # Structure the final JSON for your GitHub Pages dashboard
        output_data = {
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filter_used": f"Published After {target_date}",
            "count": len(parsed_vulns),
            "vulnerabilities": parsed_vulns
        }
        
        with open('data.json', 'w') as f:
            json.dump(output_data, f, indent=4)
            
        print(f"Successfully updated data.json with {len(parsed_vulns)} records published since {target_date}.")

    except Exception as e:
        print(f"Error fetching data: {e}")

if __name__ == "__main__":
    fetch_data()
