import requests
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime

def fetch_data():
    # Retrieve secrets from GitHub Environment Variables
    username = os.getenv("QUALYS_USERNAME")
    password = os.getenv("QUALYS_PASSWORD")
    base_url = os.getenv("QUALYS_URL") # e.g., https://qualysapi.qg2.apps.qualys.com
    
    # API Endpoint for Severity 5 vulnerabilities (Critical)
    # We use 'details=Basic' to keep the payload size small for GitHub Pages
    api_endpoint = f"{base_url}/api/2.0/fo/knowledge_base/vuln/?action=list&severity=5&details=Basic"
    
    headers = {
        'X-Requested-With': 'Python Requests'
    }

    try:
        response = requests.get(api_endpoint, auth=(username, password), headers=headers)
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
                "published": vuln.findtext('PUBLISHED_DATETIME')
            })
            
        # Structure the final JSON
        output_data = {
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_sev5": len(parsed_vulns),
            "recent_qids": parsed_vulns[:10]  # Store top 10 for the dashboard
        }
        
        with open('data.json', 'w') as f:
            json.dump(output_data, f, indent=4)
            
        print(f"Successfully updated data.json with {len(parsed_vulns)} QIDs.")

    except Exception as e:
        print(f"Error fetching data: {e}")

if __name__ == "__main__":
    fetch_data()
