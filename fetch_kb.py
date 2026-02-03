import requests
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

def fetch_data():
    # Retrieve secrets from GitHub Actions Environment
    username = os.getenv("QUALYS_USERNAME")
    password = os.getenv("QUALYS_PASSWORD")
    base_url = os.getenv("QUALYS_URL") 
    
    # Calculate date: 7 days ago in YYYY-MM-DDTHH:MM:SSZ format
    # Using timezone-aware UTC for accuracy
    delta_date = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # API Parameters
    api_endpoint = f"{base_url}/api/2.0/fo/knowledge_base/vuln/"
    params = {
        'action': 'list',
        'details': 'Basic',
        'published_after': delta_date
    }
    
    headers = {'X-Requested-With': 'Python Requests'}

    try:
        response = requests.get(api_endpoint, auth=(username, password), params=params, headers=headers)
        response.raise_for_status()
        
        # Parse XML
        root = ET.fromstring(response.content)
        vuln_list = root.findall('.//VULN')
        
        parsed_results = []
        for vuln in vuln_list:
            parsed_results.append({
                "qid": vuln.findtext('QID'),
                "title": vuln.findtext('TITLE'),
                "severity": vuln.findtext('SEVERITY'),
                "category": vuln.findtext('CATEGORY'),
                "published": vuln.findtext('PUBLISHED_DATETIME')
            })
            
        # Final JSON structure
        output = {
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "time_window": f"Since {delta_date}",
            "count": len(parsed_results),
            "data": parsed_results
        }
        
        with open('data.json', 'w') as f:
            json.dump(output, f, indent=4)
            
        print(f"Success: Found {len(parsed_results)} new QIDs since {delta_date}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    fetch_data()
