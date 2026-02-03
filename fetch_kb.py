import requests
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

def fetch_data():
    username = os.getenv("QUALYS_USERNAME")
    password = os.getenv("QUALYS_PASSWORD")
    base_url = os.getenv("QUALYS_URL") 
    
    delta_date = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    api_endpoint = f"{base_url}/api/2.0/fo/knowledge_base/vuln/"
    params = {'action': 'list', 'details': 'Basic', 'published_after': delta_date}
    
    try:
        response = requests.get(api_endpoint, auth=(username, password), params=params)
        root = ET.fromstring(response.content)
        vuln_list = root.findall('.//VULN')
        
        parsed_results = []
        for v in vuln_list:
            # Capturing all common fields available in the 'Basic' details level
            parsed_results.append({
                "qid": v.findtext('QID'),
                "title": v.findtext('TITLE'),
                "category": v.findtext('CATEGORY'),
                "sub_category": v.findtext('SUB_CATEGORY'),
                "cve_id": v.findtext('CVE_ID_LIST/CVE_ID/ID') or "N/A",
                "vendor_ref": v.findtext('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE/ID') or "N/A",
                "bugtraq": v.findtext('BUGTRAQ_ID_LIST/BUGTRAQ_ID/ID') or "N/A",
                "modified": v.findtext('LAST_CUSTOMIZATION_DATETIME'),
                "published": v.findtext('PUBLISHED_DATETIME')
            })
            
        output = {
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "count": len(parsed_results),
            "data": parsed_results
        }
        
        with open('data.json', 'w') as f:
            json.dump(output, f, indent=4)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    fetch_data()
