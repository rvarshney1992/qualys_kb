import os, requests, json, xml.etree.ElementTree as ET
from datetime import datetime

def fetch_data():
    user = os.getenv("QUALYS_USERNAME")
    pw = os.getenv("QUALYS_PASSWORD")
    url = os.getenv("QUALYS_URL")
    
    # Strictly following the KB List Parameters from Guide
    params = {'action': 'list', 'details': 'All'}
    
    # Mapping verified workflow inputs to API parameters
    if os.getenv("INPUT_IDS"):
        params['ids'] = os.getenv("INPUT_IDS")
    
    if os.getenv("INPUT_DATE"):
        # Format: YYYY-MM-DD[THH:MM:SSZ]
        params['published_after'] = f"{os.getenv('INPUT_DATE')}T00:00:00Z"
        
    if os.getenv("INPUT_METHOD"):
        params['discovery_method'] = os.getenv("INPUT_METHOD")
        
    if os.getenv("INPUT_PATCHABLE"):
        params['is_patchable'] = os.getenv("INPUT_PATCHABLE")

    try:
        # V2 endpoint for KnowledgeBase
        endpoint = f"{url}/api/2.0/fo/knowledge_base/vuln/"
        headers = {"X-Requested-With": "Python Requests"}
        
        response = requests.get(endpoint, auth=(user, pw), params=params, headers=headers)
        response.raise_for_status()
        
        root = ET.fromstring(response.content)
        results = []
        
        # XML traversal based on KnowledgeBase Output DTD
        for v in root.findall('.//VULN'):
            row = {}
            for child in v:
                if len(child) > 0:
                    # Flatten nested elements (CVE_ID_LIST, RTI_LIST, etc.)
                    row[child.tag] = ", ".join([s.text for s in child.iter() if s.text and s.text.strip()])
                else:
                    row[child.tag] = child.text
            results.append(row)

        with open('data.json', 'w') as f:
            json.dump({
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "data": results,
                "params_used": params
            }, f, indent=4)
            
    except Exception as e:
        print(f"Qualys API Error: {e}")

if __name__ == "__main__":
    fetch_data()
