from content.content_cve import extract_cve_info
from data.traitement import create_json_file
from config import CVE_ID

for i in CVE_ID:
    cve_info = extract_cve_info(i)
    
    cvss_score = cve_info["cvss_score"]
    severity = cve_info["severity"]
    description = cve_info["description"]
    configurations = cve_info["configurations"]
    
    create_json_file(i, cvss_score, severity, description, configurations)