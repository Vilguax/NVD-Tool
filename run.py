from content.content_cve import extract_cve_info
from data.traitement import create_json_file
from config import CVE_ID

# appeler la fonction extract_cve_info() pour obtenir les informations de la CVE
cve_info = extract_cve_info(CVE_ID)

# extraire les informations de la CVE du dictionnaire renvoyé par content_cve()
cve_id = CVE_ID
cvss_score = cve_info["cvss_score"]
severity = cve_info["severity"]
description = cve_info["description"]
configurations = cve_info["configurations"]

# appeler la fonction create_json_file() pour ajouter les informations de la CVE au fichier JSON
create_json_file(cve_id, cvss_score, severity, description, configurations)