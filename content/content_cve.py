import nvdlib as nvd
import sys
import os
# ajouter le chemin absolu du répertoire parent au chemin de recherche de modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import CVE_ID
from data.traitement import create_json_file

def extract_cve_info(cve_id):
    # extraire les informations de la CVE en utilisant la lib nvdlib
    cve_extracted_information = nvd.searchCVE(cveId=cve_id)[0]
    cve_id = CVE_ID
    cve_cvss_score = cve_extracted_information.v30score
    cve_severity = cve_extracted_information.v30severity
    cve_description = cve_extracted_information.descriptions[0].value

    # appeler la fonction create_json_file() pour ajouter les informations de la CVE au fichier JSON
    create_json_file(cve_id, cve_cvss_score, cve_severity, cve_description)