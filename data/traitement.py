#data\traitement.py

import os
import json
from datetime import date, datetime
from .serialization import serialize_cves

def create_json_file(cve_id, cvss_score, severity, description, configurations):
    # récupérer la date actuelle au format jj_mm_aaaa
    current_date = date.today().strftime("%d_%m_%Y")

    # définir le nom de fichier avec la date du jour
    filename = f"{current_date}.json"
    file_path = os.path.join("export", filename)

    # charger le fichier de CVEs s'il existe, sinon créer un nouveau fichier
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            cves = json.load(f)
    else:
        cves = {"date": current_date, "cves": []}

    # rechercher la CVE dans le fichier JSON existant
    cve_index = -1
    for i, cve in enumerate(cves["cves"]):
        if cve["id"] == cve_id:
            cve_index = i
            break

    # créer un dictionnaire pour la nouvelle CVE
    new_cve = {
        "id": cve_id,
        "cvss_score": cvss_score,
        "severity": severity,
        "description": description,
        "configurations": configurations,
    }

    # ajouter ou mettre à jour la nouvelle CVE
    if cve_index >= 0:
        cves["cves"][cve_index] = new_cve
    else:
        cves["cves"].append(new_cve)

    # enregistrer les CVEs dans le fichier JSON
    with open(file_path, "w") as f:
        json.dump(cves, f, indent=4, default=lambda x: serialize_cves(x, cvss_score=cvss_score, description=description, configurations=configurations))
