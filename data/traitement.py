import datetime
import os
import json

def create_json_file(cve_id, cvss_score, severity, description):
    # récupérer la date actuelle au format jj_mm_aaaa
    date = datetime.date.today().strftime("%d_%m_%Y")

    # définir le nom de fichier avec la date du jour
    filename = f"{date}.json"
    file_path = os.path.join("export", filename)

    # charger le fichier de CVEs s'il existe, sinon créer un nouveau fichier
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            cves = json.load(f)
    else:
        cves = {"date": date, "cves": []}

    # ajouter la nouvelle CVE
    new_cve = {"id": cve_id, "cvss_score": cvss_score, "severity": severity, "description": description}

    cves["cves"].append(new_cve)

    # enregistrer les CVEs dans le fichier JSON
    with open(file_path, "w") as f:
        json.dump(cves, f, indent=4)
