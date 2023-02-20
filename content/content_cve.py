import nvdlib as nvd
import json
import datetime
from config import CVE_COUNT_FILE, EXPORT_DIRECTORY

def create_json_file(cve_id, cvss_score, severity, description, configurations):
    # obtenir le nombre de CVE déjà présentes dans le fichier
    try:
        with open(CVE_COUNT_FILE, "r") as f:
            cve_count = int(f.read().strip())
    except FileNotFoundError:
        cve_count = 0

    # ouvrir le fichier JSON correspondant à la date actuelle
    today = datetime.date.today().strftime("%d_%m_%Y")
    filename = f"{EXPORT_DIRECTORY}/{today}.json"
    with open(filename, "a+") as f:
        f.seek(0)
        content = f.read().strip()
        if len(content) == 0:
            # écrire le nombre de CVE déjà présentes dans le fichier
            f.write(f"Nombre de CVE dans le fichier : {cve_count}\n")
        f.write("\n")
        f.write(f"Intégration n°{cve_count + 1}\n")
        f.write(f"CVE ID : {cve_id}\n")
        f.write(f"CVSS score : {cvss_score}\n")
        f.write(f"Severity : {severity}\n")
        f.write("Description :\n")
        for desc in description:
            f.write(f"\t{desc.text}\n")
        f.write("\nConfigurations : \n")
        for i, config in enumerate(configurations):
            f.write(f"\tConfiguration n°{i+1}\n")
            f.write(json.dumps(config, indent=4)) # ajout des informations de configuration en format JSON
            f.write("\n")

    # mettre à jour le nombre de CVE dans le fichier
    with open(CVE_COUNT_FILE, "w") as f:
        f.write(str(cve_count + 1))


def extract_cve_info(cve_id):
    cve = nvd.cve.searchCVE(cveId=cve_id)[0]

    cvss_score = cve.v30score
    cvss_severity = cve.v30severity
    description = cve.descriptions

    # extraire les configurations de la CVE
    configurations = []
    for configuration in cve.configurations:
        nodes = []
        for node in configuration.nodes:
            cpe_match = []
            for match in node.cpeMatch:
                print(dir(match))
                cpe_match.append({
                    "vulnerable": match.vulnerable,
                    "criteria": match.criteria,
                    "matchCriteriaId": match.cpe_name,
                    "versionStartIncluding": match.versionStartIncluding if hasattr(match, 'versionStartIncluding') else None,
                })
            nodes.append({
                "operator": node.operator,
                "negate": node.negate,
                "cpeMatch": cpe_match
            })
        configurations.append({"nodes": nodes})

    return {
        "id": cve_id,
        "cvss_score": cvss_score,
        "severity": cvss_severity,
        "description": description,
        "configurations": configurations
    }