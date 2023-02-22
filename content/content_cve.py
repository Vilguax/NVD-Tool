import re
import nvdlib as nvd
from config import CVE_ID
from data.traitement import create_json_file

def extract_cve_info(cve_id):
    try:
        cve = nvd.searchCVE(cveId=cve_id)[0]

        cve_id = CVE_ID
        cve_cvss_score = cve.v30score
        cve_severity = cve.v30severity
        cve_description = cve.descriptions[0].value

        configurations = []
        for i, config in enumerate(cve.configurations):
            conf = config.nodes

            txt = ', '.join(str(x) for x in conf)

            for match in re.finditer(r'cpe:2.3:', txt):
                cpe = txt[match.start():].split()[0][:-2].split(":")
                cpe_parsed = ":".join(cpe[:3] + cpe[4:6] + ["*", "*", "*", "*", "*", "*"])
                configurations.append((cpe_parsed, i+1))

        create_json_file(cve_id, cve_cvss_score, cve_severity, cve_description, configurations)

        return {
            "id": cve_id,
            "cvss_score": cve_cvss_score,
            "severity": cve_severity,
            "description": cve_description,
            "configurations": configurations
        }
    except Exception as e:
        print(f"An error occurred while extracting CVE information: {str(e)}")
        return None
