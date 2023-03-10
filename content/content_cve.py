#content/content_cve.py

import re
import nvdlib as nvd
from data.traitement import create_json_file

def extract_cve_info(cve_id):
    try:
        cve = nvd.searchCVE(cveId=cve_id)[0]

        cve_id = cve.id
            
        if hasattr(cve, 'v31score'):
            cve_cvss_score = cve.v31score
            cve_severity = cve.v31severity
        elif hasattr(cve, 'v30score'):
            cve_cvss_score = cve.v30score
            cve_severity = cve.v30severity
        else:
            cve_cvss_score = '//'
            cve_severity = '//'

        if cve_cvss_score == '': # remplacer par '//'
            cve_cvss_score = '//'

        if cve_severity == '': # remplacer par '//'
            cve_severity = '//'


        cve_description = cve.descriptions[0].value

        configurations = []
        for i, config in enumerate(cve.configurations):
            conf = config.nodes

            txt = ', '.join(str(x) for x in conf)

            cpe_parsed = ''

        configurations = []
        for i, config in enumerate(cve.configurations):
            conf = config.nodes
            txt = ', '.join(str(x) for x in conf)
            cpe_parsed = ''
            version_start = ''
            version_end = ''
            for match in re.finditer(r'cpe:2.3:', txt):
                cpe = txt[match.start():].split()[0][:-2].split(":")
                cpe_parsed = ":".join(cpe[:3] + cpe[4:6] + ["*", "*", "*", "*", "*", "*"])
                configurations.append((cpe_parsed, i+1, version_start, version_end))
            for match in re.finditer(r'versionStartIncluding:\s*([^\s,]+)', txt):
                version_start = match.group(1)
            for match in re.finditer(r'versionEndExcluding:\s*([^\s,]+)', txt):
                version_end = match.group(1)
                
        configurations.append((cpe_parsed, i+1, version_start, version_end))

                
        create_json_file(cve_id, cve_cvss_score, cve_severity, cve_description, configurations)

        return {
            "id": cve_id,
            "cvss_score": cve_cvss_score,
            "severity": cve_severity,
            "description": cve_description,
            "configurations": configurations
        }
    except Exception as e:
        print(f"La CVE {cve_id} semble ??tre r??cente et n'est pas encore compl??te dans la base de donn??es NVD.")
        return None