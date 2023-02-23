#config.py

import os
import nvdlib as nvd
import datetime

# CVE à scraper 
#CVE_ID = "CVE-2019-0708"

end = datetime.datetime.now()
last4h = end - datetime.timedelta(hours=4)

last_4_h_cves = nvd.searchCVE(lastModStartDate=last4h, lastModEndDate=end)

CVE_ID = [getattr(cve, 'id') for cve in last_4_h_cves]


# Fichier contenant le compteur de CVEs traitées
CVE_COUNT_FILE = os.path.join(os.path.dirname(__file__), "data/cve_count.txt")

# Répertoire d'export des fichiers de CVEs traitées
EXPORT_DIRECTORY = os.path.join(os.path.dirname(__file__), "export")

# Fichier de configuration JSON
CONFIG_JSON_FILE = os.path.join(os.path.dirname(__file__), "data/config.json")