import os

# CVE à scraper 
CVE_ID = "CVE-2019-0708"

# Fichier contenant le compteur de CVEs traitées
CVE_COUNT_FILE = os.path.join(os.path.dirname(__file__), "data/cve_count.txt")

# Répertoire d'export des fichiers de CVEs traitées
EXPORT_DIRECTORY = os.path.join(os.path.dirname(__file__), "export")

# Fichier de configuration JSON
CONFIG_JSON_FILE = os.path.join(os.path.dirname(__file__), "data/config.json")