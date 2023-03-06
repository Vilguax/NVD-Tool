#data/serialisation.py

def serialise_cves(cve, cvss_score, description, configurations):
    if hasattr(cve, 'v30score'):
        cvss_score = cve.v30score
    if hasattr(cve, 'v30severity'):
        severity = cve.v30severity
    if hasattr(cve, 'descriptions'):
        description = cve.descriptions

    configurations = []
    for config in cve.configurations:
        vendor = config["vendor"]["vendor_data"]["vendor_name"]
        product = config["product"]["product_data"]["product_name"]
        version = config["version"]["version_data"]["version_value"]

        # Créer un dictionnaire pour stocker les informations de chaque configuration
        config_dict = {"vendor": vendor, "product": product, "version": version}

        # Vérifier si des informations supplémentaires sont disponibles pour la configuration
        if "update" in config["version"]["version_data"]:
            config_dict["update"] = config["version"]["version_data"]["update"]

        if "edition" in config["product"]["product_data"]:
            config_dict["edition"] = config["product"]["product_data"]["edition"]

        if "language" in config["product"]["product_data"]:
            config_dict["language"] = config["product"]["product_data"]["language"]

        if "sw_edition" in config["product"]["product_data"]:
            config_dict["sw_edition"] = config["product"]["product_data"]["sw_edition"]

        if "target_sw" in config["product"]["product_data"]:
            config_dict["target_sw"] = config["product"]["product_data"]["target_sw"]

        if "target_hw" in config["product"]["product_data"]:
            config_dict["target_hw"] = config["product"]["product_data"]["target_hw"]

        # Ajouter le dictionnaire de configuration à la liste de configurations
        configurations.append(config_dict)

    return {
        "id": cve.cve_id,
        "cvss_score": cvss_score,
        "severity": severity,
        "description": description,
        "configurations": configurations,
    }
