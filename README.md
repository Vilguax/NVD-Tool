## Projet NVD-tool


> Le projet NVD-tool CVE Scraper est un outil Python qui récupère les informations les plus récentes sur les vulnérabilités CVE (Common Vulnerabilities and Exposures) de la base de données du National Vulnerability Database (NVD) et les exporte dans des fichiers JSON.

> Par défaut la configuration permet la récupération automatique des CVE signalé par le NVD comme "modifié" à un maximum de 4h (pouvant être modifié évidemment) 

## Utilisation :
> Le projet utilise Python 3 et dépend de plusieurs packages qui doivent être installés avant de pouvoir l'exécuter. Pour installer les dépendances, exécutez la commande suivante : pip install -r requirements.txt

> Le script est exécuté à l'aide du fichier run.py, qui extrait les informations sur les vulnérabilités CVE et les enregistre dans des fichiers JSON dans le répertoire export/.

## Configuration
> Le script utilise le fichier config.py pour récupérer les identifiants des vulnérabilités CVE à extraire. Vous pouvez modifier les identifiants des vulnérabilités dans ce fichier pour extraire les informations sur d'autres CVE.

## Fichiers
> Le projet contient les fichiers suivants :

[run.py](#) le fichier principal qui extrait les informations sur les vulnérabilités CVE et les enregistre dans des fichiers JSON.
[config.py](#) le fichier de configuration qui contient les identifiants des vulnérabilités CVE à extraire, ainsi que d'autres paramètres de configuration.
[data/serialization.py](#) le module de sérialisation pour les objets CVE.
[data/traitement.py](#) le module de traitement pour la création de fichiers JSON.
[content/content_cve.py](#) le module de récupération d'informations sur les vulnérabilités CVE.
[export/dont_delete.md](#) un fichier pour indiquer qu'il ne faut pas supprimer le dossier d'export.

## Export
> Les fichiers JSON créés par le script sont enregistrés dans le répertoire export/. Il ne faut pas supprimer ce dossier, même si les fichiers JSON qu'il contient peuvent être supprimés en toute sécurité une fois qu'ils ne sont plus nécessaires.

> Pour plus d'informations sur les vulnérabilités CVE, consultez le site du NVD et/ou de la lib NVDlib.